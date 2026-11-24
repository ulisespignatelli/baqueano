package exposure

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

// Multi combina varias fuentes de exposicion. La primera es la principal (si su clave falla, el escaneo
// se detiene); las demas suman y confirman: si una falla, se la deja de consultar y se anota.
type Multi struct {
	Sources []Source

	mu       sync.Mutex
	disabled map[string]bool
	notes    []string
}

// NewMulti combina fuentes; con una sola, devuelve esa misma.
func NewMulti(srcs ...Source) Source {
	if len(srcs) == 1 {
		return srcs[0]
	}
	return &Multi{Sources: srcs}
}

func (m *Multi) Name() string {
	var n []string
	for _, s := range m.Sources {
		n = append(n, s.Name())
	}
	return strings.Join(n, "+")
}

// SourceNames devuelve las fuentes activas (para el consenso).
func (m *Multi) SourceNames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n []string
	for _, s := range m.Sources {
		if !m.disabled[s.Name()] {
			n = append(n, s.Name())
		}
	}
	return n
}

// BeginScan reinicia el estado por escaneo de todas las fuentes.
func (m *Multi) BeginScan() {
	m.mu.Lock()
	m.disabled, m.notes = map[string]bool{}, nil
	m.mu.Unlock()
	for _, s := range m.Sources {
		if b, ok := s.(interface{ BeginScan() }); ok {
			b.BeginScan()
		}
	}
}

// Notes devuelve lo que paso con las fuentes secundarias.
func (m *Multi) Notes() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.notes...)
}

func (m *Multi) disable(name, why string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.disabled == nil {
		m.disabled = map[string]bool{}
	}
	if !m.disabled[name] {
		m.disabled[name] = true
		m.notes = append(m.notes, fmt.Sprintf("Se dejó de consultar %s en este escaneo: %s.", Label(name), why))
	}
}

func (m *Multi) isDisabled(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.disabled[name]
}

// Host consulta todas las fuentes y combina lo que ven.
func (m *Multi) Host(ctx context.Context, ip string) ([]domain.Service, bool, error) {
	var lists [][]domain.Service
	for i, s := range m.Sources {
		if m.isDisabled(s.Name()) {
			continue
		}
		found, _, err := s.Host(ctx, ip)
		if err != nil {
			if i == 0 {
				return nil, false, err // la principal manda
			}
			switch {
			case errors.Is(err, ErrBudget):
				m.disable(s.Name(), "se alcanzó el tope de consultas por escaneo (cada consulta consume créditos)")
			case errors.Is(err, ErrCensysAuth), errors.Is(err, ErrAuth):
				m.disable(s.Name(), err.Error())
			default:
				m.disable(s.Name(), err.Error())
			}
			continue
		}
		lists = append(lists, tag(found, s.Name()))
	}
	out := Merge(lists...)
	return out, len(out) > 0, nil
}

// SearchNetwork busca la red en la fuente principal y confirma cada IP encontrada con las demas.
func (m *Multi) SearchNetwork(ctx context.Context, cidr string, maxPages int) ([]domain.Service, error) {
	ns, ok := m.Sources[0].(NetworkSearcher)
	if !ok {
		return nil, errors.New("la fuente principal no busca redes")
	}
	found, err := ns.SearchNetwork(ctx, cidr, maxPages)
	if err != nil {
		return nil, err
	}
	lists := [][]domain.Service{tag(found, m.Sources[0].Name())}
	ips := map[string]bool{}
	for _, s := range found {
		ips[s.IP] = true
	}
	keys := make([]string, 0, len(ips))
	for ip := range ips {
		keys = append(keys, ip)
	}
	sort.Strings(keys)
	for _, s := range m.Sources[1:] {
		for _, ip := range keys {
			if m.isDisabled(s.Name()) || ctx.Err() != nil {
				break
			}
			more, _, err := s.Host(ctx, ip)
			if err != nil {
				m.disable(s.Name(), err.Error())
				break
			}
			lists = append(lists, tag(more, s.Name()))
		}
	}
	return Merge(lists...), nil
}

func tag(svcs []domain.Service, name string) []domain.Service {
	out := make([]domain.Service, len(svcs))
	for i, s := range svcs {
		if len(s.SeenBy) == 0 {
			s.SeenBy = []string{name}
		}
		out[i] = s
	}
	return out
}

// Merge combina listas de servicios de distintas fuentes. Para cada puerto se queda con los datos de la
// primera fuente que los tenga, suma las CVE de todas y anota quien lo vio.
func Merge(lists ...[]domain.Service) []domain.Service {
	byKey := map[string]*domain.Service{}
	var order []string
	for _, l := range lists {
		for _, s := range l {
			k := s.Key()
			cur, ok := byKey[k]
			if !ok {
				c := s
				c.SeenBy = append([]string(nil), s.SeenBy...)
				byKey[k] = &c
				order = append(order, k)
				continue
			}
			for _, n := range s.SeenBy {
				if !contains(cur.SeenBy, n) {
					cur.SeenBy = append(cur.SeenBy, n)
				}
			}
			if cur.Product == "" {
				cur.Product, cur.Version = s.Product, s.Version
			} else if cur.Version == "" && strings.EqualFold(cur.Product, s.Product) {
				cur.Version = s.Version
			}
			if cur.Module == "" {
				cur.Module = s.Module
			}
			if cur.Title == "" {
				cur.Title = s.Title
			}
			if cur.Cert == nil {
				cur.Cert = s.Cert
			}
			if cur.Banner == "" {
				cur.Banner = s.Banner
			}
			for _, c := range s.CPEs {
				if !contains(cur.CPEs, c) {
					cur.CPEs = append(cur.CPEs, c)
				}
			}
			for _, t := range s.Tags {
				if !contains(cur.Tags, t) {
					cur.Tags = append(cur.Tags, t)
				}
			}
			for _, v := range s.Vulns {
				dup := false
				for i := range cur.Vulns {
					if cur.Vulns[i].CVE == v.CVE {
						dup = true
						cur.Vulns[i].Verified = cur.Vulns[i].Verified || v.Verified
						cur.Vulns[i].KEV = cur.Vulns[i].KEV || v.KEV
					}
				}
				if !dup {
					cur.Vulns = append(cur.Vulns, v)
				}
			}
			if s.SeenAt.After(cur.SeenAt) {
				cur.SeenAt = s.SeenAt
			}
		}
	}
	out := make([]domain.Service, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// Label es el nombre legible de una fuente (o combinacion).
func Label(name string) string {
	labels := map[string]string{"shodan": "Shodan (API REST)", "internetdb": "Shodan InternetDB", "censys": "Censys (Platform API)"}
	var out []string
	for _, n := range strings.Split(name, "+") {
		if l := labels[n]; l != "" {
			out = append(out, l)
		} else {
			out = append(out, n)
		}
	}
	return strings.Join(out, " + ")
}
