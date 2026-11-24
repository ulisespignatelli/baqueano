// Package exposure obtiene lo que internet ve de una IP. Usa datos ya recolectados por Shodan: Baqueano
// no escanea ni envia trafico a los equipos analizados.
package exposure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

// Source es una fuente de exposicion.
type Source interface {
	Name() string
	// Host devuelve los servicios conocidos de una IP. found=false si la fuente no tiene datos.
	Host(ctx context.Context, ip string) (services []domain.Service, found bool, err error)
}

// NetworkSearcher es opcional: buscar una red entera en una sola consulta (mas barato que IP por IP).
type NetworkSearcher interface {
	SearchNetwork(ctx context.Context, cidr string, maxPages int) ([]domain.Service, error)
}

// ErrAuth indica una clave invalida o sin permisos. Detiene el escaneo: seguir no tiene sentido.
var ErrAuth = errors.New("la clave de Shodan es inválida o no tiene acceso a esta función")

// ---------------------------------------------------------------- Shodan (API REST, requiere membresia)

// Shodan es el cliente de la API REST. La consulta por IP no consume creditos de consulta; buscar una red
// (net:) consume 1 credito por pagina de 100 resultados.
type Shodan struct {
	key  string
	Base string
	HTTP *http.Client
	mu   sync.Mutex
	last time.Time
	Rate time.Duration // espera minima entre pedidos (la API admite ~1 por segundo)
}

// NewShodan crea el cliente. La clave nunca se escribe en errores ni registros.
func NewShodan(key string) *Shodan {
	return &Shodan{key: key, Base: "https://api.shodan.io", HTTP: &http.Client{Timeout: 30 * time.Second}, Rate: 1100 * time.Millisecond}
}

func (s *Shodan) Name() string { return "shodan" }

func (s *Shodan) wait(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.Rate - time.Since(s.last); d > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
	}
	s.last = time.Now()
	return nil
}

// get hace el pedido; reintenta ante 429/5xx. Los errores nunca incluyen la URL (lleva la clave).
func (s *Shodan) get(ctx context.Context, path string, q url.Values, out any) (int, error) {
	q.Set("key", s.key)
	u := strings.TrimSuffix(s.Base, "/") + path + "?" + q.Encode()
	for attempt := 0; ; attempt++ {
		if err := s.wait(ctx); err != nil {
			return 0, err
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		req.Header.Set("User-Agent", "baqueano")
		resp, err := s.HTTP.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			if attempt < 2 {
				continue
			}
			return 0, errors.New("Shodan no respondió") // sin el error original: contiene la URL con la clave
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusOK:
			if err := json.Unmarshal(body, out); err != nil {
				return resp.StatusCode, errors.New("respuesta inválida de Shodan")
			}
			return resp.StatusCode, nil
		case resp.StatusCode == http.StatusNotFound:
			return resp.StatusCode, nil
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			return resp.StatusCode, ErrAuth
		case (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && attempt < 3:
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 2 * time.Second):
			}
			continue
		default:
			var e struct{ Error string }
			_ = json.Unmarshal(body, &e)
			msg := e.Error
			if msg == "" {
				msg = http.StatusText(resp.StatusCode)
			}
			return resp.StatusCode, fmt.Errorf("Shodan respondió %d: %s", resp.StatusCode, msg)
		}
	}
}

// APIInfo devuelve el plan y los creditos disponibles (sirve para validar la clave).
func (s *Shodan) APIInfo(ctx context.Context) (plan string, queryCredits int, err error) {
	var info struct {
		Plan         string `json:"plan"`
		QueryCredits int    `json:"query_credits"`
	}
	code, err := s.get(ctx, "/api-info", url.Values{}, &info)
	if err == nil && code == http.StatusNotFound {
		err = ErrAuth
	}
	return info.Plan, info.QueryCredits, err
}

type shodanHost struct {
	IPStr     string         `json:"ip_str"`
	Org       string         `json:"org"`
	ISP       string         `json:"isp"`
	Country   string         `json:"country_code"`
	Hostnames []string       `json:"hostnames"`
	Data      []shodanBanner `json:"data"`
}

type shodanBanner struct {
	IPStr     string   `json:"ip_str"`
	Port      int      `json:"port"`
	Transport string   `json:"transport"`
	Product   string   `json:"product"`
	Version   string   `json:"version"`
	CPE23     []string `json:"cpe23"`
	CPE       []string `json:"cpe"`
	Data      string   `json:"data"`
	Tags      []string `json:"tags"`
	Hostnames []string `json:"hostnames"`
	Org       string   `json:"org"`
	Timestamp string   `json:"timestamp"`
	Location  struct {
		Country string `json:"country_code"`
	} `json:"location"`
	Shodan struct {
		Module string `json:"module"`
	} `json:"_shodan"`
	HTTP *struct {
		Title string `json:"title"`
	} `json:"http"`
	Vulns map[string]struct {
		CVSS     *float64 `json:"cvss"`
		EPSS     *float64 `json:"epss"`
		KEV      bool     `json:"kev"`
		Verified bool     `json:"verified"`
		Summary  string   `json:"summary"`
	} `json:"vulns"`
	SSL *struct {
		Versions []string `json:"versions"`
		Cert     struct {
			Expired bool              `json:"expired"`
			Expires string            `json:"expires"`
			Subject map[string]string `json:"subject"`
			Issuer  map[string]string `json:"issuer"`
		} `json:"cert"`
	} `json:"ssl"`
}

// Host consulta /shodan/host/{ip}.
func (s *Shodan) Host(ctx context.Context, ip string) ([]domain.Service, bool, error) {
	var h shodanHost
	code, err := s.get(ctx, "/shodan/host/"+url.PathEscape(ip), url.Values{}, &h)
	if err != nil || code == http.StatusNotFound {
		return nil, false, err
	}
	out := make([]domain.Service, 0, len(h.Data))
	for _, b := range h.Data {
		sv := bannerToService(b, "shodan")
		sv.IP = ip
		if sv.Org == "" {
			sv.Org = h.Org
		}
		if sv.Country == "" {
			sv.Country = h.Country
		}
		if len(sv.Hostnames) == 0 {
			sv.Hostnames = h.Hostnames
		}
		out = append(out, sv)
	}
	return dedupeServices(out), true, nil
}

// SearchNetwork usa la busqueda "net:" (1 credito de consulta por pagina de 100 resultados).
func (s *Shodan) SearchNetwork(ctx context.Context, cidr string, maxPages int) ([]domain.Service, error) {
	var out []domain.Service
	for page := 1; page <= maxPages; page++ {
		var r struct {
			Matches []shodanBanner `json:"matches"`
			Total   int            `json:"total"`
		}
		q := url.Values{"query": {"net:" + cidr}, "page": {fmt.Sprint(page)}}
		if _, err := s.get(ctx, "/shodan/host/search", q, &r); err != nil {
			return out, err
		}
		for _, b := range r.Matches {
			sv := bannerToService(b, "shodan")
			sv.IP = b.IPStr
			out = append(out, sv)
		}
		if page*100 >= r.Total || len(r.Matches) == 0 {
			break
		}
	}
	return dedupeServices(out), nil
}

func bannerToService(b shodanBanner, src string) domain.Service {
	sv := domain.Service{Port: b.Port, Transport: strings.ToLower(b.Transport), Product: b.Product, Version: b.Version,
		Module: strings.ToLower(strings.TrimSuffix(b.Shodan.Module, "-simple-new")), Tags: b.Tags, Hostnames: b.Hostnames,
		Org: b.Org, Country: b.Location.Country, Source: src}
	if sv.Transport == "" {
		sv.Transport = "tcp"
	}
	sv.Banner = firstLine(b.Data)
	sv.CPEs = b.CPE23
	if len(sv.CPEs) == 0 {
		sv.CPEs = b.CPE
	}
	if b.HTTP != nil {
		sv.Title = strings.TrimSpace(b.HTTP.Title)
		if len(sv.Title) > 160 {
			sv.Title = sv.Title[:160]
		}
	}
	if t, err := time.Parse("2006-01-02T15:04:05.999999", b.Timestamp); err == nil {
		sv.SeenAt = t.UTC()
	}
	for id, v := range b.Vulns {
		vu := domain.Vuln{CVE: strings.ToUpper(id), KEV: v.KEV, Verified: v.Verified, Summary: v.Summary, Origin: src}
		if v.CVSS != nil {
			vu.CVSS = *v.CVSS
		}
		if v.EPSS != nil {
			vu.EPSS = *v.EPSS
		}
		if len(vu.Summary) > 300 {
			vu.Summary = vu.Summary[:300] + "…"
		}
		sv.Vulns = append(sv.Vulns, vu)
	}
	sortVulns(sv.Vulns)
	if b.SSL != nil {
		c := &domain.Cert{Subject: b.SSL.Cert.Subject["CN"], Issuer: b.SSL.Cert.Issuer["CN"], Expired: b.SSL.Cert.Expired}
		if t, err := time.Parse("20060102150405Z", b.SSL.Cert.Expires); err == nil {
			c.NotAfter = t.UTC()
		}
		for _, v := range b.SSL.Versions {
			if !strings.HasPrefix(v, "-") { // Shodan marca con "-" las versiones que el servidor NO acepta
				c.Versions = append(c.Versions, v)
			}
		}
		for _, t := range b.Tags {
			if t == "self-signed" {
				c.SelfSigned = true
			}
		}
		sv.Cert = c
	}
	return sv
}

// ---------------------------------------------------------------- InternetDB (gratuita, sin clave)

// InternetDB es la API gratuita de Shodan: puertos, CPE, etiquetas y CVE por IP, sin detalle de banners.
type InternetDB struct {
	Base string
	HTTP *http.Client
}

// NewInternetDB crea el cliente.
func NewInternetDB() *InternetDB {
	return &InternetDB{Base: "https://internetdb.shodan.io", HTTP: &http.Client{Timeout: 20 * time.Second}}
}

func (i *InternetDB) Name() string { return "internetdb" }

// Host consulta /{ip}.
func (i *InternetDB) Host(ctx context.Context, ip string) ([]domain.Service, bool, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(i.Base, "/")+"/"+url.PathEscape(ip), nil)
	resp, err := i.HTTP.Do(req)
	if err != nil {
		return nil, false, errors.New("InternetDB no respondió")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("InternetDB respondió %d", resp.StatusCode)
	}
	var r struct {
		Ports     []int    `json:"ports"`
		CPEs      []string `json:"cpes"`
		Hostnames []string `json:"hostnames"`
		Tags      []string `json:"tags"`
		Vulns     []string `json:"vulns"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&r); err != nil {
		return nil, false, errors.New("respuesta inválida de InternetDB")
	}
	// InternetDB no dice que CVE corresponde a que puerto: se asignan al host (primer servicio) y se
	// marcan como no verificadas.
	var out []domain.Service
	for n, p := range r.Ports {
		sv := domain.Service{IP: ip, Port: p, Transport: "tcp", Tags: r.Tags, CPEs: r.CPEs, Hostnames: r.Hostnames, Source: "internetdb"}
		if n == 0 {
			for _, v := range r.Vulns {
				sv.Vulns = append(sv.Vulns, domain.Vuln{CVE: strings.ToUpper(v), Origin: "internetdb"})
			}
		}
		out = append(out, sv)
	}
	return out, true, nil
}

func dedupeServices(in []domain.Service) []domain.Service {
	seen := map[string]int{}
	var out []domain.Service
	for _, s := range in {
		if i, ok := seen[s.Key()]; ok {
			if s.SeenAt.After(out[i].SeenAt) { // Shodan puede traer varios banners del mismo puerto
				out[i] = s
			}
			continue
		}
		seen[s.Key()] = len(out)
		out = append(out, s)
	}
	return out
}

func sortVulns(v []domain.Vuln) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && less(v[j], v[j-1]); j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

func less(a, b domain.Vuln) bool {
	if a.KEV != b.KEV {
		return a.KEV
	}
	if a.EPSS != b.EPSS {
		return a.EPSS > b.EPSS
	}
	if a.CVSS != b.CVSS {
		return a.CVSS > b.CVSS
	}
	return a.CVE < b.CVE
}

// firstLine devuelve la linea del banner que identifica el software: el encabezado Server en HTTP o
// la primera linea en el resto ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"). Alcanza para reconocer
// la distro sin guardar contenido de mas.
func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if len(l) > 7 && strings.EqualFold(l[:7], "server:") {
			return strings.TrimSpace(l)
		}
	}
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
