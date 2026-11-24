package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

// Valores validos del contexto de activos.
var (
	Environments  = []string{"produccion", "pruebas", "desarrollo"}
	Criticalities = []string{"alta", "normal", "baja"}
)

var sevOrder = []domain.Severity{domain.SevInfo, domain.SevLow, domain.SevMedium, domain.SevHigh, domain.SevCritical}

func shift(s domain.Severity, d int) domain.Severity {
	i := s.Rank() - 1 + d
	if s == domain.SevInfo || i < 1 { // info no sube por contexto; nada baja a info
		if s == domain.SevInfo {
			return s
		}
		i = 1
	}
	if i >= len(sevOrder) {
		i = len(sevOrder) - 1
	}
	return sevOrder[i]
}

// ValidPattern dice si un patron de activo es valido: nombre, *.sufijo, IP o red.
func ValidPattern(p string) error {
	p = strings.TrimSpace(strings.ToLower(p))
	switch {
	case p == "":
		return errors.New("falta el activo (nombre, *.subdominio, IP o red)")
	case strings.Contains(p, "/"):
		if _, err := netip.ParsePrefix(p); err != nil {
			return fmt.Errorf("red inválida: %s", p)
		}
	case net.ParseIP(p) != nil:
	default:
		name := strings.TrimPrefix(p, "*.")
		if len(name) > 253 || !strings.Contains(name, ".") || strings.ContainsAny(name, " *:/") {
			return fmt.Errorf("activo inválido: %s", p)
		}
	}
	return nil
}

// target reune los nombres e IP con que se puede reconocer el activo de un hallazgo.
type target struct {
	names []string
	ips   []netip.Addr
}

func targetsOf(snap domain.Snapshot) func(asset string) target {
	byIP, byName := map[string][]string{}, map[string][]string{}
	for _, a := range snap.Assets {
		for _, ip := range a.IPs {
			if a.Hostname != "" {
				byIP[ip] = append(byIP[ip], strings.ToLower(a.Hostname))
				byName[strings.ToLower(a.Hostname)] = append(byName[strings.ToLower(a.Hostname)], ip)
			}
		}
	}
	return func(asset string) target {
		host := asset
		if h, _, err := net.SplitHostPort(asset); err == nil {
			host = h
		}
		host = strings.ToLower(host)
		var t target
		ipStrs := []string{}
		if net.ParseIP(host) != nil {
			ipStrs = append(ipStrs, host)
			t.names = byIP[host]
		} else {
			t.names = []string{host}
			ipStrs = byName[host]
		}
		for _, x := range ipStrs {
			if a, err := netip.ParseAddr(x); err == nil {
				t.ips = append(t.ips, a)
			}
		}
		return t
	}
}

func (t target) matches(pattern string) bool {
	p := strings.TrimSpace(strings.ToLower(pattern))
	switch {
	case p == "":
		return true
	case strings.Contains(p, "/"):
		pref, err := netip.ParsePrefix(p)
		if err != nil {
			return false
		}
		for _, ip := range t.ips {
			if pref.Contains(ip) {
				return true
			}
		}
	case net.ParseIP(p) != nil:
		a, _ := netip.ParseAddr(p)
		for _, ip := range t.ips {
			if ip == a {
				return true
			}
		}
	case strings.HasPrefix(p, "*."):
		for _, n := range t.names {
			if strings.HasSuffix(n, p[1:]) {
				return true
			}
		}
	default:
		for _, n := range t.names {
			if n == p {
				return true
			}
		}
	}
	return false
}

func ruleMatches(pattern, rule string) bool {
	switch {
	case pattern == "*":
		return true
	case strings.HasSuffix(pattern, "*"):
		return strings.HasPrefix(rule, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == rule
}

// ApplyPolicy aplica a un escaneo el contexto, las reglas y los estados de la organizacion. No modifica
// lo guardado: la severidad original queda en BaseSeverity.
func ApplyPolicy(snap *domain.Snapshot, o domain.Organization, now time.Time) {
	tgt := targetsOf(*snap)
	out := make([]domain.Finding, len(snap.Findings))
	for i, f := range snap.Findings {
		if f.BaseSeverity == "" {
			f.BaseSeverity = f.Severity
		}
		f.Severity, f.Adjustments = f.BaseSeverity, nil
		t := tgt(f.Asset)
		for _, c := range o.Contexts {
			if t.matches(c.Match) {
				f.Environment, f.Criticality, f.Owner = c.Environment, c.Criticality, c.Owner
				break
			}
		}
		ruled := false
		for _, r := range o.Rules {
			if ruleMatches(r.Rule, f.Rule) && t.matches(r.Match) && (r.Environment == "" || r.Environment == f.Environment) {
				if f.Severity != r.Severity {
					f.Adjustments = append(f.Adjustments, fmt.Sprintf("Regla de la organización: %s → %s. %s", f.Severity, r.Severity, r.Note))
				}
				f.Severity, ruled = r.Severity, true
				break
			}
		}
		if !ruled {
			exploited := f.Vuln != nil && (f.Vuln.KEV || f.Vuln.Priority == "P1")
			switch {
			case (f.Environment == "desarrollo" || f.Environment == "pruebas") && !exploited:
				if n := shift(f.Severity, -1); n != f.Severity {
					f.Adjustments = append(f.Adjustments, fmt.Sprintf("Ambiente de %s: baja de %s a %s.", f.Environment, f.Severity, n))
					f.Severity = n
				}
			}
			switch f.Criticality {
			case "alta":
				if n := shift(f.Severity, 1); n != f.Severity {
					f.Adjustments = append(f.Adjustments, fmt.Sprintf("Activo de criticidad alta: sube de %s a %s.", f.Severity, n))
					f.Severity = n
				}
			case "baja":
				if !exploited {
					if n := shift(f.Severity, -1); n != f.Severity {
						f.Adjustments = append(f.Adjustments, fmt.Sprintf("Activo de criticidad baja: baja de %s a %s.", f.Severity, n))
						f.Severity = n
					}
				}
			}
		}
		f.State = nil
		if st, ok := o.States[f.ID]; ok {
			st := st
			if st.Status == domain.StatusAccepted && st.Until != nil && now.After(*st.Until) {
				st.Note = fmt.Sprintf("La aceptación venció el %s. Motivo anterior: %s", st.Until.Format("2006-01-02"), st.Note)
				st.Status = domain.StatusOpen
			}
			f.State = &st
		}
		out[i] = f
	}
	snap.Findings = out
}

// Snapshot devuelve un escaneo con la politica de su organizacion aplicada.
func (s *Service) Snapshot(ctx context.Context, id string) (domain.Snapshot, error) {
	sn, err := s.Repo.GetSnapshot(ctx, id)
	if err != nil {
		return sn, err
	}
	if o, err := s.Repo.GetOrg(ctx, sn.OrgID); err == nil {
		ApplyPolicy(&sn, o, s.now())
	}
	return sn, nil
}

// SnapshotMetas devuelve los resumenes de una organizacion con la politica aplicada (puntajes coherentes
// con lo que se ve en cada escaneo).
func (s *Service) SnapshotMetas(ctx context.Context, orgID string, limit int) ([]SnapshotMeta, error) {
	metas, err := s.Repo.ListSnapshots(ctx, orgID)
	if err != nil {
		return nil, err
	}
	o, err := s.Repo.GetOrg(ctx, orgID)
	if err != nil {
		return metas, nil
	}
	if !hasPolicy(o) {
		return metas, nil
	}
	for i := range metas {
		if limit > 0 && i >= limit {
			break
		}
		sn, err := s.Repo.GetSnapshot(ctx, metas[i].ID)
		if err != nil {
			continue
		}
		ApplyPolicy(&sn, o, s.now())
		metas[i] = Meta(sn)
	}
	return metas, nil
}

func hasPolicy(o domain.Organization) bool {
	return len(o.Contexts) > 0 || len(o.Rules) > 0 || len(o.States) > 0
}

// ---- Edicion de la politica ----

func (s *Service) editOrg(ctx context.Context, orgID string, fn func(o *domain.Organization) error) (domain.Organization, error) {
	s.editMu.Lock() // leer-modificar-guardar sin pisar otra edicion simultanea (p. ej. una alerta enviada)
	defer s.editMu.Unlock()
	o, err := s.Repo.GetOrg(ctx, orgID)
	if err != nil {
		return o, err
	}
	if err := fn(&o); err != nil {
		return o, err
	}
	return o, s.Repo.SaveOrg(ctx, o)
}

func oneOf(v string, allowed []string, what string) error {
	if v == "" {
		return nil
	}
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return fmt.Errorf("%s inválido: %q (valores: %s)", what, v, strings.Join(allowed, ", "))
}

func clean(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		s = s[:max]
	}
	return s
}

// SaveContext crea o actualiza (por ID) el contexto de un grupo de activos.
func (s *Service) SaveContext(ctx context.Context, orgID string, c domain.AssetContext) (domain.Organization, error) {
	return s.editOrg(ctx, orgID, func(o *domain.Organization) error {
		c.Match = strings.ToLower(strings.TrimSpace(c.Match))
		c.Owner, c.Note = clean(c.Owner, 120), clean(c.Note, 300)
		if err := ValidPattern(c.Match); err != nil {
			return err
		}
		if err := oneOf(c.Environment, Environments, "ambiente"); err != nil {
			return err
		}
		if err := oneOf(c.Criticality, Criticalities, "criticidad"); err != nil {
			return err
		}
		if c.Environment == "" && c.Criticality == "" && c.Owner == "" {
			return errors.New("indicá al menos el ambiente, la criticidad o el responsable")
		}
		for i, x := range o.Contexts {
			if x.ID == c.ID && c.ID != "" {
				o.Contexts[i] = c
				s.audit(o, "contexto actualizado", c.Match)
				return nil
			}
		}
		if len(o.Contexts) >= 100 {
			return errors.New("máximo 100 contextos por organización")
		}
		c.ID = newID()
		o.Contexts = append(o.Contexts, c)
		s.audit(o, "contexto agregado", describeContext(c))
		return nil
	})
}

func describeContext(c domain.AssetContext) string {
	return strings.Join(nonEmptyStr(c.Match, c.Environment, c.Criticality, c.Owner), " · ")
}

func nonEmptyStr(xs ...string) []string {
	var out []string
	for _, x := range xs {
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

// DeleteContext borra un contexto.
func (s *Service) DeleteContext(ctx context.Context, orgID, id string) (domain.Organization, error) {
	return s.editOrg(ctx, orgID, func(o *domain.Organization) error {
		for i, x := range o.Contexts {
			if x.ID == id {
				o.Contexts = append(o.Contexts[:i], o.Contexts[i+1:]...)
				s.audit(o, "contexto borrado", x.Match)
				return nil
			}
		}
		return ErrNotFound
	})
}

// SaveRule crea o actualiza una regla de severidad.
func (s *Service) SaveRule(ctx context.Context, orgID string, r domain.SeverityRule) (domain.Organization, error) {
	return s.editOrg(ctx, orgID, func(o *domain.Organization) error {
		r.Rule = strings.ToUpper(strings.TrimSpace(r.Rule))
		r.Match = strings.ToLower(strings.TrimSpace(r.Match))
		r.Note = clean(r.Note, 300)
		if r.Rule == "" || len(r.Rule) > 40 || strings.ContainsAny(r.Rule, " /") {
			return errors.New("control inválido (por ejemplo PX-RDP, PX-* o *)")
		}
		if r.Match != "" {
			if err := ValidPattern(r.Match); err != nil {
				return err
			}
		}
		if err := oneOf(r.Environment, Environments, "ambiente"); err != nil {
			return err
		}
		if r.Severity.Rank() == 0 {
			return errors.New("severidad inválida")
		}
		if len(r.Note) < 5 {
			return errors.New("explicá el motivo de la regla (queda en el historial)")
		}
		for i, x := range o.Rules {
			if x.ID == r.ID && r.ID != "" {
				o.Rules[i] = r
				s.audit(o, "regla actualizada", fmt.Sprintf("%s → %s: %s", r.Rule, r.Severity, r.Note))
				return nil
			}
		}
		if len(o.Rules) >= 100 {
			return errors.New("máximo 100 reglas por organización")
		}
		r.ID = newID()
		o.Rules = append(o.Rules, r)
		s.audit(o, "regla agregada", fmt.Sprintf("%s → %s: %s", r.Rule, r.Severity, r.Note))
		return nil
	})
}

// DeleteRule borra una regla.
func (s *Service) DeleteRule(ctx context.Context, orgID, id string) (domain.Organization, error) {
	return s.editOrg(ctx, orgID, func(o *domain.Organization) error {
		for i, x := range o.Rules {
			if x.ID == id {
				o.Rules = append(o.Rules[:i], o.Rules[i+1:]...)
				s.audit(o, "regla borrada", x.Rule)
				return nil
			}
		}
		return ErrNotFound
	})
}

// StateChange es el pedido de cambiar el estado de un hallazgo.
type StateChange struct {
	Status string `json:"status"`
	Note   string `json:"note"`
	By     string `json:"by"`
	Until  string `json:"until"` // AAAA-MM-DD, obligatorio para aceptar el riesgo
}

// SetState cambia el estado de un hallazgo. Aceptar un riesgo exige motivo, responsable y vencimiento
// (hasta un año): asi ninguna aceptacion queda olvidada.
func (s *Service) SetState(ctx context.Context, orgID, findingID string, c StateChange) (domain.Organization, error) {
	return s.editOrg(ctx, orgID, func(o *domain.Organization) error {
		if !validID(findingID) {
			return ErrNotFound
		}
		c.Note, c.By = clean(c.Note, 500), clean(c.By, 120)
		st := domain.FindingState{Status: c.Status, Note: c.Note, By: c.By, At: s.now()}
		switch c.Status {
		case domain.StatusOpen:
			if _, ok := o.States[findingID]; ok {
				delete(o.States, findingID)
				s.audit(o, "hallazgo reabierto", findingID+ifNote(c.Note))
			}
			return nil
		case domain.StatusInProgress:
		case domain.StatusFalsePositive, domain.StatusAccepted:
			if len(c.Note) < 5 {
				return errors.New("explicá el motivo (queda en el historial)")
			}
			if len(c.By) < 3 {
				return errors.New("indicá quién toma la decisión")
			}
			if c.Status == domain.StatusAccepted {
				until, err := time.Parse("2006-01-02", c.Until)
				if err != nil {
					return errors.New("la aceptación necesita una fecha de vencimiento (AAAA-MM-DD)")
				}
				until = until.Add(24*time.Hour - time.Second)
				if !until.After(s.now()) || until.After(s.now().AddDate(1, 0, 0)) {
					return errors.New("el vencimiento tiene que ser en el futuro y como máximo dentro de un año")
				}
				st.Until = &until
			}
		default:
			return fmt.Errorf("estado inválido: %q", c.Status)
		}
		if o.States == nil {
			o.States = map[string]domain.FindingState{}
		}
		if len(o.States) >= 5000 {
			return errors.New("demasiados estados guardados")
		}
		o.States[findingID] = st
		detail := findingID + " · " + c.Status + ifNote(c.Note)
		if st.Until != nil {
			detail += " · vence " + st.Until.Format("2006-01-02")
		}
		s.audit(o, "estado de hallazgo", detail)
		return nil
	})
}

func ifNote(n string) string {
	if n == "" {
		return ""
	}
	return " · " + n
}

func validID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
