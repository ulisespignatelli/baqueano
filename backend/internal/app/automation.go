package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
	"github.com/ulisespignatelli/baqueano/backend/internal/notify"
)

// Notifier envia avisos (notify.Sender lo cumple).
type Notifier interface {
	Send(ctx context.Context, a domain.Alert, m notify.Message) (map[string]string, error)
}

var allEvents = []string{domain.EventNewFinding, domain.EventEscalated, domain.EventNewService, domain.EventKEV, domain.EventEveryScan}

// SaveAlert crea o actualiza una alerta. Si el destino llega enmascarado (como lo muestra el panel), se
// conserva el guardado.
func (s *Service) SaveAlert(ctx context.Context, orgID string, a domain.Alert) (domain.Organization, error) {
	return s.editOrg(ctx, orgID, func(o *domain.Organization) error {
		a.Name = clean(a.Name, 80)
		a.Target = strings.TrimSpace(a.Target)
		if a.Name == "" {
			return errors.New("poné un nombre a la alerta")
		}
		var prev *domain.Alert
		for i := range o.Alerts {
			if o.Alerts[i].ID == a.ID && a.ID != "" {
				prev = &o.Alerts[i]
			}
		}
		if prev != nil && notify.IsMasked(a.Target) && prev.Channel == a.Channel {
			a.Target = prev.Target
		}
		if err := notify.ValidateTarget(a.Channel, a.Target); err != nil {
			return err
		}
		if len(a.Events) == 0 {
			return errors.New("elegí al menos un evento")
		}
		for _, e := range a.Events {
			if err := oneOf(e, allEvents, "evento"); err != nil {
				return err
			}
		}
		if a.MinSeverity != "" && a.MinSeverity.Rank() == 0 {
			return errors.New("severidad mínima inválida")
		}
		for i, r := range a.Rules {
			a.Rules[i] = strings.ToUpper(strings.TrimSpace(r))
		}
		if prev != nil {
			a.LastSent, a.LastError, a.Tickets = prev.LastSent, prev.LastError, prev.Tickets
			*prev = a
			s.audit(o, "alerta actualizada", a.Name+" · "+a.Channel)
			return nil
		}
		if len(o.Alerts) >= 20 {
			return errors.New("máximo 20 alertas por organización")
		}
		a.ID, a.Tickets = newID(), nil
		o.Alerts = append(o.Alerts, a)
		s.audit(o, "alerta agregada", a.Name+" · "+a.Channel)
		return nil
	})
}

// DeleteAlert borra una alerta.
func (s *Service) DeleteAlert(ctx context.Context, orgID, id string) (domain.Organization, error) {
	return s.editOrg(ctx, orgID, func(o *domain.Organization) error {
		for i, x := range o.Alerts {
			if x.ID == id {
				o.Alerts = append(o.Alerts[:i], o.Alerts[i+1:]...)
				s.audit(o, "alerta borrada", x.Name)
				return nil
			}
		}
		return ErrNotFound
	})
}

// TestAlert envia un aviso de prueba.
func (s *Service) TestAlert(ctx context.Context, orgID, id string) error {
	if s.Notifier == nil {
		return errors.New("el envío de avisos no está configurado")
	}
	o, err := s.Repo.GetOrg(ctx, orgID)
	if err != nil {
		return err
	}
	for _, a := range o.Alerts {
		if a.ID != id {
			continue
		}
		m := notify.Message{Event: "baqueano.test", OrgID: o.ID, Org: o.Name, Test: true, At: s.now(),
			Title: "Prueba de Baqueano · " + o.Name, Summary: "Si ves este mensaje, la alerta «" + a.Name + "» está bien configurada.",
			Items: []notify.Item{{Severity: domain.SevHigh, Title: "Ejemplo de hallazgo", Asset: "203.0.113.10:3389", Change: "nuevo", Rule: "EJEMPLO"}}}
		if a.Channel == "jira" {
			m.Items[0].FindingID = "prueba-" + s.now().Format("20060102150405")
		}
		_, err := s.Notifier.Send(ctx, a, m)
		return err
	}
	return ErrNotFound
}

// SetSchedule programa escaneos o reevaluaciones periodicas.
func (s *Service) SetSchedule(ctx context.Context, orgID string, sc domain.Schedule) (domain.Organization, error) {
	return s.editOrg(ctx, orgID, func(o *domain.Organization) error {
		if !sc.Enabled {
			if o.Schedule != nil {
				o.Schedule.Enabled = false
			}
			s.audit(o, "programación desactivada", "")
			return nil
		}
		if sc.Hours < 6 || sc.Hours > 24*30 {
			return errors.New("la frecuencia tiene que estar entre 6 horas y 30 días")
		}
		if err := oneOf(sc.Mode, []string{"escanear", "reevaluar"}, "modo"); err != nil || sc.Mode == "" {
			return errors.New("el modo es «escanear» o «reevaluar»")
		}
		next := s.now().Add(time.Duration(sc.Hours) * time.Hour)
		if o.Schedule != nil && o.Schedule.LastRun.IsZero() {
			next = s.now().Add(time.Minute) // la primera corrida, enseguida
		}
		prev := o.Schedule
		o.Schedule = &domain.Schedule{Enabled: true, Hours: sc.Hours, Mode: sc.Mode, NextRun: next}
		if prev != nil {
			o.Schedule.LastRun, o.Schedule.LastError = prev.LastRun, prev.LastError
		}
		s.audit(o, "programación", fmt.Sprintf("%s cada %d h", sc.Mode, sc.Hours))
		return nil
	})
}

// Due devuelve las organizaciones con una corrida programada pendiente.
func (s *Service) Due(ctx context.Context) ([]domain.Organization, error) {
	orgs, err := s.Repo.ListOrgs(ctx)
	if err != nil {
		return nil, err
	}
	var out []domain.Organization
	for _, o := range orgs {
		if sc := o.Schedule; sc != nil && sc.Enabled && !s.now().Before(sc.NextRun) {
			out = append(out, o)
		}
	}
	return out, nil
}

func (s *Service) markRun(ctx context.Context, orgID string, runErr error) {
	_, _ = s.editOrg(ctx, orgID, func(o *domain.Organization) error {
		if o.Schedule == nil {
			return nil
		}
		o.Schedule.LastRun = s.now()
		o.Schedule.NextRun = s.now().Add(time.Duration(o.Schedule.Hours) * time.Hour)
		o.Schedule.LastError = ""
		if runErr != nil {
			o.Schedule.LastError = runErr.Error()
		}
		return nil
	})
}

// RunDue ejecuta, una por una y esperando, las corridas pendientes. Pensado para cron o el Programador
// de tareas de Windows (baqueano run-due).
func (s *Service) RunDue(ctx context.Context, progress Progress) (int, error) {
	due, err := s.Due(ctx)
	if err != nil {
		return 0, err
	}
	for _, o := range due {
		var err error
		if o.Schedule.Mode == "reevaluar" {
			_, err = s.Reassess(ctx, o.ID, progress)
		} else {
			_, err = s.Scan(ctx, o.ID, progress)
		}
		s.markRun(ctx, o.ID, err)
	}
	return len(due), nil
}

// StartDue lanza en segundo plano las corridas pendientes (lo usa el servidor cada minuto).
func (s *Service) StartDue(ctx context.Context) {
	due, err := s.Due(ctx)
	if err != nil {
		return
	}
	for _, o := range due {
		run := s.Scan
		if o.Schedule.Mode == "reevaluar" {
			if s.Intel == nil {
				s.markRun(ctx, o.ID, errors.New("reevaluar necesita la base de inteligencia"))
				continue
			}
			run = s.Reassess
		}
		orgID := o.ID
		if _, err := s.startJobDone(orgID, run, func(err error) { s.markRun(context.Background(), orgID, err) }); err != nil && !errors.Is(err, ErrBusy) {
			s.markRun(ctx, orgID, err)
		}
	}
}

// afterSnapshot evalua las alertas de la organizacion con lo que cambio en el escaneo.
func (s *Service) afterSnapshot(ctx context.Context, snap domain.Snapshot) {
	if s.Notifier == nil {
		return
	}
	o, err := s.Repo.GetOrg(ctx, snap.OrgID)
	if err != nil || len(o.Alerts) == 0 {
		return
	}
	cur, err := s.Snapshot(ctx, snap.ID)
	if err != nil {
		return
	}
	ch, err := s.Changes(ctx, snap.ID)
	if err != nil {
		return
	}
	type result struct {
		id      string
		err     error
		tickets map[string]string
		sent    bool
	}
	var results []result
	for _, a := range o.Alerts {
		if !a.Enabled {
			continue
		}
		m, ok := buildMessage(a, o, cur, ch)
		if !ok {
			continue
		}
		m.Link = panelLink(o.ID)
		tk, err := s.Notifier.Send(ctx, a, m)
		results = append(results, result{a.ID, err, tk, true})
	}
	if len(results) == 0 {
		return
	}
	_, _ = s.editOrg(ctx, o.ID, func(o *domain.Organization) error {
		for _, r := range results {
			for i := range o.Alerts {
				a := &o.Alerts[i]
				if a.ID != r.id {
					continue
				}
				now := s.now()
				a.LastSent, a.LastError = &now, ""
				if r.err != nil {
					a.LastError = r.err.Error()
				}
				for k, v := range r.tickets {
					if a.Tickets == nil {
						a.Tickets = map[string]string{}
					}
					a.Tickets[k] = v
				}
			}
		}
		return nil
	})
}

func panelLink(orgID string) string {
	base := strings.TrimRight(os.Getenv("BAQUEANO_URL"), "/")
	if base == "" {
		return ""
	}
	return base + "/#/orgs/" + orgID + "/findings"
}

func has(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// buildMessage arma el aviso de una alerta segun sus eventos y filtros. ok=false: no hay nada que avisar.
func buildMessage(a domain.Alert, o domain.Organization, cur domain.Snapshot, ch Changes) (notify.Message, bool) {
	keep := func(f domain.Finding) bool {
		if !f.Active() || (a.MinSeverity != "" && f.Severity.Rank() < a.MinSeverity.Rank()) {
			return false
		}
		if len(a.Rules) == 0 {
			return true
		}
		for _, r := range a.Rules {
			if ruleMatches(r, f.Rule) || strings.HasPrefix(f.Rule, r) {
				return true
			}
		}
		return false
	}
	item := func(f domain.Finding, change string) notify.Item {
		return notify.Item{FindingID: f.ID, Rule: f.Rule, Severity: f.Severity, Title: f.Title, Asset: f.Asset, Detail: f.Detail,
			Change: change, KEV: f.Vuln != nil && f.Vuln.KEV}
	}
	seen := map[string]bool{}
	var items []notify.Item
	add := func(it notify.Item) {
		if it.FindingID != "" && seen[it.FindingID] {
			return
		}
		seen[it.FindingID] = true
		items = append(items, it)
	}
	first := ch.PreviousID == ""
	newFindings := ch.NewFindings
	if first {
		newFindings = cur.Findings
	}
	if has(a.Events, domain.EventKEV) {
		for _, f := range newFindings {
			if f.Vuln != nil && f.Vuln.KEV && keep(f) {
				add(item(f, "kev"))
			}
		}
		for _, c := range ch.SeverityChanges {
			if c.Up && c.Finding.Vuln != nil && c.Finding.Vuln.KEV && keep(c.Finding) {
				add(item(c.Finding, "kev"))
			}
		}
	}
	if has(a.Events, domain.EventNewFinding) {
		for _, f := range newFindings {
			if keep(f) {
				add(item(f, "nuevo"))
			}
		}
	}
	if has(a.Events, domain.EventEscalated) {
		for _, c := range ch.SeverityChanges {
			if c.Up && keep(c.Finding) {
				add(item(c.Finding, "sube-severidad"))
			}
		}
	}
	if has(a.Events, domain.EventNewService) && len(a.Rules) == 0 {
		for _, sv := range ch.NewServices {
			add(notify.Item{Severity: domain.SevInfo, Title: strings.TrimSpace(sv.Product + " " + sv.Version + " (" + sv.Module + ")"),
				Asset: fmt.Sprintf("%s:%d", sv.IP, sv.Port), Change: "servicio-nuevo"})
		}
	}
	summaryOnly := has(a.Events, domain.EventEveryScan)
	if len(items) == 0 && !summaryOnly {
		return notify.Message{}, false
	}
	active := 0
	for _, f := range cur.Findings {
		if f.Active() {
			active++
		}
	}
	title := fmt.Sprintf("Baqueano · %s: %d novedad%s", o.Name, len(items), map[bool]string{true: "", false: "es"}[len(items) == 1])
	if len(items) == 0 {
		title = fmt.Sprintf("Baqueano · %s: sin novedades", o.Name)
	}
	summary := fmt.Sprintf("Puntaje %d/100 · %d hallazgos activos · %d nuevos, %d resueltos, %d cambiaron de severidad.",
		cur.Score(), active, len(newFindings), len(ch.ResolvedFindings), len(ch.SeverityChanges))
	if first {
		summary = fmt.Sprintf("Primer escaneo: puntaje %d/100 · %d hallazgos activos.", cur.Score(), active)
	}
	return notify.Message{Event: "baqueano.scan", OrgID: o.ID, Org: o.Name, SnapshotID: cur.ID, Title: title, Summary: summary,
		Score: cur.Score(), Items: items, At: cur.FinishedAt}, true
}
