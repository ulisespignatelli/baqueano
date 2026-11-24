package app_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ulisespignatelli/baqueano/backend/internal/adapters/store"
	"github.com/ulisespignatelli/baqueano/backend/internal/app"
	"github.com/ulisespignatelli/baqueano/backend/internal/demodata"
	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
	"github.com/ulisespignatelli/baqueano/backend/internal/intel"
	"github.com/ulisespignatelli/baqueano/backend/internal/notify"
)

type fakeNotifier struct {
	mu   sync.Mutex
	sent []notify.Message
	to   []domain.Alert
}

func (f *fakeNotifier) Send(_ context.Context, a domain.Alert, m notify.Message) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent, f.to = append(f.sent, m), append(f.to, a)
	tk := map[string]string{}
	if a.Channel == "jira" {
		for _, it := range m.Items {
			if it.FindingID != "" {
				tk[it.FindingID] = "SEC-" + it.FindingID[:4]
			}
		}
	}
	return tk, nil
}

func TestAlertsAndSchedule(t *testing.T) {
	ctx := context.Background()
	repo, _ := store.Open(t.TempDir())
	if _, err := demodata.Build(ctx, repo, start); err != nil {
		t.Fatal(err)
	}
	now := start.Add(8 * 24 * time.Hour)
	eng := intel.NewMemory(demodata.Intel())
	fn := &fakeNotifier{}
	svc := &app.Service{Repo: repo, Intel: eng, Notifier: fn, Now: func() time.Time { return now }}
	ov, _ := svc.Overview(ctx)
	acme := ov.Orgs[0].ID
	if o, _ := repo.GetOrg(ctx, acme); len(o.Alerts) > 0 { // la demo trae alertas propias
		for _, a := range o.Alerts {
			if _, err := svc.DeleteAlert(ctx, acme, a.ID); err != nil {
				t.Logf("borrar %s: %v", a.Name, err)
			}
		}
	}

	// Validaciones.
	for _, a := range []domain.Alert{
		{Name: "x", Channel: "slack", Target: "http://hooks.slack.com/x", Events: []string{"kev"}},
		{Name: "x", Channel: "slack", Target: "https://hooks.slack.com/x", Events: []string{"cualquiera"}},
		{Name: "", Channel: "jira", Target: "SEC", Events: []string{"kev"}},
	} {
		if _, err := svc.SaveAlert(ctx, acme, a); err == nil {
			t.Errorf("alerta inválida aceptada: %+v", a)
		}
	}
	// Una alerta solo de KEV y una de Jira para criticas nuevas.
	o, err := svc.SaveAlert(ctx, acme, domain.Alert{Name: "KEV a Slack", Channel: "slack", Target: "https://hooks.slack.com/services/T/B/secreto123", Events: []string{"kev"}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SaveAlert(ctx, acme, domain.Alert{Name: "Críticas a Jira", Channel: "jira", Target: "SEC", Events: []string{"hallazgo-nuevo", "sube-severidad"}, MinSeverity: domain.SevCritical, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// El panel devuelve el destino enmascarado: guardar sin cambiarlo conserva el original.
	a := o.Alerts[0]
	a.Target = notify.Mask(a.Channel, a.Target)
	a.Name = "KEV a Slack (renombrada)"
	o, _ = svc.SaveAlert(ctx, acme, a)
	if o.Alerts[0].Target != "https://hooks.slack.com/services/T/B/secreto123" {
		t.Fatalf("el destino enmascarado debía conservar el original: %s", o.Alerts[0].Target)
	}

	// CISA agrega CVE-2099-0106 a KEV: la reevaluacion avisa a las dos alertas.
	now = now.Add(time.Hour)
	eng.DB().KEV["CVE-2099-0106"] = intel.KEVEntry{Due: "2099-03-01"}
	if _, err := svc.Reassess(ctx, acme, nil); err != nil {
		t.Fatal(err)
	}
	if len(fn.sent) != 2 {
		t.Fatalf("esperaba 2 avisos, hubo %d", len(fn.sent))
	}
	for i, m := range fn.sent {
		if len(m.Items) != 1 || !strings.Contains(m.Items[0].Title, "CVE-2099-0106") {
			t.Errorf("aviso %d (%s): %+v", i, fn.to[i].Name, m.Items)
		}
	}
	o, _ = repo.GetOrg(ctx, acme)
	if o.Alerts[1].Tickets == nil || len(o.Alerts[1].Tickets) != 1 || o.Alerts[0].LastSent == nil {
		t.Errorf("debía guardar el ticket y la fecha de envío: %+v", o.Alerts)
	}
	// Sin cambios, no hay avisos.
	now = now.Add(time.Hour)
	if _, err := svc.Reassess(ctx, acme, nil); err != nil {
		t.Fatal(err)
	}
	if len(fn.sent) != 2 {
		t.Errorf("sin novedades no debía avisar: %d", len(fn.sent))
	}

	// Programacion: la primera corrida es enseguida; run-due la ejecuta y reprograma.
	if _, err := svc.SetSchedule(ctx, acme, domain.Schedule{Enabled: true, Hours: 2, Mode: "reevaluar"}); err == nil {
		t.Error("frecuencia menor a 6 h aceptada")
	}
	if _, err := svc.SetSchedule(ctx, acme, domain.Schedule{Enabled: true, Hours: 24, Mode: "reevaluar"}); err != nil {
		t.Fatal(err)
	}
	if n, _ := svc.RunDue(ctx, nil); n != 0 {
		t.Error("todavía no tocaba")
	}
	now = now.Add(25 * time.Hour)
	if n, err := svc.RunDue(ctx, nil); n != 1 || err != nil {
		t.Fatalf("run-due: %d %v", n, err)
	}
	o, _ = repo.GetOrg(ctx, acme)
	if o.Schedule.LastRun != now || !o.Schedule.NextRun.Equal(now.Add(24*time.Hour)) || o.Schedule.LastError != "" {
		t.Errorf("programación: %+v", o.Schedule)
	}
}

func TestPrune(t *testing.T) {
	ctx := context.Background()
	repo, _ := store.Open(t.TempDir())
	if _, err := demodata.Build(ctx, repo, start); err != nil {
		t.Fatal(err)
	}
	now := start.Add(400 * 24 * time.Hour)
	svc := &app.Service{Repo: repo, Now: func() time.Time { return now }}
	if n, err := svc.Prune(ctx, 365, 1); n != 1 || err != nil { // Acme tiene 2 escaneos viejos: queda el ultimo
		t.Fatalf("prune: %d %v", n, err)
	}
	if n, _ := svc.Prune(ctx, 365, 1); n != 0 {
		t.Error("el último escaneo de cada organización nunca se borra")
	}
}
