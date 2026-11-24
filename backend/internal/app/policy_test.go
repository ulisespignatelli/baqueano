package app_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ulisespignatelli/baqueano/backend/internal/adapters/store"
	"github.com/ulisespignatelli/baqueano/backend/internal/app"
	"github.com/ulisespignatelli/baqueano/backend/internal/demodata"
	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

func find(fs []domain.Finding, rule, asset string) *domain.Finding {
	for i := range fs {
		if fs[i].Rule == rule && strings.HasPrefix(fs[i].Asset, asset) {
			return &fs[i]
		}
	}
	return nil
}

func TestPolicy(t *testing.T) {
	ctx := context.Background()
	repo, _ := store.Open(t.TempDir())
	if _, err := demodata.Build(ctx, repo, start); err != nil {
		t.Fatal(err)
	}
	now := start.Add(8 * 24 * time.Hour)
	svc := &app.Service{Repo: repo, Now: func() time.Time { return now }}
	ov, _ := svc.Overview(ctx)
	acme := ov.Orgs[0]
	before := acme.Latest.Score

	// Contexto: el FTP (198.51.100.50) es de desarrollo; Grafana (198.51.100.40) es critico.
	if _, err := svc.SaveContext(ctx, acme.ID, domain.AssetContext{Match: "198.51.100.50", Environment: "desarrollo", Owner: "Equipo Web"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SaveContext(ctx, acme.ID, domain.AssetContext{Match: "198.51.100.40/32", Criticality: "alta"}); err != nil {
		t.Fatal(err)
	}
	// Regla: los paneles de administracion son criticos para esta organizacion.
	if _, err := svc.SaveRule(ctx, acme.ID, domain.SeverityRule{Rule: "HY-01", Severity: domain.SevCritical, Note: "Política interna: ningún panel público"}); err != nil {
		t.Fatal(err)
	}
	sn, err := svc.Snapshot(ctx, acme.Latest.ID)
	if err != nil {
		t.Fatal(err)
	}
	ftp := find(sn.Findings, "PX-FTP", "198.51.100.50")
	if ftp == nil || ftp.BaseSeverity != domain.SevHigh || ftp.Severity != domain.SevMedium || ftp.Owner != "Equipo Web" || len(ftp.Adjustments) != 1 {
		t.Fatalf("FTP de desarrollo debía bajar a media: %+v", ftp)
	}
	panel := find(sn.Findings, "HY-01", "198.51.100.40")
	if panel == nil || panel.Severity != domain.SevCritical || !strings.Contains(panel.Adjustments[0], "Política interna") {
		t.Fatalf("la regla debía fijar el panel en crítica: %+v", panel)
	}
	grafana := find(sn.Findings, "VU-01", "198.51.100.40")
	if grafana == nil || grafana.Criticality != "alta" || grafana.Severity != domain.SevCritical {
		t.Fatalf("la CVE de Grafana (KEV) sigue crítica en un activo crítico: %+v", grafana)
	}
	if ssh := find(sn.Findings, "PX-SSH", "198.51.100.50"); ssh != nil && ssh.Environment != "desarrollo" {
		t.Errorf("el contexto por IP alcanza a todos los puertos: %+v", ssh)
	}

	// Estados: aceptar el riesgo exige motivo, responsable y vencimiento.
	if _, err := svc.SetState(ctx, acme.ID, ftp.ID, app.StateChange{Status: "aceptado", Note: "ok"}); err == nil {
		t.Error("aceptar sin motivo suficiente debía fallar")
	}
	if _, err := svc.SetState(ctx, acme.ID, ftp.ID, app.StateChange{Status: "aceptado", Note: "Se da de baja en marzo", By: "Ulises", Until: now.AddDate(2, 0, 0).Format("2006-01-02")}); err == nil {
		t.Error("vencimiento a más de un año debía fallar")
	}
	until := now.AddDate(0, 0, 10).Format("2006-01-02")
	if _, err := svc.SetState(ctx, acme.ID, ftp.ID, app.StateChange{Status: "aceptado", Note: "Se da de baja en marzo", By: "Ulises", Until: until}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetState(ctx, acme.ID, panel.ID, app.StateChange{Status: "falso-positivo", Note: "Es un honeypot del equipo", By: "Ulises"}); err != nil {
		t.Fatal(err)
	}
	sn, _ = svc.Snapshot(ctx, acme.Latest.ID)
	if f := find(sn.Findings, "PX-FTP", "198.51.100.50"); f.State == nil || f.State.Status != "aceptado" || f.Active() {
		t.Fatalf("estado: %+v", f.State)
	}
	ov, _ = svc.Overview(ctx)
	if ov.Orgs[0].Latest.Score <= before && ov.Orgs[1].Latest != nil && ov.Orgs[0].ID == acme.ID {
		t.Errorf("sacar un hallazgo del puntaje debía mejorarlo: antes %d, ahora %d", before, ov.Orgs[0].Latest.Score)
	}

	// Vencida la aceptacion, el hallazgo vuelve a contar y lo dice.
	now = now.AddDate(0, 0, 11)
	sn, _ = svc.Snapshot(ctx, acme.Latest.ID)
	if f := find(sn.Findings, "PX-FTP", "198.51.100.50"); f.State.Status != "abierto" || !f.Active() || !strings.Contains(f.State.Note, "venció") {
		t.Fatalf("aceptación vencida: %+v", f.State)
	}
	o, _ := repo.GetOrg(ctx, acme.ID)
	if n := len(o.Audit); n < 5 || o.Audit[n-1].Action != "estado de hallazgo" {
		t.Errorf("todo debía quedar en el historial: %+v", o.Audit[n-1])
	}

	// Validaciones.
	for _, c := range []domain.AssetContext{{Match: "no valido", Environment: "desarrollo"}, {Match: "a.example", Environment: "staging"}, {Match: "a.example"}} {
		if _, err := svc.SaveContext(ctx, acme.ID, c); err == nil {
			t.Errorf("contexto inválido aceptado: %+v", c)
		}
	}
	if _, err := svc.SaveRule(ctx, acme.ID, domain.SeverityRule{Rule: "PX-*", Severity: "urgente", Note: "motivo largo"}); err == nil {
		t.Error("severidad inválida aceptada")
	}
	if _, err := svc.SetState(ctx, acme.ID, "../../etc", app.StateChange{Status: "en-curso"}); err == nil {
		t.Error("ID de hallazgo inválido aceptado")
	}
}
