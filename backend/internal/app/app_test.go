package app_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ulisespignatelli/baqueano/backend/internal/adapters/store"
	"github.com/ulisespignatelli/baqueano/backend/internal/app"
	"github.com/ulisespignatelli/baqueano/backend/internal/demodata"
	"github.com/ulisespignatelli/baqueano/backend/internal/discovery"
	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

var start = time.Date(2026, 11, 16, 14, 0, 0, 0, time.UTC)

func TestScenario(t *testing.T) {
	ctx := context.Background()
	repo, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	exp, err := demodata.Build(ctx, repo, start)
	if err != nil {
		t.Fatal(err)
	}
	svc := &app.Service{Repo: repo}
	o, err := svc.Overview(ctx)
	if err != nil || len(o.Orgs) != 2 {
		t.Fatalf("overview: %v %+v", err, o)
	}
	acme := o.Orgs[0] // ordenadas de peor a mejor
	if acme.Name != "Acme Logística" || len(acme.Trend) != 2 || acme.Trend[1].Score <= acme.Trend[0].Score {
		t.Fatalf("Acme mejora entre escaneos: %+v", acme.Trend)
	}
	snap, err := repo.GetSnapshot(ctx, acme.Latest.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range snap.Services {
		if strings.Contains(s.Product, "NO DEBE APARECER") || strings.HasPrefix(s.IP, "192.0.2.") {
			t.Fatalf("se consultó una IP de un tercero (CDN/SaaS): %+v", s)
		}
	}
	rules := map[string]bool{}
	for _, f := range snap.Findings {
		rules[f.Rule] = true
	}
	for _, r := range []string{"PX-ICS", "PX-DB", "VU-01", "DNS-01", "HY-01", "HY-02", "TLS-01", "TLS-03", "TLS-04", "PX-FTP", "PX-SSH"} {
		if !rules[r] {
			t.Errorf("falta %s", r)
		}
	}
	if rules["PX-RDP"] || rules["TLS-02"] {
		t.Error("RDP se cerró y el certificado del correo se renovó")
	}
	clinicOrg := o.Orgs[1]
	clinicSnap, _ := repo.GetSnapshot(ctx, clinicOrg.Latest.ID)
	if len(clinicSnap.Authorization) != 1 || !strings.Contains(clinicSnap.Authorization[0], "declarado") {
		t.Fatalf("Clínica Norte se analiza con alcance declarado: %+v", clinicSnap.Authorization)
	}
	if exp.Calls > 10 {
		t.Errorf("la red declarada se resuelve con una búsqueda, no IP por IP: %d consultas", exp.Calls)
	}

	ch, err := svc.Changes(ctx, snap.ID)
	if err != nil || ch.PreviousID == "" {
		t.Fatalf("cambios: %v", err)
	}
	if len(ch.NewServices) != 1 || ch.NewServices[0].Port != 9200 || len(ch.ClosedServices) != 2 {
		t.Fatalf("servicios nuevos/cerrados: %+v / %+v", ch.NewServices, ch.ClosedServices)
	}
	resolved := map[string]bool{}
	for _, f := range ch.ResolvedFindings {
		resolved[f.Rule] = true
	}
	if !resolved["PX-RDP"] || !resolved["TLS-02"] || len(ch.NewFindings) != 1 {
		t.Fatalf("hallazgos resueltos/nuevos: %v / %+v", resolved, ch.NewFindings)
	}
}

func TestAuthorization(t *testing.T) {
	ctx := context.Background()
	repo, _ := store.Open(t.TempDir())
	now := start
	dns, names, exp := demodata.World(now, 0, map[string]string{demodata.Acme: "otro-token"})
	ct := demodata.CTServer(names)
	defer ct.Close()
	d := discovery.New()
	d.CTBase, d.DNS = ct.URL, dns
	svc := &app.Service{Repo: repo, DNS: dns, Discovery: d, Exposure: exp, Now: func() time.Time { return now }}
	org, err := svc.CreateOrg(ctx, app.NewOrg{Name: "Acme", Domains: []string{demodata.Acme}})
	if err != nil {
		t.Fatal(err)
	}
	// Sin declaración y con un TXT que no es el suyo: nada autorizado.
	if _, err := svc.Scan(ctx, org.ID, nil); err == nil || !strings.Contains(err.Error(), "autorizado") {
		t.Fatalf("sin autorización no se escanea: %v", err)
	}
	if exp.Calls != 0 {
		t.Fatal("no debería haber consultado nada")
	}
	// Verificación DNS opcional: se publica el token, se verifica; si se retira, se pierde.
	dns.TXT[demodata.Acme] = []string{"baqueano-verify=" + org.Domains[0].Token}
	org, _ = svc.VerifyDomains(ctx, org.ID)
	if !org.Domains[0].Verified() {
		t.Fatal("debería verificar")
	}
	delete(dns.TXT, demodata.Acme)
	org, _ = svc.VerifyDomains(ctx, org.ID)
	if org.Domains[0].Verified() {
		t.Fatal("al retirar el registro se retira la verificación")
	}
	// Con la declaración de responsabilidad se puede escanear sin tocar el DNS.
	if _, err := svc.Attest(ctx, org.ID, "x"); err == nil {
		t.Fatal("la declaración necesita un nombre")
	}
	org, err = svc.Attest(ctx, org.ID, "Ulises Pignatelli")
	if err != nil || org.Attestation == nil || org.Attestation.Statement != domain.AttestationText {
		t.Fatalf("declaración: %v %+v", err, org.Attestation)
	}
	org, _ = svc.AddNetwork(ctx, org.ID, "203.0.113.0/28")
	snap, err := svc.Scan(ctx, org.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Authorization) == 0 || !strings.Contains(snap.Authorization[0], "Ulises Pignatelli") || len(snap.Networks) != 1 {
		t.Fatalf("el escaneo deja constancia de la autorización: %+v", snap)
	}
	got, _ := repo.GetOrg(ctx, org.ID)
	actions := map[string]bool{}
	for _, a := range got.Audit {
		actions[a.Action] = true
	}
	for _, a := range []string{"organización creada", "dominio verificado en DNS", "verificación DNS retirada", "declaración de responsabilidad", "red agregada", "escaneo"} {
		if !actions[a] {
			t.Errorf("falta en la auditoría: %s", a)
		}
	}
}

func TestOrgValidation(t *testing.T) {
	repo, _ := store.Open(t.TempDir())
	svc := &app.Service{Repo: repo}
	ctx := context.Background()
	for name, in := range map[string]app.NewOrg{
		"nombre vacío":      {Name: "", Domains: []string{"a.example"}},
		"sin dominios":      {Name: "X"},
		"dominio repetido":  {Name: "X", Domains: []string{"a.example", "A.EXAMPLE"}},
		"dominio inválido":  {Name: "X", Domains: []string{"no es un dominio"}},
		"red privada":       {Name: "X", Domains: []string{"a.example"}, Networks: []string{"10.0.0.0/24"}},
		"red enorme":        {Name: "X", Domains: []string{"a.example"}, Networks: []string{"8.0.0.0/8"}},
		"responsable corto": {Name: "X", Domains: []string{"a.example"}, DeclaredBy: "u"},
	} {
		if _, err := svc.CreateOrg(ctx, in); err == nil {
			t.Errorf("%s: debería fallar", name)
		}
	}
	if _, err := svc.StartScan("nope"); err != app.ErrNotFound {
		t.Error("escanear una organización inexistente")
	}
}

func TestBackgroundJob(t *testing.T) {
	ctx := context.Background()
	repo, _ := store.Open(t.TempDir())
	now := start
	svc := &app.Service{Repo: repo, Now: func() time.Time { return now }}
	org, _ := svc.CreateOrg(ctx, app.NewOrg{Name: "Acme", Domains: []string{demodata.Acme}, DeclaredBy: "Equipo de prueba"})
	dns, names, exp := demodata.World(now, 0, map[string]string{demodata.Acme: org.Domains[0].Token})
	ct := demodata.CTServer(names)
	defer ct.Close()
	d := discovery.New()
	d.CTBase, d.DNS = ct.URL, dns
	svc.DNS, svc.Discovery, svc.Exposure = dns, d, exp

	j, err := svc.StartScan(org.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StartScan(org.ID); err != app.ErrBusy && err != nil {
		t.Fatalf("un segundo escaneo simultáneo: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		v, err := svc.GetJob(j.ID)
		if err != nil {
			t.Fatal(err)
		}
		if v.Status == "done" {
			if _, err := repo.GetSnapshot(ctx, v.SnapshotID); err != nil {
				t.Fatalf("el escaneo terminado tiene que estar guardado: %v", err)
			}
			return
		}
		if v.Status == "error" || time.Now().After(deadline) {
			t.Fatalf("job: %+v", v)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
