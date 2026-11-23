package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ulisespignatelli/baqueano/backend/internal/adapters/store"
	"github.com/ulisespignatelli/baqueano/backend/internal/app"
	"github.com/ulisespignatelli/baqueano/backend/internal/demodata"
	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

func setup(t *testing.T, cfg Config) (*Server, *app.Service) {
	t.Helper()
	repo, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := demodata.Build(context.Background(), repo, time.Date(2026, 11, 16, 14, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	svc := &app.Service{Repo: repo}
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(svc, cfg), svc
}

func do(h http.Handler, method, path string, body any, hdr map[string]string) *httptest.ResponseRecorder {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	req.Host = "127.0.0.1:8080"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var csrf = map[string]string{"X-Requested-With": "baqueano"}

func TestReadFlow(t *testing.T) {
	h, _ := setup(t, Config{Loopback: true, Source: "shodan"})
	var o app.Overview
	rec := do(h, "GET", "/api/v1/overview", nil, nil)
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &o) != nil || len(o.Orgs) != 2 {
		t.Fatalf("overview: %d %s", rec.Code, rec.Body)
	}
	org := o.Orgs[0]
	var detail struct {
		Snapshots []app.SnapshotMeta `json:"snapshots"`
	}
	json.Unmarshal(do(h, "GET", "/api/v1/orgs/"+org.ID, nil, nil).Body.Bytes(), &detail)
	if len(detail.Snapshots) != 2 {
		t.Fatalf("historial: %+v", detail)
	}
	var snap SnapshotView
	rec = do(h, "GET", "/api/v1/snapshots/"+org.Latest.ID, nil, nil)
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &snap) != nil || snap.Score != org.Latest.Score || len(snap.Findings) == 0 {
		t.Fatalf("snapshot: %d", rec.Code)
	}
	if rec := do(h, "GET", "/api/v1/snapshots/"+org.Latest.ID+"/changes", nil, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "resolved_findings") {
		t.Fatal("changes")
	}
	rec = do(h, "GET", "/api/v1/snapshots/"+org.Latest.ID+"/export?format=csv", nil, nil)
	if rec.Code != 200 || !strings.HasPrefix(rec.Body.String(), "severidad,regla") {
		t.Fatalf("csv: %d", rec.Code)
	}
	for _, p := range []string{"/api/v1/orgs/nope", "/api/v1/snapshots/nope", "/api/v1/snapshots/..%2F..%2Fetc%2Fpasswd", "/api/v1/jobs/nope", "/api/v1/nada"} {
		if rec := do(h, "GET", p, nil, nil); rec.Code != 404 {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
}

func TestCreateOrgFlow(t *testing.T) {
	h, _ := setup(t, Config{Loopback: true})
	if rec := do(h, "POST", "/api/v1/orgs", map[string]any{"name": "X", "domains": []string{"x.example"}, "attestation": map[string]any{"by": "Ulises", "accepted": false}}, csrf); rec.Code != 400 {
		t.Fatalf("declaración sin aceptar: %d", rec.Code)
	}
	rec := do(h, "POST", "/api/v1/orgs", map[string]any{"name": "Nueva", "domains": []string{"nueva.example"}, "networks": []string{"198.51.100.0/24"},
		"attestation": map[string]any{"by": "Ulises Pignatelli", "accepted": true}}, csrf)
	if rec.Code != 201 {
		t.Fatalf("crear: %d %s", rec.Code, rec.Body)
	}
	var org domain.Organization
	json.Unmarshal(rec.Body.Bytes(), &org)
	if len(org.Domains) != 1 || len(org.Domains[0].Token) != 32 || org.Attestation == nil || len(org.Networks) != 1 {
		t.Fatalf("org: %+v", org)
	}
	if rec := do(h, "POST", "/api/v1/orgs/"+org.ID+"/domains", map[string]string{"domain": "otro.example"}, csrf); rec.Code != 200 {
		t.Fatalf("agregar dominio: %d", rec.Code)
	}
	if rec := do(h, "POST", "/api/v1/orgs/"+org.ID+"/networks", map[string]string{"network": "10.0.0.0/8"}, csrf); rec.Code != 400 {
		t.Fatalf("red privada: %d", rec.Code)
	}
	if rec := do(h, "POST", "/api/v1/orgs/"+org.ID+"/networks", map[string]string{"network": "203.0.113.0/26"}, csrf); rec.Code != 200 {
		t.Fatalf("red: %d %s", rec.Code, rec.Body)
	}
	if rec := do(h, "POST", "/api/v1/orgs/"+org.ID+"/attestation", map[string]any{"by": "Otra Persona", "accepted": true}, csrf); rec.Code != 200 {
		t.Fatalf("declaración: %d", rec.Code)
	}
	if rec := do(h, "POST", "/api/v1/orgs", map[string]any{"name": "Mala", "domains": []string{"no es dominio"}}, csrf); rec.Code != 400 {
		t.Fatalf("dominio inválido: %d", rec.Code)
	}
	if rec := do(h, "DELETE", "/api/v1/orgs/"+org.ID, nil, csrf); rec.Code != 204 {
		t.Fatalf("borrar: %d", rec.Code)
	}
}

func TestSecurity(t *testing.T) {
	h, _ := setup(t, Config{Loopback: true, Token: "s3creto"})
	body := map[string]any{"name": "X", "domains": []string{"x.example"}}
	if rec := do(h, "POST", "/api/v1/orgs", body, csrf); rec.Code != 401 {
		t.Errorf("sin token: %d", rec.Code)
	}
	if rec := do(h, "POST", "/api/v1/orgs", body, map[string]string{"Authorization": "Bearer s3creto"}); rec.Code != 403 {
		t.Errorf("sin anti-CSRF: %d", rec.Code)
	}
	req := httptest.NewRequest("GET", "/api/v1/overview", nil)
	req.Host = "evil.example"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMisdirectedRequest || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Errorf("DNS rebinding / CSP: %d", rec.Code)
	}
}

func TestCSVInjection(t *testing.T) {
	var b bytes.Buffer
	writeFindingsCSV(&b, domain.Snapshot{Findings: []domain.Finding{{Title: "=HYPERLINK(\"http://evil\")", Asset: "+1", Detail: "@SUM(A1)"}}})
	if strings.Contains(b.String(), ",=HYPERLINK") || strings.Contains(b.String(), ",+1") || strings.Contains(b.String(), ",@SUM") {
		t.Fatalf("celdas sin escapar: %s", b.String())
	}
}

func TestDemoSnapshot(t *testing.T) {
	_, svc := setup(t, Config{})
	out := t.TempDir()
	if err := WriteSnapshot(context.Background(), svc, out); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"health.json", "overview.json"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Error("falta", f)
		}
	}
	entries, _ := os.ReadDir(filepath.Join(out, "snapshots"))
	if len(entries) != 6 { // 3 escaneos: .json + carpeta con changes.json
		t.Errorf("snapshots: %d", len(entries))
	}
}
