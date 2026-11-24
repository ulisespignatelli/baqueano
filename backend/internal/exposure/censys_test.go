package exposure

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

// Formato segun la documentacion publica de la Platform API v3 (result.resource.services[]).
const censysFixture = `{"result":{"resource":{"ip":"198.51.100.40","location":{"country":"Argentina"},"autonomous_system":{"name":"Proveedor de ejemplo"},
"services":[
 {"port":3000,"protocol":"HTTP","transport_protocol":"tcp","scan_time":"2099-01-20T10:00:00Z",
  "software":[{"vendor":"Grafana Labs","product":"Grafana","version":"9.1.0","part":"a","cpe":"cpe:2.3:a:grafana:grafana:9.1.0:*:*:*:*:*:*:*"}],
  "endpoints":[{"http":{"html_title":"Grafana"}}],
  "vulns":[{"id":"CVE-2099-0102","kev":true}]},
 {"port":22,"protocol":"SSH","transport_protocol":"tcp","scan_time":"2099-01-19T10:00:00Z",
  "software":[{"vendor":"Canonical","product":"Ubuntu Linux","part":"o"},{"vendor":"OpenBSD","product":"OpenSSH","version":"8.9p1","part":"a"}]},
 {"port":443,"protocol":"HTTP","transport_protocol":"tcp","cert":{"parsed":{"subject_dn":"CN=vpn.acme.example, O=Acme","issuer_dn":"CN=vpn.acme.example, O=Acme","validity_period":{"not_after":"2020-01-01T00:00:00Z"}}}}
]}}}`

func TestCensys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token-secreto" || strings.Contains(r.URL.RawQuery, "token") {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path != "/v3/global/asset/host/198.51.100.40" || r.URL.Query().Get("organization_id") != "org-1" {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte(censysFixture))
	}))
	defer srv.Close()
	c := NewCensys("token-secreto", "org-1")
	c.Base, c.Gap, c.MaxLookups = srv.URL, 0, 2
	svcs, found, err := c.Host(context.Background(), "198.51.100.40")
	if err != nil || !found || len(svcs) != 3 {
		t.Fatalf("host: %v %v %d", err, found, len(svcs))
	}
	g := svcs[0]
	if g.Product != "Grafana Labs Grafana" || g.Version != "9.1.0" || g.Title != "Grafana" || g.Module != "http" || len(g.CPEs) != 1 ||
		len(g.Vulns) != 1 || !g.Vulns[0].KEV || g.Vulns[0].Origin != "censys" || g.Org != "Proveedor de ejemplo" {
		t.Errorf("grafana: %+v", g)
	}
	if svcs[1].Product != "OpenBSD OpenSSH" || svcs[1].Version != "8.9p1" {
		t.Errorf("el sistema operativo no es el producto del servicio: %+v", svcs[1])
	}
	if c := svcs[2].Cert; c == nil || c.Subject != "vpn.acme.example" || !c.Expired || !c.SelfSigned {
		t.Errorf("certificado: %+v", svcs[2].Cert)
	}
	if _, found, err := c.Host(context.Background(), "198.51.100.41"); found || err != nil {
		t.Errorf("404 = sin datos: %v %v", found, err)
	}
	if _, _, err := c.Host(context.Background(), "198.51.100.40"); !errors.Is(err, ErrBudget) {
		t.Errorf("debía respetar el tope de consultas: %v", err)
	}
	bad := NewCensys("otro", "")
	bad.Base, bad.Gap = srv.URL, 0
	if _, _, err := bad.Host(context.Background(), "198.51.100.40"); !errors.Is(err, ErrCensysAuth) || strings.Contains(err.Error(), "otro") {
		t.Errorf("token inválido: %v", err)
	}
}

type fakeSrc struct {
	name string
	svcs map[string][]domain.Service
	err  error
}

func (f fakeSrc) Name() string { return f.name }
func (f fakeSrc) Host(_ context.Context, ip string) ([]domain.Service, bool, error) {
	if f.err != nil {
		return nil, false, f.err
	}
	return f.svcs[ip], len(f.svcs[ip]) > 0, nil
}

func TestMulti(t *testing.T) {
	ip := "198.51.100.40"
	shodan := fakeSrc{name: "shodan", svcs: map[string][]domain.Service{ip: {
		{IP: ip, Port: 3000, Transport: "tcp", Product: "Grafana", Version: "", Vulns: []domain.Vuln{{CVE: "CVE-2099-0001", Origin: "shodan"}}},
		{IP: ip, Port: 8080, Transport: "tcp", Product: "Jetty"}}}}
	censys := fakeSrc{name: "censys", svcs: map[string][]domain.Service{ip: {
		{IP: ip, Port: 3000, Transport: "tcp", Product: "Grafana", Version: "9.1.0", Vulns: []domain.Vuln{{CVE: "CVE-2099-0001", Verified: true}, {CVE: "CVE-2099-0002"}}},
		{IP: ip, Port: 5432, Transport: "tcp", Product: "PostgreSQL"}}}}
	m := NewMulti(shodan, censys).(*Multi)
	m.BeginScan()
	svcs, found, err := m.Host(context.Background(), ip)
	if err != nil || !found || len(svcs) != 3 || m.Name() != "shodan+censys" {
		t.Fatalf("multi: %v %v %+v", err, found, svcs)
	}
	g := svcs[0]
	if strings.Join(g.SeenBy, ",") != "shodan,censys" || g.Version != "9.1.0" || len(g.Vulns) != 2 || !g.Vulns[0].Verified {
		t.Errorf("combinación del puerto 3000: %+v", g)
	}
	if strings.Join(svcs[1].SeenBy, ",") != "shodan" || strings.Join(svcs[2].SeenBy, ",") != "censys" {
		t.Errorf("cada puerto debía anotar quién lo vio: %+v", svcs)
	}
	// Si la secundaria falla, se la deja de lado con una nota; si falla la principal, se detiene.
	m2 := NewMulti(shodan, fakeSrc{name: "censys", err: ErrCensysAuth}).(*Multi)
	m2.BeginScan()
	if _, _, err := m2.Host(context.Background(), ip); err != nil || len(m2.Notes()) != 1 || len(m2.SourceNames()) != 1 {
		t.Errorf("secundaria con error: %v %v", err, m2.Notes())
	}
	m3 := NewMulti(fakeSrc{name: "shodan", err: ErrAuth}, censys).(*Multi)
	if _, _, err := m3.Host(context.Background(), ip); !errors.Is(err, ErrAuth) {
		t.Errorf("la principal manda: %v", err)
	}
	if Label("shodan+censys") != "Shodan (API REST) + Censys (Platform API)" {
		t.Errorf("etiqueta: %s", Label("shodan+censys"))
	}
}
