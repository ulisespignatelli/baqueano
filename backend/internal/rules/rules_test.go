package rules

import (
	"testing"
	"time"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

var now = time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)

func rulesOf(fs []domain.Finding) map[string]domain.Severity {
	m := map[string]domain.Severity{}
	for _, f := range fs {
		m[f.Rule+"@"+f.Asset] = f.Severity
	}
	return m
}

func TestExposedServices(t *testing.T) {
	svcs := []domain.Service{
		{IP: "198.51.100.1", Port: 3389, Transport: "tcp", Module: "rdp"},
		{IP: "198.51.100.1", Port: 9200, Transport: "tcp", Module: "http"}, // Elasticsearch habla HTTP: coincide por puerto
		{IP: "198.51.100.1", Port: 502, Transport: "tcp"},                  // sin modulo (InternetDB)
		{IP: "198.51.100.1", Port: 22, Transport: "tcp", Module: "ssh"},
		{IP: "198.51.100.1", Port: 443, Transport: "tcp", Module: "https"},
	}
	got := rulesOf(Evaluate(nil, svcs, Options{Now: now}))
	want := map[string]domain.Severity{"PX-RDP@198.51.100.1:3389": domain.SevCritical, "PX-DB@198.51.100.1:9200": domain.SevCritical,
		"PX-ICS@198.51.100.1:502": domain.SevCritical, "PX-SSH@198.51.100.1:22": domain.SevMedium}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, quería %q (todo: %v)", k, got[k], v, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("hallazgos de más: %v", got)
	}
}

func TestVulnSeverity(t *testing.T) {
	cases := []struct {
		v    domain.Vuln
		want domain.Severity
	}{
		{domain.Vuln{CVE: "CVE-2099-1", KEV: true, Verified: false}, domain.SevCritical}, // KEV no baja aunque no esté verificada
		{domain.Vuln{CVE: "CVE-2099-2", EPSS: 0.4, Verified: true}, domain.SevHigh},
		{domain.Vuln{CVE: "CVE-2099-3", EPSS: 0.4, Verified: false}, domain.SevMedium}, // inferida: baja un nivel
		{domain.Vuln{CVE: "CVE-2099-4", CVSS: 9.8, Verified: true}, domain.SevHigh},
		{domain.Vuln{CVE: "CVE-2099-5", CVSS: 9.8}, domain.SevMedium},
		{domain.Vuln{CVE: "CVE-2099-6", CVSS: 7.1}, domain.SevLow},
		{domain.Vuln{CVE: "CVE-2099-7"}, domain.SevLow},
	}
	for _, c := range cases {
		fs := Evaluate(nil, []domain.Service{{IP: "198.51.100.2", Port: 443, Module: "https", Vulns: []domain.Vuln{c.v}}}, Options{Now: now})
		if len(fs) != 1 || fs[0].Severity != c.want || fs[0].CVE != c.v.CVE {
			t.Errorf("%s: %+v, quería %s", c.v.CVE, fs, c.want)
		}
		if !c.v.Verified && fs[0].Title[len(fs[0].Title)-len("(por confirmar)"):] != "(por confirmar)" {
			t.Errorf("%s: una vulnerabilidad inferida tiene que decirlo en el título", c.v.CVE)
		}
	}
}

func TestTLSAndHygiene(t *testing.T) {
	svcs := []domain.Service{
		{IP: "198.51.100.3", Port: 443, Module: "https", Cert: &domain.Cert{NotAfter: now.Add(-24 * time.Hour)}},
		{IP: "198.51.100.4", Port: 443, Module: "https", Cert: &domain.Cert{NotAfter: now.Add(10 * 24 * time.Hour), Versions: []string{"TLSv1", "TLSv1.2"}}},
		{IP: "198.51.100.5", Port: 443, Module: "https", Cert: &domain.Cert{NotAfter: now.Add(300 * 24 * time.Hour), SelfSigned: true}},
		{IP: "198.51.100.6", Port: 8080, Module: "http", Title: "Dashboard [Jenkins]"},
		{IP: "198.51.100.7", Port: 443, Module: "https", Title: "FortiGate - Login"}, // portal VPN: público por diseño
		{IP: "198.51.100.8", Port: 80, Module: "http", Product: "Apache httpd", Version: "2.2.15", Tags: []string{"eol-product"}},
		{IP: "198.51.100.8", Port: 443, Module: "https", Product: "Apache httpd", Version: "2.2.15", Tags: []string{"eol-product"}},
	}
	got := rulesOf(Evaluate(nil, svcs, Options{Now: now}))
	for k, v := range map[string]domain.Severity{
		"TLS-01@198.51.100.3:443": domain.SevHigh, "TLS-02@198.51.100.4:443": domain.SevMedium, "TLS-04@198.51.100.4:443": domain.SevMedium,
		"TLS-03@198.51.100.5:443": domain.SevLow, "HY-01@198.51.100.6:8080": domain.SevHigh, "HY-02@198.51.100.8": domain.SevMedium,
	} {
		if got[k] != v {
			t.Errorf("%s: %q, quería %q", k, got[k], v)
		}
	}
	if _, ok := got["HY-01@198.51.100.7:443"]; ok {
		t.Error("un portal de VPN no es un panel de administración")
	}
	if _, ok := got["HY-03@198.51.100.8:80"]; ok {
		t.Error("HTTP con HTTPS en la misma IP no es 'solo HTTP'")
	}
}

func TestDanglingCNAMEAndOrder(t *testing.T) {
	assets := []domain.Asset{
		{Hostname: "blog.acme.example", CNAME: "acme.herokuapp.com", ThirdParty: "Heroku", Resolves: false},
		{Hostname: "shop.acme.example", CNAME: "acme.myshopify.com", ThirdParty: "Shopify", Resolves: true},
		{Hostname: "old.acme.example", CNAME: "old.internal.example", Resolves: false}, // no es un proveedor conocido
	}
	fs := Evaluate(assets, []domain.Service{{IP: "198.51.100.9", Port: 23, Module: "telnet"}}, Options{Now: now})
	if len(fs) != 2 || fs[0].Rule != "PX-TELNET" || fs[1].Rule != "DNS-01" || fs[1].Asset != "blog.acme.example" {
		t.Fatalf("hallazgos: %+v", fs)
	}
	again := Evaluate(assets, []domain.Service{{IP: "198.51.100.9", Port: 23, Module: "telnet"}}, Options{Now: now})
	if again[0].ID != fs[0].ID {
		t.Fatal("los ID tienen que ser estables entre escaneos")
	}
}

func TestScoreCurve(t *testing.T) {
	clean := domain.Snapshot{}
	if clean.Score() != 100 {
		t.Fatal("sin hallazgos = 100")
	}
	bad := domain.Snapshot{Findings: []domain.Finding{{Severity: domain.SevCritical}, {Severity: domain.SevCritical}, {Severity: domain.SevCritical}, {Severity: domain.SevCritical}}}
	better := domain.Snapshot{Findings: bad.Findings[:3]}
	if !(bad.Score() > 0 && better.Score() > bad.Score()) {
		t.Fatalf("cada corrección tiene que notarse: %d → %d", bad.Score(), better.Score())
	}
}
