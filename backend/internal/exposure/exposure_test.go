package exposure

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const secret = "CLAVE-SUPER-SECRETA-123"

// Respuesta ficticia con la estructura de /shodan/host/{ip}.
const hostJSON = `{"ip_str":"198.51.100.30","org":"Proveedor de ejemplo","country_code":"AR","hostnames":["vpn.acme.example"],
"data":[
 {"port":443,"transport":"tcp","product":"nginx","version":"1.24.0","cpe23":["cpe:2.3:a:f5:nginx:1.24.0"],"tags":["self-signed"],
  "timestamp":"2026-11-20T10:11:12.123456","_shodan":{"module":"https"},"http":{"title":"  Portal  "},
  "vulns":{"cve-2099-0002":{"cvss":5.0,"epss":0.001,"verified":false,"summary":"ficticia"},"CVE-2099-0001":{"cvss":9.8,"epss":0.9,"kev":true,"verified":true,"summary":"ficticia KEV"}},
  "ssl":{"versions":["-SSLv3","TLSv1","-TLSv1.1","TLSv1.2"],"cert":{"expired":false,"expires":"20270101000000Z","subject":{"CN":"vpn.acme.example"},"issuer":{"CN":"CA de ejemplo"}}}},
 {"port":443,"transport":"tcp","product":"nginx","timestamp":"2026-01-01T00:00:00.000000","_shodan":{"module":"https"}},
 {"port":3389,"transport":"tcp","_shodan":{"module":"rdp"},"timestamp":"2026-11-19T00:00:00.000000"}
]}`

func server(t *testing.T, h http.HandlerFunc) *Shodan {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	s := NewShodan(secret)
	s.Base, s.Rate = ts.URL, 0
	return s
}

func TestShodanHost(t *testing.T) {
	s := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != secret || r.URL.Path != "/shodan/host/198.51.100.30" {
			http.Error(w, `{"error":"bad"}`, 401)
			return
		}
		w.Write([]byte(hostJSON))
	})
	svcs, found, err := s.Host(context.Background(), "198.51.100.30")
	if err != nil || !found || len(svcs) != 2 {
		t.Fatalf("host: %v %v %d", err, found, len(svcs))
	}
	https := svcs[0]
	if https.Port != 443 || https.Product != "nginx" || https.Title != "Portal" || https.Org != "Proveedor de ejemplo" || https.Country != "AR" {
		t.Fatalf("servicio: %+v", https)
	}
	if https.SeenAt.Year() != 2026 || https.SeenAt.Month() != 11 {
		t.Fatalf("se queda con el banner más reciente del puerto: %v", https.SeenAt)
	}
	if len(https.Vulns) != 2 || https.Vulns[0].CVE != "CVE-2099-0001" || !https.Vulns[0].KEV || https.Vulns[1].CVE != "CVE-2099-0002" {
		t.Fatalf("vulns ordenadas por KEV/EPSS: %+v", https.Vulns)
	}
	c := https.Cert
	if c == nil || !c.SelfSigned || c.Subject != "vpn.acme.example" || c.NotAfter.Year() != 2027 || strings.Join(c.Versions, ",") != "TLSv1,TLSv1.2" {
		t.Fatalf("certificado: %+v", c)
	}
	if len(https.Hostnames) != 1 {
		t.Fatal("hereda los hostnames del host")
	}
}

func TestShodanErrorsNeverLeakKey(t *testing.T) {
	codes := map[string]int{"/shodan/host/198.51.100.1": 404, "/shodan/host/198.51.100.2": 401, "/shodan/host/198.51.100.3": 418}
	s := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(codes[r.URL.Path])
		w.Write([]byte(`{"error":"algo"}`))
	})
	_, found, err := s.Host(context.Background(), "198.51.100.1")
	if err != nil || found {
		t.Fatal("404 = sin datos, no error")
	}
	if _, _, err := s.Host(context.Background(), "198.51.100.2"); !errors.Is(err, ErrAuth) {
		t.Fatalf("401: %v", err)
	}
	_, _, err = s.Host(context.Background(), "198.51.100.3")
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("418: %v", err)
	}
	// Servidor caído: el error de red de Go incluye la URL (con la clave). No puede filtrarse.
	dead := NewShodan(secret)
	dead.Base, dead.Rate = "http://127.0.0.1:1", 0
	dead.HTTP.Timeout = time.Second
	_, _, err = dead.Host(context.Background(), "198.51.100.4")
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("error de red filtra datos: %v", err)
	}
}

func TestShodanRetry(t *testing.T) {
	n := 0
	s := server(t, func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			w.WriteHeader(429)
			return
		}
		w.Write([]byte(`{"data":[]}`))
	})
	start := time.Now()
	if _, found, err := s.Host(context.Background(), "198.51.100.5"); err != nil || !found || n != 2 {
		t.Fatalf("reintento ante 429: %v %v %d", err, found, n)
	}
	if time.Since(start) < time.Second {
		t.Fatal("tiene que esperar antes de reintentar")
	}
}

func TestSearchNetwork(t *testing.T) {
	s := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("query") != "net:203.0.113.0/28" {
			http.Error(w, "{}", 400)
			return
		}
		w.Write([]byte(`{"total":2,"matches":[{"ip_str":"203.0.113.1","port":502,"transport":"tcp","_shodan":{"module":"modbus"}},{"ip_str":"203.0.113.2","port":22,"_shodan":{"module":"ssh"}}]}`))
	})
	svcs, err := s.SearchNetwork(context.Background(), "203.0.113.0/28", 2)
	if err != nil || len(svcs) != 2 || svcs[0].IP != "203.0.113.1" || svcs[1].Transport != "tcp" {
		t.Fatalf("búsqueda de red: %v %+v", err, svcs)
	}
}

func TestInternetDB(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/198.51.100.9" {
			w.Write([]byte(`{"ip":"198.51.100.9","ports":[22,443],"cpes":["cpe:/a:openbsd:openssh"],"hostnames":["a.example"],"tags":["cloud"],"vulns":["CVE-2099-0009"]}`))
			return
		}
		http.Error(w, `{"detail":"No information available"}`, 404)
	}))
	defer ts.Close()
	db := NewInternetDB()
	db.Base = ts.URL
	svcs, found, err := db.Host(context.Background(), "198.51.100.9")
	if err != nil || !found || len(svcs) != 2 || len(svcs[0].Vulns) != 1 || svcs[0].Vulns[0].Verified || svcs[1].Source != "internetdb" {
		t.Fatalf("internetdb: %v %v %+v", err, found, svcs)
	}
	if _, found, err := db.Host(context.Background(), "198.51.100.10"); found || err != nil {
		t.Fatal("404 = sin datos")
	}
}
