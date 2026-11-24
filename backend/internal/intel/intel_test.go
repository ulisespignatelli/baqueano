package intel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

func TestIdentify(t *testing.T) {
	cases := []struct {
		names, cpes []string
		want        string
	}{
		{[]string{"Apache httpd"}, nil, "apache-httpd"},
		{nil, []string{"cpe:2.3:a:apache:http_server:2.4.49"}, "apache-httpd"},
		{nil, []string{"cpe:/a:openbsd:openssh:8.9p1"}, "openssh"},
		{[]string{"Apache Software Foundation Apache HTTP Server"}, nil, "apache-httpd"},
		{[]string{"PHP PHP"}, nil, "php"},
		{[]string{"Fortinet FortiOS, FortiProxy"}, nil, "fortios"},
		{[]string{"Redis key-value store"}, nil, "redis"},
		{[]string{"Software Raro"}, nil, "name:software raro"},
	}
	for _, c := range cases {
		got := Identify(c.names, c.cpes)
		if !contains(got, c.want) {
			t.Errorf("Identify(%v,%v) = %v, quería %s", c.names, c.cpes, got, c.want)
		}
	}
	if got := Identify([]string{"n/a"}, nil); len(got) != 0 {
		t.Errorf("n/a no es un producto: %v", got)
	}
}

func TestDistro(t *testing.T) {
	cases := map[string]string{
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10":     "Ubuntu",
		"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3":       "Debian",
		"Server: Apache/2.4.41 (Ubuntu)":               "Ubuntu",
		"Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k": "Red Hat / derivadas",
		"Server: nginx/1.24.0":                         "",
	}
	for banner, want := range cases {
		d := DetectDistro("", banner)
		got := ""
		if d != nil {
			got = d.Name
		}
		if got != want {
			t.Errorf("%q: distro %q, quería %q", banner, got, want)
		}
	}
	if v := upstreamVersion("2.4.41-4ubuntu3.17"); v != "2.4.41" {
		t.Errorf("upstreamVersion = %q", v)
	}
	if v := upstreamVersion("10.2.9-h1"); v != "10.2.9-h1" {
		t.Errorf("no debe cortar hotfixes: %q", v)
	}
}

const nvdFixture = `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2099-1000","published":"2099-01-02T00:00:00.000","vulnStatus":"Analyzed",
"descriptions":[{"lang":"en","value":"Example overflow."},{"lang":"es","value":"Desbordamiento de ejemplo."}],
"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
"weaknesses":[{"description":[{"value":"CWE-787"}]}],
"configurations":[{"nodes":[{"operator":"OR","negate":false,"cpeMatch":[
 {"vulnerable":true,"criteria":"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*","versionStartIncluding":"1.20.0","versionEndExcluding":"1.24.1"},
 {"vulnerable":false,"criteria":"cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"}]}]}]}}]}`

func TestParseNVD(t *testing.T) {
	recs, total, err := ParseNVD([]byte(nvdFixture))
	if err != nil || total != 1 || len(recs) != 1 {
		t.Fatalf("ParseNVD: %v %d %d", err, total, len(recs))
	}
	r := recs[0]
	if r.Summary != "Desbordamiento de ejemplo." || r.CVSS != 9.8 || r.CWE[0] != "CWE-787" || r.Published != "2099-01-02" {
		t.Errorf("metadatos: %+v", r)
	}
	if len(r.Affected) != 1 || !contains(r.Affected[0].Products, "nginx") {
		t.Fatalf("solo el producto vulnerable, no la plataforma: %+v", r.Affected)
	}
	db := newDB()
	db.AddRecord(r)
	for v, want := range map[string]string{"1.22.1": Probable, "1.24.1": Dismissed, "1.18.0": Dismissed} {
		keep, dis := Assess(domain.Service{Product: "nginx", Version: v, Vulns: []domain.Vuln{{CVE: "CVE-2099-1000"}}}, db, nil)
		got := ""
		for _, x := range append(keep, dis...) {
			got = x.Confidence
		}
		if got != want {
			t.Errorf("nginx %s: %s, quería %s", v, got, want)
		}
	}
	keep, _ := Assess(domain.Service{Product: "nginx", Version: "1.22.1", Vulns: []domain.Vuln{{CVE: "CVE-2099-1000"}}}, db, nil)
	if keep[0].FixedIn != "1.24.1" {
		t.Errorf("versión corregida: %q", keep[0].FixedIn)
	}
}

func TestPriority(t *testing.T) {
	cases := []struct {
		v    domain.Vuln
		want string
	}{
		{domain.Vuln{KEV: true, Confidence: Unverified, CVSS: 5}, "P1"},
		{domain.Vuln{SSVC: &domain.SSVC{Exploitation: "active"}, Confidence: Probable}, "P1"},
		{domain.Vuln{SSVC: &domain.SSVC{Exploitation: "poc", Automatable: "yes"}, Confidence: Probable}, "P2"},
		{domain.Vuln{CVSS: 9.8, Confidence: Probable}, "P2"},
		{domain.Vuln{CVSS: 9.8, Confidence: Unverified}, "P3"},
		{domain.Vuln{CVSS: 7.5, EPSS: 0.002, Confidence: Probable}, "P3"},
		{domain.Vuln{CVSS: 5.3, Confidence: Probable}, "P4"},
		{domain.Vuln{CVSS: 9.8, KEV: false, Confidence: Unlikely}, "P4"},
		{domain.Vuln{EPSS: 0.7, Confidence: Probable}, "P1"},
	}
	for i, c := range cases {
		v := c.v
		prioritize(&v)
		if v.Priority != c.want {
			t.Errorf("caso %d: %s (%s), quería %s", i, v.Priority, v.PriorityReason, c.want)
		}
	}
}

// fakeSources simula todas las fuentes con el formato de su documentacion.
func fakeSources(t *testing.T, calls *atomic.Int32) *httptest.Server {
	regre, err := os.ReadFile("../../../bench/records/CVE-2024-6387.json")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/kev.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"catalogVersion":"2099.01.01","vulnerabilities":[{"cveID":"CVE-2099-1000","vendorProject":"F5","product":"NGINX","vulnerabilityName":"Ejemplo","dateAdded":"2099-01-01","dueDate":"2099-01-22","requiredAction":"Aplicar parches","knownRansomwareCampaignUse":"Known"}]}`)
	})
	mux.HandleFunc("/cves/", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if strings.HasSuffix(r.URL.Path, "/2024/6xxx/CVE-2024-6387.json") {
			w.Write(regre)
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/epss", func(w http.ResponseWriter, r *http.Request) {
		var rows []string
		for _, id := range strings.Split(r.URL.Query().Get("cve"), ",") {
			rows = append(rows, fmt.Sprintf(`{"cve":"%s","epss":"0.61","percentile":"0.98","date":"2099-01-01"}`, id))
		}
		fmt.Fprintf(w, `{"status":"OK","data":[%s]}`, strings.Join(rows, ","))
	})
	mux.HandleFunc("/nvd", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apiKey") != "clave-secreta" || strings.Contains(r.URL.RawQuery, "clave") {
			t.Errorf("la clave de la NVD tiene que ir en el encabezado, nunca en la URL")
		}
		if strings.Contains(r.URL.Query().Get("virtualMatchString"), "nginx:1.22.1") {
			fmt.Fprint(w, nvdFixture)
			return
		}
		fmt.Fprint(w, `{"totalResults":0,"vulnerabilities":[]}`)
	})
	mux.HandleFunc("/eol/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/nginx") {
			fmt.Fprint(w, `{"result":{"releases":[{"name":"1.22","isEol":true,"eolFrom":"2023-04-11","latest":{"name":"1.22.1"}},{"name":"1.26","isEol":false,"latest":{"name":"1.26.2"}}]}}`)
			return
		}
		http.NotFound(w, r)
	})
	return httptest.NewServer(mux)
}

func TestEnrich(t *testing.T) {
	var calls atomic.Int32
	srv := fakeSources(t, &calls)
	defer srv.Close()
	c := NewClient()
	c.KEVURLs = []string{srv.URL + "/kev.json"}
	c.CVEURL = srv.URL + "/cves/%s/%s/%s.json"
	c.CVEAPI = ""
	c.EPSSURL, c.NVDURL, c.EOLURL, c.NVDKey = srv.URL+"/epss", srv.URL+"/nvd", srv.URL+"/eol/%s", "clave-secreta"
	path := t.TempDir() + "/intel.json.gz"
	e, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	e.Client = c
	if err := e.Update(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	svcs := []domain.Service{
		{IP: "198.51.100.1", Port: 443, Product: "nginx", Version: "1.22.1"}, // la fuente no informo nada: la NVD si
		{IP: "198.51.100.2", Port: 22, Product: "OpenSSH", Version: "9.8p1", Banner: "SSH-2.0-OpenSSH_9.8p1",
			Vulns: []domain.Vuln{{CVE: "CVE-2024-6387", Origin: "shodan"}}}, // ya corregida: se descarta
		{IP: "198.51.100.3", Port: 22, Product: "OpenSSH", Version: "8.9p1", Banner: "SSH-2.0-OpenSSH_8.9p1",
			Vulns: []domain.Vuln{{CVE: "CVE-2024-6387", Origin: "shodan"}}},
	}
	out, rep := e.Enrich(context.Background(), svcs, nil)
	if rep.FromNVD != 1 || rep.Dismissed != 1 || rep.Kept != 2 {
		t.Fatalf("reporte: %+v", rep)
	}
	ng := out[0].Vulns[0]
	if ng.CVE != "CVE-2099-1000" || ng.Origin != "baqueano" || !ng.KEV || !ng.Ransomware || ng.Priority != "P1" || ng.FixedIn != "1.24.1" || ng.EPSSPercentile != 0.98 {
		t.Errorf("nginx: %+v", ng)
	}
	if out[0].EOL == nil || out[0].EOL.Cycle != "1.22" || out[0].EOL.Since != "2023-04-11" {
		t.Errorf("fin de soporte: %+v", out[0].EOL)
	}
	if len(out[1].Vulns) != 0 || len(out[1].Dismissed) != 1 || !strings.Contains(out[1].Dismissed[0].Reason, "9.8p1") {
		t.Errorf("OpenSSH 9.8p1 debía quedar descartada con motivo: %+v", out[1])
	}
	if v := out[2].Vulns[0]; v.Confidence != Probable || v.SSVC == nil || v.FixedIn == "" {
		t.Errorf("OpenSSH 8.9p1: %+v", v)
	}

	// La base queda guardada: sin conexion da el mismo resultado y no vuelve a consultar.
	before := calls.Load()
	e2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	out2, _ := e2.Enrich(context.Background(), svcs, nil)
	if calls.Load() != before || len(out2[0].Vulns) != 1 || len(out2[1].Dismissed) != 1 {
		t.Errorf("sin conexión debía usar la base guardada: %+v", out2)
	}
	st := e2.Status()
	if st.Online || st.KEVCatalog != "2099.01.01" || st.Records < 2 {
		t.Errorf("estado: %+v", st)
	}
	if _, err := e2.Lookup(context.Background(), "CVE-2024-6387"); err != nil {
		t.Errorf("Lookup: %v", err)
	}
	if _, err := e2.Lookup(context.Background(), "no-es-cve"); err == nil {
		t.Error("Lookup debía rechazar identificadores inválidos")
	}
}

func TestClientErrorsHideURL(t *testing.T) {
	c := NewClient()
	c.HTTP.Timeout, c.Retries = time.Second, 1
	c.EPSSURL = "http://127.0.0.1:1/epss"
	_, err := c.EPSS(context.Background(), []string{"CVE-2099-0001"}, time.Now())
	if err == nil || strings.Contains(err.Error(), "/epss") {
		t.Errorf("el error no debe incluir la URL: %v", err)
	}
}
