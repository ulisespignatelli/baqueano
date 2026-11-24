// Package demodata arma un escenario FICTICIO para la demo y los tests: dominios .example (RFC 2606),
// IP de documentacion (RFC 5737) y CVE inventadas (CVE-2099-*). Pasa por el pipeline real; solo las
// fuentes externas (DNS, Certificate Transparency, Shodan) estan simuladas.
package demodata

import (
	"context"
	"encoding/json"
	"github.com/ulisespignatelli/baqueano/backend/internal/exposure"
	"github.com/ulisespignatelli/baqueano/backend/internal/intel"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/ulisespignatelli/baqueano/backend/internal/app"
	"github.com/ulisespignatelli/baqueano/backend/internal/discovery"
	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

// DNS simulado.
type DNS struct {
	TXT   map[string][]string
	CNAME map[string]string
	A     map[string][]string
}

func notFound(n string) error { return &net.DNSError{Err: "no such host", Name: n, IsNotFound: true} }

func (d *DNS) LookupTXT(_ context.Context, n string) ([]string, error) {
	if v, ok := d.TXT[n]; ok {
		return v, nil
	}
	return nil, notFound(n)
}

func (d *DNS) LookupCNAME(_ context.Context, n string) (string, error) {
	if v, ok := d.CNAME[n]; ok {
		return v + ".", nil
	}
	if _, ok := d.A[n]; ok {
		return n + ".", nil
	}
	return "", notFound(n)
}

func (d *DNS) LookupHost(_ context.Context, n string) ([]string, error) {
	if v, ok := d.A[n]; ok {
		return v, nil
	}
	if c, ok := d.CNAME[n]; ok {
		if v, ok := d.A[c]; ok {
			return v, nil
		}
	}
	return nil, notFound(n)
}

// Exposure simulado: implementa exposure.Source y exposure.NetworkSearcher.
type Exposure struct {
	Hosts map[string][]domain.Service
	Calls int
}

func (e *Exposure) Name() string { return "shodan" }

func (e *Exposure) Host(_ context.Context, ip string) ([]domain.Service, bool, error) {
	e.Calls++
	v, ok := e.Hosts[ip]
	return v, ok, nil
}

// Second es una segunda fuente ficticia ("censys") que coincide en parte con la primera: no ve algunos
// puertos y ve uno que la otra no. Sirve para mostrar el consenso entre fuentes.
type Second struct{ Hosts map[string][]domain.Service }

func (e *Second) Name() string { return "censys" }

func (e *Second) Host(_ context.Context, ip string) ([]domain.Service, bool, error) {
	v, ok := e.Hosts[ip]
	return v, ok, nil
}

// SecondFrom deriva la segunda fuente de la primera.
func SecondFrom(e *Exposure, now time.Time) *Second {
	skip := map[string]bool{"198.51.100.20/tcp/993": true, "203.0.113.12/tcp/502": true, "198.51.100.60/tcp/443": true}
	out := &Second{Hosts: map[string][]domain.Service{}}
	for ip, svcs := range e.Hosts {
		for _, sv := range svcs {
			if skip[sv.Key()] || strings.HasPrefix(ip, "192.0.2.") {
				continue
			}
			c := sv
			c.Source, c.SeenAt, c.Banner = "censys", now.Add(-36*time.Hour), ""
			c.Vulns = nil
			for _, v := range sv.Vulns {
				v.Origin = "censys"
				c.Vulns = append(c.Vulns, v)
			}
			out.Hosts[ip] = append(out.Hosts[ip], c)
		}
	}
	out.Hosts["198.51.100.10"] = append(out.Hosts["198.51.100.10"], domain.Service{IP: "198.51.100.10", Port: 8443, Transport: "tcp", Module: "http",
		Product: "nginx", Version: "1.24.0", Title: "Acme Logística (staging)", Source: "censys", SeenAt: now.Add(-36 * time.Hour)})
	return out
}

func (e *Exposure) SearchNetwork(_ context.Context, cidr string, _ int) ([]domain.Service, error) {
	_, n, _ := net.ParseCIDR(cidr)
	var out []domain.Service
	for ip, svcs := range e.Hosts {
		if n != nil && n.Contains(net.ParseIP(ip)) {
			out = append(out, svcs...)
		}
	}
	return out, nil
}

// CTServer simula crt.sh con los nombres dados.
func CTServer(names map[string][]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := strings.TrimPrefix(r.URL.Query().Get("q"), "%.")
		var out []map[string]string
		for _, n := range names[q] {
			out = append(out, map[string]string{"name_value": n, "common_name": n})
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
}

// ---------------------------------------------------------------- escenario

const (
	Acme   = "acme-logistica.example"
	Clinic = "clinica-norte.example"
)

func svc(ip string, port int, module, product, version string, mod func(*domain.Service)) domain.Service {
	s := domain.Service{IP: ip, Port: port, Transport: "tcp", Module: module, Product: product, Version: version,
		Source: "shodan", Org: "Proveedor de ejemplo", Country: "AR"}
	if mod != nil {
		mod(&s)
	}
	return s
}

func cert(subject string, notAfter time.Time, versions ...string) func(*domain.Service) {
	return func(s *domain.Service) {
		s.Cert = &domain.Cert{Subject: subject, Issuer: "CA de ejemplo", NotAfter: notAfter, Versions: versions}
	}
}

// World devuelve el DNS, los nombres de CT y la exposicion del mundo ficticio en un momento dado.
// week 0 = primer escaneo; week 1 = una semana despues (se cerro RDP y Redis, aparecio Elasticsearch,
// se renovo el certificado del correo).
func World(now time.Time, week int, tokens map[string]string) (*DNS, map[string][]string, *Exposure) {
	day := 24 * time.Hour
	dns := &DNS{
		TXT: map[string][]string{
			Acme: {"v=spf1 -all", "baqueano-verify=" + tokens[Acme], "baqueano-scope=203.0.113.0/28"},
		},
		CNAME: map[string]string{
			"blog." + Acme: "acme-blog.herokuapp.com", // CNAME colgante
			"shop." + Acme: "acme-tienda.myshopify.com",
			"cdn." + Acme:  "d111111abcdef8.cloudfront.net",
		},
		A: map[string][]string{
			Acme: {"198.51.100.10"}, "www." + Acme: {"198.51.100.10"}, "mail." + Acme: {"198.51.100.20"},
			"vpn." + Acme: {"198.51.100.30"}, "monitoreo." + Acme: {"198.51.100.40"}, "ftp." + Acme: {"198.51.100.50"},
			"legacy." + Acme: {"198.51.100.60"}, "intranet." + Acme: {"198.51.100.10"},
			"acme-tienda.myshopify.com": {"192.0.2.80"}, "d111111abcdef8.cloudfront.net": {"192.0.2.90"},
			Clinic: {"198.51.100.110"}, "www." + Clinic: {"198.51.100.110"}, "turnos." + Clinic: {"198.51.100.111"},
			"correo." + Clinic: {"198.51.100.112"},
		},
	}
	ct := map[string][]string{
		Acme: {"www." + Acme, "mail." + Acme, "vpn." + Acme, "monitoreo." + Acme, "ftp." + Acme, "legacy." + Acme,
			"blog." + Acme, "shop." + Acme, "cdn." + Acme, "intranet." + Acme, "*." + Acme},
		Clinic: {"www." + Clinic, "turnos." + Clinic, "correo." + Clinic},
	}
	mailCert := now.Add(12 * day)
	if week > 0 {
		mailCert = now.Add(90 * day)
	}
	hosts := map[string][]domain.Service{
		"198.51.100.10": {
			svc("198.51.100.10", 80, "http", "nginx", "1.24.0", func(s *domain.Service) { s.Title = "Acme Logística" }),
			svc("198.51.100.10", 443, "https", "nginx", "1.24.0", func(s *domain.Service) {
				cert("www."+Acme, now.Add(70*day), "TLSv1.2", "TLSv1.3")(s)
				s.Banner = "Server: nginx/1.24.0"
				s.Vulns = []domain.Vuln{{CVE: "CVE-2099-0105", Origin: "shodan"}} // ya corregida en 1.22.1: el motor la descarta
			}),
		},
		"198.51.100.20": {
			svc("198.51.100.20", 25, "smtp", "Postfix smtpd", "", nil),
			svc("198.51.100.20", 993, "imap-ssl", "Dovecot", "", cert("mail."+Acme, mailCert, "TLSv1.2", "TLSv1.3")),
		},
		"198.51.100.30": {
			svc("198.51.100.30", 443, "https", "Fortinet FortiGate SSL VPN", "", func(s *domain.Service) {
				s.Title = "FortiGate - Login"
				s.Cert = &domain.Cert{Subject: "vpn." + Acme, Issuer: "CA de ejemplo", NotAfter: now.Add(200 * day), Versions: []string{"TLSv1.2"}}
				s.Version = "7.0.11"
				s.CPEs = []string{"cpe:2.3:o:fortinet:fortios:7.0.11"}
				s.Vulns = []domain.Vuln{{CVE: "CVE-2099-0101", Verified: true, Origin: "shodan"}}
			}),
		},
		"198.51.100.40": {
			svc("198.51.100.40", 3000, "http", "Grafana", "9.1.0", func(s *domain.Service) {
				s.Title = "Grafana"
				s.Vulns = []domain.Vuln{{CVE: "CVE-2099-0102", Origin: "shodan"}}
			}),
		},
		"198.51.100.50": {
			svc("198.51.100.50", 21, "ftp", "vsftpd", "3.0.3", nil),
			svc("198.51.100.50", 22, "ssh", "OpenSSH", "8.9p1", func(s *domain.Service) {
				s.Banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
				s.Vulns = []domain.Vuln{{CVE: "CVE-2099-0104", Origin: "shodan"}}
			}),
		},
		"198.51.100.60": {
			svc("198.51.100.60", 80, "http", "Apache httpd", "2.2.15", func(s *domain.Service) {
				s.Vulns = []domain.Vuln{{CVE: "CVE-2099-0103", Origin: "shodan"}}
			}),
			svc("198.51.100.60", 443, "https", "Apache httpd", "2.2.15", func(s *domain.Service) {
				s.Tags = []string{"self-signed"}
				s.Cert = &domain.Cert{Subject: "legacy." + Acme, Issuer: "legacy." + Acme, NotAfter: now.Add(-40 * day), Expired: true, SelfSigned: true, Versions: []string{"TLSv1", "TLSv1.1", "TLSv1.2"}}
			}),
		},
		"203.0.113.10": {svc("203.0.113.10", 3389, "rdp", "Remote Desktop Protocol", "", nil)},
		"203.0.113.12": {svc("203.0.113.12", 502, "modbus", "Modbus", "", func(s *domain.Service) { s.Tags = []string{"ics"} })},
		"203.0.113.14": {svc("203.0.113.14", 6379, "redis", "Redis key-value store", "6.0.9", nil)},
		// Terceros: nunca deberian consultarse.
		"192.0.2.80": {svc("192.0.2.80", 3389, "rdp", "NO DEBE APARECER", "", nil)},
		"192.0.2.90": {svc("192.0.2.90", 23, "telnet", "NO DEBE APARECER", "", nil)},

		"198.51.100.110": {svc("198.51.100.110", 443, "https", "nginx", "1.26.0", cert("www."+Clinic, now.Add(80*day), "TLSv1.2", "TLSv1.3"))},
		"198.51.100.111": {svc("198.51.100.111", 443, "https", "nginx", "1.26.0", cert("turnos."+Clinic, now.Add(25*day), "TLSv1.2", "TLSv1.3"))},
		"198.51.100.112": {
			svc("198.51.100.112", 443, "https", "Microsoft Exchange", "", cert("correo."+Clinic, now.Add(150*day), "TLSv1.2")),
			svc("198.51.100.112", 22, "ssh", "OpenSSH", "9.6p1", nil),
		},
	}
	if week > 0 {
		delete(hosts, "203.0.113.10") // se cerro RDP
		delete(hosts, "203.0.113.14") // se cerro Redis
		hosts["203.0.113.13"] = []domain.Service{svc("203.0.113.13", 9200, "elastic", "Elasticsearch", "7.10.2", nil)}
	}
	for ip, list := range hosts {
		for i := range list {
			list[i].SeenAt = now.Add(-2 * day)
		}
		hosts[ip] = list
	}
	return dns, ct, &Exposure{Hosts: hosts}
}

// Build corre el escenario completo sobre un repositorio: crea las organizaciones, verifica y escanea
// (Acme dos veces, con una semana de diferencia). Devuelve la exposicion usada en el ultimo escaneo.
func Build(ctx context.Context, repo app.Repository, start time.Time) (*Exposure, error) {
	now := start
	eng := intel.NewMemory(Intel())
	eng.Now = func() time.Time { return now }
	// La primera semana CVE-2099-0102 todavia no esta en KEV; la segunda CISA la agrega y el hallazgo
	// sube de severidad sin que cambie nada en el servidor.
	kev0102 := eng.DB().KEV["CVE-2099-0102"]
	delete(eng.DB().KEV, "CVE-2099-0102")
	svc := &app.Service{Repo: repo, Now: func() time.Time { return now }, Intel: eng}
	// Acme verifica sus dominios en DNS; Clínica Norte usa el alcance declarado (sin tocar el DNS).
	acme, err := svc.CreateOrg(ctx, app.NewOrg{Name: "Acme Logística", Domains: []string{Acme}})
	if err != nil {
		return nil, err
	}
	clinic, err := svc.CreateOrg(ctx, app.NewOrg{Name: "Clínica Norte", Domains: []string{Clinic}, DeclaredBy: "Equipo de Seguridad (ejemplo)"})
	if err != nil {
		return nil, err
	}
	tokens := map[string]string{Acme: acme.Domains[0].Token, Clinic: clinic.Domains[0].Token}
	var last *Exposure
	for week := 0; week < 2; week++ {
		now = start.Add(time.Duration(week) * 7 * 24 * time.Hour)
		if week == 1 {
			eng.DB().KEV["CVE-2099-0102"] = kev0102
		}
		dns, names, exp := World(now, week, tokens)
		ct := CTServer(names)
		d := discovery.New()
		d.CTBase, d.DNS = ct.URL, dns
		svc.DNS, svc.Discovery, svc.Exposure = dns, d, exposure.NewMulti(exp, SecondFrom(exp, now))
		if _, err := svc.Scan(ctx, acme.ID, nil); err != nil {
			ct.Close()
			return nil, err
		}
		if week == 1 {
			if _, err := svc.Scan(ctx, clinic.ID, nil); err != nil {
				ct.Close()
				return nil, err
			}
		}
		ct.Close()
		last = exp
	}
	if err := demoPolicy(ctx, svc, acme.ID); err != nil {
		return nil, err
	}
	return last, nil
}

// demoPolicy carga el flujo de trabajo de ejemplo de Acme: contexto, una regla, estados de hallazgos,
// programacion y alertas (con destinos ficticios).
func demoPolicy(ctx context.Context, svc *app.Service, orgID string) error {
	for _, c := range []domain.AssetContext{
		{Match: "203.0.113.0/28", Environment: "produccion", Criticality: "alta", Owner: "Operaciones (planta)"},
		{Match: "vpn." + Acme, Environment: "produccion", Criticality: "alta", Owner: "Redes"},
		{Match: "legacy." + Acme, Environment: "pruebas", Owner: "Infraestructura", Note: "Servidor viejo, se apaga en marzo"},
		{Match: "198.51.100.50", Environment: "desarrollo", Owner: "Equipo Web"},
	} {
		if _, err := svc.SaveContext(ctx, orgID, c); err != nil {
			return err
		}
	}
	if _, err := svc.SaveRule(ctx, orgID, domain.SeverityRule{Rule: "HY-01", Severity: domain.SevCritical, Note: "Política interna: ningún panel de administración público"}); err != nil {
		return err
	}
	ov, err := svc.Overview(ctx)
	if err != nil {
		return err
	}
	var snapID string
	for _, o := range ov.Orgs {
		if o.ID == orgID && o.Latest != nil {
			snapID = o.Latest.ID
		}
	}
	sn, err := svc.Snapshot(ctx, snapID)
	if err != nil {
		return err
	}
	until := sn.StartedAt.AddDate(0, 2, 0).Format("2006-01-02")
	for _, f := range sn.Findings {
		var c *app.StateChange
		switch {
		case f.Rule == "PX-FTP":
			c = &app.StateChange{Status: domain.StatusAccepted, Note: "Se reemplaza por SFTP en el próximo trimestre; acceso limitado por IP", By: "Ulises (ejemplo)", Until: until}
		case f.CVE == "CVE-2099-0101":
			c = &app.StateChange{Status: domain.StatusInProgress, Note: "Ticket SEC-142: parche programado para el viernes", By: "Redes"}
		case f.Rule == "TLS-03":
			c = &app.StateChange{Status: domain.StatusFalsePositive, Note: "Certificado interno del entorno de pruebas, no lo usan clientes", By: "Infraestructura"}
		}
		if c != nil {
			if _, err := svc.SetState(ctx, orgID, f.ID, *c); err != nil {
				return err
			}
		}
	}
	if _, err := svc.SetSchedule(ctx, orgID, domain.Schedule{Enabled: true, Hours: 168, Mode: "escanear"}); err != nil {
		return err
	}
	for _, a := range []domain.Alert{
		{Name: "KEV al canal de seguridad", Channel: "slack", Target: "https://hooks.slack.com/services/EJEMPLO/EJEMPLO/ejemplo0000", Events: []string{domain.EventKEV}, Enabled: true},
		{Name: "Críticas nuevas a Jira", Channel: "jira", Target: "SEC", Events: []string{domain.EventNewFinding, domain.EventEscalated}, MinSeverity: domain.SevCritical, Enabled: true},
		{Name: "Resumen semanal por correo", Channel: "email", Target: "seguridad@acme-logistica.example", Events: []string{domain.EventEveryScan}, Enabled: true},
	} {
		if _, err := svc.SaveAlert(ctx, orgID, a); err != nil {
			return err
		}
	}
	return nil
}

// Intel arma una base de inteligencia ficticia (CVE-2099-*) que muestra cada caso del motor: una
// confirmada en KEV, una probable por rango, una descartada por version, una por confirmar por ser un
// paquete de Ubuntu, una sin datos de versiones, otra que la fuente no informo y un fin de soporte.
func Intel() *intel.DB {
	db := intel.NewDB()
	names := map[string]string{"fortios": "Fortinet FortiOS", "grafana": "Grafana", "openssh": "OpenSSH", "nginx": "nginx", "vsftpd": "vsftpd"}
	rec := func(id, summary string, cvss float64, ssvc *domain.SSVC, products []string, q string, ranges ...intel.Range) {
		db.AddRecord(&intel.Record{CVE: id, Summary: summary, CVSS: cvss, SSVC: ssvc, Published: "2099-01-15", CWE: []string{"CWE-20"},
			Sources: []string{"cve"}, Affected: []intel.Affected{{Products: products, Name: names[products[0]], Ranges: ranges, Quality: q, Source: "cve"}}})
	}
	rec("CVE-2099-0101", "Vulnerabilidad ficticia de ejemplo: ejecución remota sin autenticación en el portal SSL VPN.", 9.8,
		&domain.SSVC{Exploitation: "active", Automatable: "yes", TechnicalImpact: "total"}, []string{"fortios"}, intel.QualityStructured,
		intel.Range{Start: "7.0.0", StartInc: true, End: "7.0.12"})
	rec("CVE-2099-0102", "Vulnerabilidad ficticia de ejemplo: lectura de archivos del servidor.", 7.5,
		&domain.SSVC{Exploitation: "poc", Automatable: "no", TechnicalImpact: "partial"}, []string{"grafana"}, intel.QualityText,
		intel.Range{Start: "8.0.0", StartInc: true, End: "9.1.6", EndInc: true})
	rec("CVE-2099-0104", "Vulnerabilidad ficticia de ejemplo en el servidor SSH.", 8.1,
		&domain.SSVC{Exploitation: "poc", Automatable: "no", TechnicalImpact: "total"}, []string{"openssh"}, intel.QualityStructured,
		intel.Range{Start: "8.5p1", StartInc: true, End: "9.8p1"})
	rec("CVE-2099-0105", "Vulnerabilidad ficticia de ejemplo en el módulo de proxy.", 7.5, nil, []string{"nginx"}, intel.QualityStructured,
		intel.Range{Start: "1.20.0", StartInc: true, End: "1.22.1"})
	rec("CVE-2099-0106", "Vulnerabilidad ficticia de ejemplo: lectura de archivos fuera de la carpeta compartida del FTP.", 8.6,
		&domain.SSVC{Exploitation: "poc", Automatable: "yes", TechnicalImpact: "partial"}, []string{"vsftpd"}, intel.QualityStructured,
		intel.Range{Start: "3.0.0", StartInc: true, End: "3.0.5"})
	db.KEV["CVE-2099-0101"] = intel.KEVEntry{Vendor: "Ejemplo", Product: "SSL VPN", Name: "Ejecución remota (ficticia)", Added: "2099-01-20", Due: "2099-02-10"}
	db.KEV["CVE-2099-0102"] = intel.KEVEntry{Vendor: "Ejemplo", Product: "Grafana", Name: "Lectura de archivos (ficticia)", Added: "2099-02-01", Due: "2099-02-22", Ransomware: true}
	for id, x := range map[string][2]float64{"CVE-2099-0101": {0.94, 0.999}, "CVE-2099-0102": {0.03, 0.88}, "CVE-2099-0103": {0.002, 0.41},
		"CVE-2099-0104": {0.04, 0.9}, "CVE-2099-0106": {0.21, 0.96}} {
		db.EPSS[id] = intel.EPSSEntry{Score: x[0], Percentile: x[1], Date: "2099-01-31"}
	}
	db.NVDHits["beasts:vsftpd@3.0.3"] = []string{"CVE-2099-0106"} // la fuente no la informo: la encuentra Baqueano
	db.EOL["apache-http-server"] = []intel.Release{{Name: "2.2", IsEOL: true}, {Name: "2.4", IsEOL: false}}
	db.KEVCatalog = "ejemplo"
	at := time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)
	for _, k := range []string{"kev", "cve", "epss", "eol"} {
		db.Updated[k] = at
	}
	return db
}
