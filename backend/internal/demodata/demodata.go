// Package demodata arma un escenario FICTICIO para la demo y los tests: dominios .example (RFC 2606),
// IP de documentacion (RFC 5737) y CVE inventadas (CVE-2099-*). Pasa por el pipeline real; solo las
// fuentes externas (DNS, Certificate Transparency, Shodan) estan simuladas.
package demodata

import (
	"context"
	"encoding/json"
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
			svc("198.51.100.10", 443, "https", "nginx", "1.24.0", cert("www."+Acme, now.Add(70*day), "TLSv1.2", "TLSv1.3")),
		},
		"198.51.100.20": {
			svc("198.51.100.20", 25, "smtp", "Postfix smtpd", "", nil),
			svc("198.51.100.20", 993, "imap-ssl", "Dovecot", "", cert("mail."+Acme, mailCert, "TLSv1.2", "TLSv1.3")),
		},
		"198.51.100.30": {
			svc("198.51.100.30", 443, "https", "Fortinet FortiGate SSL VPN", "", func(s *domain.Service) {
				s.Title = "FortiGate - Login"
				s.Cert = &domain.Cert{Subject: "vpn." + Acme, Issuer: "CA de ejemplo", NotAfter: now.Add(200 * day), Versions: []string{"TLSv1.2"}}
				s.Vulns = []domain.Vuln{{CVE: "CVE-2099-0101", CVSS: 9.8, EPSS: 0.94, KEV: true, Verified: true,
					Summary: "Vulnerabilidad ficticia de ejemplo: ejecución remota en el portal SSL VPN."}}
			}),
		},
		"198.51.100.40": {
			svc("198.51.100.40", 3000, "http", "Grafana", "9.1.0", func(s *domain.Service) {
				s.Title = "Grafana"
				s.Vulns = []domain.Vuln{{CVE: "CVE-2099-0102", CVSS: 7.5, EPSS: 0.03, Verified: false, Summary: "Vulnerabilidad ficticia de ejemplo: lectura de archivos."}}
			}),
		},
		"198.51.100.50": {
			svc("198.51.100.50", 21, "ftp", "vsftpd", "3.0.3", nil),
			svc("198.51.100.50", 22, "ssh", "OpenSSH", "8.9p1", nil),
		},
		"198.51.100.60": {
			svc("198.51.100.60", 80, "http", "Apache httpd", "2.2.15", func(s *domain.Service) {
				s.Tags = []string{"eol-product"}
				s.Vulns = []domain.Vuln{{CVE: "CVE-2099-0103", CVSS: 9.8, EPSS: 0.002, Verified: false, Summary: "Vulnerabilidad ficticia de ejemplo inferida por la versión."}}
			}),
			svc("198.51.100.60", 443, "https", "Apache httpd", "2.2.15", func(s *domain.Service) {
				s.Tags = []string{"eol-product", "self-signed"}
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
	svc := &app.Service{Repo: repo, Now: func() time.Time { return now }}
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
		dns, names, exp := World(now, week, tokens)
		ct := CTServer(names)
		d := discovery.New()
		d.CTBase, d.DNS = ct.URL, dns
		svc.DNS, svc.Discovery, svc.Exposure = dns, d, exp
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
	return last, nil
}
