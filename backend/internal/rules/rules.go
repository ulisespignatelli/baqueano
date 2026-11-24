// Package rules convierte lo observado (activos y servicios) en hallazgos explicados. Es logica pura:
// mismo insumo, mismo resultado.
package rules

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

// exposedRule describe un servicio que no deberia estar abierto a internet.
type exposedRule struct {
	id, label, why, fix string
	sev                 domain.Severity
	ports               []int
	modules             []string
}

var exposed = []exposedRule{
	{"PX-RDP", "Escritorio remoto (RDP)", "Es uno de los accesos iniciales más usados por grupos de ransomware: fuerza bruta de contraseñas y vulnerabilidades del servicio.",
		"Cerrarlo a internet y acceder por VPN con MFA o por un gateway de escritorio remoto.", domain.SevCritical, []int{3389}, []string{"rdp"}},
	{"PX-SMB", "Compartición de archivos de Windows (SMB)", "SMB expuesto permite ataques directos al sistema operativo y fue la vía de gusanos como WannaCry.",
		"Bloquear los puertos 445 y 139 en el perímetro. SMB nunca debería cruzar internet.", domain.SevCritical, []int{445, 139}, []string{"smb", "netbios"}},
	{"PX-TELNET", "Telnet", "Envía usuario y contraseña en texto claro y suele estar en equipos con credenciales por defecto.",
		"Deshabilitarlo y usar SSH. Si el equipo no lo permite, aislarlo detrás de una VPN.", domain.SevCritical, []int{23}, []string{"telnet"}},
	{"PX-VNC", "VNC", "Control remoto gráfico con autenticación débil; muchas instancias aceptan conexiones sin contraseña.",
		"Cerrarlo a internet y acceder por VPN o por un túnel SSH.", domain.SevCritical, []int{5900, 5901, 5902, 5903}, []string{"vnc"}},
	{"PX-DB", "Base de datos", "Una base de datos expuesta es uno de los orígenes más comunes de filtraciones masivas de datos.",
		"Escuchar solo en la red interna o restringir por IP de origen. Nunca publicarla a internet.", domain.SevCritical,
		[]int{3306, 5432, 1433, 1521, 27017, 27018, 6379, 9200, 9300, 5984, 9042, 7474, 8086, 11211},
		[]string{"mysql", "postgresql", "mssql", "oracle-tns", "mongodb", "redis", "elastic", "couchdb", "cassandra", "memcache", "influxdb"}},
	{"PX-INFRA", "API de infraestructura (Docker, Kubernetes, etcd)", "Da control directo sobre contenedores o el clúster: suele terminar en toma completa del servidor.",
		"Cerrarla a internet y exigir autenticación mutua (TLS de cliente).", domain.SevCritical,
		[]int{2375, 2376, 2379, 2380, 6443, 10250, 10255}, []string{"docker", "kubernetes", "etcd"}},
	{"PX-ICS", "Protocolo industrial (OT/ICS)", "Los protocolos industriales no autentican a quien envía comandos: cualquiera puede leer o escribir en el equipo.",
		"Sacarlo de internet de inmediato y dar acceso remoto solo por una DMZ industrial con VPN y MFA (IEC 62443).", domain.SevCritical,
		[]int{502, 102, 20000, 44818, 2404, 47808, 9600, 5094, 18245, 5007, 1911, 1962, 20547},
		[]string{"modbus", "s7", "dnp3", "ethernetip", "iec-104", "bacnet", "omron", "hart-ip", "gesrtp", "melsec-q", "fox", "pcworx", "proconos"}},
	{"PX-FTP", "FTP", "Transfiere credenciales y archivos en texto claro; a veces permite acceso anónimo.",
		"Reemplazarlo por SFTP o HTTPS y cerrar el puerto 21.", domain.SevHigh, []int{21}, []string{"ftp"}},
	{"PX-SNMP", "SNMP", "SNMP v1/v2c usa comunidades que viajan en claro y suele filtrar la configuración del equipo.",
		"Cerrarlo a internet; para monitoreo usar SNMPv3 desde la red de gestión.", domain.SevHigh, []int{161}, []string{"snmp"}},
	{"PX-LDAP", "Directorio (LDAP)", "Expone la estructura del directorio y sirve para enumerar usuarios y ataques de fuerza bruta.",
		"Cerrarlo a internet; si un servicio externo lo necesita, usar LDAPS con origen restringido.", domain.SevHigh, []int{389, 636, 3268}, []string{"ldap"}},
	{"PX-SSH", "SSH", "Un SSH abierto a todo internet recibe fuerza bruta constante; un error de configuración o una clave débil alcanzan.",
		"Restringirlo por IP de origen o ponerlo detrás de una VPN o un bastión; deshabilitar el acceso con contraseña.", domain.SevMedium, []int{22}, []string{"ssh"}},
}

// adminTitles: titulos de paginas de administracion que no deberian ser publicas. No incluye los
// portales de VPN (FortiGate, SonicWall, GlobalProtect…): esos tienen que ser publicos por diseño.
var adminTitles = []string{"phpmyadmin", "jenkins", "grafana", "kibana", "prometheus", "rabbitmq management", "portainer",
	"webmin", "cpanel", "plesk", "tomcat", "routeros", "pfsense", "zabbix", "nagios",
	"elasticsearch", "minio console", "pgadmin", "adminer"}

// Options para la evaluacion.
type Options struct {
	Now          time.Time
	CertWarnDays int // aviso de vencimiento (por defecto 30)
}

// Evaluate devuelve los hallazgos de un escaneo, de mas grave a menos grave.
func Evaluate(assets []domain.Asset, services []domain.Service, opt Options) []domain.Finding {
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	if opt.CertWarnDays == 0 {
		opt.CertWarnDays = 30
	}
	var out []domain.Finding
	seen := map[string]bool{}
	add := func(f domain.Finding) {
		if f.ID == "" {
			f.ID = domain.FindingID(f.Rule, f.Asset, f.CVE)
		}
		if !seen[f.ID] {
			seen[f.ID] = true
			out = append(out, f)
		}
	}

	for _, a := range assets {
		// DNS-01: CNAME colgante (posible toma del subdominio)
		if a.CNAME != "" && !a.Resolves && a.ThirdParty != "" {
			add(domain.Finding{Rule: "DNS-01", Category: "dns", Severity: domain.SevHigh, Asset: a.Hostname,
				Title:  "Subdominio que apunta a un servicio de terceros que ya no existe",
				Detail: fmt.Sprintf("%s es un CNAME a %s (%s), que no resuelve.", a.Hostname, a.CNAME, a.ThirdParty),
				Recommendation: "Eliminar el registro CNAME o volver a crear el recurso en el proveedor. Mientras exista, " +
					"alguien podría registrar ese recurso y publicar contenido en el subdominio de la organización.",
				Evidence: []string{"CNAME " + a.CNAME}})
		}
	}

	for _, s := range services {
		where := fmt.Sprintf("%s:%d", s.IP, s.Port)
		host := ""
		if len(s.Hostnames) > 0 {
			host = " (" + strings.Join(s.Hostnames[:min(2, len(s.Hostnames))], ", ") + ")"
		}
		prod := strings.TrimSpace(s.Product + " " + s.Version)

		// PX-*: servicios que no deberian estar en internet
		for _, r := range exposed {
			if matches(r, s) {
				f := domain.Finding{Rule: r.id, Category: "servicio-expuesto", Severity: r.sev, Asset: where,
					Title: r.label + " accesible desde internet", Detail: fmt.Sprintf("%s%s responde en el puerto %d/%s%s. %s",
						s.IP, host, s.Port, s.Transport, ifs(prod != "", " ("+prod+")", ""), r.why),
					Recommendation: r.fix, Evidence: evidence(s)}
				if r.id == "PX-SSH" && hasTag(s, "honeypot") {
					continue
				}
				add(f)
				break
			}
		}

		// VU-*: vulnerabilidades
		for _, v := range s.Vulns {
			sev, title, detail := vulnSeverity(v)
			rec := "Actualizar el componente a una versión corregida. Si no es posible ya, restringir el acceso al servicio " +
				"o aplicar la mitigación del fabricante." + ifs(!v.Verified && v.Confidence == "", " Antes, confirmar la versión real: Shodan la infiere del banner.", "")
			if v.Priority != "" {
				rec = vulnRecommendation(v)
			}
			vv := v
			add(domain.Finding{Rule: "VU-01", Category: "vulnerabilidad", Severity: sev, Asset: where, CVE: v.CVE,
				Title:          fmt.Sprintf("%s en %s", v.CVE, ifs(prod != "", prod, fmt.Sprintf("puerto %d", s.Port))) + title,
				Detail:         detail + ifs(v.Summary != "", " "+v.Summary, ""),
				Recommendation: rec, Evidence: evidence(s), Vuln: &vv})
		}

		// TLS-*
		if c := s.Cert; c != nil {
			days := int(c.NotAfter.Sub(opt.Now).Hours() / 24)
			switch {
			case c.Expired || (!c.NotAfter.IsZero() && days < 0):
				add(domain.Finding{Rule: "TLS-01", Category: "tls", Severity: domain.SevHigh, Asset: where,
					Title: "Certificado TLS vencido", Detail: fmt.Sprintf("El certificado de %s%s venció el %s.", where, ifs(c.Subject != "", " ("+c.Subject+")", ""), c.NotAfter.Format("2006-01-02")),
					Recommendation: "Renovarlo. Un certificado vencido acostumbra a los usuarios a ignorar las advertencias del navegador.", Evidence: evidence(s)})
			case !c.NotAfter.IsZero() && days <= opt.CertWarnDays:
				add(domain.Finding{Rule: "TLS-02", Category: "tls", Severity: domain.SevMedium, Asset: where,
					Title: fmt.Sprintf("Certificado TLS vence en %d días", days), Detail: fmt.Sprintf("%s%s vence el %s.", where, ifs(c.Subject != "", " ("+c.Subject+")", ""), c.NotAfter.Format("2006-01-02")),
					Recommendation: "Renovarlo y, si es posible, automatizar la renovación (ACME).", Evidence: evidence(s)})
			}
			if c.SelfSigned {
				add(domain.Finding{Rule: "TLS-03", Category: "tls", Severity: domain.SevLow, Asset: where,
					Title: "Certificado autofirmado en un servicio público", Detail: fmt.Sprintf("%s presenta un certificado autofirmado%s.", where, ifs(c.Subject != "", " ("+c.Subject+")", "")),
					Recommendation: "Usar un certificado de una autoridad reconocida o, si el servicio es interno, sacarlo de internet.", Evidence: evidence(s)})
			}
			var old []string
			for _, v := range c.Versions {
				switch strings.ToUpper(v) {
				case "SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1":
					old = append(old, v)
				}
			}
			if len(old) > 0 {
				add(domain.Finding{Rule: "TLS-04", Category: "tls", Severity: domain.SevMedium, Asset: where,
					Title: "Acepta versiones obsoletas de TLS/SSL", Detail: fmt.Sprintf("%s acepta %s, obsoletas desde 2021 (RFC 8996).", where, strings.Join(old, ", ")),
					Recommendation: "Aceptar solo TLS 1.2 y 1.3.", Evidence: evidence(s)})
			}
		}

		// HY-*: higiene
		if t := strings.ToLower(s.Title); t != "" {
			for _, k := range adminTitles {
				if strings.Contains(t, k) {
					add(domain.Finding{Rule: "HY-01", Category: "higiene", Severity: domain.SevHigh, Asset: where,
						Title: "Panel de administración publicado en internet", Detail: fmt.Sprintf("%s muestra la página «%s».", where, s.Title),
						Recommendation: "Restringir el acceso por VPN o por IP de origen y exigir MFA. Los paneles de administración no deberían ser públicos.",
						Evidence:       evidence(s)})
					break
				}
			}
		}
		if e := s.EOL; e != nil {
			detail := fmt.Sprintf("%s%s corre %s, de la rama %s, que dejó de recibir parches de seguridad%s.", s.IP, host,
				ifs(prod != "", prod, e.Product), e.Cycle, ifs(e.Since != "", " el "+e.Since, ""))
			add(domain.Finding{ID: domain.FindingID("HY-02", s.IP, prod), Rule: "HY-02", Category: "higiene", Severity: domain.SevMedium, Asset: s.IP,
				Title: "Software sin soporte del fabricante", Detail: detail + " Fuente: " + e.Source + ".",
				Recommendation: "Pasar a una rama con soporte. Las vulnerabilidades nuevas de esta rama ya no se van a corregir.", Evidence: evidence(s)})
		} else if hasTag(s, "eol-product") || hasTag(s, "eol-os") {
			add(domain.Finding{ID: domain.FindingID("HY-02", s.IP, prod), Rule: "HY-02", Category: "higiene", Severity: domain.SevMedium, Asset: s.IP,
				Title: "Software sin soporte del fabricante", Detail: fmt.Sprintf("%s%s corre %s, que ya no recibe actualizaciones de seguridad.", s.IP, host, ifs(prod != "", prod, "un producto")),
				Recommendation: "Planificar la actualización a una versión con soporte.", Evidence: evidence(s)})
		}
		if s.Port == 80 && s.Module == "http" && !hasPort(services, s.IP, 443) {
			add(domain.Finding{Rule: "HY-03", Category: "higiene", Severity: domain.SevLow, Asset: where,
				Title: "Sitio web solo por HTTP", Detail: fmt.Sprintf("%s publica HTTP sin HTTPS en la misma IP.", where),
				Recommendation: "Publicar por HTTPS y redirigir HTTP a HTTPS.", Evidence: evidence(s)})
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity.Rank() > out[j].Severity.Rank()
		}
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		return out[i].Asset < out[j].Asset
	})
	return out
}

// vulnSeverity: KEV primero, despues EPSS, despues CVSS; las no verificadas bajan un nivel.
// vulnRecommendation arma la recomendacion con lo que sabe el motor de inteligencia.
func vulnRecommendation(v domain.Vuln) string {
	var b strings.Builder
	switch {
	case strings.HasPrefix(v.FixedIn, "una versión posterior"):
		b.WriteString("Actualizar a " + v.FixedIn + ".")
	case v.FixedIn != "":
		b.WriteString("Actualizar a " + v.FixedIn + " o posterior.")
	default:
		b.WriteString("Actualizar a una versión corregida según el aviso del fabricante.")
	}
	if v.KEV {
		b.WriteString(" Está en el catálogo KEV de CISA" + ifs(v.KEVDue != "", " (las agencias de EE. UU. tienen plazo hasta el "+v.KEVDue+")", "") + ": si no se puede actualizar ya, sacar el servicio de internet o aplicar la mitigación del fabricante, y revisar si hubo intrusión.")
	} else {
		b.WriteString(" Mientras tanto, restringir el acceso al servicio.")
	}
	switch v.Confidence {
	case "por-confirmar":
		b.WriteString(" Antes, confirmar la versión instalada en el equipo (y, si es un paquete de la distribución, su aviso de seguridad).")
	case "improbable":
		b.WriteString(" Es probable que esta versión no esté afectada: confirmarlo con el aviso del fabricante y cerrar el hallazgo.")
	}
	return b.String()
}

func vulnSeverity(v domain.Vuln) (domain.Severity, string, string) {
	if v.Priority != "" {
		sev := map[string]domain.Severity{"P1": domain.SevCritical, "P2": domain.SevHigh, "P3": domain.SevMedium, "P4": domain.SevLow}[v.Priority]
		title := map[string]string{"por-confirmar": " (por confirmar)", "improbable": " (probablemente no aplica)"}[v.Confidence]
		label := map[string]string{"P1": "Corregir hoy", "P2": "Corregir esta semana", "P3": "Corregir este mes", "P4": "Planificar"}[v.Priority]
		return sev, title, fmt.Sprintf("%s: %s. %s", label, v.PriorityReason, v.Reason)
	}
	var sev domain.Severity
	var why string
	switch {
	case v.KEV:
		sev, why = domain.SevCritical, "Está en el catálogo KEV de CISA: se explota activamente."
	case v.EPSS >= 0.1:
		sev, why = domain.SevHigh, fmt.Sprintf("EPSS %.0f%%: alta probabilidad de explotación en los próximos 30 días.", v.EPSS*100)
	case v.CVSS >= 9:
		sev, why = domain.SevHigh, fmt.Sprintf("CVSS %.1f.", v.CVSS)
	case v.CVSS >= 7 || v.EPSS >= 0.01:
		sev, why = domain.SevMedium, fmt.Sprintf("CVSS %.1f, EPSS %.1f%%.", v.CVSS, v.EPSS*100)
	default:
		sev, why = domain.SevLow, ifs(v.CVSS > 0, fmt.Sprintf("CVSS %.1f.", v.CVSS), "Sin puntaje disponible.")
	}
	title := ""
	if !v.Verified {
		title = " (por confirmar)"
		why += " Inferida por la versión del banner, no confirmada."
		if !v.KEV && sev.Rank() > domain.SevLow.Rank() {
			sev = map[domain.Severity]domain.Severity{domain.SevHigh: domain.SevMedium, domain.SevMedium: domain.SevLow}[sev]
		}
	}
	return sev, title, why
}

// matches por protocolo (si la fuente lo identifica) o por puerto. Se aceptan ambos porque las fuentes
// nombran los protocolos de forma distinta y algunos servicios (Elasticsearch, CouchDB) hablan HTTP.
func matches(r exposedRule, s domain.Service) bool {
	for _, m := range r.modules {
		if s.Module != "" && (s.Module == m || strings.HasPrefix(s.Module, m)) {
			return true
		}
	}
	for _, p := range r.ports {
		if s.Port == p {
			return true
		}
	}
	return false
}

func evidence(s domain.Service) []string {
	var e []string
	if p := strings.TrimSpace(s.Product + " " + s.Version); p != "" {
		e = append(e, "producto: "+p)
	}
	if s.Module != "" {
		e = append(e, "protocolo: "+s.Module)
	}
	if s.Org != "" {
		e = append(e, "red: "+s.Org)
	}
	if len(s.SeenBy) > 1 {
		e = append(e, "visto por: "+strings.Join(s.SeenBy, " y ")+ifs(!s.SeenAt.IsZero(), " (último: "+s.SeenAt.Format("2006-01-02")+")", ""))
	} else if len(s.SeenBy) == 1 && !s.SeenAt.IsZero() {
		e = append(e, "visto solo por "+s.SeenBy[0]+": "+s.SeenAt.Format("2006-01-02"))
	} else if !s.SeenAt.IsZero() {
		e = append(e, "visto por "+s.Source+": "+s.SeenAt.Format("2006-01-02"))
	} else if s.Source != "" {
		e = append(e, "fuente: "+s.Source)
	}
	return e
}

func hasTag(s domain.Service, t string) bool {
	for _, x := range s.Tags {
		if x == t {
			return true
		}
	}
	return false
}

func hasPort(ss []domain.Service, ip string, port int) bool {
	for _, s := range ss {
		if s.IP == ip && s.Port == port {
			return true
		}
	}
	return false
}

func ifs(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}
