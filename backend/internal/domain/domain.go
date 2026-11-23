// Package domain es el modelo de Baqueano. No depende de nada del proyecto ni de ninguna fuente externa.
package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"sort"
	"strings"
	"time"
)

// Organization es una organizacion cuya superficie se vigila. El alcance (dominios y redes) se analiza
// si alguien se hizo responsable de el con una declaracion, o si el dueño lo verifico en DNS.
type Organization struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Domains     []Domain     `json:"domains"`
	Networks    []string     `json:"networks,omitempty"` // redes declaradas por quien cargo la organizacion
	Attestation *Attestation `json:"attestation,omitempty"`
	Audit       []AuditEvent `json:"audit,omitempty"` // historial: quien hizo que y cuando
	CreatedAt   time.Time    `json:"created_at"`
}

// Attestation es la declaracion de responsabilidad de quien cargo el alcance.
type Attestation struct {
	By        string    `json:"by"`
	At        time.Time `json:"at"`
	Statement string    `json:"statement"`
}

// AttestationText es el texto que se acepta.
const AttestationText = "Declaro que soy responsable de estos dominios y redes, o que tengo autorización de su dueño para analizarlos. " +
	"Entiendo que Baqueano solo usa datos públicos y que esta declaración queda registrada."

// AuditEvent es una entrada del historial de la organizacion.
type AuditEvent struct {
	At     time.Time `json:"at"`
	Action string    `json:"action"`
	Detail string    `json:"detail,omitempty"`
}

// Authorized indica si el dominio se puede analizar: verificado en DNS o con declaracion de responsabilidad.
func (o Organization) Authorized(d Domain) bool { return d.Verified() || o.Attestation != nil }

// Domain es un dominio de la organizacion y el estado de su verificacion.
type Domain struct {
	Name       string     `json:"name"`
	Token      string     `json:"token"` // valor que el dueño publica en DNS
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	Networks   []string   `json:"networks,omitempty"` // redes CIDR declaradas en DNS por el dueño
	LastCheck  *time.Time `json:"last_check,omitempty"`
	CheckError string     `json:"check_error,omitempty"`
}

// Verified indica si el dominio paso la verificacion.
func (d Domain) Verified() bool { return d.VerifiedAt != nil }

// TXTRecord es el registro que el dueño tiene que publicar.
func (d Domain) TXTRecord() string { return "baqueano-verify=" + d.Token }

// Asset es un nombre de host o una IP descubierta dentro del alcance.
type Asset struct {
	Hostname   string   `json:"hostname,omitempty"`
	IPs        []string `json:"ips,omitempty"`
	CNAME      string   `json:"cname,omitempty"`
	Sources    []string `json:"sources"` // ct, dns, declared, shodan
	Resolves   bool     `json:"resolves"`
	ThirdParty string   `json:"third_party,omitempty"` // proveedor si apunta a un servicio de terceros (CDN, SaaS)
}

// Vuln es una vulnerabilidad asociada a un servicio por la fuente de exposicion.
type Vuln struct {
	CVE      string  `json:"cve"`
	CVSS     float64 `json:"cvss,omitempty"`
	EPSS     float64 `json:"epss,omitempty"`
	KEV      bool    `json:"kev,omitempty"`
	Verified bool    `json:"verified"` // false = inferida por la version, no confirmada
	Summary  string  `json:"summary,omitempty"`
}

// Cert resume el certificado TLS de un servicio.
type Cert struct {
	Subject    string    `json:"subject,omitempty"`
	Issuer     string    `json:"issuer,omitempty"`
	NotAfter   time.Time `json:"not_after"`
	SelfSigned bool      `json:"self_signed,omitempty"`
	Expired    bool      `json:"expired,omitempty"`
	Versions   []string  `json:"tls_versions,omitempty"` // versiones de TLS/SSL que acepta
}

// Service es un puerto abierto visto desde internet.
type Service struct {
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	Transport string    `json:"transport"`
	Product   string    `json:"product,omitempty"`
	Version   string    `json:"version,omitempty"`
	Module    string    `json:"module,omitempty"` // protocolo segun la fuente (http, ssh, rdp, modbus…)
	Title     string    `json:"http_title,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	CPEs      []string  `json:"cpes,omitempty"`
	Vulns     []Vuln    `json:"vulns,omitempty"`
	Cert      *Cert     `json:"cert,omitempty"`
	Hostnames []string  `json:"hostnames,omitempty"`
	Org       string    `json:"org,omitempty"` // organizacion de la IP segun la fuente (ISP, nube)
	Country   string    `json:"country,omitempty"`
	SeenAt    time.Time `json:"seen_at"`
	Source    string    `json:"source"` // shodan | internetdb
}

// Key identifica un servicio entre escaneos.
func (s Service) Key() string { return s.IP + "/" + strings.ToLower(s.Transport) + "/" + itoa(s.Port) }

// Severity de un hallazgo.
type Severity string

const (
	SevCritical Severity = "critica"
	SevHigh     Severity = "alta"
	SevMedium   Severity = "media"
	SevLow      Severity = "baja"
	SevInfo     Severity = "info"
)

// Rank ordena severidades (mayor = mas grave).
func (s Severity) Rank() int {
	return map[Severity]int{SevCritical: 5, SevHigh: 4, SevMedium: 3, SevLow: 2, SevInfo: 1}[s]
}

// Finding es un problema detectado, siempre con su evidencia y su correccion.
type Finding struct {
	ID             string   `json:"id"` // estable entre escaneos
	Rule           string   `json:"rule"`
	Category       string   `json:"category"` // servicio-expuesto | vulnerabilidad | tls | dns | higiene
	Severity       Severity `json:"severity"`
	Title          string   `json:"title"`
	Detail         string   `json:"detail"`
	Recommendation string   `json:"recommendation"`
	Asset          string   `json:"asset"` // IP:puerto o hostname
	Evidence       []string `json:"evidence,omitempty"`
	CVE            string   `json:"cve,omitempty"`
}

// FindingID calcula una huella estable.
func FindingID(rule, asset, extra string) string {
	h := sha256.Sum256([]byte(rule + "\x00" + asset + "\x00" + extra))
	return hex.EncodeToString(h[:])[:16]
}

// Snapshot es el resultado de un escaneo: lo que se vio de la organizacion en un momento dado.
type Snapshot struct {
	ID            string    `json:"id"`
	OrgID         string    `json:"org_id"`
	OrgName       string    `json:"org_name"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	Domains       []string  `json:"domains"`       // dominios que se analizaron
	Networks      []string  `json:"networks"`      // redes que se analizaron
	Authorization []string  `json:"authorization"` // con que autorizacion se analizo cada parte del alcance
	Assets        []Asset   `json:"assets"`
	Services      []Service `json:"services"`
	Findings      []Finding `json:"findings"`
	Sources       []string  `json:"sources"` // fuentes usadas y su estado
	Notes         []string  `json:"notes,omitempty"`
}

// IPs devuelve las IP unicas del escaneo.
func (s Snapshot) IPs() []string {
	set := map[string]bool{}
	for _, a := range s.Assets {
		for _, ip := range a.IPs {
			set[ip] = true
		}
	}
	for _, sv := range s.Services {
		set[sv.IP] = true
	}
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

// Score es el puntaje de exposicion 0-100 (100 = nada grave a la vista). Cada hallazgo suma una
// penalidad (con rendimiento decreciente dentro de la misma severidad) y el total se lleva a una curva
// exponencial: una organizacion muy expuesta queda baja pero no en cero, y cada correccion se nota.
func (s Snapshot) Score() int {
	penalty := map[Severity]float64{SevCritical: 25, SevHigh: 10, SevMedium: 4, SevLow: 1}
	seen := map[Severity]int{}
	total := 0.0
	for _, f := range s.Findings {
		n := seen[f.Severity]
		seen[f.Severity]++
		total += penalty[f.Severity] / float64(1+n/3)
	}
	return int(100*math.Exp(-total/120) + 0.5)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
