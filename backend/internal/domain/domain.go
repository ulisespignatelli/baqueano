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

	// Flujo de trabajo (v0.3): se aplican al mostrar, asi un cambio vale tambien para el historial.
	Contexts []AssetContext          `json:"contexts,omitempty"` // ambiente, criticidad y responsable de los activos
	Rules    []SeverityRule          `json:"rules,omitempty"`    // severidades propias de la organizacion
	States   map[string]FindingState `json:"states,omitempty"`   // estado de cada hallazgo, por ID estable

	// Automatizacion (v0.4).
	Schedule *Schedule `json:"schedule,omitempty"`
	Alerts   []Alert   `json:"alerts,omitempty"`
}

// AssetContext describe activos que coinciden con un patron: nombre exacto, comodin (*.dev.acme.com),
// IP o red (203.0.113.0/28).
type AssetContext struct {
	ID          string `json:"id"`
	Match       string `json:"match"`
	Environment string `json:"environment,omitempty"` // produccion | pruebas | desarrollo
	Criticality string `json:"criticality,omitempty"` // alta | normal | baja
	Owner       string `json:"owner,omitempty"`
	Note        string `json:"note,omitempty"`
}

// SeverityRule fija la severidad de un control (o de una familia: "PX-*") para la organizacion, opcionalmente
// solo en ciertos activos o ambientes.
type SeverityRule struct {
	ID          string   `json:"id"`
	Rule        string   `json:"rule"`                  // "PX-RDP", "PX-*", "VU-01", "*"
	Match       string   `json:"match,omitempty"`       // patron de activo
	Environment string   `json:"environment,omitempty"` // solo en ese ambiente
	Severity    Severity `json:"severity"`
	Note        string   `json:"note"`
}

// Estados de un hallazgo.
const (
	StatusOpen          = "abierto"
	StatusInProgress    = "en-curso"
	StatusAccepted      = "aceptado"       // riesgo aceptado, con motivo y vencimiento
	StatusFalsePositive = "falso-positivo" // con motivo
)

// FindingState es la decision de la organizacion sobre un hallazgo.
type FindingState struct {
	Status string     `json:"status"`
	Note   string     `json:"note,omitempty"`
	By     string     `json:"by,omitempty"`
	At     time.Time  `json:"at"`
	Until  *time.Time `json:"until,omitempty"` // vencimiento de la aceptacion
}

// Schedule programa escaneos o reevaluaciones periodicas.
type Schedule struct {
	Enabled   bool      `json:"enabled"`
	Hours     int       `json:"hours"` // cada cuantas horas (24 = diario, 168 = semanal)
	Mode      string    `json:"mode"`  // escanear | reevaluar
	NextRun   time.Time `json:"next_run"`
	LastRun   time.Time `json:"last_run,omitempty"`
	LastError string    `json:"last_error,omitempty"`
}

// Eventos que pueden disparar una alerta.
const (
	EventNewFinding = "hallazgo-nuevo"
	EventEscalated  = "sube-severidad"
	EventNewService = "servicio-nuevo"
	EventKEV        = "kev"     // una vulnerabilidad del alcance esta (o entro) en KEV
	EventEveryScan  = "resumen" // resumen de cada escaneo
)

// Alert envia avisos a un canal cuando pasa algo en un escaneo.
type Alert struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Channel     string            `json:"channel"` // webhook | slack | teams | email | jira
	Target      string            `json:"target"`  // URL, direcciones de correo o clave de proyecto Jira
	Events      []string          `json:"events"`
	MinSeverity Severity          `json:"min_severity,omitempty"`
	Rules       []string          `json:"rules,omitempty"` // solo estos controles (prefijos)
	Enabled     bool              `json:"enabled"`
	LastSent    *time.Time        `json:"last_sent,omitempty"`
	LastError   string            `json:"last_error,omitempty"`
	Tickets     map[string]string `json:"tickets,omitempty"` // Jira: hallazgo -> ticket (para no duplicar)
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
	Verified bool    `json:"verified"` // la fuente la confirmo (no solo la infirio por la version)
	Summary  string  `json:"summary,omitempty"`

	// Origen y evaluacion propia (motor de inteligencia).
	Origin         string   `json:"origin,omitempty"`     // quien la propuso: shodan | internetdb | baqueano
	Confidence     string   `json:"confidence,omitempty"` // confirmada | probable | por-confirmar | descartada
	Reason         string   `json:"reason,omitempty"`     // por que esa confianza, en castellano
	FixedIn        string   `json:"fixed_in,omitempty"`   // primera version corregida en la rama del servicio
	Sources        []string `json:"sources,omitempty"`    // datos usados: nvd, cve, vulnrichment, kev, epss
	Priority       string   `json:"priority,omitempty"`   // P1 hoy | P2 esta semana | P3 este mes | P4 planificar
	PriorityReason string   `json:"priority_reason,omitempty"`

	// Contexto de explotacion.
	EPSSPercentile float64  `json:"epss_percentile,omitempty"`
	KEVDue         string   `json:"kev_due,omitempty"`    // fecha limite de CISA
	Ransomware     bool     `json:"ransomware,omitempty"` // CISA la vincula con campanas de ransomware
	SSVC           *SSVC    `json:"ssvc,omitempty"`
	CWE            []string `json:"cwe,omitempty"`
	Published      string   `json:"published,omitempty"`
}

// SSVC son los puntos de decision que publica CISA (Vulnrichment).
type SSVC struct {
	Exploitation    string `json:"exploitation"`     // none | poc | active
	Automatable     string `json:"automatable"`      // yes | no
	TechnicalImpact string `json:"technical_impact"` // partial | total
}

// EOL indica que el software del servicio ya no tiene soporte del fabricante.
type EOL struct {
	Product string `json:"product"`
	Cycle   string `json:"cycle"`
	Since   string `json:"since,omitempty"`  // fecha de fin de soporte
	Latest  string `json:"latest,omitempty"` // ultima version publicada de esa rama
	Source  string `json:"source"`
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
	Dismissed []Vuln    `json:"dismissed,omitempty"` // CVE propuestas por la fuente que el motor descarto, con el motivo
	EOL       *EOL      `json:"eol,omitempty"`
	Banner    string    `json:"banner,omitempty"` // primera linea del banner (sirve para detectar parches de la distro)
	Cert      *Cert     `json:"cert,omitempty"`
	Hostnames []string  `json:"hostnames,omitempty"`
	Org       string    `json:"org,omitempty"` // organizacion de la IP segun la fuente (ISP, nube)
	Country   string    `json:"country,omitempty"`
	SeenAt    time.Time `json:"seen_at"`
	SeenBy    []string  `json:"seen_by,omitempty"` // fuentes que vieron este servicio (v0.5)
	Source    string    `json:"source"`            // shodan | internetdb
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
	Vuln           *Vuln    `json:"vuln,omitempty"` // evaluacion completa de la CVE (confianza, prioridad, contexto)

	// Aplicados al mostrar segun la politica de la organizacion.
	BaseSeverity Severity      `json:"base_severity,omitempty"` // severidad antes del contexto y las reglas
	Adjustments  []string      `json:"adjustments,omitempty"`   // por que cambio la severidad
	Environment  string        `json:"environment,omitempty"`
	Criticality  string        `json:"criticality,omitempty"`
	Owner        string        `json:"owner,omitempty"`
	State        *FindingState `json:"state,omitempty"`
}

// Active dice si el hallazgo cuenta para el puntaje: los aceptados (vigentes) y los falsos positivos no.
func (f Finding) Active() bool {
	return f.State == nil || (f.State.Status != StatusAccepted && f.State.Status != StatusFalsePositive)
}

// FindingID calcula una huella estable.
func FindingID(rule, asset, extra string) string {
	h := sha256.Sum256([]byte(rule + "\x00" + asset + "\x00" + extra))
	return hex.EncodeToString(h[:])[:16]
}

// Snapshot es el resultado de un escaneo: lo que se vio de la organizacion en un momento dado.
type Snapshot struct {
	ID            string     `json:"id"`
	OrgID         string     `json:"org_id"`
	OrgName       string     `json:"org_name"`
	StartedAt     time.Time  `json:"started_at"`
	FinishedAt    time.Time  `json:"finished_at"`
	Domains       []string   `json:"domains"`       // dominios que se analizaron
	Networks      []string   `json:"networks"`      // redes que se analizaron
	Authorization []string   `json:"authorization"` // con que autorizacion se analizo cada parte del alcance
	Assets        []Asset    `json:"assets"`
	Services      []Service  `json:"services"`
	Findings      []Finding  `json:"findings"`
	Sources       []string   `json:"sources"` // fuentes usadas y su estado
	Notes         []string   `json:"notes,omitempty"`
	Consensus     *Consensus `json:"consensus,omitempty"` // coincidencia entre fuentes de exposicion (v0.5)
}

// Consensus resume cuanto coinciden las fuentes de exposicion.
type Consensus struct {
	Sources  []string `json:"sources"`
	Services int      `json:"services"`
	All      int      `json:"all"`    // servicios que vieron todas las fuentes
	Single   int      `json:"single"` // servicios que vio una sola
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
		if !f.Active() {
			continue
		}
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
