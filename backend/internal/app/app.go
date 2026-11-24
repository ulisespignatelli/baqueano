package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ulisespignatelli/baqueano/backend/internal/discovery"
	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
	"github.com/ulisespignatelli/baqueano/backend/internal/exposure"
	"github.com/ulisespignatelli/baqueano/backend/internal/intel"
	"github.com/ulisespignatelli/baqueano/backend/internal/rules"
	"github.com/ulisespignatelli/baqueano/backend/internal/scope"
)

// Intel es el motor de inteligencia de vulnerabilidades (intel.Engine lo cumple).
type Intel interface {
	Enrich(ctx context.Context, svcs []domain.Service, progress func(string)) ([]domain.Service, intel.Report)
}

// Discoverer es el puerto de descubrimiento (discovery.Discoverer lo cumple).
type Discoverer interface {
	Discover(ctx context.Context, domain string) discovery.Result
}

// Service reune los casos de uso.
type Service struct {
	Repo      Repository
	DNS       scope.Resolver
	Discovery Discoverer
	Exposure  exposure.Source // nil = sin fuente (solo descubrimiento)
	Intel     Intel           // nil = se usa lo que informa la fuente, sin evaluar
	Notifier  Notifier        // nil = no se envian alertas
	Now       func() time.Time
	MaxIPs    int // tope de IP consultadas por escaneo (por defecto 300)
	MaxPages  int // paginas de busqueda por red declarada (por defecto 2 = 200 servicios, 2 creditos)

	editMu sync.Mutex
	jobsMu sync.Mutex
	jobs   map[string]*Job
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// ---------------------------------------------------------------- organizaciones

// NewOrg son los datos para crear una organizacion.
type NewOrg struct {
	Name     string
	Domains  []string
	Networks []string
	// DeclaredBy es el nombre de quien acepta la declaracion de responsabilidad. Si esta vacio, la
	// organizacion solo se podra analizar en los dominios verificados por DNS.
	DeclaredBy string
}

// CreateOrg crea una organizacion.
func (s *Service) CreateOrg(ctx context.Context, in NewOrg) (domain.Organization, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 120 {
		return domain.Organization{}, errors.New("el nombre es obligatorio (hasta 120 caracteres)")
	}
	o := domain.Organization{ID: newID(), Name: name, CreatedAt: s.now()}
	for _, d := range in.Domains {
		if err := addDomain(&o, d); err != nil {
			return o, err
		}
	}
	if len(o.Domains) == 0 {
		return o, errors.New("hace falta al menos un dominio")
	}
	for _, n := range in.Networks {
		if err := addNetwork(&o, n); err != nil {
			return o, err
		}
	}
	s.audit(&o, "organización creada", fmt.Sprintf("dominios: %s%s", domainNames(o), netList(o.Networks)))
	if strings.TrimSpace(in.DeclaredBy) != "" {
		if err := s.attest(&o, in.DeclaredBy); err != nil {
			return o, err
		}
	}
	return o, s.Repo.SaveOrg(ctx, o)
}

// Attest registra la declaracion de responsabilidad sobre el alcance.
func (s *Service) Attest(ctx context.Context, orgID, by string) (domain.Organization, error) {
	o, err := s.Repo.GetOrg(ctx, orgID)
	if err != nil {
		return o, err
	}
	if err := s.attest(&o, by); err != nil {
		return o, err
	}
	return o, s.Repo.SaveOrg(ctx, o)
}

func (s *Service) attest(o *domain.Organization, by string) error {
	by = strings.TrimSpace(by)
	if len(by) < 3 || len(by) > 120 {
		return errors.New("la declaración necesita el nombre de quien se hace responsable (de 3 a 120 caracteres)")
	}
	o.Attestation = &domain.Attestation{By: by, At: s.now(), Statement: domain.AttestationText}
	s.audit(o, "declaración de responsabilidad", by)
	return nil
}

// AddDomain suma un dominio a una organizacion.
func (s *Service) AddDomain(ctx context.Context, orgID, d string) (domain.Organization, error) {
	o, err := s.Repo.GetOrg(ctx, orgID)
	if err != nil {
		return o, err
	}
	if err := addDomain(&o, d); err != nil {
		return o, err
	}
	s.audit(&o, "dominio agregado", o.Domains[len(o.Domains)-1].Name)
	return o, s.Repo.SaveOrg(ctx, o)
}

// AddNetwork suma una red declarada.
func (s *Service) AddNetwork(ctx context.Context, orgID, n string) (domain.Organization, error) {
	o, err := s.Repo.GetOrg(ctx, orgID)
	if err != nil {
		return o, err
	}
	if err := addNetwork(&o, n); err != nil {
		return o, err
	}
	s.audit(&o, "red agregada", o.Networks[len(o.Networks)-1])
	return o, s.Repo.SaveOrg(ctx, o)
}

func addDomain(o *domain.Organization, raw string) error {
	d, err := scope.NormalizeDomain(raw)
	if err != nil {
		return err
	}
	for _, x := range o.Domains {
		if x.Name == d {
			return fmt.Errorf("%s ya está en la organización", d)
		}
	}
	if len(o.Domains) >= 20 {
		return errors.New("máximo 20 dominios por organización")
	}
	o.Domains = append(o.Domains, domain.Domain{Name: d, Token: scope.NewToken()})
	return nil
}

func addNetwork(o *domain.Organization, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	p, why := scope.CheckNetwork(raw)
	if why != "" {
		return fmt.Errorf("red %s: %s", raw, why)
	}
	for _, n := range o.Networks {
		if n == p.String() {
			return fmt.Errorf("la red %s ya está en la organización", n)
		}
	}
	if len(o.Networks) >= 16 {
		return errors.New("máximo 16 redes por organización")
	}
	o.Networks = append(o.Networks, p.String())
	return nil
}

func (s *Service) audit(o *domain.Organization, action, detail string) {
	o.Audit = append(o.Audit, domain.AuditEvent{At: s.now(), Action: action, Detail: detail})
	if len(o.Audit) > 300 {
		o.Audit = o.Audit[len(o.Audit)-300:]
	}
}

func domainNames(o domain.Organization) string {
	n := make([]string, len(o.Domains))
	for i, d := range o.Domains {
		n[i] = d.Name
	}
	return strings.Join(n, ", ")
}

func netList(n []string) string {
	if len(n) == 0 {
		return ""
	}
	return " · redes: " + strings.Join(n, ", ")
}

// VerifyDomains consulta los registros TXT de cada dominio (verificacion opcional) y actualiza su estado.
func (s *Service) VerifyDomains(ctx context.Context, orgID string) (domain.Organization, error) {
	o, err := s.Repo.GetOrg(ctx, orgID)
	if err != nil {
		return o, err
	}
	s.verify(ctx, &o)
	return o, s.Repo.SaveOrg(ctx, o)
}

func (s *Service) verify(ctx context.Context, o *domain.Organization) {
	if s.DNS == nil {
		return
	}
	now := s.now()
	for i := range o.Domains {
		d := &o.Domains[i]
		was := d.Verified()
		d.LastCheck = &now
		res, err := scope.Verify(ctx, s.DNS, d.Name, d.Token)
		if err != nil {
			d.VerifiedAt, d.Networks = nil, nil // si el dueño retiro el registro, se retira la verificacion
			d.CheckError = err.Error()
			if was {
				s.audit(o, "verificación DNS retirada", d.Name)
			}
			continue
		}
		if d.VerifiedAt == nil {
			d.VerifiedAt = &now
			s.audit(o, "dominio verificado en DNS", d.Name)
		}
		d.Networks = res.Networks
		d.CheckError = ""
		if len(res.Rejected) > 0 {
			d.CheckError = "redes rechazadas: " + strings.Join(res.Rejected, "; ")
		}
	}
}

// ---------------------------------------------------------------- escaneo

// Progress recibe mensajes de avance.
type Progress func(msg string)

// Scan analiza una organizacion. Vuelve a verificar el DNS antes de empezar: si el dueño retiro la
// autorizacion, ese dominio no se analiza.
func (s *Service) Scan(ctx context.Context, orgID string, progress Progress) (domain.Snapshot, error) {
	if progress == nil {
		progress = func(string) {}
	}
	o, err := s.Repo.GetOrg(ctx, orgID)
	if err != nil {
		return domain.Snapshot{}, err
	}
	progress("Comprobando la autorización…")
	s.verify(ctx, &o)
	snap := domain.Snapshot{ID: newID(), OrgID: o.ID, OrgName: o.Name, StartedAt: s.now()}
	if a := o.Attestation; a != nil {
		snap.Authorization = append(snap.Authorization, fmt.Sprintf("Alcance declarado por %s el %s.", a.By, a.At.Format("2006-01-02")))
	}
	nets := map[string]bool{}
	for _, d := range o.Domains {
		switch {
		case d.Verified():
			snap.Domains = append(snap.Domains, d.Name)
			snap.Authorization = append(snap.Authorization, d.Name+": verificado en DNS.")
			for _, n := range d.Networks {
				nets[n] = true
			}
		case o.Authorized(d):
			snap.Domains = append(snap.Domains, d.Name)
		default:
			snap.Notes = append(snap.Notes, fmt.Sprintf("%s no se analizó: no está verificado en DNS y no hay declaración de responsabilidad.", d.Name))
		}
	}
	if o.Attestation != nil {
		for _, n := range o.Networks {
			nets[n] = true
		}
	}
	for n := range nets {
		snap.Networks = append(snap.Networks, n)
	}
	sort.Strings(snap.Networks)
	if len(snap.Domains) == 0 {
		_ = s.Repo.SaveOrg(ctx, o)
		return snap, errors.New("no hay nada autorizado para analizar: aceptá la declaración de responsabilidad o verificá un dominio en DNS")
	}
	s.audit(&o, "escaneo", fmt.Sprintf("%d dominios, %d redes", len(snap.Domains), len(snap.Networks)))
	if err := s.Repo.SaveOrg(ctx, o); err != nil {
		return domain.Snapshot{}, err
	}

	// 1. Descubrimiento
	assets := map[string]*domain.Asset{}
	for _, d := range snap.Domains {
		progress("Buscando subdominios de " + d + " en Certificate Transparency…")
		res := s.Discovery.Discover(ctx, d)
		snap.Notes = append(snap.Notes, res.Notes...)
		for _, a := range res.Assets {
			a := a
			if !scope.InDomains(a.Hostname, snap.Domains) {
				continue
			}
			assets[a.Hostname] = &a
		}
	}
	snap.Sources = append(snap.Sources, "Certificate Transparency (crt.sh)", "DNS público")

	// 2. IP a consultar: las de nombres propios (no las de CDN/SaaS de terceros) y las de redes declaradas.
	ipSet := map[string]bool{}
	skippedThird := 0
	for _, a := range assets {
		if a.ThirdParty != "" {
			skippedThird += len(a.IPs)
			continue
		}
		for _, ip := range a.IPs {
			ipSet[ip] = true
		}
	}
	if skippedThird > 0 {
		snap.Notes = append(snap.Notes, fmt.Sprintf("No se consultaron %d IP de servicios de terceros (CDN, SaaS): pertenecen al proveedor, no a la organización.", skippedThird))
	}
	var services []domain.Service
	if s.Exposure == nil {
		snap.Notes = append(snap.Notes, "Sin fuente de exposición configurada: solo se hizo el descubrimiento de activos.")
	} else {
		snap.Sources = append(snap.Sources, exposure.Label(s.Exposure.Name()))
		if b, ok := s.Exposure.(interface{ BeginScan() }); ok {
			b.BeginScan()
		}
		// 2a. Redes declaradas: una busqueda por red si la fuente lo permite.
		if ns, ok := s.Exposure.(exposure.NetworkSearcher); ok {
			for _, n := range snap.Networks {
				progress("Consultando la red " + n + "…")
				found, err := ns.SearchNetwork(ctx, n, s.maxPages())
				if errors.Is(err, exposure.ErrAuth) {
					return snap, err
				}
				if err != nil {
					snap.Notes = append(snap.Notes, fmt.Sprintf("No se pudo consultar la red %s: %v.", n, err))
				}
				services = append(services, found...)
				for _, sv := range found {
					delete(ipSet, sv.IP) // ya cubierta
				}
			}
		} else {
			for _, ip := range scope.ExpandNetworks(snap.Networks) {
				ipSet[ip] = true
			}
		}
		// 2b. IP una por una.
		ips := make([]string, 0, len(ipSet))
		for ip := range ipSet {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		if len(ips) > s.maxIPs() {
			snap.Notes = append(snap.Notes, fmt.Sprintf("Hay %d IP; se consultaron las primeras %d.", len(ips), s.maxIPs()))
			ips = ips[:s.maxIPs()]
		}
		failed := 0
		for i, ip := range ips {
			if ctx.Err() != nil {
				return snap, ctx.Err()
			}
			progress(fmt.Sprintf("Consultando %s (%d de %d)…", ip, i+1, len(ips)))
			found, _, err := s.Exposure.Host(ctx, ip)
			if errors.Is(err, exposure.ErrAuth) {
				return snap, err
			}
			if err != nil {
				failed++
				continue
			}
			services = append(services, found...)
		}
		if failed > 0 {
			snap.Notes = append(snap.Notes, fmt.Sprintf("%d IP no se pudieron consultar; volvé a escanear más tarde.", failed))
		}
	}

	if m, ok := s.Exposure.(*exposure.Multi); ok {
		snap.Notes = append(snap.Notes, m.Notes()...)
		snap.Consensus = consensus(m.SourceNames(), services)
	}

	// 3. Activos de redes declaradas que no tienen nombre
	for _, sv := range services {
		if !hasIP(assets, sv.IP) {
			key := "ip:" + sv.IP
			if _, ok := assets[key]; !ok {
				assets[key] = &domain.Asset{IPs: []string{sv.IP}, Sources: []string{"red declarada"}, Resolves: true}
			}
		}
	}
	for _, a := range assets {
		snap.Assets = append(snap.Assets, *a)
	}
	sort.Slice(snap.Assets, func(i, j int) bool { return assetKey(snap.Assets[i]) < assetKey(snap.Assets[j]) })
	sort.Slice(services, func(i, j int) bool {
		if services[i].IP != services[j].IP {
			return services[i].IP < services[j].IP
		}
		return services[i].Port < services[j].Port
	})
	snap.Services = services

	// 4. Hallazgos
	s.evaluateVulns(ctx, &snap, progress)
	progress("Evaluando hallazgos…")
	snap.Findings = rules.Evaluate(snap.Assets, snap.Services, rules.Options{Now: s.now()})
	snap.FinishedAt = s.now()
	if err := s.Repo.SaveSnapshot(ctx, snap); err != nil {
		return snap, err
	}
	s.afterSnapshot(ctx, snap)
	progress("Listo.")
	return snap, nil
}

func (s *Service) maxIPs() int {
	if s.MaxIPs > 0 {
		return s.MaxIPs
	}
	return 300
}

func (s *Service) maxPages() int {
	if s.MaxPages > 0 {
		return s.MaxPages
	}
	return 2
}

func hasIP(assets map[string]*domain.Asset, ip string) bool {
	for _, a := range assets {
		for _, x := range a.IPs {
			if x == ip {
				return true
			}
		}
	}
	return false
}

func assetKey(a domain.Asset) string {
	if a.Hostname != "" {
		return "0" + a.Hostname
	}
	if len(a.IPs) > 0 {
		return "1" + a.IPs[0]
	}
	return "2"
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// evaluateVulns pasa los servicios por el motor de inteligencia, si hay uno.
func (s *Service) evaluateVulns(ctx context.Context, snap *domain.Snapshot, progress Progress) {
	if s.Intel == nil || len(snap.Services) == 0 {
		return
	}
	progress("Evaluando vulnerabilidades con la base de inteligencia…")
	svcs, rep := s.Intel.Enrich(ctx, snap.Services, func(m string) { progress(m) })
	snap.Services = svcs
	src := fmt.Sprintf("Inteligencia de vulnerabilidades: %d CVE evaluadas, %d descartadas por versión", rep.Candidates, rep.Dismissed)
	if rep.FromNVD > 0 {
		src += fmt.Sprintf(", %d encontradas por Baqueano", rep.FromNVD)
	}
	snap.Sources = append(snap.Sources, src)
	snap.Notes = append(snap.Notes, rep.Notes...)
}

// Reassess vuelve a evaluar el ultimo escaneo de una organizacion con la inteligencia actual, sin
// consultar la fuente de exposicion: sirve para enterarse de CVE nuevas o de cambios en KEV/EPSS
// sin gastar creditos. Genera un escaneo nuevo marcado como reevaluacion.
func (s *Service) Reassess(ctx context.Context, orgID string, progress Progress) (domain.Snapshot, error) {
	if progress == nil {
		progress = func(string) {}
	}
	if s.Intel == nil {
		return domain.Snapshot{}, errors.New("no hay base de inteligencia configurada")
	}
	o, err := s.Repo.GetOrg(ctx, orgID)
	if err != nil {
		return domain.Snapshot{}, err
	}
	metas, err := s.Repo.ListSnapshots(ctx, o.ID)
	if err != nil {
		return domain.Snapshot{}, err
	}
	if len(metas) == 0 {
		return domain.Snapshot{}, errors.New("la organización todavía no tiene escaneos para reevaluar")
	}
	prev, err := s.Repo.GetSnapshot(ctx, metas[0].ID)
	if err != nil {
		return domain.Snapshot{}, err
	}
	base := prev.StartedAt
	snap := domain.Snapshot{ID: newID(), OrgID: o.ID, OrgName: o.Name, StartedAt: s.now(), Domains: prev.Domains, Networks: prev.Networks,
		Authorization: prev.Authorization, Assets: prev.Assets}
	snap.Sources = []string{"Reevaluación sin escanear: exposición vista el " + base.Format("2006-01-02 15:04") + " UTC"}
	for _, x := range prev.Sources {
		if !strings.HasPrefix(x, "Inteligencia de vulnerabilidades") && !strings.HasPrefix(x, "Reevaluación") {
			snap.Sources = append(snap.Sources, x)
		}
	}
	// Volver a las CVE tal como las propuso la fuente: las encontradas por Baqueano se recalculan.
	for _, sv := range prev.Services {
		raw := sv
		raw.Vulns, raw.Dismissed, raw.EOL = nil, nil, nil
		for _, v := range append(append([]domain.Vuln(nil), sv.Vulns...), sv.Dismissed...) {
			if v.Origin == "baqueano" {
				continue
			}
			raw.Vulns = append(raw.Vulns, domain.Vuln{CVE: v.CVE, Verified: v.Verified, Origin: v.Origin})
		}
		snap.Services = append(snap.Services, raw)
	}
	s.evaluateVulns(ctx, &snap, progress)
	progress("Evaluando hallazgos…")
	snap.Findings = rules.Evaluate(snap.Assets, snap.Services, rules.Options{Now: s.now()})
	snap.FinishedAt = s.now()
	if err := s.Repo.SaveSnapshot(ctx, snap); err != nil {
		return snap, err
	}
	s.afterSnapshot(ctx, snap)
	progress("Listo.")
	return snap, nil
}

// consensus resume cuanto coinciden las fuentes: un puerto que ven todas es mas confiable que uno que ve
// una sola (puede ser un dato viejo o un error de identificacion).
func consensus(sources []string, svcs []domain.Service) *domain.Consensus {
	if len(sources) < 2 {
		return nil
	}
	c := &domain.Consensus{Sources: sources, Services: len(svcs)}
	for _, sv := range svcs {
		switch {
		case len(sv.SeenBy) >= len(sources):
			c.All++
		case len(sv.SeenBy) == 1:
			c.Single++
		}
	}
	return c
}
