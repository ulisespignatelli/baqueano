package intel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

// Niveles de confianza de que una CVE afecta de verdad al servicio.
const (
	Confirmed  = "confirmada"    // la fuente lo verifico con una prueba
	Probable   = "probable"      // la version cae en un rango afectado publicado
	Unverified = "por-confirmar" // falta informacion para afirmarlo o descartarlo
	Unlikely   = "improbable"    // fuera de tramos explicitos publicados en texto: se muestra, con prioridad minima
	Dismissed  = "descartada"    // datos estructurados dicen que esta version no esta afectada
)

var sourceLabel = map[string]string{"nvd": "NVD", "cve": "registro CVE", "cisa-adp": "CISA (Vulnrichment)"}

// target es lo que se sabe del servicio para evaluarlo.
type target struct {
	products []string
	version  string
	distro   *Distro
}

func targetOf(s domain.Service) target {
	t := target{products: Identify([]string{s.Product}, s.CPEs), version: strings.TrimSpace(s.Version)}
	for _, raw := range s.CPEs {
		if c, ok := ParseCPE(raw); ok && t.version == "" && c.Version != "" {
			t.version = c.Version
		}
	}
	t.version = upstreamVersion(t.version)
	t.distro = DetectDistro(s.Version, s.Banner)
	return t
}

// upstreamVersion saca el sufijo de empaquetado: "8.9p1 Ubuntu-3ubuntu0.10" -> "8.9p1", "2.4.41-4ubuntu3" -> "2.4.41".
func upstreamVersion(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.IndexAny(v, " ("); i > 0 {
		v = v[:i]
	}
	for _, sep := range []string{"-", "+", "~"} {
		if i := strings.Index(v, sep); i > 0 {
			rest := strings.ToLower(v[i+1:])
			if strings.Contains(rest, "ubuntu") || strings.Contains(rest, "deb") || strings.HasPrefix(rest, "el") || isDigits(rest) {
				v = v[:i]
			}
		}
	}
	return v
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

func overlaps(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// verdict es la conclusion sobre una CVE en un servicio.
type verdict struct {
	confidence string
	reason     string
	fixedIn    string
	sources    []string
}

// judge decide si la CVE afecta al servicio, con que confianza y por que.
func judge(t target, rec *Record, verified bool) verdict {
	if verified {
		v := verdict{confidence: Confirmed, reason: "La fuente la confirmó con una prueba sobre el servicio, no solo por la versión."}
		if r := judge(t, rec, false); r.fixedIn != "" {
			v.fixedIn, v.sources = r.fixedIn, r.sources
		}
		return v
	}
	if rec != nil && rec.Rejected {
		return verdict{confidence: Dismissed, reason: "El programa CVE rechazó este identificador: no es una vulnerabilidad válida.", sources: []string{"cve"}}
	}
	if t.version == "" {
		return verdict{confidence: Unverified, reason: "El servicio no muestra su versión: la fuente la asoció solo por el producto."}
	}
	if rec == nil {
		return verdict{confidence: Unverified, reason: "No hay datos de versiones afectadas para contrastar la versión " + t.version + "."}
	}
	// Entradas del registro que hablan de este producto; si ninguna lo nombra, las que no dicen producto.
	var entries []Affected
	for _, a := range rec.Affected {
		if len(t.products) > 0 && overlaps(a.Products, t.products) {
			entries = append(entries, a)
		}
	}
	if len(entries) == 0 {
		for _, a := range rec.Affected {
			if len(a.Products) == 0 {
				entries = append(entries, a)
			}
		}
	}
	if len(entries) == 0 {
		return verdict{confidence: Unverified, reason: "Los datos publicados no mencionan este producto: puede ser una asociación errónea de la fuente."}
	}
	var srcs []string
	addSrc := func(s string) {
		if !contains(srcs, s) {
			srcs = append(srcs, s)
		}
	}
	structuredRanges, textRanges, textSpans, noInfo := false, false, true, false
	var shown []string
	for _, a := range entries {
		addSrc(a.Source)
		if a.NotAffected {
			continue
		}
		for _, u := range a.Unaffected {
			if u.Contains(t.version) && a.Quality == QualityStructured {
				return verdict{confidence: Dismissed, sources: srcs,
					reason: fmt.Sprintf("Según %s, la versión %s figura como no afectada (%s).", sourceLabel[a.Source], t.version, u)}
			}
		}
		if a.AllVersions && a.Source == "nvd" {
			return verdict{confidence: Probable, sources: srcs, reason: "Según la NVD, todas las versiones del producto están afectadas."}
		}
		if a.AllVersions || len(a.Ranges) == 0 {
			noInfo = true
			continue
		}
		for _, r := range a.Ranges {
			if r.Contains(t.version) && a.Quality == QualityText && len(a.Ranges) == 1 && r.Exact != "" {
				// Una sola version suelta en texto (registros viejos): puede ser la afectada o la corregida.
				return verdict{confidence: Unverified, sources: srcs,
					reason: fmt.Sprintf("El registro nombra solo la versión %s, sin aclarar si es la afectada o la que la corrige.", r.Exact)}
			}
			if r.Contains(t.version) {
				v := verdict{confidence: Probable, sources: srcs, fixedIn: fixedIn(r),
					reason: fmt.Sprintf("La versión %s está dentro del rango afectado (%s) según %s.", t.version, r, sourceLabel[a.Source])}
				if a.Quality == QualityText {
					v.reason += " El rango se interpretó de texto libre."
				}
				return v
			}
			if len(shown) < 4 {
				shown = append(shown, r.String())
			}
		}
		if a.Quality == QualityStructured {
			structuredRanges = true
		} else {
			textRanges = true
			for _, r := range a.Ranges {
				if r.Start == "" || r.End == "" {
					textSpans = false // una version suelta ("4.92") no es un tramo: puede querer decir "antes de"
				}
			}
		}
	}
	switch {
	case structuredRanges && !textRanges:
		return verdict{confidence: Dismissed, sources: srcs,
			reason: fmt.Sprintf("La versión %s no está en ningún rango afectado (%s).", t.version, strings.Join(shown, "; "))}
	case textRanges && textSpans && !noInfo:
		return verdict{confidence: Unlikely, sources: srcs,
			reason: fmt.Sprintf("La versión %s queda fuera de los tramos publicados (%s). Como esos tramos están en texto libre, no se descarta: queda con la prioridad más baja.", t.version, strings.Join(shown, "; "))}
	case structuredRanges || textRanges:
		return verdict{confidence: Unverified, sources: srcs,
			reason: fmt.Sprintf("La versión %s no figura en los rangos publicados (%s), pero parte de esos datos está en texto libre: no alcanza para descartarla.", t.version, strings.Join(shown, "; "))}
	case noInfo:
		return verdict{confidence: Unverified, sources: srcs, reason: "Los datos publicados no detallan qué versiones están afectadas."}
	}
	return verdict{confidence: Unverified, sources: srcs, reason: "No hay datos suficientes para confirmarla ni descartarla."}
}

func fixedIn(r Range) string {
	if r.End == "" {
		return ""
	}
	if r.EndInc {
		return "una versión posterior a " + r.End
	}
	return r.End
}

// Assess evalua todas las CVE candidatas de un servicio (las que propuso la fuente y las que encontro
// la NVD para su version) y devuelve las que quedan y las descartadas, con su motivo.
func Assess(s domain.Service, db *DB, extra []string) (keep, dismissed []domain.Vuln) {
	t := targetOf(s)
	cands := map[string]domain.Vuln{}
	var order []string
	for _, v := range s.Vulns {
		v.CVE = strings.ToUpper(v.CVE)
		if _, ok := cands[v.CVE]; !ok {
			order = append(order, v.CVE)
		}
		cands[v.CVE] = v
	}
	for _, id := range extra {
		if _, ok := cands[id]; !ok {
			cands[id] = domain.Vuln{CVE: id, Origin: "baqueano"}
			order = append(order, id)
		}
	}
	for _, id := range order {
		v := cands[id]
		rec := db.Records[id]
		vd := judge(t, rec, v.Verified)
		if vd.confidence == Probable && t.distro != nil {
			pkg := ""
			if t.distro.Package != "" {
				pkg = " (" + t.distro.Package + ")"
			}
			vd.confidence = Unverified
			vd.reason += fmt.Sprintf(" Pero el servicio usa un paquete de %s%s: las distribuciones corrigen sin cambiar la versión de origen. Confirmalo con el aviso de seguridad de la distribución.", t.distro.Name, pkg)
		}
		v.Confidence, v.Reason, v.FixedIn = vd.confidence, vd.reason, vd.fixedIn
		v.Sources = vd.sources
		enrich(&v, rec, db)
		if v.Confidence == Dismissed {
			dismissed = append(dismissed, v)
			continue
		}
		prioritize(&v)
		keep = append(keep, v)
	}
	sort.SliceStable(keep, func(i, j int) bool {
		if keep[i].Priority != keep[j].Priority {
			return keep[i].Priority < keep[j].Priority
		}
		return keep[i].CVSS > keep[j].CVSS
	})
	return keep, dismissed
}

func enrich(v *domain.Vuln, rec *Record, db *DB) {
	add := func(s string) {
		if !contains(v.Sources, s) {
			v.Sources = append(v.Sources, s)
		}
	}
	if rec != nil {
		if rec.CVSS > 0 {
			v.CVSS = rec.CVSS
		}
		if rec.Summary != "" {
			v.Summary = rec.Summary
		}
		v.SSVC, v.CWE, v.Published = rec.SSVC, rec.CWE, rec.Published
		if rec.SSVC != nil {
			add("cisa-adp")
		}
	}
	if k, ok := db.KEV[v.CVE]; ok {
		v.KEV, v.KEVDue, v.Ransomware = true, k.Due, k.Ransomware
		add("kev")
	}
	if e, ok := db.EPSS[v.CVE]; ok {
		v.EPSS, v.EPSSPercentile = e.Score, e.Percentile
		add("epss")
	}
	if len(v.Summary) > 600 {
		v.Summary = v.Summary[:600] + "…"
	}
}

// prioritize ordena por riesgo real: primero lo que se esta explotando, despues lo probable, y la
// severidad tecnica (CVSS) al final. Lo que esta por confirmar baja un nivel, salvo que este en KEV.
func prioritize(v *domain.Vuln) {
	var why []string
	level := 4
	set := func(l int, reason string) {
		if l < level {
			level = l
		}
		why = append(why, reason)
	}
	if v.KEV {
		r := "CISA confirma que se está explotando (KEV)"
		if v.KEVDue != "" {
			r += ", con plazo de corrección al " + v.KEVDue
		}
		set(1, r)
	}
	if v.Ransomware {
		set(1, "se usa en campañas de ransomware")
	}
	if s := v.SSVC; s != nil {
		switch s.Exploitation {
		case "active":
			set(1, "explotación activa según SSVC de CISA")
		case "poc":
			if s.Automatable == "yes" {
				set(2, "hay prueba de concepto pública y el ataque es automatizable")
			} else {
				set(3, "hay prueba de concepto pública")
			}
		}
		if s.TechnicalImpact == "total" && level > 2 && v.CVSS >= 9 {
			set(2, "impacto técnico total")
		}
	}
	switch {
	case v.EPSS >= 0.5:
		set(1, fmt.Sprintf("EPSS %.2f: alta probabilidad de explotación en 30 días", v.EPSS))
	case v.EPSS >= 0.1:
		set(2, fmt.Sprintf("EPSS %.2f", v.EPSS))
	case v.EPSS >= 0.01:
		set(3, fmt.Sprintf("EPSS %.2f", v.EPSS))
	}
	switch {
	case v.CVSS >= 9:
		set(2, fmt.Sprintf("CVSS %.1f (crítica)", v.CVSS))
	case v.CVSS >= 7:
		set(3, fmt.Sprintf("CVSS %.1f (alta)", v.CVSS))
	case v.CVSS > 0:
		why = append(why, fmt.Sprintf("CVSS %.1f", v.CVSS))
	}
	if v.Confidence == Unverified && !v.KEV && level < 4 {
		level++
		why = append(why, "baja un nivel hasta confirmar que la versión está afectada")
	}
	if v.Confidence == Unlikely {
		level = 4
		why = append(why, "probablemente no afecta a esta versión")
	}
	if len(why) == 0 {
		why = append(why, "sin señales de explotación conocidas")
	}
	v.Priority = fmt.Sprintf("P%d", level)
	v.PriorityReason = strings.Join(why, "; ")
}

// AssessEOL dice si el producto del servicio ya no tiene soporte, segun endoflife.date.
func AssessEOL(s domain.Service, db *DB) *domain.EOL {
	t := targetOf(s)
	if t.version == "" {
		return nil
	}
	for _, id := range t.products {
		slug := eolOf[id]
		rels := db.EOL[slug]
		if slug == "" || len(rels) == 0 {
			continue
		}
		var best *Release
		for i := range rels {
			r := &rels[i]
			if inBranch(t.version, r.Name) && (best == nil || len(r.Name) > len(best.Name)) {
				best = r
			}
		}
		if best != nil && best.IsEOL {
			return &domain.EOL{Product: s.Product, Cycle: best.Name, Since: best.EOLFrom, Latest: best.Latest, Source: "endoflife.date"}
		}
	}
	return nil
}
