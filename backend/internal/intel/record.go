package intel

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

// Calidad de los datos de versiones: solo los datos estructurados alcanzan para descartar una CVE.
const (
	QualityStructured = "estructurado"  // rangos con campos (NVD, versionType semver/custom con lessThan)
	QualityText       = "texto"         // interpretado de texto libre ("8.5.0 to 8.5.50")
	QualityNone       = "sin-versiones" // "n/a", "unspecified"
)

// Affected dice que versiones de un producto afecta una CVE, segun una fuente.
type Affected struct {
	Products    []string `json:"products,omitempty"` // vacio = el registro no dice el producto
	Name        string   `json:"name"`               // como lo publico la fuente
	Ranges      []Range  `json:"ranges,omitempty"`
	Unaffected  []Range  `json:"unaffected,omitempty"`
	AllVersions bool     `json:"all_versions,omitempty"` // afectado sin detalle de versiones
	NotAffected bool     `json:"not_affected,omitempty"` // el producto entero no esta afectado
	Quality     string   `json:"quality"`
	Source      string   `json:"source"` // nvd | cve | cisa-adp
}

// Record es lo que se sabe de una CVE, combinando fuentes.
type Record struct {
	CVE       string       `json:"cve"`
	Summary   string       `json:"summary,omitempty"`
	Published string       `json:"published,omitempty"`
	CVSS      float64      `json:"cvss,omitempty"`
	Vector    string       `json:"vector,omitempty"`
	CWE       []string     `json:"cwe,omitempty"`
	SSVC      *domain.SSVC `json:"ssvc,omitempty"`
	Affected  []Affected   `json:"affected,omitempty"`
	Sources   []string     `json:"sources,omitempty"`
	Rejected  bool         `json:"rejected,omitempty"`
}

func (r *Record) addSource(s string) {
	for _, x := range r.Sources {
		if x == s {
			return
		}
	}
	r.Sources = append(r.Sources, s)
}

// merge suma lo que aporta otra fuente sin pisar lo que ya habia (los rangos se acumulan).
func (r *Record) merge(o *Record) {
	if r.Summary == "" {
		r.Summary = o.Summary
	}
	if r.Published == "" {
		r.Published = o.Published
	}
	if o.CVSS > 0 && (r.CVSS == 0 || o.Vector != "" && r.Vector == "") {
		r.CVSS, r.Vector = o.CVSS, o.Vector
	}
	if len(r.CWE) == 0 {
		r.CWE = o.CWE
	}
	if r.SSVC == nil {
		r.SSVC = o.SSVC
	}
	r.Rejected = r.Rejected || o.Rejected
	for _, src := range o.Sources {
		// reemplazar los rangos de esa fuente (pueden haberse corregido)
		keep := r.Affected[:0]
		for _, a := range r.Affected {
			if a.Source != src && !(src == "cve" && a.Source == "cisa-adp") {
				keep = append(keep, a)
			}
		}
		r.Affected = keep
		r.addSource(src)
	}
	r.Affected = append(r.Affected, o.Affected...)
}

// ---- CVE JSON 5.x (cvelistV5 / Vulnrichment) ----

type cve5 struct {
	Meta struct {
		ID        string `json:"cveId"`
		State     string `json:"state"`
		Published string `json:"datePublished"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA cve5Container   `json:"cna"`
		ADP []cve5Container `json:"adp"`
	} `json:"containers"`
}

type cve5Container struct {
	Title    string `json:"title"`
	Provider struct {
		ShortName string `json:"shortName"`
	} `json:"providerMetadata"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Affected []struct {
		Vendor        string   `json:"vendor"`
		Product       string   `json:"product"`
		PackageName   string   `json:"packageName"`
		CPEs          []string `json:"cpes"`
		DefaultStatus string   `json:"defaultStatus"`
		Versions      []struct {
			Version string `json:"version"`
			Status  string `json:"status"`
			Type    string `json:"versionType"`
			LT      string `json:"lessThan"`
			LTE     string `json:"lessThanOrEqual"`
			Changes []struct {
				At     string `json:"at"`
				Status string `json:"status"`
			} `json:"changes"`
		} `json:"versions"`
	} `json:"affected"`
	Metrics []struct {
		V40   *cvssData       `json:"cvssV4_0"`
		V31   *cvssData       `json:"cvssV3_1"`
		V30   *cvssData       `json:"cvssV3_0"`
		Other json.RawMessage `json:"other"`
	} `json:"metrics"`
	ProblemTypes []struct {
		Descriptions []struct {
			CWE string `json:"cweId"`
		} `json:"descriptions"`
	} `json:"problemTypes"`
}

type cvssData struct {
	Score  float64 `json:"baseScore"`
	Vector string  `json:"vectorString"`
}

// ParseCVE5 interpreta un registro del programa CVE (formato 5.x), incluido el bloque de CISA.
func ParseCVE5(b []byte) (*Record, error) {
	var d cve5
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	r := &Record{CVE: strings.ToUpper(d.Meta.ID), Rejected: d.Meta.State == "REJECTED", Sources: []string{"cve"}}
	if len(d.Meta.Published) >= 10 {
		r.Published = d.Meta.Published[:10]
	}
	containers := append([]cve5Container{d.Containers.CNA}, d.Containers.ADP...)
	for i, c := range containers {
		src := "cve"
		if i > 0 {
			if !strings.Contains(c.Title, "Vulnrichment") && c.Provider.ShortName != "CISA-ADP" {
				continue // otros ADP (p. ej. "CVE Program Container") solo traen referencias
			}
			src = "cisa-adp"
		}
		if r.Summary == "" {
			r.Summary = pickDesc(c.Descriptions)
		}
		for _, m := range c.Metrics {
			for _, v := range []*cvssData{m.V31, m.V40, m.V30} {
				if v != nil && v.Score > 0 && r.CVSS == 0 {
					r.CVSS, r.Vector = v.Score, v.Vector
				}
			}
			if len(m.Other) > 0 && r.SSVC == nil {
				r.SSVC = parseSSVC(m.Other)
			}
		}
		for _, p := range c.ProblemTypes {
			for _, d := range p.Descriptions {
				if d.CWE != "" && !contains(r.CWE, d.CWE) {
					r.CWE = append(r.CWE, d.CWE)
				}
			}
		}
		for _, a := range c.Affected {
			name := strings.TrimSpace(strings.Join(nonEmpty(a.Vendor, a.Product, a.PackageName), " "))
			if isDistroEntry(a.Vendor, a.CPEs) {
				continue // paquetes de distribucion: no describen la version de origen
			}
			names := nonEmpty(a.Product, a.PackageName)
			if len(nonEmpty(a.Vendor)) == 1 && len(nonEmpty(a.Product)) == 1 {
				names = append(names, a.Vendor+" "+a.Product)
			}
			af := Affected{Name: name, Source: src, Quality: QualityNone, Products: Identify(names, a.CPEs)}
			for _, v := range a.Versions {
				if v.Type == "rpm" || v.Type == "deb" || v.Type == "git" {
					continue
				}
				rs, q := cve5Ranges(v.Version, v.LT, v.LTE, v.Status, len(v.Changes) > 0)
				if q == QualityStructured && v.Type == "" && v.LT == "" && v.LTE == "" && len(rs) == 1 && rs[0].Exact != "" && v.Status == "affected" {
					// Registros viejos con una sola version suelta y sin tipo: muchas veces quiere decir
					// "hasta" o "antes de" (Exim CVE-2019-10149 dice 4.92). No alcanza para descartar.
					q = QualityText
				}
				if len(v.Changes) > 0 && q == QualityStructured {
					rs = withChanges(rs, v.Status, v.Changes)
				}
				af.Quality = worse(af.Quality, q, len(rs) > 0)
				if rs == nil && q == QualityNone {
					if v.Status == "affected" {
						af.AllVersions = true
					} else if v.Status == "unaffected" {
						af.NotAffected = true
					}
					continue
				}
				for _, rg := range rs {
					if rg.status == "affected" {
						af.Ranges = append(af.Ranges, rg.Range)
					} else {
						af.Unaffected = append(af.Unaffected, rg.Range)
					}
				}
			}
			if len(a.Versions) == 0 && a.DefaultStatus == "affected" {
				af.AllVersions = true
			}
			r.Affected = append(r.Affected, af)
		}
	}
	return r, nil
}

func isDistroEntry(vendor string, cpes []string) bool {
	v := strings.ToLower(vendor)
	if v == "red hat" || v == "debian" && len(cpes) > 0 || v == "canonical" || v == "suse" {
		for _, c := range cpes {
			if strings.Contains(c, "enterprise_linux") || strings.Contains(c, "debian_linux") || strings.Contains(c, "ubuntu_linux") {
				return true
			}
		}
		return v == "red hat"
	}
	return false
}

type statusRange struct {
	Range
	status string
}

var (
	reSpan   = regexp.MustCompile(`(?i)(\d[\w.\-]*)\s+(?:to|through|thru|hasta|-|–)\s+(?:[a-z][a-z ]*?\s)?(\d[\w.\-]*)`)
	reBefore = regexp.MustCompile(`(?i)(?:before|prior to|earlier than|<)\s*(=)?\s*(\d[\w.\-]*)`)
	reBranch = regexp.MustCompile(`^(\d+(?:\.\d+)*)\.(?:x|\*)$`)
	reVer    = regexp.MustCompile(`\d+(?:\.\d+)+[\w\-]*|\d+[a-z]+\d*`)
)

// cve5Ranges convierte una entrada de version del registro CVE en tramos, y dice que tan confiables son.
func cve5Ranges(version, lt, lte, status string, hasChanges bool) ([]statusRange, string) {
	version, lt, lte = strings.TrimSpace(version), strings.TrimSpace(lt), strings.TrimSpace(lte)
	if status != "affected" && status != "unaffected" {
		return nil, QualityNone
	}
	end, inc := lt, false
	if end == "" {
		end, inc = lte, true
	}
	if end != "" && end != "*" {
		r := Range{EndInc: inc}
		q := QualityStructured
		switch {
		case reBranch.MatchString(version):
			r.Prefix = reBranch.FindStringSubmatch(version)[1]
		case IsVersion(version) && version != "0":
			r.Start, r.StartInc = version, true
		case version == "0" || version == "*" || version == "" || strings.EqualFold(version, "unspecified"):
		default:
			// "Apache HTTP Server 2.4" -> rama 2.4
			if m := reVer.FindString(version); m != "" {
				r.Start, r.StartInc = m, true
			}
			q = QualityText
		}
		switch {
		case IsVersion(end):
			r.End = end
			// "Apache HTTP Server 2.4" hasta 2.4.51: el texto solo nombra la rama y el final es un campo
			// estructurado. Es tan confiable como un rango con campos.
			if q == QualityText && r.Start != "" && inBranch(end, r.Start) && len(parse(r.Start)) < len(parse(end)) {
				r.Prefix, r.Start, r.StartInc = r.Start, "", false
				q = QualityStructured
			}
		case strings.HasSuffix(end, "*"):
			// "17.0.x*" o "log4j-core*": comodin. Si hay rama numerica, limita a esa rama.
			b := strings.TrimSuffix(strings.TrimSuffix(end, "*"), ".x")
			if IsVersion(b) {
				r.Prefix, r.End = b, ""
			}
			q = QualityText
		default:
			q = QualityText
		}
		if r.Start == "" && r.End == "" && r.Prefix == "" {
			return nil, QualityNone
		}
		return []statusRange{{r, status}}, q
	}
	low := strings.ToLower(version)
	switch low {
	case "", "n/a", "na", "unspecified", "*", "all", "all versions", "0", "unknown":
		return nil, QualityNone
	}
	if IsVersion(version) && !hasChanges {
		return []statusRange{{Range{Exact: version}, status}}, QualityStructured
	}
	if m := reBranch.FindStringSubmatch(version); m != nil {
		return []statusRange{{Range{Prefix: m[1]}, status}}, QualityStructured
	}
	// Texto libre: tramos "A to B", cotas "before X" y versiones sueltas.
	var out []statusRange
	text := version
	for _, m := range reSpan.FindAllStringSubmatch(text, -1) {
		out = append(out, statusRange{Range{Start: m[1], StartInc: true, End: m[2], EndInc: true}, status})
	}
	text = reSpan.ReplaceAllString(text, " ")
	for _, m := range reBefore.FindAllStringSubmatch(text, -1) {
		if len(out) > 0 {
			continue // "0.6.18 thru 1.20.0 before 1.20.1": la cota ya esta en el tramo
		}
		out = append(out, statusRange{Range{End: m[2], EndInc: m[1] == "="}, status})
	}
	text = reBefore.ReplaceAllString(text, " ")
	if len(out) == 0 {
		for _, v := range reVer.FindAllString(text, -1) {
			out = append(out, statusRange{Range{Exact: v}, status})
		}
	}
	if len(out) == 0 {
		return nil, QualityNone
	}
	return out, QualityText
}

// withChanges parte un tramo segun los cambios de estado ("changes" del formato CVE 5).
func withChanges(rs []statusRange, status string, changes []struct {
	At     string `json:"at"`
	Status string `json:"status"`
}) []statusRange {
	if len(rs) != 1 {
		return rs
	}
	base := rs[0].Range
	cur, curStatus := base.Start, status
	var out []statusRange
	for _, c := range changes {
		if !IsVersion(c.At) {
			return rs
		}
		out = append(out, statusRange{Range{Start: cur, StartInc: cur != "", End: c.At, Prefix: base.Prefix}, curStatus})
		cur, curStatus = c.At, c.Status
	}
	out = append(out, statusRange{Range{Start: cur, StartInc: true, End: base.End, EndInc: base.EndInc, Prefix: base.Prefix}, curStatus})
	return out
}

func worse(cur, q string, hasRanges bool) string {
	if !hasRanges {
		return cur
	}
	if cur == QualityNone || cur == "" {
		return q
	}
	if q == QualityText {
		return QualityText
	}
	return cur
}

func parseSSVC(raw json.RawMessage) *domain.SSVC {
	var o struct {
		Type    string `json:"type"`
		Content struct {
			Options []map[string]string `json:"options"`
		} `json:"content"`
	}
	if json.Unmarshal(raw, &o) != nil || o.Type != "ssvc" {
		return nil
	}
	s := &domain.SSVC{}
	for _, m := range o.Content.Options {
		for k, v := range m {
			v = strings.ToLower(v)
			switch strings.ToLower(k) {
			case "exploitation":
				s.Exploitation = v
			case "automatable":
				s.Automatable = v
			case "technical impact":
				s.TechnicalImpact = v
			}
		}
	}
	if s.Exploitation == "" {
		return nil
	}
	return s
}

// ---- NVD API 2.0 ----

type nvdResponse struct {
	Total int `json:"totalResults"`
	Vulns []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			Status       string `json:"vulnStatus"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				V40 []struct {
					Data cvssData `json:"cvssData"`
				} `json:"cvssMetricV40"`
				V31 []struct {
					Data cvssData `json:"cvssData"`
				} `json:"cvssMetricV31"`
				V30 []struct {
					Data cvssData `json:"cvssData"`
				} `json:"cvssMetricV30"`
			} `json:"metrics"`
			Weaknesses []struct {
				Description []struct {
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Configurations []struct {
				Nodes []struct {
					Negate   bool `json:"negate"`
					CPEMatch []struct {
						Vulnerable bool   `json:"vulnerable"`
						Criteria   string `json:"criteria"`
						StartInc   string `json:"versionStartIncluding"`
						StartExc   string `json:"versionStartExcluding"`
						EndInc     string `json:"versionEndIncluding"`
						EndExc     string `json:"versionEndExcluding"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// ParseNVD interpreta una respuesta de /rest/json/cves/2.0.
func ParseNVD(b []byte) ([]*Record, int, error) {
	var d nvdResponse
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, 0, err
	}
	var out []*Record
	for _, v := range d.Vulns {
		c := v.CVE
		r := &Record{CVE: strings.ToUpper(c.ID), Sources: []string{"nvd"}, Rejected: c.Status == "Rejected"}
		if len(c.Published) >= 10 {
			r.Published = c.Published[:10]
		}
		r.Summary = pickDesc(c.Descriptions)
		for _, set := range [][]cvssData{pickData(c.Metrics.V31), pickData(c.Metrics.V40), pickData(c.Metrics.V30)} {
			if len(set) > 0 && r.CVSS == 0 {
				r.CVSS, r.Vector = set[0].Score, set[0].Vector
			}
		}
		for _, w := range c.Weaknesses {
			for _, d := range w.Description {
				if strings.HasPrefix(d.Value, "CWE-") && !contains(r.CWE, d.Value) {
					r.CWE = append(r.CWE, d.Value)
				}
			}
		}
		byProduct := map[string]*Affected{}
		var order []string
		for _, cfg := range c.Configurations {
			for _, n := range cfg.Nodes {
				if n.Negate {
					continue
				}
				for _, m := range n.CPEMatch {
					if !m.Vulnerable {
						continue // plataforma sobre la que corre, no el producto vulnerable
					}
					cp, ok := ParseCPE(m.Criteria)
					if !ok {
						continue
					}
					k := cp.key()
					af := byProduct[k]
					if af == nil {
						af = &Affected{Name: k, Products: Identify(nil, []string{m.Criteria}), Quality: QualityStructured, Source: "nvd"}
						byProduct[k] = af
						order = append(order, k)
					}
					rg := Range{}
					switch {
					case cp.Version != "":
						rg.Exact = cp.Version
					default:
						rg.Start, rg.StartInc = m.StartInc, m.StartInc != ""
						if m.StartExc != "" {
							rg.Start = m.StartExc
						}
						rg.End, rg.EndInc = m.EndExc, false
						if m.EndInc != "" {
							rg.End, rg.EndInc = m.EndInc, true
						}
					}
					if rg.Exact == "" && rg.Start == "" && rg.End == "" {
						af.AllVersions = true
						continue
					}
					af.Ranges = append(af.Ranges, rg)
				}
			}
		}
		for _, k := range order {
			r.Affected = append(r.Affected, *byProduct[k])
		}
		out = append(out, r)
	}
	return out, d.Total, nil
}

func pickData(xs []struct {
	Data cvssData `json:"cvssData"`
}) []cvssData {
	var out []cvssData
	for _, x := range xs {
		out = append(out, x.Data)
	}
	return out
}

func pickDesc(ds []struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}) string {
	var en string
	for _, d := range ds {
		l := strings.ToLower(d.Lang)
		if strings.HasPrefix(l, "es") {
			return clip(d.Value)
		}
		if en == "" && strings.HasPrefix(l, "en") {
			en = d.Value
		}
	}
	return clip(en)
}

func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 600 {
		s = s[:600] + "…"
	}
	return s
}

func nonEmpty(xs ...string) []string {
	var out []string
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x != "" && !strings.EqualFold(x, "n/a") {
			out = append(out, x)
		}
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
