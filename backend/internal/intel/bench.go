package intel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

// Case es un caso del benchmark: un servicio, una CVE propuesta y la respuesta correcta.
type Case struct {
	Product  string   `json:"product"`
	Version  string   `json:"version"`
	Banner   string   `json:"banner,omitempty"`
	CPEs     []string `json:"cpes,omitempty"`
	CVE      string   `json:"cve"`
	Affected bool     `json:"affected"`
	Note     string   `json:"note"`
}

// Corpus es el conjunto de casos.
type Corpus struct {
	Description string `json:"description"`
	Cases       []Case `json:"cases"`
}

// CaseResult es lo que contesto el motor en un caso.
type CaseResult struct {
	Case
	Confidence string `json:"confidence"`
	Reason     string `json:"reason"`
	Outcome    string `json:"outcome"` // acierto | falso-positivo | descarte-peligroso | pendiente
}

// BenchResult resume el benchmark.
type BenchResult struct {
	Cases                       []CaseResult
	TP, FP, TN, FNHard, Pending int
	PendingAffected             int
	Unlikely, UnlikelyAffected  int
	Positives, Negatives        int
}

// Precision: de lo que el motor afirma que esta afectado, cuanto lo esta de verdad.
func (r BenchResult) Precision() float64 { return ratio(r.TP, r.TP+r.FP) }

// Recall: de lo que esta afectado, cuanto afirma el motor.
func (r BenchResult) Recall() float64 { return ratio(r.TP, r.Positives) }

// BaselinePrecision: aceptar todo lo que propone la fuente sin verificar.
func (r BenchResult) BaselinePrecision() float64 { return ratio(r.Positives, len(r.Cases)) }

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

// LoadBench lee el corpus y los registros.
func LoadBench(dir string) (Corpus, *DB, error) {
	var c Corpus
	b, err := os.ReadFile(filepath.Join(dir, "corpus.json"))
	if err != nil {
		return c, nil, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, nil, fmt.Errorf("corpus.json: %w", err)
	}
	db := newDB()
	files, _ := filepath.Glob(filepath.Join(dir, "records", "*.json"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return c, nil, err
		}
		r, err := ParseCVE5(b)
		if err != nil {
			return c, nil, fmt.Errorf("%s: %w", filepath.Base(f), err)
		}
		db.AddRecord(r)
	}
	return c, db, nil
}

// RunBench evalua cada caso como si la fuente hubiera propuesto la CVE por la version (sin verificar).
func RunBench(c Corpus, db *DB) BenchResult {
	var res BenchResult
	for _, k := range c.Cases {
		s := domain.Service{Product: k.Product, Version: k.Version, Banner: k.Banner, CPEs: k.CPEs,
			Vulns: []domain.Vuln{{CVE: k.CVE, Origin: "shodan"}}}
		keep, dis := Assess(s, db, nil)
		cr := CaseResult{Case: k}
		for _, v := range append(keep, dis...) {
			if v.CVE == strings.ToUpper(k.CVE) {
				cr.Confidence, cr.Reason = v.Confidence, v.Reason
			}
		}
		if k.Affected {
			res.Positives++
		} else {
			res.Negatives++
		}
		switch cr.Confidence {
		case Confirmed, Probable:
			if k.Affected {
				res.TP++
				cr.Outcome = "acierto"
			} else {
				res.FP++
				cr.Outcome = "falso-positivo"
			}
		case Dismissed:
			if k.Affected {
				res.FNHard++
				cr.Outcome = "descarte-peligroso"
			} else {
				res.TN++
				cr.Outcome = "acierto"
			}
		case Unlikely:
			res.Unlikely++
			if k.Affected {
				res.UnlikelyAffected++
				cr.Outcome = "improbable-afectada"
			} else {
				cr.Outcome = "improbable"
			}
		default:
			res.Pending++
			if k.Affected {
				res.PendingAffected++
			}
			cr.Outcome = "pendiente"
		}
		res.Cases = append(res.Cases, cr)
	}
	return res
}

// Markdown arma el informe del benchmark.
func (r BenchResult) Markdown() string {
	var b strings.Builder
	pct := func(x float64) string { return fmt.Sprintf("%.0f %%", x*100) }
	fmt.Fprintf(&b, "# Benchmark de precisión\n\n")
	fmt.Fprintf(&b, "Generado con `baqueano bench`. %d casos reales: un servicio visto desde internet, una CVE que la fuente de exposición propone por la versión, y si de verdad lo afecta según el aviso del fabricante. Los registros son copias del repositorio oficial [cvelistV5](https://github.com/CVEProject/cvelistV5) (incluye los datos de CISA Vulnrichment). Esta corrida es **sin conexión y sin NVD**: es el piso, no el techo.\n\n", len(r.Cases))
	fmt.Fprintf(&b, "| Métrica | Sin verificar (v0.1) | Baqueano |\n|---|---|---|\n")
	fmt.Fprintf(&b, "| Precisión (de lo que se informa como vulnerable, cuánto lo es) | %s | **%s** |\n", pct(r.BaselinePrecision()), pct(r.Precision()))
	fmt.Fprintf(&b, "| Falsos positivos | %d | **%d** |\n", r.Negatives, r.FP)
	fmt.Fprintf(&b, "| Descartes peligrosos (afectada pero descartada) | 0 | **%d** |\n", r.FNHard)
	fmt.Fprintf(&b, "| Afectadas que se informan con confianza | %d de %d | %d de %d (%s) |\n", r.Positives, r.Positives, r.TP, r.Positives, pct(r.Recall()))
	fmt.Fprintf(&b, "| Descartadas correctamente (con datos estructurados) | 0 | %d |\n", r.TN)
	fmt.Fprintf(&b, "| «Improbables» (fuera de tramos en texto, prioridad mínima) | 0 | %d (%d sí afectadas) |\n", r.Unlikely, r.UnlikelyAffected)
	fmt.Fprintf(&b, "| «Por confirmar» | 0 | %d (%d sí afectadas) |\n\n", r.Pending, r.PendingAffected)
	b.WriteString("Solo se descarta con datos estructurados. Lo que no se puede afirmar queda **por confirmar** (baja un nivel de prioridad salvo que esté en KEV) y lo que cae fuera de tramos escritos en texto libre queda **improbable**, visible pero al final de la lista.\n\n")
	b.WriteString("## Casos\n\n| Resultado | Servicio | CVE | ¿Afectada? | Baqueano dijo | Motivo |\n|---|---|---|---|---|---|\n")
	cs := append([]CaseResult(nil), r.Cases...)
	order := map[string]int{"descarte-peligroso": 0, "falso-positivo": 1, "improbable-afectada": 2, "pendiente": 3, "improbable": 4, "acierto": 5}
	sort.SliceStable(cs, func(i, j int) bool { return order[cs[i].Outcome] < order[cs[j].Outcome] })
	icon := map[string]string{"acierto": "✅", "falso-positivo": "❌ falso positivo", "descarte-peligroso": "⛔ descarte peligroso", "pendiente": "⏳ por confirmar", "improbable": "✅ improbable", "improbable-afectada": "⚠️ improbable pero afectada"}
	for _, c := range cs {
		svc := c.Product + " " + c.Version
		if c.Banner != "" && strings.Contains(strings.ToLower(c.Banner), "ubuntu") {
			svc += " (paquete de Ubuntu)"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s — %s | %s | %s |\n", icon[c.Outcome], svc, c.CVE, map[bool]string{true: "sí", false: "no"}[c.Affected], c.Note, c.Confidence, strings.ReplaceAll(c.Reason, "|", "/"))
	}
	b.WriteString("\n## Qué muestran los errores\n\n")
	b.WriteString("- Los casos «por confirmar» con CVE de OpenSSH vienen de registros sin versiones (`n/a`). Con la NVD (o con `NVD_API_KEY`) esos rangos se completan.\n")
	b.WriteString("- Exim CVE-2019-10149: el registro oficial dice «4.92», que es justamente la versión corregida. Por eso los datos de texto libre nunca alcanzan para descartar.\n")
	b.WriteString("- Tomcat CVE-2020-1938: el registro escribe «9.0.0.30» en lugar de 9.0.30, así que 9.0.30 queda como improbable aunque está afectada. Sigue en la lista, y como está en KEV conserva la marca de explotación activa.\n")
	return b.String()
}
