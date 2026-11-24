package httpapi

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

// writeFindingsCSV exporta los hallazgos para planillas o tickets. Las celdas que empiezan con =, +, -
// o @ se escapan para que Excel no las ejecute como formulas (inyeccion CSV).
func writeFindingsCSV(w io.Writer, sn domain.Snapshot) {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"severidad", "prioridad", "confianza", "regla", "categoria", "activo", "cve", "kev", "epss", "corregida_en", "titulo", "detalle", "correccion", "id"})
	for _, f := range sn.Findings {
		var prio, conf, kev, epss, fixed string
		if v := f.Vuln; v != nil {
			prio, conf, fixed = v.Priority, v.Confidence, cell(v.FixedIn)
			if v.KEV {
				kev = "si"
			}
			if v.EPSS > 0 {
				epss = strconv.FormatFloat(v.EPSS, 'f', 4, 64)
			}
		}
		_ = cw.Write([]string{string(f.Severity), prio, conf, f.Rule, f.Category, cell(f.Asset), f.CVE, kev, epss, fixed, cell(f.Title), cell(f.Detail), cell(f.Recommendation), f.ID})
	}
	cw.Flush()
}

func cell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
