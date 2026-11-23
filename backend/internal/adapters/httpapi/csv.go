package httpapi

import (
	"encoding/csv"
	"io"
	"strings"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

// writeFindingsCSV exporta los hallazgos para planillas o tickets. Las celdas que empiezan con =, +, -
// o @ se escapan para que Excel no las ejecute como formulas (inyeccion CSV).
func writeFindingsCSV(w io.Writer, sn domain.Snapshot) {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"severidad", "regla", "categoria", "activo", "cve", "titulo", "detalle", "correccion", "id"})
	for _, f := range sn.Findings {
		_ = cw.Write([]string{string(f.Severity), f.Rule, f.Category, cell(f.Asset), f.CVE, cell(f.Title), cell(f.Detail), cell(f.Recommendation), f.ID})
	}
	cw.Flush()
}

func cell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
