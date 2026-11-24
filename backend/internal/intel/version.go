// Package intel es el motor de inteligencia de vulnerabilidades: decide si una CVE afecta de verdad a
// un servicio comparando su version con los rangos publicados (NVD, registro CVE, Vulnrichment), la
// enriquece con contexto de explotacion (KEV, EPSS, SSVC) y le asigna una prioridad explicada.
package intel

import (
	"strconv"
	"strings"
	"unicode"
)

// part es un pedazo de una version: un numero o una etiqueta ("p", "rc", "beta", "h"…).
type part struct {
	num   int
	label string
	isNum bool
}

// pre son etiquetas de versiones previas a la final (9.0.0.M1 < 9.0.0, 2.0-rc1 < 2.0).
var pre = map[string]int{"dev": 1, "snapshot": 1, "a": 2, "alpha": 2, "b": 3, "beta": 3, "m": 4, "milestone": 4, "pre": 5, "rc": 6, "cr": 6}

func parse(v string) []part {
	v = strings.ToLower(strings.TrimSpace(v))
	var out []part
	i := 0
	for i < len(v) {
		c := rune(v[i])
		switch {
		case unicode.IsDigit(c):
			j := i
			for j < len(v) && unicode.IsDigit(rune(v[j])) {
				j++
			}
			n, _ := strconv.Atoi(strings.TrimLeft(v[i:j], "0") + "0")
			out = append(out, part{num: n / 10, isNum: true})
			i = j
		case unicode.IsLetter(c):
			j := i
			for j < len(v) && unicode.IsLetter(rune(v[j])) {
				j++
			}
			out = append(out, part{label: v[i:j]})
			i = j
		default:
			i++ // separadores: . - _ + ~
		}
	}
	return out
}

// rank ordena una etiqueta frente al final de la version: las previas van antes (negativo), las
// posteriores (p1 de OpenSSH, h1 de PAN-OS) despues.
func rank(p part) int {
	if p.isNum {
		return 1
	}
	if r, ok := pre[p.label]; ok {
		return r - 10
	}
	return 1
}

// Compare devuelve -1, 0 o 1. Entiende las formas habituales: 2.4.49, 8.9p1, 9.0.0.M1, 10.2.9-h1, 1.0rc2.
func Compare(a, b string) int {
	pa, pb := parse(a), parse(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		switch {
		case i >= len(pa):
			if pb[i].isNum && pb[i].num == 0 {
				continue // 1.18 == 1.18.0
			}
			return sign(-rank(pb[i]))
		case i >= len(pb):
			if pa[i].isNum && pa[i].num == 0 {
				continue
			}
			return sign(rank(pa[i]))
		}
		x, y := pa[i], pb[i]
		switch {
		case x.isNum && y.isNum:
			if x.num != y.num {
				return sign(x.num - y.num)
			}
		case x.isNum != y.isNum:
			// numero contra etiqueta: 1.0 > 1.0rc1, pero 8.9.1 > 8.9p1 no tiene sentido real; se ordena por rank
			if r := rank(x) - rank(y); r != 0 {
				return sign(r)
			}
			if x.isNum {
				return 1
			}
			return -1
		default:
			rx, ry := rank(x), rank(y)
			if rx != ry {
				return sign(rx - ry)
			}
			if x.label != y.label {
				return sign(strings.Compare(x.label, y.label))
			}
		}
	}
	return 0
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// IsVersion dice si el texto parece una version (empieza con un numero y no es un comodin suelto).
func IsVersion(s string) bool {
	s = strings.TrimSpace(s)
	return s != "" && unicode.IsDigit(rune(s[0])) && !strings.ContainsAny(s, " *")
}

// Range es un tramo de versiones. Prefix limita el tramo a una rama (7.1.x -> "7.1").
type Range struct {
	Exact    string `json:"exact,omitempty"`
	Start    string `json:"start,omitempty"`
	StartInc bool   `json:"start_inc,omitempty"`
	End      string `json:"end,omitempty"`
	EndInc   bool   `json:"end_inc,omitempty"`
	Prefix   string `json:"prefix,omitempty"`
}

// Contains dice si la version cae en el tramo.
func (r Range) Contains(v string) bool {
	if r.Exact != "" {
		return Compare(v, r.Exact) == 0
	}
	if r.Prefix != "" && !inBranch(v, r.Prefix) {
		return false
	}
	if r.Start != "" {
		c := Compare(v, r.Start)
		if c < 0 || (c == 0 && !r.StartInc) {
			return false
		}
	}
	if r.End != "" {
		c := Compare(v, r.End)
		if c > 0 || (c == 0 && !r.EndInc) {
			return false
		}
	}
	return r.Exact != "" || r.Start != "" || r.End != "" || r.Prefix != ""
}

// inBranch: 7.1.33 esta en la rama 7.1; 7.10.2 no.
func inBranch(v, prefix string) bool {
	pv, pp := parse(v), parse(prefix)
	if len(pv) < len(pp) {
		return false
	}
	for i := range pp {
		if pv[i] != pp[i] {
			return false
		}
	}
	return true
}

// String describe el tramo en castellano para los informes.
func (r Range) String() string {
	if r.Exact != "" {
		return r.Exact
	}
	var s []string
	if r.Prefix != "" && r.Start == "" {
		s = append(s, "rama "+r.Prefix+".x")
	}
	if r.Start != "" && r.Start != "0" {
		s = append(s, "desde "+r.Start+map[bool]string{true: "", false: " (exclusive)"}[r.StartInc])
	}
	if r.End != "" {
		if r.EndInc {
			s = append(s, "hasta "+r.End)
		} else {
			s = append(s, "antes de "+r.End)
		}
	}
	if len(s) == 0 {
		return "todas"
	}
	return strings.Join(s, ", ")
}
