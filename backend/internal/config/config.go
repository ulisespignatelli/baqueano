// Package config lee la configuracion del entorno y de un archivo .env local. La clave de Shodan nunca
// se guarda en el repositorio ni se muestra.
package config

import (
	"bufio"
	"os"
	"strings"
)

// LoadDotEnv carga variables de un archivo .env sin pisar las que ya existen en el entorno.
func LoadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(strings.TrimPrefix(k, "export "))
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if _, exists := os.LookupEnv(k); !exists && k != "" {
			os.Setenv(k, v)
		}
	}
}

// Mask muestra solo los ultimos 4 caracteres de un secreto.
func Mask(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return strings.Repeat("•", 8) + s[len(s)-4:]
}
