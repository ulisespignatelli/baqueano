package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCLI(t *testing.T) {
	dir := t.TempDir()
	var out, errb bytes.Buffer
	code, err := run(context.Background(), []string{"org", "add", "Acme", "acme.example", "--responsable", "Ulises Pignatelli", "--red", "198.51.100.0/24", "--data", dir}, &out, &errb)
	if err != nil || code != 0 || !strings.Contains(out.String(), "Declaración registrada a nombre de Ulises Pignatelli") || !strings.Contains(out.String(), "TXT  \"baqueano-verify=") {
		t.Fatalf("org add: %d %v %s", code, err, out.String())
	}
	out.Reset()
	if code, _ := run(context.Background(), []string{"org", "list", "--data", dir}, &out, &errb); code != 0 || !strings.Contains(out.String(), "declarado") {
		t.Fatalf("org list: %s", out.String())
	}
	if code, _ := run(context.Background(), []string{"demo", "--data", t.TempDir(), "--out", t.TempDir()}, &out, &errb); code != 0 {
		t.Fatal("demo")
	}
	t.Setenv("SHODAN_API_KEY", "")
	if _, err := run(context.Background(), []string{"scan", "x", "--source", "shodan", "--data", dir}, &out, &errb); err == nil || !strings.Contains(err.Error(), "SHODAN_API_KEY") {
		t.Fatalf("shodan sin clave: %v", err)
	}
	if code, _ := run(context.Background(), []string{"nada"}, &out, &errb); code != 2 {
		t.Fatal("comando desconocido")
	}
}
