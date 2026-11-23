package scope

import (
	"context"
	"errors"
	"net"
	"testing"
)

type fakeDNS map[string][]string

func (f fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func TestVerify(t *testing.T) {
	dns := fakeDNS{
		"acme.example": {"v=spf1 -all", "baqueano-verify=abc123",
			"baqueano-scope=203.0.113.0/24, 198.51.100.7, 10.0.0.0/8, 8.0.0.0/8, basura"},
		"otro.example": {"baqueano-verify=otro-token"},
	}
	r, err := Verify(context.Background(), dns, "acme.example", "abc123")
	if err != nil || !r.Verified {
		t.Fatalf("debería verificar: %v", err)
	}
	if len(r.Networks) != 2 || r.Networks[0] != "203.0.113.0/24" || r.Networks[1] != "198.51.100.7/32" {
		t.Fatalf("redes: %v", r.Networks)
	}
	if len(r.Rejected) != 3 {
		t.Fatalf("debería rechazar la privada, la enorme y la inválida: %v", r.Rejected)
	}
	if _, err := Verify(context.Background(), dns, "otro.example", "abc123"); !errors.Is(err, ErrNotVerified) {
		t.Fatal("un token ajeno no verifica")
	}
	if _, err := Verify(context.Background(), dns, "nada.example", "abc123"); !errors.Is(err, ErrNotVerified) {
		t.Fatal("dominio sin TXT")
	}
}

func TestNormalizeAndMembership(t *testing.T) {
	for in, want := range map[string]string{"https://Acme.Example/": "acme.example", " acme.example. ": "acme.example"} {
		if got, err := NormalizeDomain(in); err != nil || got != want {
			t.Errorf("%q → %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "localhost", "-a.example", "a..example", "ñandú.example"} {
		if _, err := NormalizeDomain(bad); err == nil {
			t.Errorf("%q debería ser inválido", bad)
		}
	}
	d := []string{"acme.example"}
	if !InDomains("www.acme.example", d) || !InDomains("ACME.example.", d) || InDomains("notacme.example", d) || InDomains("acme.example.evil.test", d) {
		t.Fatal("pertenencia a dominios")
	}
	if !InNetworks("203.0.113.9", []string{"203.0.113.0/24"}) || InNetworks("203.0.114.1", []string{"203.0.113.0/24"}) {
		t.Fatal("pertenencia a redes")
	}
	if n := len(ExpandNetworks([]string{"198.51.100.0/30"})); n != 4 {
		t.Fatalf("expandir /30: %d", n)
	}
}
