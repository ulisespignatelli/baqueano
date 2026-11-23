// Package scope decide QUE se puede analizar. Baqueano solo mira lo que el dueño autorizo publicando
// registros DNS en su propio dominio:
//
//	baqueano-verify=<token>          prueba que controla el dominio
//	baqueano-scope=203.0.113.0/24    (opcional) redes propias que tambien se pueden analizar
//
// Asi el consentimiento es verificable por cualquiera y no depende de la palabra de quien usa la
// herramienta.
package scope

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Resolver es lo que se necesita de DNS (net.Resolver lo cumple; los tests usan uno falso).
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// MaxNetworkAddrs limita el tamaño de una red declarada (un /20 en IPv4). Evita que un registro mal
// escrito o malicioso convierta el analisis en un barrido de medio proveedor.
const MaxNetworkAddrs = 4096

// NewToken genera un token de verificacion.
func NewToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// NormalizeDomain limpia y valida un nombre de dominio.
func NormalizeDomain(d string) (string, error) {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(strings.TrimPrefix(d, "https://"), "http://")
	d = strings.TrimSuffix(strings.SplitN(d, "/", 2)[0], ".")
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") {
		return "", fmt.Errorf("dominio inválido %q", d)
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("dominio inválido %q", d)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return "", fmt.Errorf("dominio inválido %q (usar la forma punycode para nombres con acentos)", d)
			}
		}
	}
	return d, nil
}

// Result de una verificacion.
type Result struct {
	Verified bool
	Networks []string
	Rejected []string // redes declaradas que no se aceptaron, con el motivo
}

// ErrNotVerified se devuelve cuando el registro no esta publicado.
var ErrNotVerified = errors.New("no se encontró el registro TXT de verificación")

// Verify busca el token en los TXT del dominio y lee las redes declaradas.
func Verify(ctx context.Context, r Resolver, domain, token string) (Result, error) {
	txts, err := r.LookupTXT(ctx, domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return Result{}, ErrNotVerified
		}
		return Result{}, fmt.Errorf("consultando DNS de %s: %w", domain, err)
	}
	var res Result
	for _, t := range txts {
		t = strings.TrimSpace(t)
		switch {
		case t == "baqueano-verify="+token:
			res.Verified = true
		case strings.HasPrefix(t, "baqueano-scope="):
			for _, n := range strings.Split(strings.TrimPrefix(t, "baqueano-scope="), ",") {
				if n = strings.TrimSpace(n); n == "" {
					continue
				}
				if p, why := CheckNetwork(n); why != "" {
					res.Rejected = append(res.Rejected, n+": "+why)
				} else {
					res.Networks = append(res.Networks, p.String())
				}
			}
		}
	}
	if !res.Verified {
		return Result{}, ErrNotVerified
	}
	return res, nil
}

// CheckNetwork valida una red: CIDR o IP publica, de hasta MaxNetworkAddrs direcciones. Devuelve el motivo
// si se rechaza.
func CheckNetwork(s string) (netip.Prefix, string) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, err2 := netip.ParseAddr(s)
		if err2 != nil {
			return p, "no es una red CIDR ni una IP"
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	p = p.Masked()
	a := p.Addr()
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() {
		return p, "es una red privada o reservada: no se ve desde internet"
	}
	hostBits := a.BitLen() - p.Bits()
	if hostBits > 12 {
		return p, fmt.Sprintf("demasiado grande (máximo %d direcciones, por ejemplo un /20)", MaxNetworkAddrs)
	}
	return p, ""
}

// InDomains indica si un nombre pertenece a alguno de los dominios (es el dominio o un subdominio).
func InDomains(host string, domains []string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// InNetworks indica si una IP esta en alguna de las redes.
func InNetworks(ip string, networks []string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, n := range networks {
		if p, err := netip.ParsePrefix(n); err == nil && p.Contains(a) {
			return true
		}
	}
	return false
}

// ExpandNetworks devuelve todas las IP de las redes (ya acotadas por MaxNetworkAddrs cada una).
func ExpandNetworks(networks []string) []string {
	var out []string
	for _, n := range networks {
		p, err := netip.ParsePrefix(n)
		if err != nil {
			continue
		}
		for a := p.Masked().Addr(); p.Contains(a); a = a.Next() {
			out = append(out, a.String())
			if len(out) > 64*MaxNetworkAddrs {
				return out
			}
		}
	}
	return out
}
