package discovery_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ulisespignatelli/baqueano/backend/internal/demodata"
	"github.com/ulisespignatelli/baqueano/backend/internal/discovery"
)

func TestDiscover(t *testing.T) {
	dns := &demodata.DNS{
		CNAME: map[string]string{"blog.acme.example": "acme.herokuapp.com"},
		A:     map[string][]string{"acme.example": {"198.51.100.1"}, "www.acme.example": {"198.51.100.1"}, "api.acme.example": {"198.51.100.2", "198.51.100.3"}},
	}
	ct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"name_value":"api.acme.example\n*.acme.example\nblog.acme.example","common_name":"api.acme.example"},
			{"name_value":"acme.example.evil.test\notra.example\nuser@acme.example","common_name":"WWW.ACME.EXAMPLE"}]`))
	}))
	defer ct.Close()
	d := discovery.New()
	d.CTBase, d.DNS = ct.URL, dns
	res := d.Discover(context.Background(), "acme.example")
	byName := map[string]bool{}
	for _, a := range res.Assets {
		byName[a.Hostname] = true
		switch a.Hostname {
		case "api.acme.example":
			if !a.Resolves || len(a.IPs) != 2 {
				t.Errorf("api: %+v", a)
			}
		case "blog.acme.example":
			if a.Resolves || a.ThirdParty != "Heroku" || a.CNAME != "acme.herokuapp.com" {
				t.Errorf("blog: %+v", a)
			}
		}
	}
	for _, want := range []string{"acme.example", "www.acme.example", "api.acme.example", "blog.acme.example"} {
		if !byName[want] {
			t.Errorf("falta %s", want)
		}
	}
	for _, bad := range []string{"acme.example.evil.test", "otra.example", "user@acme.example", "*.acme.example"} {
		if byName[bad] {
			t.Errorf("%s no pertenece al dominio o no es un nombre válido", bad)
		}
	}
}

func TestCTDownFallsBack(t *testing.T) {
	ct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502) }))
	defer ct.Close()
	d := discovery.New()
	d.CTBase, d.DNS = ct.URL, &demodata.DNS{A: map[string][]string{"acme.example": {"198.51.100.1"}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // no esperar los reintentos
	res := d.Discover(ctx, "acme.example")
	if len(res.Assets) != 2 || len(res.Notes) != 1 {
		t.Fatalf("sin CT, igual analiza el dominio y www: %+v %v", res.Assets, res.Notes)
	}
}

func TestProvider(t *testing.T) {
	if discovery.Provider("x.s3.amazonaws.com") != "AWS S3" || discovery.Provider("herokuapp.com.evil.test") != "" || discovery.Provider("acme.github.io") != "GitHub Pages" {
		t.Fatal("proveedores")
	}
}
