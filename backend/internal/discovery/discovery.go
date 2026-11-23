// Package discovery encuentra los activos de un dominio verificado sin enviar trafico a sus servidores:
// Certificate Transparency (crt.sh) para los nombres y DNS publico para resolverlos.
package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
	"github.com/ulisespignatelli/baqueano/backend/internal/scope"
)

// DNS es lo que se usa del resolver (net.Resolver lo cumple).
type DNS interface {
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// Discoverer arma la lista de activos.
type Discoverer struct {
	HTTP     *http.Client
	CTBase   string // por defecto https://crt.sh
	DNS      DNS
	MaxHosts int // por dominio (por defecto 500)
	Workers  int
}

// New con valores por defecto.
func New() *Discoverer {
	return &Discoverer{HTTP: &http.Client{Timeout: 60 * time.Second}, CTBase: "https://crt.sh", DNS: net.DefaultResolver, MaxHosts: 500, Workers: 16}
}

// Result del descubrimiento de un dominio.
type Result struct {
	Assets []domain.Asset
	Notes  []string
}

// Discover busca los nombres del dominio y los resuelve.
func (d *Discoverer) Discover(ctx context.Context, dom string) Result {
	var res Result
	names := map[string][]string{dom: {"dominio"}, "www." + dom: {"dominio"}}
	ct, err := d.fromCT(ctx, dom)
	if err != nil {
		res.Notes = append(res.Notes, fmt.Sprintf("Certificate Transparency no respondió para %s (%v); se usan solo el dominio y www.", dom, err))
	}
	for _, n := range ct {
		names[n] = append(names[n], "ct")
	}
	hosts := make([]string, 0, len(names))
	for h := range names {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	if max := d.maxHosts(); len(hosts) > max {
		res.Notes = append(res.Notes, fmt.Sprintf("%s tiene %d nombres en Certificate Transparency; se analizaron los primeros %d.", dom, len(hosts), max))
		hosts = hosts[:max]
	}

	assets := make([]domain.Asset, len(hosts))
	var wg sync.WaitGroup
	sem := make(chan struct{}, d.workers())
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			assets[i] = d.resolve(ctx, h, names[h])
		}(i, h)
	}
	wg.Wait()
	res.Assets = assets
	return res
}

func (d *Discoverer) maxHosts() int {
	if d.MaxHosts > 0 {
		return d.MaxHosts
	}
	return 500
}

func (d *Discoverer) workers() int {
	if d.Workers > 0 {
		return d.Workers
	}
	return 16
}

type ctEntry struct {
	NameValue  string `json:"name_value"`
	CommonName string `json:"common_name"`
}

func (d *Discoverer) fromCT(ctx context.Context, dom string) ([]string, error) {
	u := strings.TrimSuffix(d.CTBase, "/") + "/?output=json&q=" + url.QueryEscape("%."+dom)
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ { // crt.sh suele fallar de forma intermitente
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		req.Header.Set("User-Agent", "baqueano (+https://github.com/ulisespignatelli/baqueano)")
		resp, err := d.HTTP.Do(req)
		if err != nil {
			lastErr = errors.New("sin respuesta")
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || err != nil {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		var entries []ctEntry
		if err := json.Unmarshal(body, &entries); err != nil {
			lastErr = errors.New("respuesta inválida")
			continue
		}
		set := map[string]bool{}
		for _, e := range entries {
			for _, n := range strings.Split(e.NameValue+"\n"+e.CommonName, "\n") {
				n = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(n)), "*.")
				if n != "" && !strings.ContainsAny(n, " @*") && scope.InDomains(n, []string{dom}) {
					set[n] = true
				}
			}
		}
		out := make([]string, 0, len(set))
		for n := range set {
			out = append(out, n)
		}
		sort.Strings(out)
		return out, nil
	}
	return nil, lastErr
}

func (d *Discoverer) resolve(ctx context.Context, host string, sources []string) domain.Asset {
	a := domain.Asset{Hostname: host, Sources: dedupe(append(sources, "dns"))}
	if cname, err := d.DNS.LookupCNAME(ctx, host); err == nil {
		cname = strings.TrimSuffix(strings.ToLower(cname), ".")
		if cname != host {
			a.CNAME = cname
			a.ThirdParty = Provider(cname)
		}
	}
	if ips, err := d.DNS.LookupHost(ctx, host); err == nil && len(ips) > 0 {
		sort.Strings(ips)
		a.IPs, a.Resolves = ips, true
	}
	return a
}

// providers: sufijos de CNAME de servicios de terceros conocidos. Si un CNAME apunta a uno de estos y
// no resuelve, alguien podria registrar ese recurso y tomar el subdominio.
var providers = []struct{ suffix, name string }{
	{"herokuapp.com", "Heroku"}, {"herokudns.com", "Heroku"}, {"azurewebsites.net", "Azure App Service"},
	{"cloudapp.net", "Azure"}, {"cloudapp.azure.com", "Azure"}, {"trafficmanager.net", "Azure Traffic Manager"},
	{"blob.core.windows.net", "Azure Blob Storage"}, {"azureedge.net", "Azure CDN"}, {"azurefd.net", "Azure Front Door"},
	{"s3.amazonaws.com", "AWS S3"}, {"amazonaws.com", "AWS"}, {"cloudfront.net", "AWS CloudFront"},
	{"elasticbeanstalk.com", "AWS Elastic Beanstalk"}, {"github.io", "GitHub Pages"}, {"netlify.app", "Netlify"},
	{"netlify.com", "Netlify"}, {"vercel.app", "Vercel"}, {"vercel-dns.com", "Vercel"}, {"pages.dev", "Cloudflare Pages"},
	{"myshopify.com", "Shopify"}, {"zendesk.com", "Zendesk"}, {"wordpress.com", "WordPress.com"}, {"ghost.io", "Ghost"},
	{"surge.sh", "Surge"}, {"fastly.net", "Fastly"}, {"edgekey.net", "Akamai"}, {"edgesuite.net", "Akamai"},
	{"akamaiedge.net", "Akamai"}, {"cdn.cloudflare.net", "Cloudflare"}, {"googleusercontent.com", "Google Cloud"},
	{"appspot.com", "Google App Engine"}, {"firebaseapp.com", "Firebase"}, {"web.app", "Firebase"},
	{"readme.io", "ReadMe"}, {"helpscoutdocs.com", "Help Scout"}, {"statuspage.io", "Statuspage"},
	{"unbouncepages.com", "Unbounce"}, {"wpengine.com", "WP Engine"}, {"pantheonsite.io", "Pantheon"},
}

// Provider devuelve el nombre del proveedor si el CNAME apunta a un servicio de terceros conocido.
func Provider(cname string) string {
	for _, p := range providers {
		if cname == p.suffix || strings.HasSuffix(cname, "."+p.suffix) {
			return p.name
		}
	}
	return ""
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	out := s[:0]
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
