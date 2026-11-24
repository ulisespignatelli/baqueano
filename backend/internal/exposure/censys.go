package exposure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

// ErrCensysAuth: el token de Censys es invalido o no tiene permiso para la API.
var ErrCensysAuth = errors.New("el token de Censys es inválido o no tiene acceso a la API")

// ErrBudget: se alcanzo el tope de consultas que consumen creditos.
var ErrBudget = errors.New("se alcanzó el tope de consultas a Censys de este escaneo")

// Censys consulta la Platform API v3 (GET /v3/global/asset/host/{ip}). Cada consulta de host consume
// creditos de la cuenta: por eso hay un tope por escaneo (MaxLookups).
type Censys struct {
	Token      string
	OrgID      string // opcional en cuentas gratuitas
	Base       string
	HTTP       *http.Client
	MaxLookups int
	Gap        time.Duration

	mu   sync.Mutex
	used int
	next time.Time
}

// NewCensys arma el cliente con la URL oficial.
func NewCensys(token, orgID string) *Censys {
	return &Censys{Token: token, OrgID: orgID, Base: "https://api.platform.censys.io", HTTP: &http.Client{Timeout: 30 * time.Second},
		MaxLookups: 100, Gap: 1100 * time.Millisecond}
}

func (c *Censys) Name() string { return "censys" }

// BeginScan reinicia el tope de consultas.
func (c *Censys) BeginScan() {
	c.mu.Lock()
	c.used = 0
	c.mu.Unlock()
}

func (c *Censys) take(ctx context.Context) error {
	c.mu.Lock()
	if c.MaxLookups > 0 && c.used >= c.MaxLookups {
		c.mu.Unlock()
		return ErrBudget
	}
	c.used++
	wait := time.Until(c.next)
	c.next = time.Now().Add(max(wait, 0) + c.Gap)
	c.mu.Unlock()
	if wait > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return nil
}

type censysHost struct {
	Result struct {
		Resource struct {
			IP       string `json:"ip"`
			Location struct {
				Country string `json:"country"`
			} `json:"location"`
			AS struct {
				Name string `json:"name"`
			} `json:"autonomous_system"`
			Services []struct {
				Port      int    `json:"port"`
				Protocol  string `json:"protocol"`
				Transport string `json:"transport_protocol"`
				ScanTime  string `json:"scan_time"`
				Software  []struct {
					Vendor  string `json:"vendor"`
					Product string `json:"product"`
					Version string `json:"version"`
					Part    string `json:"part"`
					CPE     string `json:"cpe"`
					URI     string `json:"uniform_resource_identifier"`
				} `json:"software"`
				Cert *struct {
					Parsed struct {
						SubjectDN string `json:"subject_dn"`
						IssuerDN  string `json:"issuer_dn"`
						Validity  struct {
							NotAfter string `json:"not_after"`
						} `json:"validity_period"`
					} `json:"parsed"`
				} `json:"cert"`
				Vulns []struct {
					ID  string `json:"id"`
					KEV any    `json:"kev"`
				} `json:"vulns"`
				Endpoints []struct {
					HTTP *struct {
						Title string `json:"html_title"`
					} `json:"http"`
				} `json:"endpoints"`
				Labels []struct {
					Value string `json:"value"`
				} `json:"labels"`
			} `json:"services"`
		} `json:"resource"`
	} `json:"result"`
}

var reCN = regexp.MustCompile(`(?:^|,\s*)CN=([^,]+)`)

// Host devuelve los servicios que Censys conoce de una IP.
func (c *Censys) Host(ctx context.Context, ip string) ([]domain.Service, bool, error) {
	if err := c.take(ctx); err != nil {
		return nil, false, err
	}
	u := c.Base + "/v3/global/asset/host/" + url.PathEscape(ip)
	if c.OrgID != "" {
		u += "?organization_id=" + url.QueryEscape(c.OrgID)
	}
	var body []byte
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, false, err
		}
		req.Header.Set("Authorization", "Bearer "+c.Token)
		req.Header.Set("Accept", "application/vnd.censys.api.v3.host.v1+json")
		req.Header.Set("User-Agent", "baqueano")
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, false, errors.New("no se pudo conectar con Censys") // sin la URL ni el token
		}
		body, _ = io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusOK:
		case resp.StatusCode == http.StatusNotFound:
			return nil, false, nil
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			return nil, false, ErrCensysAuth
		case (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && attempt < 2:
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 3 * time.Second):
			}
			continue
		case resp.StatusCode == http.StatusPaymentRequired:
			return nil, false, errors.New("la cuenta de Censys no tiene créditos disponibles")
		default:
			return nil, false, fmt.Errorf("Censys respondió %d", resp.StatusCode)
		}
		break
	}
	var h censysHost
	if err := json.Unmarshal(body, &h); err != nil {
		return nil, false, errors.New("respuesta de Censys con formato inesperado")
	}
	r := h.Result.Resource
	var out []domain.Service
	for _, s := range r.Services {
		if s.Port == 0 {
			continue
		}
		sv := domain.Service{IP: ip, Port: s.Port, Transport: strings.ToLower(s.Transport), Module: strings.ToLower(s.Protocol),
			Org: r.AS.Name, Country: r.Location.Country, Source: "censys"}
		if sv.Transport == "" {
			sv.Transport = "tcp"
		}
		if t, err := time.Parse(time.RFC3339, s.ScanTime); err == nil {
			sv.SeenAt = t.UTC()
		}
		for _, sw := range s.Software {
			cpe := sw.CPE
			if cpe == "" && strings.HasPrefix(sw.URI, "cpe:") {
				cpe = sw.URI
			}
			if cpe != "" {
				sv.CPEs = append(sv.CPEs, cpe)
			}
			if sv.Product == "" && sw.Product != "" && sw.Part != "o" && sw.Part != "h" {
				sv.Product = strings.TrimSpace(sw.Vendor + " " + sw.Product)
				if strings.EqualFold(sw.Vendor, sw.Product) || sw.Vendor == "" {
					sv.Product = sw.Product
				}
				sv.Version = sw.Version
			}
		}
		for _, e := range s.Endpoints {
			if e.HTTP != nil && e.HTTP.Title != "" && sv.Title == "" {
				sv.Title = clipTitle(e.HTTP.Title)
			}
		}
		for _, l := range s.Labels {
			if l.Value != "" {
				sv.Tags = append(sv.Tags, strings.ToLower(l.Value))
			}
		}
		if c := s.Cert; c != nil {
			cert := &domain.Cert{}
			if m := reCN.FindStringSubmatch(c.Parsed.SubjectDN); m != nil {
				cert.Subject = m[1]
			}
			if m := reCN.FindStringSubmatch(c.Parsed.IssuerDN); m != nil {
				cert.Issuer = m[1]
			}
			if t, err := time.Parse(time.RFC3339, c.Parsed.Validity.NotAfter); err == nil {
				cert.NotAfter = t.UTC()
				cert.Expired = time.Now().After(t)
			}
			cert.SelfSigned = c.Parsed.SubjectDN != "" && c.Parsed.SubjectDN == c.Parsed.IssuerDN
			sv.Cert = cert
		}
		for _, v := range s.Vulns {
			if strings.HasPrefix(strings.ToUpper(v.ID), "CVE-") {
				kev, _ := v.KEV.(bool)
				sv.Vulns = append(sv.Vulns, domain.Vuln{CVE: strings.ToUpper(v.ID), KEV: kev, Origin: "censys"})
			}
		}
		sortVulns(sv.Vulns)
		out = append(out, sv)
	}
	return out, len(out) > 0, nil
}

func clipTitle(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}
