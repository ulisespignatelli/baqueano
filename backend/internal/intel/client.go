package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Client consulta las fuentes publicas. Todas las URL se pueden cambiar (pruebas, espejos internos).
type Client struct {
	HTTP      *http.Client
	KEVURLs   []string // se prueban en orden
	CVEURL    string   // cvelistV5: %s = año, %s = grupo (44xxx), %s = id
	CVEAPI    string   // respaldo: API del programa CVE, %s = id
	EPSSURL   string
	NVDURL    string
	NVDKey    string
	EOLURL    string // %s = producto
	UserAgent string
	Retries   int // intentos por pedido (por defecto 3)

	nvdMu   sync.Mutex
	nvdNext time.Time
}

// ErrNotFound: la fuente no tiene ese dato.
var ErrNotFound = errors.New("no encontrado")

// NewClient arma un cliente con las URL oficiales.
func NewClient() *Client {
	return &Client{
		HTTP: &http.Client{Timeout: 60 * time.Second},
		KEVURLs: []string{
			"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
			"https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
		},
		CVEURL:    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/%s/%s/%s.json",
		CVEAPI:    "https://cveawg.mitre.org/api/cve/%s",
		EPSSURL:   "https://api.first.org/data/v1/epss",
		NVDURL:    "https://services.nvd.nist.gov/rest/json/cves/2.0",
		EOLURL:    "https://endoflife.date/api/v1/products/%s",
		UserAgent: "baqueano (+https://github.com/ulisespignatelli/baqueano)",
	}
}

func (c *Client) get(ctx context.Context, u string, hdr map[string]string, max int64) ([]byte, error) {
	var last error
	tries := c.Retries
	if tries <= 0 {
		tries = 3
	}
	for attempt := 0; attempt < tries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt*attempt) * 2 * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", c.UserAgent)
		req.Header.Set("Accept", "application/json")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			// Nunca devolver la URL: puede llevar claves en otras fuentes. El host alcanza para diagnosticar.
			last = fmt.Errorf("no se pudo conectar con %s", hostOf(u))
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, max))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusNotFound:
			return nil, ErrNotFound
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 || resp.StatusCode == http.StatusForbidden && strings.Contains(u, "nvd.nist.gov"):
			last = fmt.Errorf("%s respondió %d", hostOf(u), resp.StatusCode)
			continue
		case resp.StatusCode != http.StatusOK:
			return nil, fmt.Errorf("%s respondió %d", hostOf(u), resp.StatusCode)
		case err != nil:
			last = fmt.Errorf("respuesta incompleta de %s", hostOf(u))
			continue
		}
		return b, nil
	}
	return nil, last
}

func hostOf(u string) string {
	if p, err := url.Parse(u); err == nil && p.Host != "" {
		return p.Host
	}
	return "la fuente"
}

// KEV descarga el catalogo completo de CISA.
func (c *Client) KEV(ctx context.Context) (map[string]KEVEntry, string, error) {
	var last error
	for _, u := range c.KEVURLs {
		b, err := c.get(ctx, u, nil, 64<<20)
		if err != nil {
			last = err
			continue
		}
		var d struct {
			Version string `json:"catalogVersion"`
			Vulns   []struct {
				CVE        string `json:"cveID"`
				Vendor     string `json:"vendorProject"`
				Product    string `json:"product"`
				Name       string `json:"vulnerabilityName"`
				Added      string `json:"dateAdded"`
				Due        string `json:"dueDate"`
				Action     string `json:"requiredAction"`
				Ransomware string `json:"knownRansomwareCampaignUse"`
			} `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(b, &d); err != nil || len(d.Vulns) == 0 {
			last = fmt.Errorf("el catálogo KEV de %s no tiene el formato esperado", hostOf(u))
			continue
		}
		out := make(map[string]KEVEntry, len(d.Vulns))
		for _, v := range d.Vulns {
			out[strings.ToUpper(v.CVE)] = KEVEntry{Vendor: v.Vendor, Product: v.Product, Name: v.Name, Added: v.Added, Due: v.Due,
				Action: v.Action, Ransomware: strings.EqualFold(v.Ransomware, "Known")}
		}
		return out, d.Version, nil
	}
	return nil, "", last
}

// CVE trae el registro oficial (formato 5.x, con el bloque de CISA si existe).
func (c *Client) CVE(ctx context.Context, id string) (*Record, error) {
	year, group, ok := cvePath(id)
	if !ok {
		return nil, fmt.Errorf("identificador de CVE inválido")
	}
	b, err := c.get(ctx, fmt.Sprintf(c.CVEURL, year, group, id), nil, 8<<20)
	if err != nil && !errors.Is(err, ErrNotFound) && c.CVEAPI != "" {
		b, err = c.get(ctx, fmt.Sprintf(c.CVEAPI, id), nil, 8<<20)
	}
	if err != nil {
		return nil, err
	}
	return ParseCVE5(b)
}

// cvePath: CVE-2021-44228 -> 2021, 44xxx.
func cvePath(id string) (string, string, bool) {
	p := strings.Split(id, "-")
	if len(p) != 3 || p[0] != "CVE" || len(p[1]) != 4 {
		return "", "", false
	}
	n, err := strconv.Atoi(p[2])
	if err != nil || n < 0 {
		return "", "", false
	}
	return p[1], strconv.Itoa(n/1000) + "xxx", true
}

// EPSS consulta puntajes de hasta 100 CVE por pedido.
func (c *Client) EPSS(ctx context.Context, ids []string, now time.Time) (map[string]EPSSEntry, error) {
	out := map[string]EPSSEntry{}
	for i := 0; i < len(ids); i += 100 {
		j := min(i+100, len(ids))
		b, err := c.get(ctx, c.EPSSURL+"?cve="+url.QueryEscape(strings.Join(ids[i:j], ",")), nil, 4<<20)
		if err != nil {
			return out, err
		}
		var d struct {
			Data []struct {
				CVE        string `json:"cve"`
				EPSS       string `json:"epss"`
				Percentile string `json:"percentile"`
				Date       string `json:"date"`
			} `json:"data"`
		}
		if err := json.Unmarshal(b, &d); err != nil {
			return out, fmt.Errorf("respuesta de EPSS con formato inesperado")
		}
		for _, x := range d.Data {
			s, _ := strconv.ParseFloat(x.EPSS, 64)
			p, _ := strconv.ParseFloat(x.Percentile, 64)
			out[strings.ToUpper(x.CVE)] = EPSSEntry{Score: s, Percentile: p, Date: x.Date, Fetched: now}
		}
	}
	return out, nil
}

// NVDByCPE busca en la NVD las CVE que afectan a un producto en una version concreta. Respeta el
// limite de la NVD: 5 pedidos cada 30 s sin clave, 50 con clave.
func (c *Client) NVDByCPE(ctx context.Context, cpe string) ([]*Record, error) {
	var out []*Record
	for start := 0; ; {
		if err := c.waitNVD(ctx); err != nil {
			return out, err
		}
		q := url.Values{"virtualMatchString": {cpe}, "resultsPerPage": {"2000"}, "startIndex": {strconv.Itoa(start)}, "noRejected": {""}}
		hdr := map[string]string{}
		if c.NVDKey != "" {
			hdr["apiKey"] = c.NVDKey
		}
		b, err := c.get(ctx, c.NVDURL+"?"+strings.Replace(q.Encode(), "noRejected=", "noRejected", 1), hdr, 64<<20)
		if err != nil {
			return out, err
		}
		recs, total, err := ParseNVD(b)
		if err != nil {
			return out, fmt.Errorf("respuesta de la NVD con formato inesperado")
		}
		out = append(out, recs...)
		start += len(recs)
		if len(recs) == 0 || start >= total || start >= 4000 {
			return out, nil
		}
	}
}

func (c *Client) waitNVD(ctx context.Context) error {
	c.nvdMu.Lock()
	gap := 6500 * time.Millisecond
	if c.NVDKey != "" {
		gap = 700 * time.Millisecond
	}
	wait := time.Until(c.nvdNext)
	c.nvdNext = time.Now().Add(max(wait, 0) + gap)
	c.nvdMu.Unlock()
	if wait <= 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(wait):
		return nil
	}
}

// EOL trae las ramas de un producto y si siguen con soporte.
func (c *Client) EOL(ctx context.Context, slug string) ([]Release, error) {
	b, err := c.get(ctx, fmt.Sprintf(c.EOLURL, url.PathEscape(slug)), nil, 4<<20)
	if err != nil {
		return nil, err
	}
	var d struct {
		Result struct {
			Releases []struct {
				Name    string          `json:"name"`
				IsEOL   bool            `json:"isEol"`
				EOLFrom *string         `json:"eolFrom"`
				Latest  json.RawMessage `json:"latest"`
			} `json:"releases"`
		} `json:"result"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("respuesta de endoflife.date con formato inesperado")
	}
	var out []Release
	for _, r := range d.Result.Releases {
		rel := Release{Name: r.Name, IsEOL: r.IsEOL}
		if r.EOLFrom != nil {
			rel.EOLFrom = *r.EOLFrom
		}
		var l struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(r.Latest, &l) == nil {
			rel.Latest = l.Name
		}
		out = append(out, rel)
	}
	return out, nil
}
