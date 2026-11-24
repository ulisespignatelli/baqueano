package intel

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// KEVEntry es una vulnerabilidad del catalogo de CISA de explotacion conocida.
type KEVEntry struct {
	Vendor     string `json:"vendor"`
	Product    string `json:"product"`
	Name       string `json:"name"`
	Added      string `json:"added"`
	Due        string `json:"due"`
	Action     string `json:"action,omitempty"`
	Ransomware bool   `json:"ransomware,omitempty"`
}

// EPSSEntry es la probabilidad de explotacion en los proximos 30 dias (FIRST).
type EPSSEntry struct {
	Score      float64   `json:"score"`
	Percentile float64   `json:"percentile"`
	Date       string    `json:"date,omitempty"`
	Fetched    time.Time `json:"fetched"`
}

// Release es una rama de un producto segun endoflife.date.
type Release struct {
	Name    string `json:"name"`
	IsEOL   bool   `json:"is_eol"`
	EOLFrom string `json:"eol_from,omitempty"`
	Latest  string `json:"latest,omitempty"`
}

type fetched struct {
	At   time.Time `json:"at"`
	Miss bool      `json:"miss,omitempty"` // la fuente no tiene nada (se recuerda para no preguntar de nuevo)
}

// DB es la base local de inteligencia. Se guarda comprimida y funciona sin conexion.
type DB struct {
	KEV        map[string]KEVEntry  `json:"kev"`
	KEVCatalog string               `json:"kev_catalog,omitempty"`
	KEVUpdated time.Time            `json:"kev_updated"`
	EPSS       map[string]EPSSEntry `json:"epss"`
	Records    map[string]*Record   `json:"records"`
	RecordsAt  map[string]fetched   `json:"records_at"` // ultima consulta al registro CVE
	NVDAt      map[string]fetched   `json:"nvd_at"`     // ultima consulta a la NVD por producto@version
	NVDHits    map[string][]string  `json:"nvd_hits"`   // CVE que la NVD asocia a producto@version
	EOL        map[string][]Release `json:"eol"`
	EOLAt      map[string]fetched   `json:"eol_at"`
	Errors     map[string]string    `json:"errors,omitempty"` // ultimo error por fuente
	Updated    map[string]time.Time `json:"updated,omitempty"`
}

func newDB() *DB {
	return &DB{KEV: map[string]KEVEntry{}, EPSS: map[string]EPSSEntry{}, Records: map[string]*Record{},
		RecordsAt: map[string]fetched{}, NVDAt: map[string]fetched{}, NVDHits: map[string][]string{},
		EOL: map[string][]Release{}, EOLAt: map[string]fetched{}, Errors: map[string]string{}, Updated: map[string]time.Time{}}
}

// fill completa mapas vacios (bases guardadas por versiones anteriores).
func (d *DB) fill() {
	n := newDB()
	if d.KEV == nil {
		d.KEV = n.KEV
	}
	if d.EPSS == nil {
		d.EPSS = n.EPSS
	}
	if d.Records == nil {
		d.Records = n.Records
	}
	if d.RecordsAt == nil {
		d.RecordsAt = n.RecordsAt
	}
	if d.NVDAt == nil {
		d.NVDAt = n.NVDAt
	}
	if d.NVDHits == nil {
		d.NVDHits = n.NVDHits
	}
	if d.EOL == nil {
		d.EOL = n.EOL
	}
	if d.EOLAt == nil {
		d.EOLAt = n.EOLAt
	}
	if d.Errors == nil {
		d.Errors = n.Errors
	}
	if d.Updated == nil {
		d.Updated = n.Updated
	}
}

// AddRecord suma un registro (de cualquier fuente) a la base.
func (d *DB) AddRecord(r *Record) {
	if cur := d.Records[r.CVE]; cur != nil {
		cur.merge(r)
		return
	}
	d.Records[r.CVE] = r
}

func loadDB(path string) (*DB, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return newDB(), nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	d := newDB()
	if err := json.NewDecoder(z).Decode(d); err != nil {
		return nil, err
	}
	d.fill()
	return d, nil
}

func (d *DB) save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".intel-*")
	if err != nil {
		return err
	}
	z := gzip.NewWriter(tmp)
	if err := json.NewEncoder(z).Encode(d); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := z.Close(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}
