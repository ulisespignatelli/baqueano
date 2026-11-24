package intel

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

// Engine mantiene la base local y la completa a demanda. Sin Client trabaja solo con lo guardado.
type Engine struct {
	Client *Client // nil = sin conexion
	Now    func() time.Time

	RecordTTL time.Duration // cada cuanto se vuelve a consultar un registro CVE (por defecto 7 dias)
	EPSSTTL   time.Duration // EPSS cambia todos los dias (por defecto 24 h)
	NVDTTL    time.Duration // busqueda por producto@version en la NVD (por defecto 7 dias)
	EOLTTL    time.Duration // ramas de endoflife.date (por defecto 7 dias)
	MaxFetch  int           // tope de registros CVE nuevos por enriquecimiento (por defecto 400)
	UseNVD    bool          // la NVD es lenta sin clave: se puede desactivar

	path string
	mu   sync.Mutex
	db   *DB
}

// Open carga (o crea) la base en path.
func Open(path string) (*Engine, error) {
	db, err := loadDB(path)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer la base de inteligencia: %w", err)
	}
	return &Engine{path: path, db: db, UseNVD: true}, nil
}

// NewMemory crea un motor sin archivo (pruebas y demo).
func NewMemory(db *DB) *Engine {
	if db == nil {
		db = newDB()
	}
	db.fill()
	return &Engine{db: db}
}

// NewDB devuelve una base vacia para armar a mano.
func NewDB() *DB { return newDB() }

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now().UTC()
}

func ttl(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

func (e *Engine) save() error {
	if e.path == "" {
		return nil
	}
	return e.db.save(e.path)
}

func (e *Engine) noteErr(source string, err error) {
	if err == nil {
		delete(e.db.Errors, source)
		e.db.Updated[source] = e.now()
		return
	}
	e.db.Errors[source] = err.Error()
}

// Update descarga el catalogo KEV y refresca EPSS de las CVE conocidas.
func (e *Engine) Update(ctx context.Context, progress func(string)) error {
	if progress == nil {
		progress = func(string) {}
	}
	if e.Client == nil {
		return errors.New("sin conexión: la base de inteligencia no se puede actualizar")
	}
	progress("Descargando el catálogo KEV de CISA…")
	kev, version, err := e.Client.KEV(ctx)
	e.mu.Lock()
	if err == nil {
		e.db.KEV, e.db.KEVCatalog, e.db.KEVUpdated = kev, version, e.now()
	}
	e.noteErr("kev", err)
	ids := make([]string, 0, len(e.db.Records))
	for id := range e.db.Records {
		ids = append(ids, id)
	}
	e.mu.Unlock()
	if err != nil {
		return fmt.Errorf("KEV: %w", err)
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		progress(fmt.Sprintf("Catálogo KEV: %d vulnerabilidades explotadas.", len(kev)))
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.save()
	}
	progress(fmt.Sprintf("Catálogo KEV: %d vulnerabilidades explotadas. Actualizando EPSS de %d CVE…", len(kev), len(ids)))
	epss, eerr := e.Client.EPSS(ctx, ids, e.now())
	e.mu.Lock()
	for k, v := range epss {
		e.db.EPSS[k] = v
	}
	e.noteErr("epss", eerr)
	serr := e.save()
	e.mu.Unlock()
	if eerr != nil {
		progress("EPSS no respondió: " + eerr.Error())
	}
	return serr
}

// Report resume que se hizo en un enriquecimiento.
type Report struct {
	Candidates int      `json:"candidates"`
	Kept       int      `json:"kept"`
	Dismissed  int      `json:"dismissed"`
	FromNVD    int      `json:"from_nvd"` // CVE que encontro Baqueano y la fuente no habia informado
	Notes      []string `json:"notes,omitempty"`
}

// Enrich evalua las vulnerabilidades de cada servicio. Consulta las fuentes que falten (si hay
// conexion), guarda lo aprendido y devuelve los servicios con sus CVE evaluadas.
func (e *Engine) Enrich(ctx context.Context, svcs []domain.Service, progress func(string)) ([]domain.Service, Report) {
	if progress == nil {
		progress = func(string) {}
	}
	var rep Report
	now := e.now()

	// 1) NVD: que CVE afectan a cada producto@version (descubre lo que la fuente no informo).
	type pv struct{ cpe, key string }
	var lookups []pv
	seen := map[string]bool{}
	for _, s := range svcs {
		t := targetOf(s)
		if t.version == "" {
			continue
		}
		for _, id := range t.products {
			for _, k := range cpeKeysFor(id) {
				key := k + "@" + t.version
				if seen[key] {
					continue
				}
				seen[key] = true
				vp := strings.SplitN(k, ":", 2)
				lookups = append(lookups, pv{cpe: "cpe:2.3:" + partOf(id) + ":" + vp[0] + ":" + vp[1] + ":" + t.version, key: key})
			}
		}
	}
	if e.Client != nil && e.UseNVD && len(lookups) > 0 {
		var todo []pv
		e.mu.Lock()
		for _, l := range lookups {
			if f, ok := e.db.NVDAt[l.key]; !ok || now.Sub(f.At) > ttl(e.NVDTTL, 7*24*time.Hour) {
				todo = append(todo, l)
			}
		}
		e.mu.Unlock()
		if len(todo) > 0 {
			progress(fmt.Sprintf("Consultando la NVD para %d productos y versiones…", len(todo)))
		}
		var nvdErr error
		for _, l := range todo {
			recs, err := e.Client.NVDByCPE(ctx, l.cpe)
			if err != nil {
				nvdErr = err
				if ctx.Err() != nil {
					break
				}
				continue
			}
			e.mu.Lock()
			var hits []string
			for _, r := range recs {
				if !r.Rejected {
					hits = append(hits, r.CVE)
				}
				e.db.AddRecord(r)
				e.db.RecordsAt[r.CVE] = fetched{At: now}
			}
			e.db.NVDHits[l.key] = hits
			e.db.NVDAt[l.key] = fetched{At: now}
			e.mu.Unlock()
		}
		e.mu.Lock()
		e.noteErr("nvd", nvdErr)
		e.mu.Unlock()
		if nvdErr != nil {
			rep.Notes = append(rep.Notes, "La NVD no respondió en algunas consultas ("+nvdErr.Error()+"); se usaron los datos guardados.")
		}
	}

	// 2) Candidatas por servicio.
	extra := make([][]string, len(svcs))
	all := map[string]bool{}
	e.mu.Lock()
	for i, s := range svcs {
		for _, v := range s.Vulns {
			all[strings.ToUpper(v.CVE)] = true
		}
		t := targetOf(s)
		for _, id := range t.products {
			for _, k := range cpeKeysFor(id) {
				for _, c := range e.db.NVDHits[k+"@"+t.version] {
					extra[i] = append(extra[i], c)
					all[c] = true
				}
			}
		}
	}
	var missing, epssTodo []string
	for id := range all {
		f, ok := e.db.RecordsAt[id]
		if !ok || now.Sub(f.At) > ttl(e.RecordTTL, 7*24*time.Hour) {
			missing = append(missing, id)
		}
		if x, ok := e.db.EPSS[id]; !ok || now.Sub(x.Fetched) > ttl(e.EPSSTTL, 24*time.Hour) {
			epssTodo = append(epssTodo, id)
		}
	}
	e.mu.Unlock()
	sort.Strings(missing)
	sort.Strings(epssTodo)

	// 3) Registros CVE oficiales que falten (en paralelo, con tope).
	if e.Client != nil && len(missing) > 0 {
		limit := e.MaxFetch
		if limit <= 0 {
			limit = 400
		}
		if len(missing) > limit {
			rep.Notes = append(rep.Notes, fmt.Sprintf("Se consultaron %d de %d registros CVE nuevos; el resto en el próximo escaneo.", limit, len(missing)))
			missing = missing[:limit]
		}
		progress(fmt.Sprintf("Leyendo %d registros CVE oficiales…", len(missing)))
		var wg sync.WaitGroup
		jobs := make(chan string)
		var firstErr error
		var errMu sync.Mutex
		for w := 0; w < 8; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for id := range jobs {
					r, err := e.Client.CVE(ctx, id)
					e.mu.Lock()
					switch {
					case err == nil:
						e.db.AddRecord(r)
						e.db.RecordsAt[id] = fetched{At: now}
					case errors.Is(err, ErrNotFound):
						e.db.RecordsAt[id] = fetched{At: now, Miss: true}
					default:
						errMu.Lock()
						if firstErr == nil {
							firstErr = err
						}
						errMu.Unlock()
					}
					e.mu.Unlock()
				}
			}()
		}
		for _, id := range missing {
			if ctx.Err() != nil {
				break
			}
			jobs <- id
		}
		close(jobs)
		wg.Wait()
		e.mu.Lock()
		e.noteErr("cve", firstErr)
		e.mu.Unlock()
		if firstErr != nil {
			rep.Notes = append(rep.Notes, "Algunos registros CVE no se pudieron leer ("+firstErr.Error()+").")
		}
	}

	// 4) EPSS.
	if e.Client != nil && len(epssTodo) > 0 {
		progress(fmt.Sprintf("Consultando EPSS de %d CVE…", len(epssTodo)))
		got, err := e.Client.EPSS(ctx, epssTodo, now)
		e.mu.Lock()
		for k, v := range got {
			e.db.EPSS[k] = v
		}
		e.noteErr("epss", err)
		e.mu.Unlock()
		if err != nil {
			rep.Notes = append(rep.Notes, "EPSS no respondió ("+err.Error()+"); se usaron los datos guardados.")
		}
	}

	// 5) Fin de soporte por producto.
	if e.Client != nil {
		slugs := map[string]bool{}
		for _, s := range svcs {
			for _, id := range targetOf(s).products {
				if sl := eolOf[id]; sl != "" {
					slugs[sl] = true
				}
			}
		}
		var eolErr error
		for sl := range slugs {
			e.mu.Lock()
			f, ok := e.db.EOLAt[sl]
			e.mu.Unlock()
			if ok && now.Sub(f.At) < ttl(e.EOLTTL, 7*24*time.Hour) {
				continue
			}
			rels, err := e.Client.EOL(ctx, sl)
			e.mu.Lock()
			switch {
			case err == nil:
				e.db.EOL[sl], e.db.EOLAt[sl] = rels, fetched{At: now}
			case errors.Is(err, ErrNotFound):
				e.db.EOLAt[sl] = fetched{At: now, Miss: true}
			default:
				eolErr = err
			}
			e.mu.Unlock()
		}
		e.mu.Lock()
		e.noteErr("eol", eolErr)
		e.mu.Unlock()
	}

	// 6) Evaluacion.
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]domain.Service, len(svcs))
	for i, s := range svcs {
		keep, dis := Assess(s, e.db, extra[i])
		for _, v := range keep {
			if v.Origin == "baqueano" {
				rep.FromNVD++
			}
		}
		rep.Candidates += len(keep) + len(dis)
		rep.Kept += len(keep)
		rep.Dismissed += len(dis)
		s.Vulns, s.Dismissed = keep, dis
		if eol := AssessEOL(s, e.db); eol != nil {
			s.EOL = eol
		}
		out[i] = s
	}
	if err := e.save(); err != nil {
		rep.Notes = append(rep.Notes, "No se pudo guardar la base de inteligencia: "+err.Error())
	}
	return out, rep
}

// partOf: los equipos de red y sistemas operativos usan "o" en el CPE; el resto, "a".
func partOf(id string) string {
	switch id {
	case "fortios", "pan-os", "ios-xe":
		return "o"
	}
	return "a"
}

// SourceStatus describe una fuente de inteligencia.
type SourceStatus struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Items       int        `json:"items"`
	Updated     *time.Time `json:"updated,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// Status es el estado de la base.
type Status struct {
	Online     bool           `json:"online"`
	NVDKey     bool           `json:"nvd_key"`
	KEVCatalog string         `json:"kev_catalog,omitempty"`
	Records    int            `json:"records"`
	Sources    []SourceStatus `json:"sources"`
}

// Status describe la base y cada fuente.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	at := func(k string) *time.Time {
		if t, ok := e.db.Updated[k]; ok {
			return &t
		}
		return nil
	}
	nvdN, eolN := 0, 0
	for _, r := range e.db.Records {
		if contains(r.Sources, "nvd") {
			nvdN++
		}
	}
	for _, rs := range e.db.EOL {
		eolN += len(rs)
	}
	cveN := 0
	for _, r := range e.db.Records {
		if contains(r.Sources, "cve") {
			cveN++
		}
	}
	kevAt := at("kev")
	if kevAt == nil && !e.db.KEVUpdated.IsZero() {
		t := e.db.KEVUpdated
		kevAt = &t
	}
	st := Status{Online: e.Client != nil, NVDKey: e.Client != nil && e.Client.NVDKey != "", KEVCatalog: e.db.KEVCatalog, Records: len(e.db.Records)}
	st.Sources = []SourceStatus{
		{ID: "kev", Name: "CISA KEV", Description: "Vulnerabilidades que se están explotando, con plazo de corrección y uso en ransomware.", Items: len(e.db.KEV), Updated: kevAt, Error: e.db.Errors["kev"]},
		{ID: "cve", Name: "Registro CVE + CISA Vulnrichment", Description: "Registro oficial de cada CVE: versiones afectadas según el fabricante, CVSS, CWE y SSVC de CISA.", Items: cveN, Updated: at("cve"), Error: e.db.Errors["cve"]},
		{ID: "nvd", Name: "NVD (NIST)", Description: "Rangos de versiones en formato CPE. Descubre CVE que la fuente de exposición no informó.", Items: nvdN, Updated: at("nvd"), Error: e.db.Errors["nvd"]},
		{ID: "epss", Name: "FIRST EPSS", Description: "Probabilidad de que una CVE se explote en los próximos 30 días. Se actualiza a diario.", Items: len(e.db.EPSS), Updated: at("epss"), Error: e.db.Errors["epss"]},
		{ID: "eol", Name: "endoflife.date", Description: "Ramas de cada producto y si siguen recibiendo parches de seguridad.", Items: eolN, Updated: at("eol"), Error: e.db.Errors["eol"]},
	}
	return st
}

// CVEInfo es lo que se sabe de una CVE, para mostrarla en detalle.
type CVEInfo struct {
	Record *Record    `json:"record,omitempty"`
	KEV    *KEVEntry  `json:"kev,omitempty"`
	EPSS   *EPSSEntry `json:"epss,omitempty"`
}

// Lookup devuelve lo que hay de una CVE; si falta y hay conexion, la consulta.
func (e *Engine) Lookup(ctx context.Context, id string) (CVEInfo, error) {
	id = strings.ToUpper(strings.TrimSpace(id))
	if _, _, ok := cvePath(id); !ok {
		return CVEInfo{}, fmt.Errorf("identificador de CVE inválido")
	}
	e.mu.Lock()
	_, have := e.db.Records[id]
	e.mu.Unlock()
	if !have && e.Client != nil {
		r, err := e.Client.CVE(ctx, id)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return CVEInfo{}, err
		}
		e.mu.Lock()
		if r != nil {
			e.db.AddRecord(r)
			e.db.RecordsAt[id] = fetched{At: e.now()}
			_ = e.save()
		}
		e.mu.Unlock()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	info := CVEInfo{Record: e.db.Records[id]}
	if k, ok := e.db.KEV[id]; ok {
		info.KEV = &k
	}
	if x, ok := e.db.EPSS[id]; ok {
		info.EPSS = &x
	}
	if info.Record == nil && info.KEV == nil && info.EPSS == nil {
		return info, ErrNotFound
	}
	return info, nil
}

// DB expone la base (para la demo y las pruebas). No usar en paralelo con Enrich.
func (e *Engine) DB() *DB { return e.db }
