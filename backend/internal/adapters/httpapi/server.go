// Package httpapi expone los casos de uso por HTTP (contrato en api/openapi.yaml) y sirve el panel.
package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ulisespignatelli/baqueano/backend/internal/app"
	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

// Config del servidor.
type Config struct {
	Token    string // exigido en operaciones que modifican datos si no esta vacio
	Loopback bool   // valida el encabezado Host (defensa contra DNS rebinding)
	Version  string
	Source   string // fuente de exposicion: shodan | internetdb | none
	Logger   *slog.Logger
}

// Server es el handler HTTP.
type Server struct {
	svc *app.Service
	cfg Config
	mux *http.ServeMux
}

// New arma el servidor.
func New(svc *app.Service, cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	s := &Server{svc: svc, cfg: cfg, mux: http.NewServeMux()}
	m := s.mux
	m.HandleFunc("GET /api/v1/health", s.health)
	m.HandleFunc("GET /api/v1/overview", s.overview)
	m.HandleFunc("GET /api/v1/orgs", s.listOrgs)
	m.HandleFunc("POST /api/v1/orgs", s.mutating(s.createOrg))
	m.HandleFunc("GET /api/v1/orgs/{id}", s.getOrg)
	m.HandleFunc("DELETE /api/v1/orgs/{id}", s.mutating(s.deleteOrg))
	m.HandleFunc("POST /api/v1/orgs/{id}/domains", s.mutating(s.addDomain))
	m.HandleFunc("POST /api/v1/orgs/{id}/networks", s.mutating(s.addNetwork))
	m.HandleFunc("POST /api/v1/orgs/{id}/attestation", s.mutating(s.attest))
	m.HandleFunc("POST /api/v1/orgs/{id}/verify", s.mutating(s.verify))
	m.HandleFunc("POST /api/v1/orgs/{id}/scans", s.mutating(s.startScan))
	m.HandleFunc("GET /api/v1/jobs/{id}", s.getJob)
	m.HandleFunc("GET /api/v1/snapshots/{id}", s.getSnapshot)
	m.HandleFunc("GET /api/v1/snapshots/{id}/changes", s.changes)
	m.HandleFunc("GET /api/v1/snapshots/{id}/export", s.export)
	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { writeErr(w, 404, "ruta inexistente") })
	m.Handle("/", uiHandler())
	return s
}

// ServeHTTP aplica encabezados de seguridad, validacion de Host, registro y recuperacion.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "+
		"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if s.cfg.Loopback && !loopbackHost(r.Host) {
		writeErr(w, http.StatusMisdirectedRequest, "host no permitido")
		return
	}
	rec := &statusRecorder{ResponseWriter: w, status: 200}
	defer func() {
		if v := recover(); v != nil {
			s.cfg.Logger.Error("pánico", "error", v, "path", r.URL.Path)
			writeErr(rec, 500, "error interno")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/api/v1/jobs/") {
			s.cfg.Logger.Info("http", "method", r.Method, "path", r.URL.Path, "status", rec.status, "ms", time.Since(start).Milliseconds())
		}
	}()
	s.mux.ServeHTTP(rec, r)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) { r.status = code; r.ResponseWriter.WriteHeader(code) }

func loopbackHost(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) mutating(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Token != "" && r.Header.Get("Authorization") != "Bearer "+s.cfg.Token {
			writeErr(w, http.StatusUnauthorized, "token inválido o ausente")
			return
		}
		if r.Header.Get("X-Requested-With") != "baqueano" {
			writeErr(w, http.StatusForbidden, "falta el encabezado X-Requested-With: baqueano")
			return
		}
		next(w, r)
	}
}

// ---------------------------------------------------------------- handlers

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"status": "ok", "version": s.cfg.Version, "exposure_source": s.cfg.Source,
		"auth_required": s.cfg.Token != "", "read_only": false})
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	o, err := s.svc.Overview(r.Context())
	if s.fail(w, err) {
		return
	}
	writeJSON(w, 200, o)
}

func (s *Server) listOrgs(w http.ResponseWriter, r *http.Request) {
	o, err := s.svc.Overview(r.Context())
	if s.fail(w, err) {
		return
	}
	writeJSON(w, 200, o.Orgs)
}

// SnapshotView es un escaneo con su puntaje calculado.
type SnapshotView struct {
	domain.Snapshot
	Score int `json:"score"`
}

type orgDetail struct {
	app.OrgSummary
	Snapshots []app.SnapshotMeta `json:"snapshots"`
}

func (s *Server) getOrg(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	o, err := s.svc.Overview(r.Context())
	if s.fail(w, err) {
		return
	}
	for _, os := range o.Orgs {
		if os.ID == id {
			snaps, err := s.svc.Repo.ListSnapshots(r.Context(), id)
			if s.fail(w, err) {
				return
			}
			writeJSON(w, 200, orgDetail{OrgSummary: os, Snapshots: snaps})
			return
		}
	}
	writeErr(w, 404, "no encontrado")
}

func (s *Server) createOrg(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string   `json:"name"`
		Domains     []string `json:"domains"`
		Networks    []string `json:"networks"`
		Attestation *struct {
			By       string `json:"by"`
			Accepted bool   `json:"accepted"`
		} `json:"attestation"`
	}
	if !decode(w, r, &req) {
		return
	}
	in := app.NewOrg{Name: req.Name, Domains: req.Domains, Networks: req.Networks}
	if a := req.Attestation; a != nil {
		if !a.Accepted {
			writeErr(w, 400, "hay que aceptar la declaración de responsabilidad")
			return
		}
		in.DeclaredBy = a.By
	}
	o, err := s.svc.CreateOrg(r.Context(), in)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 201, o)
}

func (s *Server) deleteOrg(w http.ResponseWriter, r *http.Request) {
	if s.fail(w, s.svc.Repo.DeleteOrg(r.Context(), r.PathValue("id"))) {
		return
	}
	w.WriteHeader(204)
}

func (s *Server) addDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if !decode(w, r, &req) {
		return
	}
	o, err := s.svc.AddDomain(r.Context(), r.PathValue("id"), req.Domain)
	if errors.Is(err, app.ErrNotFound) {
		writeErr(w, 404, "no encontrado")
		return
	}
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, o)
}

func (s *Server) addNetwork(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Network string `json:"network"`
	}
	if !decode(w, r, &req) {
		return
	}
	o, err := s.svc.AddNetwork(r.Context(), r.PathValue("id"), req.Network)
	s.orgResult(w, o, err)
}

func (s *Server) attest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		By       string `json:"by"`
		Accepted bool   `json:"accepted"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !req.Accepted {
		writeErr(w, 400, "hay que aceptar la declaración de responsabilidad")
		return
	}
	o, err := s.svc.Attest(r.Context(), r.PathValue("id"), req.By)
	s.orgResult(w, o, err)
}

func (s *Server) orgResult(w http.ResponseWriter, o domain.Organization, err error) {
	if errors.Is(err, app.ErrNotFound) {
		writeErr(w, 404, "no encontrado")
		return
	}
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, o)
}

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	o, err := s.svc.VerifyDomains(r.Context(), r.PathValue("id"))
	if s.fail(w, err) {
		return
	}
	writeJSON(w, 200, o)
}

func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
	j, err := s.svc.StartScan(r.PathValue("id"))
	if errors.Is(err, app.ErrBusy) {
		writeErr(w, 409, err.Error())
		return
	}
	if s.fail(w, err) {
		return
	}
	writeJSON(w, 202, j.View())
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request) {
	j, err := s.svc.GetJob(r.PathValue("id"))
	if s.fail(w, err) {
		return
	}
	writeJSON(w, 200, j)
}

func (s *Server) getSnapshot(w http.ResponseWriter, r *http.Request) {
	sn, err := s.svc.Repo.GetSnapshot(r.Context(), r.PathValue("id"))
	if s.fail(w, err) {
		return
	}
	writeJSON(w, 200, SnapshotView{Snapshot: sn, Score: sn.Score()})
}

func (s *Server) changes(w http.ResponseWriter, r *http.Request) {
	c, err := s.svc.Changes(r.Context(), r.PathValue("id"))
	if s.fail(w, err) {
		return
	}
	writeJSON(w, 200, c)
}

func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	sn, err := s.svc.Repo.GetSnapshot(r.Context(), r.PathValue("id"))
	if s.fail(w, err) {
		return
	}
	format := r.URL.Query().Get("format")
	name := fmt.Sprintf("baqueano-%s-%s", safe(sn.OrgName), sn.StartedAt.Format("20060102"))
	switch format {
	case "json":
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.json"`)
		writeJSON(w, 200, sn)
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
		writeFindingsCSV(w, sn)
	default:
		writeErr(w, 400, "format debe ser json o csv")
	}
}

// ---------------------------------------------------------------- utilidades

func (s *Server) fail(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, app.ErrNotFound) {
		writeErr(w, 404, "no encontrado")
		return true
	}
	s.cfg.Logger.Error("api", "error", err)
	writeErr(w, 500, "error interno")
	return true
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeErr(w, http.StatusUnsupportedMediaType, "se espera application/json")
		return false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(v); err != nil {
		writeErr(w, 400, "JSON inválido")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func safe(s string) string {
	b := []rune(strings.ToLower(s))
	for i, r := range b {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			b[i] = '-'
		}
	}
	return string(b)
}
