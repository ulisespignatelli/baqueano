// Package store guarda organizaciones y escaneos como archivos JSON (escritura atomica), sin
// dependencias ni servidor de base de datos. Cumple app.Repository.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"github.com/ulisespignatelli/baqueano/backend/internal/app"
	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

var validID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// FileStore es el repositorio en disco.
type FileStore struct {
	dir   string
	mu    sync.RWMutex
	orgs  map[string]domain.Organization
	metas map[string]app.SnapshotMeta
}

// Open abre (o crea) el repositorio.
func Open(dir string) (*FileStore, error) {
	for _, sub := range []string{"orgs", "snapshots"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, err
		}
	}
	s := &FileStore{dir: dir, orgs: map[string]domain.Organization{}, metas: map[string]app.SnapshotMeta{}}
	if err := s.load("orgs", func(b []byte) error {
		var o domain.Organization
		if err := json.Unmarshal(b, &o); err != nil {
			return err
		}
		s.orgs[o.ID] = o
		return nil
	}); err != nil {
		return nil, err
	}
	if err := s.load("snapshots", func(b []byte) error {
		var sn domain.Snapshot
		if err := json.Unmarshal(b, &sn); err != nil {
			return err
		}
		s.metas[sn.ID] = app.Meta(sn)
		return nil
	}); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileStore) load(sub string, f func([]byte) error) error {
	entries, err := os.ReadDir(filepath.Join(s.dir, sub))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.dir, sub, e.Name()))
		if err != nil {
			return err
		}
		if err := f(b); err != nil {
			return fmt.Errorf("%s/%s dañado: %w", sub, e.Name(), err)
		}
	}
	return nil
}

func (s *FileStore) write(sub, id string, v any) error {
	if !validID.MatchString(id) {
		return fmt.Errorf("ID inválido %q", id)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Join(s.dir, sub), ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(s.dir, sub, id+".json"))
}

// SaveOrg guarda una organizacion.
func (s *FileStore) SaveOrg(_ context.Context, o domain.Organization) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.write("orgs", o.ID, o); err != nil {
		return err
	}
	s.orgs[o.ID] = o
	return nil
}

// GetOrg lee una organizacion.
func (s *FileStore) GetOrg(_ context.Context, id string) (domain.Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.orgs[id]
	if !ok {
		return o, app.ErrNotFound
	}
	return o, nil
}

// ListOrgs lista las organizaciones por nombre.
func (s *FileStore) ListOrgs(_ context.Context) ([]domain.Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.Organization, 0, len(s.orgs))
	for _, o := range s.orgs {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// DeleteOrg borra una organizacion y sus escaneos.
func (s *FileStore) DeleteOrg(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orgs[id]; !ok || !validID.MatchString(id) {
		return app.ErrNotFound
	}
	for sid, m := range s.metas {
		if m.OrgID == id {
			if err := os.Remove(filepath.Join(s.dir, "snapshots", sid+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			delete(s.metas, sid)
		}
	}
	if err := os.Remove(filepath.Join(s.dir, "orgs", id+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	delete(s.orgs, id)
	return nil
}

// SaveSnapshot guarda un escaneo.
func (s *FileStore) SaveSnapshot(_ context.Context, sn domain.Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.write("snapshots", sn.ID, sn); err != nil {
		return err
	}
	s.metas[sn.ID] = app.Meta(sn)
	return nil
}

// GetSnapshot lee un escaneo completo.
func (s *FileStore) GetSnapshot(_ context.Context, id string) (domain.Snapshot, error) {
	var sn domain.Snapshot
	if !validID.MatchString(id) {
		return sn, app.ErrNotFound
	}
	s.mu.RLock()
	_, ok := s.metas[id]
	s.mu.RUnlock()
	if !ok {
		return sn, app.ErrNotFound
	}
	b, err := os.ReadFile(filepath.Join(s.dir, "snapshots", id+".json"))
	if err != nil {
		return sn, err
	}
	return sn, json.Unmarshal(b, &sn)
}

// ListSnapshots lista resumenes, del mas nuevo al mas viejo.
func (s *FileStore) ListSnapshots(_ context.Context, orgID string) ([]app.SnapshotMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []app.SnapshotMeta{}
	for _, m := range s.metas {
		if orgID == "" || m.OrgID == orgID {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].StartedAt != out[j].StartedAt {
			return out[i].StartedAt > out[j].StartedAt
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}
