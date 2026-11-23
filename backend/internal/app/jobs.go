package app

import (
	"context"
	"errors"
	"sync"
	"time"
)

// JobView es el estado visible de un escaneo en curso.
type JobView struct {
	ID         string    `json:"id"`
	OrgID      string    `json:"org_id"`
	Status     string    `json:"status"` // running | done | error
	Message    string    `json:"message"`
	SnapshotID string    `json:"snapshot_id,omitempty"`
	Error      string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"started_at"`
}

// Job es un escaneo en curso. Un escaneo con Shodan puede tardar minutos (≈1 consulta por segundo),
// asi que la API lo lanza en segundo plano y el panel consulta el avance.
type Job struct {
	JobView
	mu sync.Mutex
}

func (j *Job) set(f func(*JobView)) {
	j.mu.Lock()
	defer j.mu.Unlock()
	f(&j.JobView)
}

// View devuelve una copia segura para leer.
func (j *Job) View() JobView {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.JobView
}

// ErrBusy: ya hay un escaneo en curso para esa organizacion.
var ErrBusy = errors.New("ya hay un escaneo en curso para esta organización")

// StartScan lanza un escaneo en segundo plano.
func (s *Service) StartScan(orgID string) (*Job, error) {
	if _, err := s.Repo.GetOrg(context.Background(), orgID); err != nil {
		return nil, err
	}
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	if s.jobs == nil {
		s.jobs = map[string]*Job{}
	}
	for _, j := range s.jobs {
		if j.OrgID == orgID && j.View().Status == "running" {
			return nil, ErrBusy
		}
	}
	j := &Job{JobView: JobView{ID: newID(), OrgID: orgID, Status: "running", Message: "Iniciando…", StartedAt: s.now()}}
	s.jobs[j.ID] = j
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
		defer cancel()
		snap, err := s.Scan(ctx, orgID, func(m string) { j.set(func(v *JobView) { v.Message = m }) })
		j.set(func(j *JobView) {
			if err != nil {
				j.Status, j.Error = "error", err.Error()
				return
			}
			j.Status, j.SnapshotID, j.Message = "done", snap.ID, "Listo."
		})
	}()
	return j, nil
}

// GetJob devuelve un trabajo.
func (s *Service) GetJob(id string) (JobView, error) {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return JobView{}, ErrNotFound
	}
	return j.View(), nil
}
