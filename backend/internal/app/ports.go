// Package app tiene los casos de uso de Baqueano. Lo usan la CLI y la API por igual.
package app

import (
	"context"
	"errors"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

// ErrNotFound lo devuelven los repositorios cuando no existe lo pedido.
var ErrNotFound = errors.New("no encontrado")

// Repository es el puerto de persistencia.
type Repository interface {
	SaveOrg(ctx context.Context, o domain.Organization) error
	GetOrg(ctx context.Context, id string) (domain.Organization, error)
	ListOrgs(ctx context.Context) ([]domain.Organization, error)
	DeleteOrg(ctx context.Context, id string) error

	SaveSnapshot(ctx context.Context, s domain.Snapshot) error
	GetSnapshot(ctx context.Context, id string) (domain.Snapshot, error)
	// ListSnapshots devuelve los resumenes de una organizacion (o de todas si orgID es ""), del mas nuevo al mas viejo.
	ListSnapshots(ctx context.Context, orgID string) ([]SnapshotMeta, error)
}

// SnapshotMeta es un escaneo sin el detalle.
type SnapshotMeta struct {
	ID         string         `json:"id"`
	OrgID      string         `json:"org_id"`
	OrgName    string         `json:"org_name"`
	StartedAt  string         `json:"started_at"`
	FinishedAt string         `json:"finished_at"`
	Score      int            `json:"score"`
	Assets     int            `json:"assets"`
	IPs        int            `json:"ips"`
	Services   int            `json:"services"`
	Findings   int            `json:"findings"`
	BySeverity map[string]int `json:"by_severity"`
}

// Meta resume un escaneo.
func Meta(s domain.Snapshot) SnapshotMeta {
	m := SnapshotMeta{ID: s.ID, OrgID: s.OrgID, OrgName: s.OrgName, StartedAt: s.StartedAt.Format("2006-01-02T15:04:05Z07:00"),
		FinishedAt: s.FinishedAt.Format("2006-01-02T15:04:05Z07:00"), Score: s.Score(), Assets: len(s.Assets), IPs: len(s.IPs()),
		Services: len(s.Services), Findings: len(s.Findings), BySeverity: map[string]int{}}
	for _, f := range s.Findings {
		m.BySeverity[string(f.Severity)]++
	}
	return m
}
