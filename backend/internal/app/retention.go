package app

import (
	"context"
	"errors"
	"time"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

// Prune borra los escaneos de mas de days dias, conservando siempre los keep mas recientes de cada
// organizacion (para que el historial y los cambios sigan teniendo contra que comparar).
func (s *Service) Prune(ctx context.Context, days, keep int) (int, error) {
	if days < 1 {
		return 0, errors.New("la retención mínima es de 1 día")
	}
	if keep < 1 {
		keep = 1
	}
	orgs, err := s.Repo.ListOrgs(ctx)
	if err != nil {
		return 0, err
	}
	limit := s.now().AddDate(0, 0, -days)
	n := 0
	for _, o := range orgs {
		metas, err := s.Repo.ListSnapshots(ctx, o.ID)
		if err != nil {
			return n, err
		}
		for i, m := range metas {
			if i < keep {
				continue
			}
			t, err := time.Parse(time.RFC3339, m.StartedAt)
			if err != nil || !t.Before(limit) {
				continue
			}
			if err := s.Repo.DeleteSnapshot(ctx, m.ID); err != nil {
				return n, err
			}
			n++
		}
		if n > 0 {
			_, _ = s.editOrg(ctx, o.ID, func(o *domain.Organization) error {
				s.audit(o, "retención", "se borraron escaneos de más de "+itoa(days)+" días")
				return nil
			})
		}
	}
	return n, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
