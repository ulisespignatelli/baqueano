package app

import (
	"context"
	"sort"
	"strings"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

// OrgSummary es una organizacion con el resumen de su ultimo escaneo y su evolucion.
type OrgSummary struct {
	domain.Organization
	Latest *SnapshotMeta  `json:"latest,omitempty"`
	Trend  []SnapshotMeta `json:"trend"` // del mas viejo al mas nuevo (hasta 20)
}

// Overview es la portada del panel.
type Overview struct {
	Orgs       []OrgSummary   `json:"orgs"`
	Score      int            `json:"score"` // promedio de los ultimos escaneos
	Assets     int            `json:"assets"`
	Services   int            `json:"services"`
	Findings   int            `json:"findings"`
	BySeverity map[string]int `json:"by_severity"`
}

// Overview arma la portada.
func (s *Service) Overview(ctx context.Context) (Overview, error) {
	orgs, err := s.Repo.ListOrgs(ctx)
	if err != nil {
		return Overview{}, err
	}
	metas, err := s.Repo.ListSnapshots(ctx, "")
	if err != nil {
		return Overview{}, err
	}
	byOrg := map[string][]SnapshotMeta{}
	for _, m := range metas { // del mas nuevo al mas viejo
		byOrg[m.OrgID] = append(byOrg[m.OrgID], m)
	}
	for _, org := range orgs {
		if hasPolicy(org) && len(byOrg[org.ID]) > 0 {
			if pm, err := s.SnapshotMetas(ctx, org.ID, 20); err == nil {
				byOrg[org.ID] = pm
			}
		}
	}
	o := Overview{Orgs: []OrgSummary{}, BySeverity: map[string]int{}, Score: 100}
	sum, n := 0, 0
	for _, org := range orgs {
		os := OrgSummary{Organization: org, Trend: []SnapshotMeta{}}
		list := byOrg[org.ID]
		if len(list) > 0 {
			l := list[0]
			os.Latest = &l
			sum += l.Score
			n++
			o.Assets += l.Assets
			o.Services += l.Services
			o.Findings += l.Findings
			for k, v := range l.BySeverity {
				o.BySeverity[k] += v
			}
		}
		for i := len(list) - 1; i >= 0 && len(os.Trend) < 20; i-- {
			os.Trend = append(os.Trend, list[i])
		}
		o.Orgs = append(o.Orgs, os)
	}
	if n > 0 {
		o.Score = sum / n
	}
	sort.SliceStable(o.Orgs, func(i, j int) bool {
		a, b := o.Orgs[i].Latest, o.Orgs[j].Latest
		if (a == nil) != (b == nil) {
			return a != nil
		}
		if a != nil && a.Score != b.Score {
			return a.Score < b.Score
		}
		return o.Orgs[i].Name < o.Orgs[j].Name
	})
	return o, nil
}

// Changes compara un escaneo con el anterior de la misma organizacion.
type Changes struct {
	PreviousID       string           `json:"previous_id,omitempty"`
	NewServices      []domain.Service `json:"new_services"`
	ClosedServices   []domain.Service `json:"closed_services"`
	NewFindings      []domain.Finding `json:"new_findings"`
	ResolvedFindings []domain.Finding `json:"resolved_findings"`
	SeverityChanges  []SeverityChange `json:"severity_changes"` // mismo hallazgo, otra severidad (p. ej. entro en KEV)
	NewAssets        []string         `json:"new_assets"`
	GoneAssets       []string         `json:"gone_assets"`
}

// SeverityChange es un hallazgo que subio o bajo de severidad entre dos escaneos.
type SeverityChange struct {
	Finding domain.Finding  `json:"finding"`
	Before  domain.Severity `json:"before"`
	Up      bool            `json:"up"`
}

// Changes calcula las diferencias con el escaneo anterior.
func (s *Service) Changes(ctx context.Context, snapID string) (Changes, error) {
	cur, err := s.Snapshot(ctx, snapID)
	if err != nil {
		return Changes{}, err
	}
	c := Changes{NewServices: []domain.Service{}, ClosedServices: []domain.Service{}, NewFindings: []domain.Finding{},
		ResolvedFindings: []domain.Finding{}, SeverityChanges: []SeverityChange{}, NewAssets: []string{}, GoneAssets: []string{}}
	metas, err := s.Repo.ListSnapshots(ctx, cur.OrgID)
	if err != nil {
		return c, err
	}
	var prevID string
	for i, m := range metas {
		if m.ID == cur.ID && i+1 < len(metas) {
			prevID = metas[i+1].ID
		}
	}
	if prevID == "" {
		return c, nil
	}
	prev, err := s.Snapshot(ctx, prevID)
	if err != nil {
		return c, err
	}
	c.PreviousID = prevID
	return diff(prev, cur, c), nil
}

func diff(prev, cur domain.Snapshot, c Changes) Changes {
	ps, cs := map[string]domain.Service{}, map[string]domain.Service{}
	for _, x := range prev.Services {
		ps[x.Key()] = x
	}
	for _, x := range cur.Services {
		cs[x.Key()] = x
	}
	for k, x := range cs {
		if _, ok := ps[k]; !ok {
			c.NewServices = append(c.NewServices, x)
		}
	}
	for k, x := range ps {
		if _, ok := cs[k]; !ok {
			c.ClosedServices = append(c.ClosedServices, x)
		}
	}
	pf, cf := map[string]domain.Finding{}, map[string]domain.Finding{}
	for _, f := range prev.Findings {
		pf[f.ID] = f
	}
	for _, f := range cur.Findings {
		cf[f.ID] = f
	}
	for id, f := range cf {
		p, ok := pf[id]
		switch {
		case !ok:
			c.NewFindings = append(c.NewFindings, f)
		case p.Severity != f.Severity:
			c.SeverityChanges = append(c.SeverityChanges, SeverityChange{Finding: f, Before: p.Severity, Up: f.Severity.Rank() > p.Severity.Rank()})
		}
	}
	sort.Slice(c.SeverityChanges, func(i, j int) bool {
		a, b := c.SeverityChanges[i], c.SeverityChanges[j]
		if a.Up != b.Up {
			return a.Up
		}
		return a.Finding.Severity.Rank() > b.Finding.Severity.Rank()
	})
	for id, f := range pf {
		if _, ok := cf[id]; !ok {
			c.ResolvedFindings = append(c.ResolvedFindings, f)
		}
	}
	pa, ca := map[string]bool{}, map[string]bool{}
	for _, a := range prev.Assets {
		pa[assetName(a)] = true
	}
	for _, a := range cur.Assets {
		ca[assetName(a)] = true
	}
	for a := range ca {
		if !pa[a] {
			c.NewAssets = append(c.NewAssets, a)
		}
	}
	for a := range pa {
		if !ca[a] {
			c.GoneAssets = append(c.GoneAssets, a)
		}
	}
	sortSvc := func(v []domain.Service) {
		sort.Slice(v, func(i, j int) bool { return v[i].Key() < v[j].Key() })
	}
	sortF := func(v []domain.Finding) {
		sort.Slice(v, func(i, j int) bool {
			if v[i].Severity != v[j].Severity {
				return v[i].Severity.Rank() > v[j].Severity.Rank()
			}
			return v[i].ID < v[j].ID
		})
	}
	sortSvc(c.NewServices)
	sortSvc(c.ClosedServices)
	sortF(c.NewFindings)
	sortF(c.ResolvedFindings)
	sort.Strings(c.NewAssets)
	sort.Strings(c.GoneAssets)
	return c
}

func assetName(a domain.Asset) string {
	if a.Hostname != "" {
		return a.Hostname
	}
	return strings.Join(a.IPs, ",")
}
