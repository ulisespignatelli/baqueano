package httpapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/ulisespignatelli/baqueano/backend/internal/app"
	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
	"github.com/ulisespignatelli/baqueano/backend/internal/intel"
)

// WriteSnapshot guarda las respuestas de la API como JSON estaticos para el modo demo del panel:
//
//	health.json  overview.json  orgs/{id}.json  snapshots/{id}.json  snapshots/{id}/changes.json
//	intel.json  intel/cves/{id}.json (si hay motor de inteligencia)
func WriteSnapshot(ctx context.Context, svc *app.Service, dir string, eng *intel.Engine) error {
	write := func(rel string, v any) error {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		b, err := json.Marshal(redact(v))
		if err != nil {
			return err
		}
		return os.WriteFile(p, b, 0o644)
	}
	if err := write("health.json", map[string]any{"status": "ok", "version": "demo", "exposure_source": "demo", "auth_required": false, "read_only": true, "intel": eng != nil}); err != nil {
		return err
	}
	o, err := svc.Overview(ctx)
	if err != nil {
		return err
	}
	if err := write("overview.json", o); err != nil {
		return err
	}
	cves := map[string]bool{}
	for _, org := range o.Orgs {
		snaps, err := svc.SnapshotMetas(ctx, org.ID, 0)
		if err != nil {
			return err
		}
		if err := write("orgs/"+org.ID+".json", orgDetail{OrgSummary: org, Snapshots: snaps}); err != nil {
			return err
		}
		for _, m := range snaps {
			sn, err := svc.Snapshot(ctx, m.ID)
			if err != nil {
				return err
			}
			for _, sv := range sn.Services {
				for _, v := range append(append([]domain.Vuln(nil), sv.Vulns...), sv.Dismissed...) {
					cves[v.CVE] = true
				}
			}
			if err := write("snapshots/"+m.ID+".json", SnapshotView{Snapshot: sn, Score: sn.Score()}); err != nil {
				return err
			}
			c, err := svc.Changes(ctx, m.ID)
			if err != nil {
				return err
			}
			if err := write("snapshots/"+m.ID+"/changes.json", c); err != nil {
				return err
			}
		}
	}
	if eng == nil {
		return nil
	}
	if err := write("intel.json", eng.Status()); err != nil {
		return err
	}
	for id := range cves {
		if info, err := eng.Lookup(ctx, id); err == nil {
			if err := write("intel/cves/"+id+".json", info); err != nil {
				return err
			}
		}
	}
	return nil
}
