import { Link, NavLink, Outlet, useParams, useSearchParams } from "react-router-dom";
import { api } from "@/shared/api";
import { useOrg, useSnapshot } from "@/shared/api/queries";
import { ErrorState, Loading, ScoreRing, SeverityBar } from "@/shared/ui";
import { fmtDateTime, fmtNum, plural } from "@/shared/lib/format";
import { ScanButton } from "./ScanButton";
import type { OrgContext } from "./context";

export function OrgLayout() {
  const { id = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const org = useOrg(id);
  const snapId = params.get("snap") ?? org.data?.latest?.id;
  const snap = useSnapshot(snapId);

  if (org.isLoading) return <Loading />;
  if (org.error || !org.data) return <ErrorState error={org.error} />;
  const o = org.data;
  const s = snap.data;
  const verified = o.domains.filter((d) => d.verified_at).length;
  const ctx: OrgContext = { org: o, snapshot: s, snapshotId: snapId };
  const q = params.toString() ? "?" + params.toString() : "";

  return (
    <>
      <div className="crumbs">
        <Link to="/">Vista general</Link> / {o.name}
      </div>
      <div className="page-head">
        <div className="row" style={{ gap: 22 }}>
          {s && <ScoreRing value={s.score} size={96} />}
          <div>
            <h1>{o.name}</h1>
            <div className="kv-inline" style={{ marginTop: 6 }}>
              <span>
                {o.attestation ? (
                  <>
                    alcance declarado por <b>{o.attestation.by}</b>
                  </>
                ) : (
                  "sin declaración de responsabilidad"
                )}
                {verified > 0 && (
                  <>
                    {" · "}
                    <b>{verified}</b> verificado{verified === 1 ? "" : "s"} en DNS
                  </>
                )}
              </span>
              {s && (
                <>
                  <span>
                    <b>{fmtNum(s.assets?.length ?? 0)}</b> activos
                  </span>
                  <span>
                    <b>{fmtNum(s.services?.length ?? 0)}</b> servicios
                  </span>
                  <span>escaneo del {fmtDateTime(s.started_at)}</span>
                </>
              )}
            </div>
          </div>
        </div>
        <div className="row" style={{ alignItems: "flex-start" }}>
          {o.snapshots.length > 1 && (
            <select
              className="input"
              aria-label="Escaneo"
              value={snapId}
              onChange={(e) =>
                setParams((p) => {
                  const n = new URLSearchParams(p);
                  n.set("snap", e.target.value);
                  return n;
                })
              }
            >
              {o.snapshots.map((m) => (
                <option key={m.id} value={m.id}>
                  {fmtDateTime(m.started_at)} · {m.score}/100
                </option>
              ))}
            </select>
          )}
          {snapId && api.exportUrl(snapId, "csv") && (
            <a className="btn" href={api.exportUrl(snapId, "csv")!} download>
              ↓ CSV
            </a>
          )}
          {api.mode === "api" && <ScanButton org={o} />}
        </div>
      </div>

      {!snapId ? (
        <div className="callout" style={{ marginBottom: 20 }}>
          {!o.attestation && verified === 0 ? (
            <>
              <b>Falta la autorización.</b> Aceptá la declaración de responsabilidad en la pestaña <Link to={`settings${q}`}>Alcance</Link>.
            </>
          ) : (
            <>
              <b>Listo para escanear.</b> {plural(o.domains.length, "dominio", "dominios")}
              {(o.networks ?? []).length > 0 ? ` y ${plural((o.networks ?? []).length, "red", "redes")}` : ""}: tocá «Escanear ahora».
            </>
          )}
        </div>
      ) : (
        s && (
          <div style={{ marginBottom: 18 }}>
            <SeverityBar counts={countBy(s.findings ?? [])} />
          </div>
        )
      )}

      <nav className="tabs" aria-label="Secciones">
        <NavLink to={`findings${q}`}>
          Hallazgos<span className="count">{fmtNum(s?.findings?.length ?? 0)}</span>
        </NavLink>
        <NavLink to={`assets${q}`}>
          Activos<span className="count">{fmtNum(s?.assets?.length ?? 0)}</span>
        </NavLink>
        <NavLink to={`services${q}`}>
          Servicios<span className="count">{fmtNum(s?.services?.length ?? 0)}</span>
        </NavLink>
        <NavLink to={`changes${q}`}>Cambios</NavLink>
        <NavLink to={`settings${q}`}>Alcance</NavLink>
      </nav>
      {snap.isLoading ? <Loading /> : <Outlet context={ctx} />}
    </>
  );
}

function countBy(fs: { severity: string }[]) {
  const m: Record<string, number> = {};
  for (const f of fs) m[f.severity] = (m[f.severity] ?? 0) + 1;
  return m;
}
