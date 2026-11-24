import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";
import type { Finding } from "@/shared/api/types";
import { Card, Empty, SeverityBadge, Tag } from "@/shared/ui";
import { CATEGORIES, SEVERITIES, STATUSES, categoryLabel, critLabel, envLabel, severityLabel, statusLabel } from "@/shared/lib/labels";
import { api } from "@/shared/api";
import { useSetState } from "@/shared/api/queries";
import { fmtNum } from "@/shared/lib/format";
import { useOrgContext } from "@/features/orgs/context";
import { filterFindings } from "./filter";
import { ConfidenceBadge, PriorityBadge, VulnPanel } from "@/features/intel/VulnIntel";

export function FindingsPage() {
  const { snapshot } = useOrgContext();
  const [params, setParams] = useSearchParams();
  const sev = params.get("sev")?.split(",").filter(Boolean) ?? [];
  const cat = params.get("cat")?.split(",").filter(Boolean) ?? [];
  const st = params.get("st")?.split(",").filter(Boolean) ?? [];
  const q = params.get("q") ?? "";
  const selected = params.get("f");

  const all = snapshot?.findings ?? [];
  const { items, facets } = useMemo(() => filterFindings(all, { severity: sev, category: cat, q, status: st }), [all, sev.join(), cat.join(), st.join(), q]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!snapshot) return <Card><Empty title="Sin escaneos todavía" /></Card>;
  if (all.length === 0)
    return (
      <Card>
        <Empty title="No hay hallazgos">
          <p>Nada de lo que se ve desde internet coincide con los controles de Baqueano. Revisá igual la pestaña Servicios.</p>
        </Empty>
      </Card>
    );

  const set = (k: string, v: string | null) =>
    setParams((p) => {
      const n = new URLSearchParams(p);
      if (v) n.set(k, v);
      else n.delete(k);
      return n;
    }, { replace: true });
  const toggle = (k: string, cur: string[], v: string) => set(k, (cur.includes(v) ? cur.filter((x) => x !== v) : [...cur, v]).join(",") || null);
  const finding = all.find((f) => f.id === selected);

  return (
    <div className="inventory">
      <aside className="filters" aria-label="Filtros">
        <div className="facet">
          <h3>Severidad</h3>
          {SEVERITIES.filter((s) => s !== "info").map((s) => (
            <button key={s} type="button" className="facet__opt" aria-pressed={sev.includes(s)} disabled={!sev.includes(s) && !facets.severity[s]} onClick={() => toggle("sev", sev, s)}>
              <span className="check" aria-hidden="true" />
              {severityLabel[s]}
              <span className="n">{fmtNum(facets.severity[s] ?? 0)}</span>
            </button>
          ))}
        </div>
        <div className="facet">
          <h3>Estado</h3>
          {STATUSES.map((x) => (
            <button key={x} type="button" className="facet__opt" aria-pressed={st.includes(x)} disabled={!st.includes(x) && !facets.status[x]} onClick={() => toggle("st", st, x)}>
              <span className="check" aria-hidden="true" />
              {statusLabel[x]}
              <span className="n">{fmtNum(facets.status[x] ?? 0)}</span>
            </button>
          ))}
          {st.length === 0 && <p className="small muted" style={{ margin: "6px 0 0" }}>Sin filtro se muestran los abiertos y en curso.</p>}
        </div>
        <div className="facet">
          <h3>Tipo</h3>
          {CATEGORIES.map((c) => (
            <button key={c} type="button" className="facet__opt" aria-pressed={cat.includes(c)} disabled={!cat.includes(c) && !facets.category[c]} onClick={() => toggle("cat", cat, c)}>
              <span className="check" aria-hidden="true" />
              {categoryLabel[c]}
              <span className="n">{fmtNum(facets.category[c] ?? 0)}</span>
            </button>
          ))}
        </div>
      </aside>
      <Card className="card--flush">
        <div className="toolbar">
          <input className="input" type="search" placeholder="Buscar por IP, subdominio, CVE o texto…" defaultValue={q} onChange={(e) => set("q", e.target.value || null)} aria-label="Buscar" />
          {(sev.length > 0 || cat.length > 0 || st.length > 0 || q) && (
            <button type="button" className="btn btn--sm btn--ghost" onClick={() => setParams((p) => { const n = new URLSearchParams(p); ["sev", "cat", "q", "st"].forEach((k) => n.delete(k)); return n; })}>
              Limpiar filtros
            </button>
          )}
        </div>
        {items.length === 0 ? (
          <Empty title="Nada coincide con los filtros" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Severidad</th>
                  <th>Hallazgo</th>
                  <th>Activo</th>
                  <th>Tipo</th>
                </tr>
              </thead>
              <tbody>
                {items.map((f) => (
                  <tr key={f.id} className={`clickable ${f.id === selected ? "selected" : ""}`} onClick={() => set("f", f.id)}>
                    <td>
                      <SeverityBadge severity={f.severity} />
                      {f.base_severity && f.base_severity !== f.severity && (
                        <div className="cell-sub" title={(f.adjustments ?? []).join(" ")}>era {severityLabel[f.base_severity as keyof typeof severityLabel] ?? f.base_severity}</div>
                      )}
                    </td>
                    <td>
                      <div className="cell-main">
                        {f.title}
                        {f.state && f.state.status !== "abierto" && <span className={`status status--${f.state.status}`}>{statusLabel[f.state.status]}</span>}
                      </div>
                      {f.vuln ? (
                        <div className="row" style={{ gap: 6, marginTop: 4, flexWrap: "wrap" }}>
                          <PriorityBadge p={f.vuln.priority} />
                          <ConfidenceBadge c={f.vuln.confidence} />
                          {f.vuln.kev && <span className="flag flag--kev">KEV</span>}
                          {f.vuln.origin === "baqueano" && <span className="flag">encontrada por Baqueano</span>}
                        </div>
                      ) : (
                        <div className="cell-sub" style={{ maxWidth: 620 }}>{f.detail}</div>
                      )}
                    </td>
                    <td className="path">
                      {f.asset}
                      {(f.owner || f.environment) && <div className="cell-sub">{[f.environment && envLabel[f.environment], f.owner].filter(Boolean).join(" · ")}</div>}
                    </td>
                    <td>
                      <span className="cat">{categoryLabel[f.category] ?? f.category}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="pager">
          <span>
            {fmtNum(items.length)} de {fmtNum(all.length)} hallazgos
          </span>
        </div>
      </Card>
      {finding && <FindingDrawer f={finding} orgId={snapshot.org_id} onClose={() => set("f", null)} />}
    </div>
  );
}

function FindingDrawer({ f, orgId, onClose }: { f: Finding; orgId: string; onClose: () => void }) {
  const close = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    close.current?.focus();
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-labelledby="f-title">
        <div className="row">
          <SeverityBadge severity={f.severity} />
          <Tag>{categoryLabel[f.category] ?? f.category}</Tag>
          <span className="spacer" />
          <button ref={close} type="button" className="btn btn--sm btn--ghost" onClick={onClose} aria-label="Cerrar">
            ✕
          </button>
        </div>
        <h2 id="f-title" style={{ marginTop: 14 }}>
          {f.title}
        </h2>
        <p className="path">{f.asset}</p>
        <section>
          <h3>Qué pasa</h3>
          {f.vuln ? <VulnPanel v={f.vuln} /> : <p style={{ margin: 0, color: "var(--text-2)" }}>{f.detail}</p>}
        </section>
        <section>
          <h3>Qué hacer</h3>
          <div className="callout">{f.recommendation}</div>
        </section>
        {(f.environment || f.criticality || f.owner || (f.adjustments ?? []).length > 0) && (
          <section>
            <h3>Contexto de la organización</h3>
            <div className="row" style={{ gap: 6, flexWrap: "wrap", marginBottom: 8 }}>
              {f.environment && <span className="flag">{envLabel[f.environment]}</span>}
              {f.criticality && <span className="flag">{critLabel[f.criticality]}</span>}
              {f.owner && <span className="flag">Responsable: {f.owner}</span>}
            </div>
            {(f.adjustments ?? []).map((a, i) => (
              <p key={i} className="small" style={{ margin: "4px 0" }}>{a}</p>
            ))}
          </section>
        )}
        <StateSection f={f} orgId={orgId} />
        {f.evidence && f.evidence.length > 0 && (
          <section>
            <h3>Evidencia</h3>
            <div className="code">{f.evidence.join("\n")}</div>
          </section>
        )}
        <section>
          <h3>Detalle</h3>
          <dl className="kv">
            <dt>Control</dt>
            <dd className="mono">{f.rule}</dd>
            {f.cve && (
              <>
                <dt>CVE</dt>
                <dd className="mono">{f.cve}</dd>
              </>
            )}
            <dt>Identificador</dt>
            <dd className="mono">{f.id}</dd>
          </dl>
        </section>
      </aside>
    </>
  );
}

function StateSection({ f, orgId }: { f: Finding; orgId: string }) {
  const cur = f.state?.status ?? "abierto";
  const [status, setStatus] = useState(cur);
  const [note, setNote] = useState("");
  const [by, setBy] = useState("");
  const [until, setUntil] = useState("");
  const save = useSetState(orgId);
  useEffect(() => {
    setStatus(f.state?.status ?? "abierto");
    setNote("");
  }, [f.id]); // eslint-disable-line react-hooks/exhaustive-deps
  const needs = status === "aceptado" || status === "falso-positivo";
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate({ fid: f.id, c: { status: status as "abierto", note, by, until: status === "aceptado" ? until : "" } });
  };
  return (
    <section>
      <h3>Estado</h3>
      {f.state && (
        <div className="callout" style={{ marginBottom: 10 }}>
          <b>{statusLabel[f.state.status]}</b>
          {f.state.by && <> · {f.state.by}</>}
          {f.state.until && <> · vence {f.state.until.slice(0, 10)}</>}
          {f.state.note && <div className="small" style={{ marginTop: 4 }}>{f.state.note}</div>}
        </div>
      )}
      {api.mode === "api" ? (
        <form onSubmit={submit} className="stack" style={{ gap: 8 }}>
          <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
            {STATUSES.map((x) => (
              <button key={x} type="button" className={`btn btn--sm ${status === x ? "btn--primary" : "btn--ghost"}`} onClick={() => setStatus(x)}>
                {statusLabel[x]}
              </button>
            ))}
          </div>
          {status !== cur || status === "en-curso" ? (
            <>
              <input className="input" placeholder={needs ? "Motivo (obligatorio, queda en el historial)" : "Nota (opcional)"} value={note} onChange={(e) => setNote(e.target.value)} aria-label="Motivo" />
              {needs && <input className="input" placeholder="Quién toma la decisión" value={by} onChange={(e) => setBy(e.target.value)} aria-label="Responsable" />}
              {status === "aceptado" && (
                <label className="small">
                  Vence (hasta un año):{" "}
                  <input className="input" type="date" value={until} onChange={(e) => setUntil(e.target.value)} aria-label="Vencimiento" style={{ width: 180, display: "inline-block" }} />
                </label>
              )}
              <div>
                <button className="btn btn--sm btn--primary" type="submit" disabled={save.isPending}>
                  Guardar estado
                </button>
              </div>
            </>
          ) : null}
          {save.isError && <span className="small" style={{ color: "var(--sev-critica)" }}>{(save.error as Error).message}</span>}
        </form>
      ) : (
        !f.state && <p className="small muted" style={{ margin: 0 }}>Abierto. En la demo no se puede cambiar el estado.</p>
      )}
    </section>
  );
}
