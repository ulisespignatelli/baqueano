import { useState, type FormEvent } from "react";
import { api } from "@/shared/api";
import { useDeleteContext, useDeleteRule, useSaveContext, useSaveRule } from "@/shared/api/queries";
import type { AssetContext, Severity, SeverityRule } from "@/shared/api/types";
import { Card, SeverityBadge } from "@/shared/ui";
import { critLabel, envLabel, severityLabel } from "@/shared/lib/labels";
import { useOrgContext } from "@/features/orgs/context";

const Err = ({ e }: { e: unknown }) => (e ? <p className="small" style={{ color: "var(--sev-critica)", margin: "6px 0 0" }}>{(e as Error).message}</p> : null);

export function PolicyPage() {
  const { org } = useOrgContext();
  const demo = api.mode === "demo";
  const saveCtx = useSaveContext(org.id);
  const delCtx = useDeleteContext(org.id);
  const saveRule = useSaveRule(org.id);
  const delRule = useDeleteRule(org.id);
  const [c, setC] = useState<AssetContext>({ match: "", environment: "produccion", criticality: "normal", owner: "" });
  const [r, setR] = useState<SeverityRule>({ rule: "", severity: "alta", note: "", match: "" });
  const contexts = org.contexts ?? [];
  const rules = org.rules ?? [];
  const addCtx = (e: FormEvent) => {
    e.preventDefault();
    saveCtx.mutate({ ...c, criticality: c.criticality === "normal" ? "" : c.criticality }, { onSuccess: () => setC({ ...c, match: "", owner: "" }) });
  };
  const addRule = (e: FormEvent) => {
    e.preventDefault();
    saveRule.mutate(r, { onSuccess: () => setR({ rule: "", severity: "alta", note: "", match: "" }) });
  };
  return (
    <div className="stack">
      <div className="callout">
        Baqueano no sabe qué es producción y qué es una prueba en tu organización: acá se lo decís. El contexto ajusta la severidad (desarrollo y
        pruebas bajan un nivel, criticidad alta sube uno; lo que está en KEV no baja nunca) y las reglas la fijan. Se aplica al instante, también a
        los escaneos anteriores, y la severidad original queda a la vista en cada hallazgo.
      </div>
      <Card title={`Contexto de los activos · ${contexts.length}`}>
        {contexts.length === 0 ? (
          <p className="muted" style={{ marginTop: 0 }}>Sin contexto cargado: todos los activos cuentan igual.</p>
        ) : (
          <ul className="list-plain">
            {contexts.map((x) => (
              <li key={x.id}>
                <span className="mono" style={{ minWidth: 220 }}>{x.match}</span>
                <span className="row" style={{ gap: 6, flexWrap: "wrap", flex: 1 }}>
                  {x.environment && <span className="flag">{envLabel[x.environment]}</span>}
                  {x.criticality && <span className="flag">{critLabel[x.criticality]}</span>}
                  {x.owner && <span className="small">Responsable: <b>{x.owner}</b></span>}
                  {x.note && <span className="small muted">{x.note}</span>}
                </span>
                {!demo && (
                  <button type="button" className="btn btn--sm btn--ghost" onClick={() => x.id && delCtx.mutate(x.id)}>
                    Quitar
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
        {!demo && (
          <form onSubmit={addCtx} style={{ marginTop: 16 }}>
            <div className="form-grid">
              <input className="input" placeholder="*.dev.miempresa.com, IP o red" value={c.match} onChange={(e) => setC({ ...c, match: e.target.value })} aria-label="Activos" />
              <select className="input" value={c.environment} onChange={(e) => setC({ ...c, environment: e.target.value as AssetContext["environment"] })} aria-label="Ambiente">
                {Object.entries(envLabel).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
              <select className="input" value={c.criticality} onChange={(e) => setC({ ...c, criticality: e.target.value as AssetContext["criticality"] })} aria-label="Criticidad">
                {Object.entries(critLabel).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
              <input className="input" placeholder="Responsable (opcional)" value={c.owner} onChange={(e) => setC({ ...c, owner: e.target.value })} aria-label="Responsable" />
              <button className="btn" type="submit" disabled={!c.match.trim() || saveCtx.isPending}>Agregar contexto</button>
            </div>
            <Err e={saveCtx.error} />
          </form>
        )}
      </Card>
      <Card title={`Reglas de severidad · ${rules.length}`}>
        {rules.length === 0 ? (
          <p className="muted" style={{ marginTop: 0 }}>Sin reglas: se usan las severidades de Baqueano.</p>
        ) : (
          <ul className="list-plain">
            {rules.map((x) => (
              <li key={x.id}>
                <span className="mono" style={{ minWidth: 120 }}>{x.rule}</span>
                <SeverityBadge severity={x.severity} />
                <span className="small" style={{ flex: 1 }}>
                  {x.note}
                  {(x.match || x.environment) && <span className="muted"> · solo en {[x.match, x.environment && envLabel[x.environment]].filter(Boolean).join(", ")}</span>}
                </span>
                {!demo && (
                  <button type="button" className="btn btn--sm btn--ghost" onClick={() => x.id && delRule.mutate(x.id)}>
                    Quitar
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
        {!demo && (
          <form onSubmit={addRule} style={{ marginTop: 16 }}>
            <div className="form-grid">
              <input className="input" placeholder="Control: PX-RDP, PX-* o *" value={r.rule} onChange={(e) => setR({ ...r, rule: e.target.value })} aria-label="Control" />
              <select className="input" value={r.severity} onChange={(e) => setR({ ...r, severity: e.target.value as Severity })} aria-label="Severidad">
                {(["critica", "alta", "media", "baja", "info"] as Severity[]).map((k) => <option key={k} value={k}>{severityLabel[k]}</option>)}
              </select>
              <input className="input" placeholder="Solo en (opcional): activo o red" value={r.match} onChange={(e) => setR({ ...r, match: e.target.value })} aria-label="Activos" />
              <input className="input" placeholder="Motivo (queda en el historial)" value={r.note} onChange={(e) => setR({ ...r, note: e.target.value })} aria-label="Motivo" />
              <button className="btn" type="submit" disabled={!r.rule.trim() || r.note.trim().length < 5 || saveRule.isPending}>Agregar regla</button>
            </div>
            <Err e={saveRule.error} />
          </form>
        )}
      </Card>
    </div>
  );
}
