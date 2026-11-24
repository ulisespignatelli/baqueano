import { Link } from "react-router-dom";
import type { Confidence, Range, Vuln } from "@/shared/api/types";
import { confidenceHelp, confidenceLabel, dataSourceLabel, originLabel, priorityLabel, ssvcLabel } from "./labels";

export function PriorityBadge({ p }: { p?: string }) {
  if (!p) return null;
  return (
    <span className={`prio prio--${p}`} title={priorityLabel[p]}>
      {p} · {priorityLabel[p]}
    </span>
  );
}

export function ConfidenceBadge({ c }: { c?: Confidence }) {
  if (!c) return null;
  return (
    <span className={`conf conf--${c}`} title={confidenceHelp[c]}>
      {confidenceLabel[c]}
    </span>
  );
}

const pct = (x: number) => `${(x * 100).toFixed(x < 0.01 ? 2 : 0)} %`;

/** Todo lo que el motor sabe de una CVE en un servicio, para el panel de detalle. */
export function VulnPanel({ v }: { v: Vuln }) {
  return (
    <div className="stack" style={{ gap: 14 }}>
      <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
        <PriorityBadge p={v.priority} />
        <ConfidenceBadge c={v.confidence} />
        {v.kev && <span className="flag flag--kev">KEV · explotada</span>}
        {v.ransomware && <span className="flag flag--kev">ransomware</span>}
        {v.origin === "baqueano" && <span className="flag">encontrada por Baqueano</span>}
      </div>
      {v.summary && <p style={{ margin: 0, color: "var(--text-2)" }}>{v.summary}</p>}
      {v.priority_reason && (
        <div>
          <h4>Por qué esta prioridad</h4>
          <p className="small" style={{ margin: 0 }}>{v.priority_reason}.</p>
        </div>
      )}
      {v.reason && (
        <div>
          <h4>¿Afecta a esta versión?</h4>
          <p className="small" style={{ margin: 0 }}>{v.reason}</p>
        </div>
      )}
      <dl className="kv">
        {v.fixed_in && (
          <>
            <dt>Corregida en</dt>
            <dd className="mono">{v.fixed_in}</dd>
          </>
        )}
        {(v.cvss ?? 0) > 0 && (
          <>
            <dt>CVSS</dt>
            <dd className="mono">{v.cvss?.toFixed(1)}</dd>
          </>
        )}
        {(v.epss ?? 0) > 0 && (
          <>
            <dt>EPSS</dt>
            <dd>
              <span className="mono">{pct(v.epss ?? 0)}</span>
              <span className="muted small"> de probabilidad de explotación en 30 días{v.epss_percentile ? ` · percentil ${Math.round(v.epss_percentile * 100)}` : ""}</span>
            </dd>
          </>
        )}
        {v.ssvc && (
          <>
            <dt>SSVC (CISA)</dt>
            <dd>
              {ssvcLabel.exploitation[v.ssvc.exploitation] ?? v.ssvc.exploitation} · {ssvcLabel.automatable[v.ssvc.automatable] ?? v.ssvc.automatable} ·{" "}
              {ssvcLabel.technical_impact[v.ssvc.technical_impact] ?? v.ssvc.technical_impact}
            </dd>
          </>
        )}
        {v.kev_due && (
          <>
            <dt>Plazo CISA</dt>
            <dd className="mono">{v.kev_due}</dd>
          </>
        )}
        {(v.cwe ?? []).length > 0 && (
          <>
            <dt>Debilidad</dt>
            <dd className="mono">{(v.cwe ?? []).join(", ")}</dd>
          </>
        )}
        {v.published && (
          <>
            <dt>Publicada</dt>
            <dd className="mono">{v.published}</dd>
          </>
        )}
        {v.origin && (
          <>
            <dt>Propuesta por</dt>
            <dd>{originLabel[v.origin] ?? v.origin}</dd>
          </>
        )}
        {(v.sources ?? []).length > 0 && (
          <>
            <dt>Datos de</dt>
            <dd>{(v.sources ?? []).map((s) => dataSourceLabel[s] ?? s).join(" · ")}</dd>
          </>
        )}
      </dl>
      <Link to={`/intel/cve/${v.cve}`} className="small">
        Ver todo lo que se sabe de {v.cve} →
      </Link>
    </div>
  );
}

export function rangeText(r: Range) {
  if (r.exact) return r.exact;
  const parts: string[] = [];
  if (r.prefix && !r.start) parts.push(`rama ${r.prefix}.x`);
  if (r.start && r.start !== "0") parts.push(`desde ${r.start}${r.start_inc ? "" : " (exclusive)"}`);
  if (r.end) parts.push(`${r.end_inc ? "hasta" : "antes de"} ${r.end}`);
  return parts.join(", ") || "todas";
}
