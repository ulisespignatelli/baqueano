import { Link, useParams } from "react-router-dom";
import { useCVE } from "@/shared/api/queries";
import { ApiError } from "@/shared/api/types";
import { Card, Empty, ErrorState, Loading } from "@/shared/ui";
import { dataSourceLabel, qualityLabel, ssvcLabel } from "./labels";
import { rangeText } from "./VulnIntel";

export function CVEPage() {
  const { id = "" } = useParams();
  const { data, isLoading, error } = useCVE(id);
  if (isLoading) return <Loading />;
  if (error instanceof ApiError && error.status === 404)
    return (
      <Card>
        <Empty title={`No hay datos de ${id}`}>
          <p>La base local no la tiene y no se pudo consultar (o el servidor corre sin conexión).</p>
        </Empty>
      </Card>
    );
  if (error || !data) return <ErrorState error={error} />;
  const r = data.record;
  return (
    <>
      <div className="page-head">
        <div>
          <p className="small"><Link to="/intel">Inteligencia</Link> / CVE</p>
          <h1 className="mono">{id}</h1>
          {r?.summary && <p>{r.summary}</p>}
        </div>
      </div>
      <div className="grid grid--2" style={{ marginBottom: 16 }}>
        <Card title="Contexto de explotación">
          <dl className="kv">
            <dt>KEV (CISA)</dt>
            <dd>
              {data.kev ? (
                <>
                  <span className="flag flag--kev">explotada</span> agregada {data.kev.added}, plazo {data.kev.due}
                  {data.kev.ransomware && <> · <b style={{ color: "var(--sev-critica)" }}>usada en ransomware</b></>}
                  {data.kev.action && <div className="small muted" style={{ marginTop: 4 }}>{data.kev.action}</div>}
                </>
              ) : (
                <span className="muted">No está en el catálogo</span>
              )}
            </dd>
            <dt>EPSS</dt>
            <dd>{data.epss ? <><span className="mono">{(data.epss.score * 100).toFixed(2)} %</span> <span className="muted small">percentil {Math.round(data.epss.percentile * 100)} · {data.epss.date}</span></> : <span className="muted">Sin dato</span>}</dd>
            <dt>SSVC</dt>
            <dd>
              {r?.ssvc ? (
                <>
                  {ssvcLabel.exploitation[r.ssvc.exploitation] ?? r.ssvc.exploitation} · {ssvcLabel.automatable[r.ssvc.automatable] ?? r.ssvc.automatable} ·{" "}
                  {ssvcLabel.technical_impact[r.ssvc.technical_impact] ?? r.ssvc.technical_impact}
                </>
              ) : (
                <span className="muted">Sin dato</span>
              )}
            </dd>
          </dl>
        </Card>
        <Card title="Datos técnicos">
          <dl className="kv">
            <dt>CVSS</dt>
            <dd className="mono">{r?.cvss ? r.cvss.toFixed(1) : "—"} {r?.vector && <span className="muted small">{r.vector}</span>}</dd>
            <dt>Debilidad</dt>
            <dd className="mono">{(r?.cwe ?? []).join(", ") || "—"}</dd>
            <dt>Publicada</dt>
            <dd className="mono">{r?.published || "—"}</dd>
            <dt>Fuentes</dt>
            <dd>{(r?.sources ?? []).map((s) => dataSourceLabel[s] ?? s).join(" · ") || "—"}</dd>
            {r?.rejected && (
              <>
                <dt>Estado</dt>
                <dd style={{ color: "var(--sev-alta)" }}>Rechazada por el programa CVE</dd>
              </>
            )}
          </dl>
        </Card>
      </div>
      <Card title="Versiones afectadas, por fuente" className="card--flush" >
        {(r?.affected ?? []).length === 0 ? (
          <Empty title="Sin datos de versiones" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Producto</th>
                  <th>Versiones afectadas</th>
                  <th>Fuente</th>
                  <th>Calidad del dato</th>
                </tr>
              </thead>
              <tbody>
                {(r?.affected ?? []).map((a, i) => (
                  <tr key={i}>
                    <td>{a.name || <span className="muted">(sin nombre)</span>}</td>
                    <td className="small">
                      {a.not_affected ? (
                        <span className="muted">no afectado</span>
                      ) : (a.ranges ?? []).length > 0 ? (
                        (a.ranges ?? []).map(rangeText).join(" · ")
                      ) : a.all_versions ? (
                        <span className="muted">sin detalle de versiones</span>
                      ) : (
                        "—"
                      )}
                      {(a.unaffected ?? []).length > 0 && <div className="cell-sub">no afectadas: {(a.unaffected ?? []).map(rangeText).join(" · ")}</div>}
                    </td>
                    <td className="small">{dataSourceLabel[a.source] ?? a.source}</td>
                    <td>
                      <span className={`quality quality--${a.quality}`}>{qualityLabel[a.quality] ?? a.quality}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="pager">
          <span>Solo los datos estructurados alcanzan para descartar una CVE. Los de texto libre se interpretan, pero nunca descartan.</span>
        </div>
      </Card>
    </>
  );
}
