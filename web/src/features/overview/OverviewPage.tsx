import { Link, useNavigate } from "react-router-dom";
import { api } from "@/shared/api";
import { useOverview } from "@/shared/api/queries";
import { Card, Empty, ErrorState, Loading, ScoreRing, SeverityBar, Sparkline, Stat } from "@/shared/ui";
import { fmtDateTime, fmtNum, plural } from "@/shared/lib/format";

export function OverviewPage() {
  const { data, isLoading, error } = useOverview();
  const navigate = useNavigate();
  if (isLoading) return <Loading />;
  if (error || !data) return <ErrorState error={error} />;

  if (data.orgs.length === 0) {
    return (
      <Card>
        <Empty title="Todavía no hay organizaciones">
          <p>
            Cargá los dominios y redes de una organización de la que seas responsable o que te haya autorizado. Baqueano solo usa datos públicos
            y deja registrada tu declaración.
          </p>
          <Link className="btn btn--primary" to="/orgs/new">
            Agregar organización
          </Link>
        </Empty>
      </Card>
    );
  }

  const crit = data.by_severity["critica"] ?? 0;
  const high = data.by_severity["alta"] ?? 0;
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Vista general</h1>
          <p>Lo que se ve desde internet de cada organización, según su último escaneo.</p>
        </div>
        {api.mode === "api" && (
          <Link className="btn btn--primary" to="/orgs/new">
            + Nueva organización
          </Link>
        )}
      </div>
      <div className="stack">
        <Card>
          <div className="hero">
            <ScoreRing value={data.score} label="puntaje medio" />
            <div className="hero__text">
              <h2>{crit > 0 ? `${plural(crit, "problema crítico", "problemas críticos")} a la vista de cualquiera` : high > 0 ? "Sin críticos, pero con riesgos altos" : "Superficie bajo control"}</h2>
              <p>
                {fmtNum(data.assets)} activos y {fmtNum(data.services)} servicios publicados en {plural(data.orgs.length, "organización", "organizaciones")}. El
                puntaje baja con cada hallazgo y sube con cada corrección.
              </p>
              <SeverityBar counts={data.by_severity} />
            </div>
          </div>
        </Card>
        <div className="grid grid--stats">
          <Stat label="Críticos" value={fmtNum(crit)} hint="corregir hoy" tone={crit ? "danger" : "ok"} />
          <Stat label="Altos" value={fmtNum(high)} hint="corregir esta semana" tone={high ? "warn" : "ok"} />
          <Stat label="Servicios expuestos" value={fmtNum(data.services)} />
          <Stat label="Activos" value={fmtNum(data.assets)} hint="subdominios e IP" />
        </div>
        <Card title="Organizaciones" className="card--flush">
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Organización</th>
                  <th className="num">Puntaje</th>
                  <th>Evolución</th>
                  <th>Hallazgos</th>
                  <th className="num">Servicios</th>
                  <th>Último escaneo</th>
                </tr>
              </thead>
              <tbody>
                {data.orgs.map((o) => {
                  const verified = o.domains.filter((d) => d.verified_at).length;
                  return (
                    <tr key={o.id} className="clickable" onClick={() => navigate(`/orgs/${o.id}`)}>
                      <td>
                        <Link className="asset-name" to={`/orgs/${o.id}`} onClick={(e) => e.stopPropagation()}>
                          {o.name}
                        </Link>
                        <div className="cell-sub">
                          {o.domains.map((d) => d.name).join(", ")} · {o.attestation ? "alcance declarado" : "sin declaración"}
                          {verified > 0 ? ` · ${verified} verificado${verified === 1 ? "" : "s"} en DNS` : ""}
                        </div>
                      </td>
                      <td className="num">
                        <strong>{o.latest ? o.latest.score : "—"}</strong>
                      </td>
                      <td>
                        <Sparkline points={o.trend.map((t) => t.score)} />
                      </td>
                      <td>{o.latest ? <SeverityBar counts={o.latest.by_severity} compact /> : <span className="muted small">sin escanear</span>}</td>
                      <td className="num">{o.latest ? fmtNum(o.latest.services) : "—"}</td>
                      <td className="muted">{o.latest ? fmtDateTime(o.latest.started_at) : "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </>
  );
}
