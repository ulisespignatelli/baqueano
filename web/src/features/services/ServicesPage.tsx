import { Link } from "react-router-dom";
import { Card, Empty, Tag } from "@/shared/ui";
import { confidenceLabel, priorityLabel } from "@/features/intel/labels";
import { fmtDate } from "@/shared/lib/format";
import { useOrgContext } from "@/features/orgs/context";

const niceSource: Record<string, string> = { shodan: "Shodan", censys: "Censys", internetdb: "InternetDB" };

export function ServicesPage() {
  const { snapshot: s } = useOrgContext();
  if (!s) return <Card><Empty title="Sin escaneos todavía" /></Card>;
  const svcs = s.services ?? [];
  if (svcs.length === 0)
    return (
      <Card>
        <Empty title="No se vieron servicios">
          <p>Ninguna IP propia tiene puertos abiertos según la fuente de exposición, o no hay fuente configurada.</p>
        </Empty>
      </Card>
    );
  const c = s.consensus;
  return (
    <div className="stack">
    {c && (
      <div className="callout">
        <b>Consenso entre fuentes:</b> {c.sources.map((x) => niceSource[x] ?? x).join(" y ")} coinciden en <b>{c.all}</b> de {c.services} servicios.{" "}
        {c.single > 0 && <>{c.single} los vio una sola fuente: puede ser un puerto que se cerró hace poco o que una de ellas todavía no escaneó.</>}
      </div>
    )}
    <Card className="card--flush">
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>IP : puerto</th>
              <th>Servicio</th>
              <th>Certificado</th>
              <th>Vulnerabilidades</th>
              <th>Visto</th>
            </tr>
          </thead>
          <tbody>
            {svcs.map((v) => (
              <tr key={`${v.ip}/${v.transport}/${v.port}`}>
                <td>
                  <div className="cell-main mono">
                    {v.ip}:{v.port}
                    <span className="muted">/{v.transport}</span>
                  </div>
                  {(v.hostnames ?? []).length > 0 && <div className="cell-sub">{(v.hostnames ?? []).slice(0, 2).join(", ")}</div>}
                </td>
                <td>
                  <div>{[v.product, v.version].filter(Boolean).join(" ") || v.module || "—"}</div>
                  <div className="chips" style={{ marginTop: 4 }}>
                    {v.module && <span className="cat">{v.module}</span>}
                    {v.http_title && <span className="cat" title="Título de la página">«{v.http_title}»</span>}
                    {(v.tags ?? []).map((t) => (
                      <Tag key={t}>{t}</Tag>
                    ))}
                    {v.eol && (
                      <span className="flag flag--kev" title={`Rama ${v.eol.cycle} sin parches de seguridad${v.eol.since ? " desde " + v.eol.since : ""} (${v.eol.source})`}>
                        sin soporte
                      </span>
                    )}
                  </div>
                </td>
                <td className="small">
                  {v.cert ? (
                    <>
                      <div>{v.cert.subject || "—"}</div>
                      <div className="cell-sub" style={{ color: v.cert.expired ? "var(--sev-critica)" : undefined }}>
                        {v.cert.expired ? "vencido" : "vence"} {fmtDate(v.cert.not_after)}
                        {v.cert.self_signed ? " · autofirmado" : ""}
                      </div>
                      {(v.cert.tls_versions ?? []).length > 0 && <div className="cell-sub">{(v.cert.tls_versions ?? []).join(" · ")}</div>}
                    </>
                  ) : (
                    "—"
                  )}
                </td>
                <td>
                  {(v.vulns ?? []).length === 0 && (v.dismissed ?? []).length === 0 ? (
                    "—"
                  ) : (
                    <div className="chips">
                      {(v.vulns ?? []).slice(0, 4).map((x) => (
                        <Link
                          key={x.cve}
                          to={`/intel/cve/${x.cve}`}
                          className={`vchip vchip--${x.priority ?? (x.kev ? "P1" : "P4")} ${x.confidence === "por-confirmar" || x.confidence === "improbable" ? "vchip--dim" : ""}`}
                          title={[x.priority && `${x.priority} · ${priorityLabel[x.priority]}`, x.confidence && confidenceLabel[x.confidence], x.reason].filter(Boolean).join(" — ")}
                        >
                          {x.cve}
                          {x.kev ? " · KEV" : ""}
                        </Link>
                      ))}
                      {(v.vulns ?? []).length > 4 && <span className="small muted">+{(v.vulns ?? []).length - 4}</span>}
                      {(v.dismissed ?? []).length > 0 && (
                        <span className="small muted" title={(v.dismissed ?? []).map((d) => `${d.cve}: ${d.reason}`).join("\n")} style={{ cursor: "help", textDecoration: "underline dotted" }}>
                          {(v.dismissed ?? []).length} descartada{(v.dismissed ?? []).length === 1 ? "" : "s"} por versión
                        </span>
                      )}
                    </div>
                  )}
                </td>
                <td className="small muted">
                  {v.seen_at && !v.seen_at.startsWith("0001") ? fmtDate(v.seen_at) : "—"}
                  <div className="cell-sub">
                    {(v.seen_by ?? [v.source]).map((x) => niceSource[x] ?? x).join(" + ")}
                    {s.consensus && (v.seen_by ?? []).length === 1 && <span title="Lo vio una sola fuente: puede ser un dato viejo" style={{ color: "var(--sev-media)" }}> · una sola fuente</span>}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="pager">
        <span>Color = prioridad (rojo: corregir hoy) · borde punteado = por confirmar o improbable · KEV = explotada según CISA · pasá el mouse para ver el motivo</span>
      </div>
    </Card>
    </div>
  );
}
