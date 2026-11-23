import { Card, Empty, Tag } from "@/shared/ui";
import { fmtDate } from "@/shared/lib/format";
import { useOrgContext } from "@/features/orgs/context";

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
  return (
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
                  {(v.vulns ?? []).length === 0 ? (
                    "—"
                  ) : (
                    <div className="chips">
                      {(v.vulns ?? []).slice(0, 4).map((x) => (
                        <span key={x.cve} className="cat mono" style={{ borderColor: x.kev ? "var(--sev-critica)" : undefined, color: x.kev ? "var(--sev-critica)" : undefined }} title={x.summary}>
                          {x.cve}
                          {x.kev ? " · KEV" : ""}
                          {!x.verified ? " ?" : ""}
                        </span>
                      ))}
                      {(v.vulns ?? []).length > 4 && <span className="small muted">+{(v.vulns ?? []).length - 4}</span>}
                    </div>
                  )}
                </td>
                <td className="small muted">
                  {v.seen_at && !v.seen_at.startsWith("0001") ? fmtDate(v.seen_at) : "—"}
                  <div className="cell-sub">{v.source}</div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="pager">
        <span>«?» = vulnerabilidad inferida por la versión, sin confirmar · KEV = explotada activamente según CISA</span>
      </div>
    </Card>
  );
}
