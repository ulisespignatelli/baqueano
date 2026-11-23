import { Card, Empty, Tag } from "@/shared/ui";
import { useOrgContext } from "@/features/orgs/context";

export function AssetsPage() {
  const { snapshot: s } = useOrgContext();
  if (!s) return <Card><Empty title="Sin escaneos todavía" /></Card>;
  const assets = s.assets ?? [];
  return (
    <div className="stack">
      <Card className="card--flush">
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Activo</th>
                <th>IP</th>
                <th>Apunta a</th>
                <th>Origen</th>
              </tr>
            </thead>
            <tbody>
              {assets.map((a) => (
                <tr key={(a.hostname ?? "") + (a.ips ?? []).join()}>
                  <td>
                    <div className="cell-main">{a.hostname ?? (a.ips ?? [])[0]}</div>
                    {!a.resolves && <div className="cell-sub">no resuelve</div>}
                  </td>
                  <td className="path">{(a.ips ?? []).join(", ") || "—"}</td>
                  <td>
                    {a.cname ? <span className="path">{a.cname}</span> : "—"}
                    {a.third_party && (
                      <div style={{ marginTop: 4 }}>
                        <Tag title="Servicio de terceros: sus IP no se consultan porque pertenecen al proveedor">tercero · {a.third_party}</Tag>
                      </div>
                    )}
                  </td>
                  <td>
                    <div className="chips">
                      {a.sources.map((x) => (
                        <span key={x} className="cat">
                          {x === "ct" ? "Certificate Transparency" : x}
                        </span>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <Card title="Alcance y fuentes de este escaneo">
        <div className="kv-inline" style={{ marginBottom: 12 }}>
          <span>
            Dominios: <b>{s.domains.join(", ")}</b>
          </span>
          {(s.networks ?? []).length > 0 && (
            <span>
              Redes declaradas: <b>{(s.networks ?? []).join(", ")}</b>
            </span>
          )}
          <span>
            Fuentes: <b>{s.sources.join(" · ")}</b>
          </span>
          {(s.authorization ?? []).length > 0 && (
            <span>
              Autorización: <b>{(s.authorization ?? []).join(" ")}</b>
            </span>
          )}
        </div>
        {(s.notes ?? []).length > 0 && (
          <ul className="notes">
            {(s.notes ?? []).map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
