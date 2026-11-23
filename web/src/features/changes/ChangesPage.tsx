import { useChanges } from "@/shared/api/queries";
import { Card, Empty, ErrorState, Loading, SeverityBadge } from "@/shared/ui";
import { useOrgContext } from "@/features/orgs/context";

export function ChangesPage() {
  const { snapshotId } = useOrgContext();
  const { data, isLoading, error } = useChanges(snapshotId);
  if (!snapshotId) return <Card><Empty title="Sin escaneos todavía" /></Card>;
  if (isLoading) return <Loading />;
  if (error || !data) return <ErrorState error={error} />;
  if (!data.previous_id)
    return (
      <Card>
        <Empty title="Es el primer escaneo">
          <p>Cuando vuelvas a escanear, acá vas a ver qué servicios se abrieron o cerraron y qué hallazgos aparecieron o se resolvieron.</p>
        </Empty>
      </Card>
    );
  const none = data.new_services.length + data.closed_services.length + data.new_findings.length + data.resolved_findings.length + data.new_assets.length + data.gone_assets.length === 0;
  if (none) return <Card><Empty title="Sin cambios desde el escaneo anterior" /></Card>;
  return (
    <div className="grid grid--2">
      <Card title={`Hallazgos nuevos · ${data.new_findings.length}`}>
        <ul className="change-list">
          {data.new_findings.map((f) => (
            <li key={f.id}>
              <span className="sign plus">+</span>
              <SeverityBadge severity={f.severity} />
              <span>
                {f.title} <span className="path">{f.asset}</span>
              </span>
            </li>
          ))}
          {data.new_findings.length === 0 && <li className="muted">Ninguno.</li>}
        </ul>
      </Card>
      <Card title={`Hallazgos resueltos · ${data.resolved_findings.length}`}>
        <ul className="change-list">
          {data.resolved_findings.map((f) => (
            <li key={f.id}>
              <span className="sign minus">✓</span>
              <SeverityBadge severity={f.severity} />
              <span>
                {f.title} <span className="path">{f.asset}</span>
              </span>
            </li>
          ))}
          {data.resolved_findings.length === 0 && <li className="muted">Ninguno.</li>}
        </ul>
      </Card>
      <Card title="Servicios">
        <ul className="change-list">
          {data.new_services.map((v) => (
            <li key={"n" + v.ip + v.port}>
              <span className="sign plus">+</span>
              <span className="mono">
                {v.ip}:{v.port}
              </span>
              <span className="muted">{[v.product, v.module].filter(Boolean).join(" · ")} — nuevo</span>
            </li>
          ))}
          {data.closed_services.map((v) => (
            <li key={"c" + v.ip + v.port}>
              <span className="sign minus">−</span>
              <span className="mono">
                {v.ip}:{v.port}
              </span>
              <span className="muted">{[v.product, v.module].filter(Boolean).join(" · ")} — cerrado</span>
            </li>
          ))}
          {data.new_services.length + data.closed_services.length === 0 && <li className="muted">Sin cambios.</li>}
        </ul>
      </Card>
      <Card title="Activos">
        <ul className="change-list">
          {data.new_assets.map((a) => (
            <li key={"n" + a}>
              <span className="sign plus">+</span>
              <span className="mono">{a}</span>
            </li>
          ))}
          {data.gone_assets.map((a) => (
            <li key={"g" + a}>
              <span className="sign minus">−</span>
              <span className="mono">{a}</span>
            </li>
          ))}
          {data.new_assets.length + data.gone_assets.length === 0 && <li className="muted">Sin cambios.</li>}
        </ul>
      </Card>
    </div>
  );
}
