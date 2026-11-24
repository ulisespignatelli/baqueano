import { useState, type FormEvent } from "react";
import { api } from "@/shared/api";
import { useDeleteAlert, useSaveAlert, useSetSchedule, useTestAlert } from "@/shared/api/queries";
import type { Alert } from "@/shared/api/types";
import { Card } from "@/shared/ui";
import { fmtDateTime } from "@/shared/lib/format";
import { channelLabel, eventLabel, severityLabel } from "@/shared/lib/labels";
import { useOrgContext } from "@/features/orgs/context";

const placeholder: Record<string, string> = {
  webhook: "https://mi-servidor/webhook",
  slack: "https://hooks.slack.com/services/…",
  teams: "URL del flujo de trabajo de Teams",
  email: "seguridad@miempresa.com",
  jira: "Clave del proyecto (SEC)",
};
const help: Record<string, string> = {
  webhook: "Recibe el aviso en JSON. Con BAQUEANO_WEBHOOK_SECRET va firmado (encabezado X-Baqueano-Signature, HMAC-SHA256).",
  slack: "Webhook entrante de una app de Slack.",
  teams: "Webhook de un flujo de trabajo de Teams («Publicar en un canal cuando se recibe una solicitud de webhook»).",
  email: "Usa el servidor de correo de SMTP_ADDR, SMTP_USER, SMTP_PASSWORD y SMTP_FROM.",
  jira: "Crea un ticket por hallazgo, sin duplicar. Usa JIRA_URL, JIRA_EMAIL y JIRA_API_TOKEN.",
};
const blank: Alert = { name: "", channel: "slack", target: "", events: ["kev", "hallazgo-nuevo"], min_severity: "alta", enabled: true };

export function AutomationPage() {
  const { org } = useOrgContext();
  const demo = api.mode === "demo";
  const sched = useSetSchedule(org.id);
  const save = useSaveAlert(org.id);
  const del = useDeleteAlert(org.id);
  const test = useTestAlert(org.id);
  const sc = org.schedule;
  const [hours, setHours] = useState(String(sc?.hours ?? 168));
  const [mode, setMode] = useState(sc?.mode ?? "escanear");
  const [a, setA] = useState<Alert>(blank);
  const [tested, setTested] = useState<string>();
  const alerts = org.alerts ?? [];
  const toggleEvent = (e: string) => setA({ ...a, events: a.events.includes(e as never) ? a.events.filter((x) => x !== e) : [...a.events, e as never] });
  const addAlert = (e: FormEvent) => {
    e.preventDefault();
    save.mutate(a, { onSuccess: () => setA(blank) });
  };
  return (
    <div className="stack">
      <Card title="Escaneos programados">
        {sc?.enabled ? (
          <p style={{ marginTop: 0 }}>
            <span className="verif verif--ok">✓ Activo</span> {sc.mode === "reevaluar" ? "Reevalúa (sin consultar Shodan)" : "Escanea"} cada{" "}
            <b>{sc.hours % 24 === 0 ? `${sc.hours / 24} día${sc.hours === 24 ? "" : "s"}` : `${sc.hours} h`}</b>. Próxima corrida: <b>{fmtDateTime(sc.next_run!)}</b>
            {sc.last_run && !sc.last_run.startsWith("0001") && <> · última: {fmtDateTime(sc.last_run)}</>}
            {sc.last_error && <span style={{ color: "var(--sev-critica)" }}> · error: {sc.last_error}</span>}
          </p>
        ) : (
          <p className="muted" style={{ marginTop: 0 }}>Sin programación: los escaneos se lanzan a mano.</p>
        )}
        <p className="small muted">
          Corre mientras esté abierto <code>baqueano serve</code>. Si no, programá <code>baqueano run-due</code> en cron o en el Programador de tareas de Windows.
        </p>
        {!demo && (
          <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
            <select className="input" value={mode} onChange={(e) => setMode(e.target.value as "escanear")} aria-label="Modo" style={{ width: 220 }}>
              <option value="escanear">Escanear (consulta Shodan)</option>
              <option value="reevaluar">Reevaluar (sin Shodan)</option>
            </select>
            <select className="input" value={hours} onChange={(e) => setHours(e.target.value)} aria-label="Frecuencia" style={{ width: 160 }}>
              <option value="24">Todos los días</option>
              <option value="72">Cada 3 días</option>
              <option value="168">Todas las semanas</option>
              <option value="720">Cada 30 días</option>
            </select>
            <button type="button" className="btn btn--primary" disabled={sched.isPending} onClick={() => sched.mutate({ enabled: true, hours: Number(hours), mode })}>
              {sc?.enabled ? "Actualizar" : "Programar"}
            </button>
            {sc?.enabled && (
              <button type="button" className="btn btn--ghost" onClick={() => sched.mutate({ enabled: false, hours: sc.hours, mode: sc.mode })}>
                Desactivar
              </button>
            )}
          </div>
        )}
        {sched.isError && <p className="small" style={{ color: "var(--sev-critica)" }}>{(sched.error as Error).message}</p>}
      </Card>

      <Card title={`Alertas · ${alerts.length}`}>
        {alerts.length === 0 ? (
          <p className="muted" style={{ marginTop: 0 }}>Sin alertas: los cambios se ven solo en el panel.</p>
        ) : (
          <ul className="list-plain">
            {alerts.map((x) => (
              <li key={x.id}>
                <span style={{ minWidth: 220 }}>
                  <b>{x.name}</b>
                  <div className="small muted">{channelLabel[x.channel]} · <span className="mono">{x.target}</span></div>
                </span>
                <span className="small" style={{ flex: 1 }}>
                  {x.events.map((e) => eventLabel[e]).join(", ")}
                  {x.min_severity && <> · desde {severityLabel[x.min_severity as keyof typeof severityLabel] ?? x.min_severity}</>}
                  {(x.rules ?? []).length > 0 && <> · solo {(x.rules ?? []).join(", ")}</>}
                  <div className="muted">
                    {x.last_sent ? `Último envío ${fmtDateTime(x.last_sent)}` : "Todavía no envió nada"}
                    {x.tickets && Object.keys(x.tickets).length > 0 && ` · ${Object.keys(x.tickets).length} tickets creados`}
                    {x.last_error && <span style={{ color: "var(--sev-critica)" }}> · error: {x.last_error}</span>}
                  </div>
                </span>
                {!x.enabled && <span className="flag">pausada</span>}
                {!demo && (
                  <span className="row" style={{ gap: 4 }}>
                    <button type="button" className="btn btn--sm btn--ghost" disabled={test.isPending} onClick={() => x.id && test.mutate(x.id, { onSuccess: () => setTested(x.id), onError: () => setTested(undefined) })}>
                      {tested === x.id ? "Enviada ✓" : "Probar"}
                    </button>
                    <button type="button" className="btn btn--sm btn--ghost" onClick={() => x.id && del.mutate(x.id)}>Quitar</button>
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
        {test.isError && <p className="small" style={{ color: "var(--sev-critica)" }}>La prueba falló: {(test.error as Error).message}</p>}
        {!demo && (
          <form onSubmit={addAlert} className="stack" style={{ gap: 10, marginTop: 18 }}>
            <div className="form-grid">
              <input className="input" placeholder="Nombre" value={a.name} onChange={(e) => setA({ ...a, name: e.target.value })} aria-label="Nombre" />
              <select className="input" value={a.channel} onChange={(e) => setA({ ...a, channel: e.target.value as Alert["channel"], target: "" })} aria-label="Canal">
                {Object.entries(channelLabel).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
              <input className="input" placeholder={placeholder[a.channel]} value={a.target} onChange={(e) => setA({ ...a, target: e.target.value })} aria-label="Destino" style={{ gridColumn: "span 2" }} />
              <select className="input" value={a.min_severity} onChange={(e) => setA({ ...a, min_severity: e.target.value })} aria-label="Severidad mínima">
                <option value="">Cualquier severidad</option>
                {(["critica", "alta", "media", "baja"] as const).map((k) => <option key={k} value={k}>Desde {severityLabel[k].toLowerCase()}</option>)}
              </select>
            </div>
            <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
              {Object.entries(eventLabel).map(([k, v]) => (
                <button key={k} type="button" className={`btn btn--sm ${a.events.includes(k as never) ? "btn--primary" : "btn--ghost"}`} onClick={() => toggleEvent(k)}>
                  {v}
                </button>
              ))}
              <input className="input" style={{ width: 240 }} placeholder="Solo controles (opcional): PX-RDP, VU-" value={(a.rules ?? []).join(", ")}
                onChange={(e) => setA({ ...a, rules: e.target.value.split(/[\s,]+/).filter(Boolean) })} aria-label="Controles" />
            </div>
            <p className="small muted" style={{ margin: 0 }}>{help[a.channel]} Las URL de webhook se guardan en tu equipo y el panel nunca las vuelve a mostrar completas.</p>
            <div>
              <button className="btn btn--primary" type="submit" disabled={!a.name.trim() || !a.target.trim() || a.events.length === 0 || save.isPending}>
                Agregar alerta
              </button>
            </div>
            {save.isError && <p className="small" style={{ color: "var(--sev-critica)", margin: 0 }}>{(save.error as Error).message}</p>}
          </form>
        )}
      </Card>
    </div>
  );
}
