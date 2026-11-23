import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "@/shared/api";
import { useAddDomain, useAddNetwork, useAttest, useDeleteOrg, useVerify } from "@/shared/api/queries";
import { Card } from "@/shared/ui";
import { fmtDateTime } from "@/shared/lib/format";
import { ATTESTATION_TEXT } from "@/shared/lib/labels";
import { useOrgContext } from "@/features/orgs/context";

function AddForm({ placeholder, label, onAdd, pending, error }: { placeholder: string; label: string; onAdd: (v: string, done: () => void) => void; pending: boolean; error?: Error | null }) {
  const [v, setV] = useState("");
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (v.trim()) onAdd(v.trim(), () => setV(""));
  };
  return (
    <form onSubmit={submit}>
      <div className="row">
        <input className="input" style={{ flex: 1 }} placeholder={placeholder} value={v} onChange={(e) => setV(e.target.value)} aria-label={label} />
        <button className="btn" type="submit" disabled={pending || !v.trim()}>
          {label}
        </button>
      </div>
      {error && <p className="small" style={{ color: "var(--sev-critica)" }}>{error.message}</p>}
    </form>
  );
}

export function SettingsPage() {
  const { org } = useOrgContext();
  const verify = useVerify(org.id);
  const addDomain = useAddDomain(org.id);
  const addNetwork = useAddNetwork(org.id);
  const attest = useAttest(org.id);
  const del = useDeleteOrg();
  const navigate = useNavigate();
  const [by, setBy] = useState("");
  const [accepted, setAccepted] = useState(false);
  const [copied, setCopied] = useState<string>();
  const demo = api.mode === "demo";
  const copy = (t: string) => void navigator.clipboard?.writeText(t).then(() => setCopied(t));

  return (
    <div className="stack">
      <Card title="Autorización">
        {org.attestation ? (
          <>
            <p style={{ marginTop: 0 }}>
              <span className="verif verif--ok">✓ Alcance declarado</span> por <b>{org.attestation.by}</b> el {fmtDateTime(org.attestation.at)}
            </p>
            <p className="small muted" style={{ margin: 0 }}>«{org.attestation.statement}»</p>
          </>
        ) : demo ? (
          <p className="muted" style={{ margin: 0 }}>Sin declaración: solo se analizan los dominios verificados en DNS.</p>
        ) : (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (accepted && by.trim()) attest.mutate(by.trim());
            }}
            className="stack"
            style={{ gap: 12 }}
          >
            <p style={{ margin: 0 }}>Sin declaración, solo se analizan los dominios verificados en DNS.</p>
            <label style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
              <input type="checkbox" checked={accepted} onChange={(e) => setAccepted(e.target.checked)} style={{ marginTop: 4 }} />
              <span>{ATTESTATION_TEXT}</span>
            </label>
            <div className="row">
              <input className="input" style={{ flex: 1 }} placeholder="Tu nombre" value={by} onChange={(e) => setBy(e.target.value)} aria-label="Tu nombre" />
              <button className="btn btn--primary" type="submit" disabled={!accepted || by.trim().length < 3 || attest.isPending}>
                Aceptar
              </button>
            </div>
            {attest.isError && <span className="small" style={{ color: "var(--sev-critica)" }}>{(attest.error as Error).message}</span>}
          </form>
        )}
      </Card>

      <div className="grid grid--2">
        <Card title="Dominios">
          <div className="stack" style={{ gap: 10 }}>
            {org.domains.map((d) => (
              <div key={d.name} className="row">
                <b>{d.name}</b>
                {d.verified_at ? <span className="verif verif--ok">✓ verificado en DNS</span> : org.attestation ? <span className="verif muted">declarado</span> : <span className="verif verif--no">sin autorización</span>}
              </div>
            ))}
          </div>
          {!demo && (
            <div style={{ marginTop: 16 }}>
              <AddForm placeholder="otrodominio.com" label="Agregar dominio" pending={addDomain.isPending} error={addDomain.error as Error | null} onAdd={(v, done) => addDomain.mutate(v, { onSuccess: done })} />
            </div>
          )}
        </Card>
        <Card title="Redes de IP">
          {(org.networks ?? []).length === 0 && org.domains.every((d) => (d.networks ?? []).length === 0) ? (
            <p className="muted" style={{ marginTop: 0 }}>Sin redes declaradas: se analizan las IP a las que apuntan los dominios.</p>
          ) : (
            <ul className="notes" style={{ marginBottom: 0 }}>
              {(org.networks ?? []).map((n) => (
                <li key={n} className="mono">{n} <span className="muted">· declarada</span></li>
              ))}
              {org.domains.flatMap((d) => (d.networks ?? []).map((n) => (
                <li key={d.name + n} className="mono">{n} <span className="muted">· publicada en el DNS de {d.name}</span></li>
              )))}
            </ul>
          )}
          {!demo && (
            <div style={{ marginTop: 16 }}>
              <AddForm placeholder="203.0.113.0/24" label="Agregar red" pending={addNetwork.isPending} error={addNetwork.error as Error | null} onAdd={(v, done) => addNetwork.mutate(v, { onSuccess: done })} />
            </div>
          )}
        </Card>
      </div>

      <Card
        title="Verificación DNS (opcional)"
        actions={!demo && <button type="button" className="btn btn--sm" onClick={() => verify.mutate()} disabled={verify.isPending}>{verify.isPending ? "Verificando…" : "Verificar ahora"}</button>}
      >
        <p className="muted" style={{ marginTop: 0 }}>
          No es necesaria para escanear. Sirve como constancia de que el dueño del dominio autoriza el análisis: publicá el registro como <b>TXT</b>{" "}
          en la raíz del dominio. También podés declarar redes ahí con <code>baqueano-scope=203.0.113.0/24</code>.
        </p>
        <div className="stack" style={{ gap: 12 }}>
          {org.domains.map((d) => {
            const rec = `baqueano-verify=${d.token}`;
            return (
              <div key={d.name} className="txt-record">
                <span style={{ minWidth: 200 }}>{d.name}</span>
                <code>{demo ? "baqueano-verify=…" : rec}</code>
                {!demo && (
                  <button type="button" className="btn btn--sm btn--ghost" onClick={() => copy(rec)}>
                    {copied === rec ? "Copiado" : "Copiar"}
                  </button>
                )}
                {d.verified_at ? <span className="verif verif--ok">✓ {fmtDateTime(d.verified_at)}</span> : d.check_error && <span className="small muted">{d.check_error}</span>}
              </div>
            );
          })}
        </div>
        {verify.isError && <p style={{ color: "var(--sev-critica)" }}>{(verify.error as Error).message}</p>}
      </Card>

      <Card title="Historial de auditoría" className="card--flush">
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Fecha</th>
                <th>Acción</th>
                <th>Detalle</th>
              </tr>
            </thead>
            <tbody>
              {[...(org.audit ?? [])].reverse().slice(0, 50).map((a, i) => (
                <tr key={i}>
                  <td className="muted small" style={{ whiteSpace: "nowrap" }}>{fmtDateTime(a.at)}</td>
                  <td>{a.action}</td>
                  <td className="small muted">{a.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {!demo && (
        <Card title="Zona peligrosa">
          <button
            type="button"
            className="btn btn--danger"
            onClick={() => {
              if (confirm(`¿Borrar ${org.name} y todos sus escaneos? No se puede deshacer.`)) del.mutate(org.id, { onSuccess: () => navigate("/") });
            }}
          >
            Borrar organización
          </button>
        </Card>
      )}
    </div>
  );
}
