import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "@/shared/api";
import { useIntel, useUpdateIntel } from "@/shared/api/queries";
import { Card, ErrorState, Loading, Stat } from "@/shared/ui";
import { fmtDateTime, fmtNum } from "@/shared/lib/format";

const REPO = "https://github.com/ulisespignatelli/baqueano";

export function IntelPage() {
  const { data, isLoading, error } = useIntel();
  const update = useUpdateIntel();
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const [bad, setBad] = useState(false);
  if (isLoading) return <Loading />;
  if (error || !data) return <ErrorState error={error} />;
  const lookup = (e: FormEvent) => {
    e.preventDefault();
    const id = q.trim().toUpperCase();
    if (!/^CVE-\d{4}-\d{4,}$/.test(id)) return setBad(true);
    setBad(false);
    navigate(`/intel/cve/${id}`);
  };
  const kev = data.sources.find((s) => s.id === "kev");
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Inteligencia de vulnerabilidades</h1>
          <p>
            Baqueano no le cree a ciegas a la fuente de exposición: contrasta cada CVE con los rangos de versiones que publica el fabricante y la
            NVD, la descarta si la versión no está afectada y la prioriza según lo que se está explotando de verdad.
          </p>
        </div>
        {api.mode === "api" && (
          <button type="button" className="btn btn--primary" disabled={update.isPending || !data.online} onClick={() => update.mutate()}
            title={data.online ? undefined : "El servidor corre con --offline"}>
            {update.isPending ? "Actualizando…" : "Actualizar KEV y EPSS"}
          </button>
        )}
      </div>
      {update.isError && <div className="callout" style={{ marginBottom: 16, color: "var(--sev-critica)" }}>{(update.error as Error).message}</div>}
      <div className="grid grid--4" style={{ marginBottom: 22 }}>
        <Stat label="CVE con datos" value={fmtNum(data.records)} hint="registros en la base local" />
        <Stat label="Explotadas (KEV)" value={fmtNum(kev?.items ?? 0)} hint={data.kev_catalog ? `catálogo ${data.kev_catalog}` : "sin descargar"} tone={(kev?.items ?? 0) > 0 ? undefined : "warn"} />
        <Stat label="Modo" value={data.online ? "En línea" : "Sin conexión"} hint={data.online ? "completa lo que falta en cada escaneo" : "usa solo la base guardada"} />
        <Stat label="Clave de la NVD" value={data.nvd_key ? "Sí" : "No"} hint={data.nvd_key ? "50 consultas cada 30 s" : "opcional: 10 veces más rápido"} />
      </div>
      <div className="grid grid--2">
        <Card title="Fuentes">
          <ul className="sources">
            {data.sources.map((s) => (
              <li key={s.id}>
                <div className="row">
                  <b>{s.name}</b>
                  <span className="spacer" />
                  <span className="mono small">{fmtNum(s.items)}</span>
                </div>
                <div className="small muted">{s.description}</div>
                <div className="small" style={{ marginTop: 2 }}>
                  {s.updated ? `Actualizada ${fmtDateTime(s.updated)}` : <span className="muted">Todavía sin datos</span>}
                  {s.error && <span style={{ color: "var(--sev-alta)" }}> · último error: {s.error}</span>}
                </div>
              </li>
            ))}
          </ul>
        </Card>
        <div className="stack">
          <Card title="Buscar una CVE">
            <form onSubmit={lookup} className="row">
              <input className="input" style={{ flex: 1 }} placeholder="CVE-2024-6387" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Identificador de CVE" />
              <button className="btn" type="submit">Ver</button>
            </form>
            {bad && <p className="small" style={{ color: "var(--sev-critica)" }}>El formato es CVE-AAAA-NNNN.</p>}
            {api.mode === "demo" && <p className="small muted">En la demo solo están las CVE ficticias de los ejemplos (CVE-2099-0101 a 0106).</p>}
          </Card>
          <Card title="Cómo decide">
            <ol className="steps">
              <li><b>Candidatas:</b> las CVE que propone Shodan y las que la NVD asocia a la versión exacta del servicio.</li>
              <li><b>Versión contra rangos:</b> compara la versión (8.9p1, 9.0.0.M1, 10.2.9-h1…) con los rangos de cada fuente. Solo descarta con datos estructurados.</li>
              <li><b>Paquetes de distribución:</b> si el banner dice Ubuntu, Debian o RHEL, la deja «por confirmar» porque las distros corrigen sin cambiar la versión.</li>
              <li><b>Prioridad:</b> KEV, ransomware y SSVC primero; después EPSS; CVSS al final.</li>
            </ol>
            <a className="small" href={`${REPO}/blob/main/docs/benchmark.md`} target="_blank" rel="noreferrer">
              Ver el benchmark de precisión con casos reales →
            </a>
          </Card>
        </div>
      </div>
    </>
  );
}
