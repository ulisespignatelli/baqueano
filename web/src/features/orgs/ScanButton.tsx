import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useHealth, useInvalidateOrg, useJob, useStartReassess, useStartScan } from "@/shared/api/queries";
import type { OrgDetail } from "@/shared/api/types";

/** Lanza un escaneo y muestra el avance hasta que termina. */
export function ScanButton({ org }: { org: OrgDetail }) {
  const start = useStartScan(org.id);
  const reassess = useStartReassess(org.id);
  const health = useHealth();
  const canReassess = !!health.data?.intel && org.snapshots.length > 0;
  const [jobId, setJobId] = useState<string>();
  const job = useJob(jobId);
  const invalidate = useInvalidateOrg();
  const [, setParams] = useSearchParams();
  const authorized = !!org.attestation || org.domains.some((d) => d.verified_at);

  useEffect(() => {
    if (job.data?.status === "done") {
      invalidate(org.id);
      setParams((p) => {
        const n = new URLSearchParams(p);
        n.delete("snap");
        return n;
      });
    }
  }, [job.data?.status]); // eslint-disable-line react-hooks/exhaustive-deps

  const running = job.data?.status === "running" || start.isPending || reassess.isPending;
  return (
    <div className="stack" style={{ gap: 8, minWidth: 280 }}>
      <button
        type="button"
        className="btn btn--primary"
        disabled={running || !authorized}
        title={authorized ? undefined : "Primero aceptá la declaración de responsabilidad en la pestaña Alcance"}
        onClick={() => start.mutate(undefined, { onSuccess: (j) => setJobId(j.id) })}
      >
        {running ? "Trabajando…" : "Escanear ahora"}
      </button>
      {canReassess && !running && (
        <button
          type="button"
          className="btn btn--sm btn--ghost"
          title="Vuelve a evaluar el último escaneo con la inteligencia actual (KEV, EPSS, CVE nuevas) sin consultar Shodan"
          onClick={() => reassess.mutate(undefined, { onSuccess: (j) => setJobId(j.id) })}
        >
          Reevaluar sin escanear
        </button>
      )}
      {running && (
        <>
          <div className="progress">
            <i />
          </div>
          <span className="small muted">{job.data?.message ?? "Iniciando…"}</span>
        </>
      )}
      {job.data?.status === "error" && <span className="small" style={{ color: "var(--sev-critica)" }}>{job.data.error}</span>}
      {start.isError && <span className="small" style={{ color: "var(--sev-critica)" }}>{(start.error as Error).message}</span>}
      {reassess.isError && <span className="small" style={{ color: "var(--sev-critica)" }}>{(reassess.error as Error).message}</span>}
    </div>
  );
}
