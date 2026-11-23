import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useInvalidateOrg, useJob, useStartScan } from "@/shared/api/queries";
import type { OrgDetail } from "@/shared/api/types";

/** Lanza un escaneo y muestra el avance hasta que termina. */
export function ScanButton({ org }: { org: OrgDetail }) {
  const start = useStartScan(org.id);
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

  const running = job.data?.status === "running" || start.isPending;
  return (
    <div className="stack" style={{ gap: 8, minWidth: 280 }}>
      <button
        type="button"
        className="btn btn--primary"
        disabled={running || !authorized}
        title={authorized ? undefined : "Primero aceptá la declaración de responsabilidad en la pestaña Alcance"}
        onClick={() => start.mutate(undefined, { onSuccess: (j) => setJobId(j.id) })}
      >
        {running ? "Escaneando…" : "Escanear ahora"}
      </button>
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
    </div>
  );
}
