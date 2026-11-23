import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "@/shared/api";
import { useCreateOrg } from "@/shared/api/queries";
import { Card } from "@/shared/ui";
import { ATTESTATION_TEXT } from "@/shared/lib/labels";

const split = (s: string) => s.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);

export function NewOrgPage() {
  const [name, setName] = useState("");
  const [domains, setDomains] = useState("");
  const [networks, setNetworks] = useState("");
  const [by, setBy] = useState("");
  const [accepted, setAccepted] = useState(false);
  const create = useCreateOrg();
  const navigate = useNavigate();
  if (api.mode === "demo") return <Card><p>La demo es de solo lectura.</p></Card>;

  const ready = name.trim() && domains.trim() && accepted && by.trim().length >= 3;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    create.mutate(
      { name: name.trim(), domains: split(domains), networks: split(networks), attestation: { by: by.trim(), accepted } },
      { onSuccess: (o) => navigate(`/orgs/${o.id}`) },
    );
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Nueva organización</h1>
          <p>Cargá el alcance: dominios y, si querés, redes de IP propias. Baqueano analiza solo eso, con datos públicos y sin tocar los equipos.</p>
        </div>
      </div>
      <Card>
        <form onSubmit={submit} className="stack" style={{ maxWidth: 680 }}>
          <div className="field">
            <label htmlFor="org-name">Nombre</label>
            <input id="org-name" className="input" placeholder="Mi empresa" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="org-domains">Dominios (uno por línea o separados por coma)</label>
            <textarea id="org-domains" className="input" rows={3} placeholder={"miempresa.com\nmiempresa.com.ar"} value={domains} onChange={(e) => setDomains(e.target.value)} />
            <span className="small muted">Se incluyen sus subdominios. Los nombres que apuntan a servicios de terceros (CDN, SaaS) no se consultan.</span>
          </div>
          <div className="field">
            <label htmlFor="org-nets">Redes de IP propias (opcional)</label>
            <textarea id="org-nets" className="input" rows={2} placeholder="203.0.113.0/24" value={networks} onChange={(e) => setNetworks(e.target.value)} />
            <span className="small muted">IP públicas o redes de hasta un /20 cada una.</span>
          </div>
          <div className="callout">
            <label style={{ display: "flex", gap: 12, alignItems: "flex-start", cursor: "pointer" }}>
              <input type="checkbox" checked={accepted} onChange={(e) => setAccepted(e.target.checked)} style={{ marginTop: 4 }} />
              <span>{ATTESTATION_TEXT}</span>
            </label>
            <div className="field" style={{ marginTop: 12 }}>
              <label htmlFor="org-by">Tu nombre (queda en el historial de la organización)</label>
              <input id="org-by" className="input" placeholder="Nombre y apellido" value={by} onChange={(e) => setBy(e.target.value)} />
            </div>
          </div>
          <div className="row">
            <button className="btn btn--primary" type="submit" disabled={create.isPending || !ready}>
              Crear organización
            </button>
            {create.isError && <span style={{ color: "var(--sev-critica)" }}>{(create.error as Error).message}</span>}
          </div>
        </form>
      </Card>
    </>
  );
}
