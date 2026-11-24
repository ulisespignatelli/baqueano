import { ApiError, type DataSource } from "./types";

// Modo demostración: JSON estáticos generados con `baqueano demo` (organizaciones ficticias).
const cache = new Map<string, Promise<unknown>>();
function get<T>(path: string): Promise<T> {
  let p = cache.get(path);
  if (!p) {
    p = fetch(`${import.meta.env.BASE_URL}demo/${path}`).then(async (r) => {
      if (!r.ok) throw new ApiError(r.status, r.status === 404 ? "no encontrado" : r.statusText);
      return r.json();
    });
    p.catch(() => cache.delete(path));
    cache.set(path, p);
  }
  return p as Promise<T>;
}
const safe = (id: string) => {
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(id)) throw new ApiError(404, "no encontrado");
  return id;
};
const readOnly = () => Promise.reject(new ApiError(403, "La demo es de solo lectura: instalá Baqueano para analizar tus dominios."));

export const demoSource: DataSource = {
  mode: "demo",
  health: () => get("health.json"),
  overview: () => get("overview.json"),
  org: (id) => get(`orgs/${safe(id)}.json`),
  snapshot: (id) => get(`snapshots/${safe(id)}.json`),
  changes: (id) => get(`snapshots/${safe(id)}/changes.json`),
  createOrg: readOnly,
  addDomain: readOnly,
  verify: readOnly,
  addNetwork: readOnly,
  attest: readOnly,
  deleteOrg: readOnly,
  startScan: readOnly,
  job: readOnly,
  startReassess: readOnly,
  intel: () => get("intel.json"),
  updateIntel: readOnly,
  cve: (id) => {
    if (!/^CVE-\d{4}-\d{4,}$/.test(id)) return Promise.reject(new ApiError(404, "no encontrado"));
    return get(`intel/cves/${id}.json`);
  },
  exportUrl: () => null,
};
