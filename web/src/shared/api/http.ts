import { ApiError, type DataSource } from "./types";

const BASE = "/api/v1";
const enc = encodeURIComponent;

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    ...init,
    headers: {
      Accept: "application/json",
      "X-Requested-With": "baqueano", // defensa contra CSRF
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
    },
  });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      msg = ((await res.json()) as { error?: string }).error ?? msg;
    } catch {
      /* sin JSON */
    }
    throw new ApiError(res.status, msg);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}

const post = <T,>(path: string, body?: unknown) => request<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });

export const httpSource: DataSource = {
  mode: "api",
  health: () => request("/health"),
  overview: () => request("/overview"),
  org: (id) => request(`/orgs/${enc(id)}`),
  snapshot: (id) => request(`/snapshots/${enc(id)}`),
  changes: (id) => request(`/snapshots/${enc(id)}/changes`),
  createOrg: (req) => post("/orgs", req),
  addDomain: (id, domain) => post(`/orgs/${enc(id)}/domains`, { domain }),
  verify: (id) => post(`/orgs/${enc(id)}/verify`),
  addNetwork: (id, network) => post(`/orgs/${enc(id)}/networks`, { network }),
  attest: (id, by) => post(`/orgs/${enc(id)}/attestation`, { by, accepted: true }),
  deleteOrg: (id) => request(`/orgs/${enc(id)}`, { method: "DELETE" }),
  startScan: (id) => post(`/orgs/${enc(id)}/scans`),
  job: (id) => request(`/jobs/${enc(id)}`),
  startReassess: (id) => post(`/orgs/${enc(id)}/reassess`),
  intel: () => request("/intel"),
  updateIntel: () => post("/intel/update"),
  cve: (id) => request(`/intel/cves/${enc(id)}`),
  saveContext: (id, c) => post(`/orgs/${enc(id)}/contexts`, c),
  deleteContext: (id, cid) => request(`/orgs/${enc(id)}/contexts/${enc(cid)}`, { method: "DELETE" }),
  saveRule: (id, r) => post(`/orgs/${enc(id)}/rules`, r),
  deleteRule: (id, rid) => request(`/orgs/${enc(id)}/rules/${enc(rid)}`, { method: "DELETE" }),
  setState: (id, fid, c) => post(`/orgs/${enc(id)}/findings/${enc(fid)}/state`, c),
  saveAlert: (id, a) => post(`/orgs/${enc(id)}/alerts`, a),
  deleteAlert: (id, aid) => request(`/orgs/${enc(id)}/alerts/${enc(aid)}`, { method: "DELETE" }),
  testAlert: (id, aid) => post(`/orgs/${enc(id)}/alerts/${enc(aid)}/test`),
  setSchedule: (id, sc) => post(`/orgs/${enc(id)}/schedule`, sc),
  exportUrl: (id, format) => `${BASE}/snapshots/${enc(id)}/export?format=${format}`,
};
