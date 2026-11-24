import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./index";
import type { CreateOrgRequest } from "./types";

export const keys = {
  health: ["health"] as const,
  overview: ["overview"] as const,
  org: (id: string) => ["org", id] as const,
  snapshot: (id: string) => ["snapshot", id] as const,
  changes: (id: string) => ["snapshot", id, "changes"] as const,
  job: (id: string) => ["job", id] as const,
  intel: ["intel"] as const,
  cve: (id: string) => ["cve", id] as const,
};

export const useIntel = () => useQuery({ queryKey: keys.intel, queryFn: api.intel });
export const useCVE = (id: string) => useQuery({ queryKey: keys.cve(id), queryFn: () => api.cve(id), staleTime: 300_000 });
export function useUpdateIntel() {
  const qc = useQueryClient();
  return useMutation({ mutationFn: () => api.updateIntel(), onSuccess: (st) => qc.setQueryData(keys.intel, st) });
}
export function useStartReassess(id: string) {
  return useMutation({ mutationFn: () => api.startReassess(id) });
}

export const useHealth = () => useQuery({ queryKey: keys.health, queryFn: api.health, staleTime: 60_000 });
export const useOverview = () => useQuery({ queryKey: keys.overview, queryFn: api.overview });
export const useOrg = (id: string) => useQuery({ queryKey: keys.org(id), queryFn: () => api.org(id) });
export const useSnapshot = (id?: string) =>
  useQuery({ queryKey: keys.snapshot(id ?? ""), queryFn: () => api.snapshot(id!), enabled: !!id, staleTime: Infinity });
export const useChanges = (id?: string) =>
  useQuery({ queryKey: keys.changes(id ?? ""), queryFn: () => api.changes(id!), enabled: !!id, staleTime: Infinity });

/** Consulta el avance de un escaneo cada segundo hasta que termina. */
export const useJob = (id?: string) =>
  useQuery({
    queryKey: keys.job(id ?? ""),
    queryFn: () => api.job(id!),
    enabled: !!id,
    refetchInterval: (q) => (q.state.data?.status === "running" || !q.state.data ? 1000 : false),
  });

function useInvalidateOrg() {
  const qc = useQueryClient();
  return (id?: string) => {
    void qc.invalidateQueries({ queryKey: keys.overview });
    if (id) void qc.invalidateQueries({ queryKey: keys.org(id) });
  };
}

export function useCreateOrg() {
  const inv = useInvalidateOrg();
  return useMutation({ mutationFn: (req: CreateOrgRequest) => api.createOrg(req), onSuccess: (o) => inv(o.id) });
}
export function useAddDomain(id: string) {
  const inv = useInvalidateOrg();
  return useMutation({ mutationFn: (d: string) => api.addDomain(id, d), onSuccess: () => inv(id) });
}
export function useVerify(id: string) {
  const inv = useInvalidateOrg();
  return useMutation({ mutationFn: () => api.verify(id), onSuccess: () => inv(id) });
}
export function useAddNetwork(id: string) {
  const inv = useInvalidateOrg();
  return useMutation({ mutationFn: (n: string) => api.addNetwork(id, n), onSuccess: () => inv(id) });
}
export function useAttest(id: string) {
  const inv = useInvalidateOrg();
  return useMutation({ mutationFn: (by: string) => api.attest(id, by), onSuccess: () => inv(id) });
}

export function useDeleteOrg() {
  const inv = useInvalidateOrg();
  return useMutation({ mutationFn: (id: string) => api.deleteOrg(id), onSuccess: () => inv() });
}
export function useStartScan(id: string) {
  return useMutation({ mutationFn: () => api.startScan(id) });
}
export { useInvalidateOrg };
