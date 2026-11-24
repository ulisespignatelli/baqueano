import type { Finding } from "@/shared/api/types";

export interface FindingFilter {
  severity: string[];
  category: string[];
  q: string;
  /** Estados a mostrar. Vacío = los activos (abiertos y en curso). */
  status?: string[];
}

export const statusOf = (x: Finding) => x.state?.status ?? "abierto";

/** Filtra hallazgos. Cada faceta cuenta con los demás filtros aplicados (no con el suyo). */
export function filterFindings(all: Finding[], f: FindingFilter) {
  const q = f.q.trim().toLowerCase();
  const facets = { severity: {} as Record<string, number>, category: {} as Record<string, number>, status: {} as Record<string, number> };
  const items: Finding[] = [];
  const status = f.status ?? [];
  for (const x of all) {
    if (q && !`${x.title} ${x.detail} ${x.asset} ${x.cve ?? ""} ${x.rule} ${x.owner ?? ""}`.toLowerCase().includes(q)) continue;
    const st = statusOf(x);
    const mSt = status.length === 0 ? st === "abierto" || st === "en-curso" : status.includes(st);
    const mSev = f.severity.length === 0 || f.severity.includes(x.severity);
    const mCat = f.category.length === 0 || f.category.includes(x.category);
    if (mSev && mCat) facets.status[st] = (facets.status[st] ?? 0) + 1;
    if (!mSt) continue;
    if (mCat) facets.severity[x.severity] = (facets.severity[x.severity] ?? 0) + 1;
    if (mSev) facets.category[x.category] = (facets.category[x.category] ?? 0) + 1;
    if (mSev && mCat) items.push(x);
  }
  return { items, facets };
}
