import { describe, expect, it } from "vitest";
import type { Finding } from "@/shared/api/types";
import { filterFindings } from "./filter";

const f = (id: string, severity: Finding["severity"], category: Finding["category"], asset: string, cve?: string): Finding => ({
  id, rule: "X", category, severity, title: `t${id}`, detail: "d", recommendation: "r", asset, cve,
});
const all = [f("1", "critica", "servicio-expuesto", "203.0.113.10:3389"), f("2", "alta", "tls", "198.51.100.1:443"), f("3", "media", "vulnerabilidad", "198.51.100.2:80", "CVE-2099-0001"), f("4", "critica", "vulnerabilidad", "198.51.100.3:443")];

describe("filterFindings", () => {
  it("sin filtros", () => {
    const r = filterFindings(all, { severity: [], category: [], q: "" });
    expect(r.items).toHaveLength(4);
    expect(r.facets.severity).toEqual({ critica: 2, alta: 1, media: 1 });
  });
  it("las facetas no se achican por su propio filtro", () => {
    const r = filterFindings(all, { severity: ["critica"], category: [], q: "" });
    expect(r.items.map((x) => x.id)).toEqual(["1", "4"]);
    expect(r.facets.severity.alta).toBe(1);
    expect(r.facets.category).toEqual({ "servicio-expuesto": 1, vulnerabilidad: 1 });
  });
  it("busca por CVE, IP y combina", () => {
    expect(filterFindings(all, { severity: [], category: [], q: "cve-2099" }).items.map((x) => x.id)).toEqual(["3"]);
    expect(filterFindings(all, { severity: [], category: ["vulnerabilidad"], q: "198.51.100.3" }).items.map((x) => x.id)).toEqual(["4"]);
  });
});
