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

describe("estados", () => {
  const mk = (id: string, status?: string) =>
    ({ id, rule: "PX-RDP", category: "servicio-expuesto", severity: "alta", title: id, detail: "", recommendation: "", asset: "x",
      state: status ? { status, at: "2099-01-01T00:00:00Z" } : undefined }) as Finding;
  const all = [mk("a"), mk("b", "en-curso"), mk("c", "aceptado"), mk("d", "falso-positivo")];
  it("por defecto muestra solo los activos y cuenta todos", () => {
    const r = filterFindings(all, { severity: [], category: [], q: "" });
    expect(r.items.map((x) => x.id)).toEqual(["a", "b"]);
    expect(r.facets.status).toEqual({ abierto: 1, "en-curso": 1, aceptado: 1, "falso-positivo": 1 });
  });
  it("filtra por estado", () => {
    expect(filterFindings(all, { severity: [], category: [], q: "", status: ["aceptado"] }).items.map((x) => x.id)).toEqual(["c"]);
  });
});
