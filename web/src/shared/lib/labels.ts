import type { Severity } from "@/shared/api/types";

export const SEVERITIES: Severity[] = ["critica", "alta", "media", "baja", "info"];

export const severityLabel: Record<Severity, string> = {
  critica: "Crítica",
  alta: "Alta",
  media: "Media",
  baja: "Baja",
  info: "Info",
};

export const CATEGORIES = ["servicio-expuesto", "vulnerabilidad", "tls", "dns", "higiene"] as const;

export const categoryLabel: Record<string, string> = {
  "servicio-expuesto": "Servicio expuesto",
  vulnerabilidad: "Vulnerabilidad",
  tls: "TLS",
  dns: "DNS",
  higiene: "Higiene",
};

export const sourceLabel: Record<string, string> = {
  shodan: "Shodan (API)",
  internetdb: "Shodan InternetDB (gratuita)",
  none: "Sin fuente de exposición",
  demo: "Datos de demostración",
  censys: "Censys",
};

/** Nombre legible de una fuente o combinación ("shodan+censys"). */
export const sourceName = (s: string) => s.split("+").map((x) => sourceLabel[x] ?? x).join(" + ");

export const statusLabel: Record<string, string> = { abierto: "Abierto", "en-curso": "En curso", aceptado: "Riesgo aceptado", "falso-positivo": "Falso positivo" };
export const STATUSES = ["abierto", "en-curso", "aceptado", "falso-positivo"] as const;
export const envLabel: Record<string, string> = { produccion: "Producción", pruebas: "Pruebas", desarrollo: "Desarrollo" };
export const critLabel: Record<string, string> = { alta: "Criticidad alta", normal: "Criticidad normal", baja: "Criticidad baja" };
export const channelLabel: Record<string, string> = { webhook: "Webhook", slack: "Slack", teams: "Microsoft Teams", email: "Correo", jira: "Jira" };
export const eventLabel: Record<string, string> = {
  "hallazgo-nuevo": "Hallazgo nuevo",
  "sube-severidad": "Sube la severidad",
  "servicio-nuevo": "Servicio nuevo",
  kev: "Vulnerabilidad en KEV",
  resumen: "Resumen de cada escaneo",
};

/** Mismo texto que domain.AttestationText en el backend. */
export const ATTESTATION_TEXT =
  "Declaro que soy responsable de estos dominios y redes, o que tengo autorización de su dueño para analizarlos. " +
  "Entiendo que Baqueano solo usa datos públicos y que esta declaración queda registrada.";
