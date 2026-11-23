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
};

/** Mismo texto que domain.AttestationText en el backend. */
export const ATTESTATION_TEXT =
  "Declaro que soy responsable de estos dominios y redes, o que tengo autorización de su dueño para analizarlos. " +
  "Entiendo que Baqueano solo usa datos públicos y que esta declaración queda registrada.";
