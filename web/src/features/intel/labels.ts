import type { Confidence } from "@/shared/api/types";

export const priorityLabel: Record<string, string> = { P1: "Corregir hoy", P2: "Esta semana", P3: "Este mes", P4: "Planificar" };

export const confidenceLabel: Record<Confidence, string> = {
  confirmada: "Confirmada",
  probable: "Probable",
  "por-confirmar": "Por confirmar",
  improbable: "Improbable",
  descartada: "Descartada",
};

export const confidenceHelp: Record<Confidence, string> = {
  confirmada: "La fuente la verificó con una prueba sobre el servicio.",
  probable: "La versión del servicio está dentro de un rango afectado publicado.",
  "por-confirmar": "Falta información para afirmarla o descartarla. Baja un nivel de prioridad salvo que esté en KEV.",
  improbable: "La versión queda fuera de los tramos publicados en texto libre. Se muestra con la prioridad más baja.",
  descartada: "Datos estructurados dicen que esta versión no está afectada.",
};

export const dataSourceLabel: Record<string, string> = {
  nvd: "NVD",
  cve: "Registro CVE",
  "cisa-adp": "CISA Vulnrichment",
  kev: "CISA KEV",
  epss: "FIRST EPSS",
};

export const originLabel: Record<string, string> = {
  shodan: "Shodan",
  internetdb: "Shodan InternetDB",
  baqueano: "Baqueano (versión contra NVD)",
};

export const ssvcLabel: { exploitation: Record<string, string>; automatable: Record<string, string>; technical_impact: Record<string, string> } = {
  exploitation: { none: "sin explotación conocida", poc: "prueba de concepto pública", active: "explotación activa" },
  automatable: { yes: "automatizable", no: "no automatizable" },
  technical_impact: { partial: "impacto parcial", total: "impacto total" },
};

export const qualityLabel: Record<string, string> = {
  estructurado: "estructurado",
  texto: "texto libre",
  "sin-versiones": "sin versiones",
};
