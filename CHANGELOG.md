# Cambios

## v0.5.0 — Varias fuentes de exposición
- Censys (Platform API v3) como segunda fuente, combinable con Shodan o InternetDB (`--source shodan,censys`).
- Consenso entre fuentes: cada servicio dice quién lo vio y el escaneo resume cuánto coinciden.
- Tope de consultas a Censys por escaneo (`CENSYS_MAX_LOOKUPS`), porque cada consulta consume créditos.
- Imagen Docker, binarios para Windows, Linux y macOS con sumas SHA-256, política de seguridad, modelo de amenazas y política de datos.
- `baqueano prune` para aplicar una retención.

## v0.4.0 — Automatización
- Escaneos o reevaluaciones programados (`serve` los ejecuta; `baqueano run-due` para cron o el Programador de tareas).
- Alertas por webhook (firmado con HMAC-SHA256), Slack, Microsoft Teams, correo y Jira (un ticket por hallazgo, sin duplicar).
- Filtros por evento (hallazgo nuevo, sube la severidad, servicio nuevo, KEV, resumen), severidad mínima y controles.

## v0.3.0 — Flujo de trabajo
- Contexto de activos: ambiente, criticidad y responsable por nombre, comodín, IP o red.
- Reglas de severidad propias de la organización.
- Estados de hallazgos: en curso, riesgo aceptado (con motivo, responsable y vencimiento) y falso positivo.
- La política se aplica al mostrar: vale al instante, también para el historial, y la severidad original queda a la vista.

## v0.2.0 — Inteligencia de vulnerabilidades
- Motor propio: versión contra rangos del registro CVE, CISA Vulnrichment y NVD; detección de paquetes de distribución; prioridad P1–P4 con KEV, ransomware, SSVC y EPSS; fin de soporte.
- Reevaluar sin escanear y cambios de severidad entre escaneos.
- Benchmark de precisión con casos reales en cada build.

## v0.1.0
- Alcance con responsable y auditoría, descubrimiento pasivo, exposición con Shodan, hallazgos explicados, cambios, panel y demo.
