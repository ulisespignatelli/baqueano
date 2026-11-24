# Política de datos

## Qué se guarda y dónde

Todo queda **en el equipo donde corre Baqueano**, en la carpeta de datos (`.baqueano` por defecto, `--data` para cambiarla). No hay servidor central ni telemetría.

| Archivo | Contenido |
|---|---|
| `orgs/*.json` | Organizaciones: alcance, declaración, historial de auditoría, contexto, reglas, estados, programación y alertas (con las URL de webhook) |
| `snapshots/*.json` | Cada escaneo: activos, servicios, hallazgos y fuentes |
| `intel/intel.json.gz` | Base de inteligencia: KEV, EPSS, registros CVE y rangos de versiones (datos públicos) |

Los archivos se escriben de forma atómica y con permisos solo para el usuario. La carpeta está en `.gitignore`.

## Qué sale del equipo

- **A las fuentes de exposición** (Shodan, Censys, InternetDB): las IP del alcance, una por consulta.
- **A crt.sh y al DNS público**: los dominios del alcance.
- **A las fuentes de inteligencia** (registro CVE, NVD, EPSS, endoflife.date, CISA): identificadores de CVE y nombres y versiones de producto. Nunca IP ni dominios.
- **A los destinos de alertas que configures**: el resumen y los hallazgos del escaneo.

## Retención

Los escaneos se guardan hasta que los borres. Para aplicar una retención:

```bash
baqueano prune --dias 365 --conservar 3   # borra los de más de un año, pero nunca los 3 últimos de cada organización
```

Se puede programar con cron o con el Programador de tareas de Windows. Cada borrado queda en el historial de la organización.

Borrar una organización desde el panel borra también todos sus escaneos.

## Secretos

Las claves (`SHODAN_API_KEY`, `CENSYS_API_TOKEN`, `NVD_API_KEY`, `JIRA_API_TOKEN`, `SMTP_PASSWORD`, `BAQUEANO_WEBHOOK_SECRET`) se leen del entorno o de `.env` y **nunca se guardan con los datos**. Las URL de webhook sí se guardan, porque son el destino de la alerta; la API nunca las devuelve completas.
