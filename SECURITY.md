# Política de seguridad

## Cómo reportar una vulnerabilidad

Si encontrás una vulnerabilidad en Baqueano, **no abras un issue público**. Reportala de forma privada desde la pestaña
**Security → Report a vulnerability** del repositorio (GitHub Private Vulnerability Reporting).

Incluí, si podés: versión, pasos para reproducirla, impacto y una propuesta de corrección. Respondo dentro de los 7 días y
coordino la publicación de la corrección con quien la reportó.

## Versiones con soporte

Solo la última versión publicada recibe correcciones de seguridad.

## Alcance

Entran en alcance, por ejemplo:
- que el servidor exponga datos o secretos (claves de Shodan, Censys, NVD, Jira o SMTP, o URL de webhooks);
- que se pueda analizar algo fuera del alcance declarado o verificado;
- falsificación de pedidos (CSRF), DNS rebinding o saltear el token de acceso;
- que un dato malicioso de una fuente externa (Shodan, Censys, registros CVE) ejecute código o inyecte contenido en el panel o en las exportaciones.

No entran: problemas en las fuentes externas mismas, ni configuraciones expuestas a propósito (por ejemplo, `serve` en `0.0.0.0` sin red de por medio).

## Diseño

El [modelo de amenazas](docs/modelo-de-amenazas.md) describe qué protege Baqueano, de quién y con qué controles.
La [política de datos](docs/datos.md) explica qué se guarda, dónde y por cuánto tiempo.
