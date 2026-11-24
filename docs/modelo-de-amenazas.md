# Modelo de amenazas

Baqueano junta información sensible: qué tiene expuesto una organización, qué vulnerabilidades tiene y qué decidió no corregir.
En manos equivocadas, eso es un mapa de ataque. Este documento dice qué se protege, de quién y cómo.

## Activos a proteger

| Activo | Por qué importa |
|---|---|
| Inventario, hallazgos y estados de cada organización | Es un mapa de ataque priorizado: incluye lo que se aceptó no corregir |
| Claves de Shodan, Censys y NVD | Gastan créditos de la cuenta y permiten consultas en su nombre |
| Credenciales de Jira y SMTP, URL de webhooks | Permiten escribir en sistemas de la organización |
| La herramienta misma | No debe poder usarse para mirar a terceros |

## Amenazas y controles

| Amenaza | Control |
|---|---|
| Usar Baqueano contra organizaciones ajenas | Alcance con responsable identificado y auditoría, verificación DNS opcional, solo subdominios de lo cargado, redes de hasta /20, nunca IP de terceros ni redes privadas ([ADR 0001](adr/0001-autorizacion-verificable.md)), solo datos pasivos ([ADR 0002](adr/0002-solo-pasivo-sin-terceros.md)) |
| Otro sitio web que el usuario visita manda pedidos al panel local (CSRF) | Toda operación que modifica exige el encabezado `X-Requested-With: baqueano`, que un formulario o un `<img>` de otro origen no pueden enviar |
| DNS rebinding contra el panel en `127.0.0.1` | Se valida el encabezado `Host` cuando el servidor escucha en localhost |
| Acceso por la red al panel | Escuchar fuera de localhost exige `--token`; en el contenedor también |
| Filtración de claves | Solo en el entorno o `.env` (en `.gitignore`); nunca en URL de pedidos (la de la NVD va en un encabezado), errores, registros ni respuestas de la API; se enmascaran al mostrarlas ([ADR 0004](adr/0004-secretos.md)) |
| Filtración de URL de webhooks | Se guardan en el equipo y la API las devuelve enmascaradas; guardar el valor enmascarado conserva el original |
| Datos maliciosos en banners, títulos o registros CVE | El panel nunca inserta HTML (React escapa todo); la política de contenido (CSP) bloquea scripts externos; las celdas CSV que empiezan con `= + - @` se neutralizan |
| SSRF desde las alertas | Los destinos de webhook tienen que ser `https` (http solo hacia el propio equipo), sin credenciales en la URL y sin seguir redirecciones |
| Descarte silencioso de una vulnerabilidad real | El motor solo descarta con datos estructurados; un benchmark en cada build falla si aparece un descarte peligroso ([ADR 0005](adr/0005-motor-de-inteligencia.md)) |
| Aceptaciones de riesgo olvidadas | Toda aceptación exige motivo, responsable y vencimiento (máximo un año); al vencer, el hallazgo vuelve a contar y lo dice |
| Ediciones simultáneas que se pisan | Las ediciones de una organización se serializan y el almacenamiento entrega copias independientes |
| Binarios alterados | Cada versión publica `SHA256SUMS.txt`; la imagen se construye en GitHub Actions desde el código |

## Fuera de alcance

- Un atacante con acceso al equipo donde corre Baqueano: puede leer la carpeta de datos. Usá cifrado de disco (BitLocker, FileVault, LUKS).
- La exactitud de las fuentes externas: Baqueano la mide (benchmark, consenso entre fuentes) pero no la garantiza.
