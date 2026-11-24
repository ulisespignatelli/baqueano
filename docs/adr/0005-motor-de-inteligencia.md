# ADR 0005 — Motor propio de inteligencia de vulnerabilidades

**Estado:** aceptada · **Fecha:** 2026-11

## Contexto
Las fuentes de exposición (Shodan, InternetDB) asocian CVE a un servicio por la versión del banner. Esa lista tiene muchos falsos positivos: versiones ya corregidas, paquetes de distribución con el parche retroportado, rangos mal cargados. En la primera versión Baqueano la copiaba tal cual, y en el benchmark solo el 46 % de lo que informaba era cierto.

Además, desde abril de 2026 la NVD ya no enriquece todas las CVE: muchas quedan sin rangos de versiones. Depender de una sola fuente no alcanza.

## Decisión
- Un motor (`internal/intel`) **juzga** cada CVE candidata comparando la versión del servicio con los rangos de tres fuentes: el **registro CVE oficial** (cvelistV5, en GitHub), el bloque de **CISA Vulnrichment** dentro de ese registro y la **NVD** (búsqueda por CPE con la versión exacta, que además encuentra CVE que la fuente no informó).
- **Nunca se descarta con datos poco confiables.** Solo los rangos estructurados (campos `lessThan`, `versionType`, CPE de la NVD) alcanzan para descartar. Los rangos en texto libre se interpretan para afirmar, pero si la versión cae afuera la CVE queda «improbable» (visible, prioridad mínima); una versión suelta en texto queda «por confirmar».
- Si el banner muestra un paquete de distribución, una CVE probable pasa a «por confirmar».
- La prioridad (P1 a P4) ordena por explotación real (KEV, ransomware, SSVC) antes que por severidad técnica (CVSS). Lo que está por confirmar baja un nivel salvo que esté en KEV.
- La base es local (`<datos>/intel/intel.json.gz`) y funciona sin conexión. Las fuentes se consultan a demanda con caché y respetando sus límites (NVD: 5 pedidos cada 30 s sin clave). La clave de la NVD va en un encabezado, nunca en la URL ni en los errores.
- Un **benchmark** con casos reales corre en cada build. El CI falla si aparece un descarte peligroso (una CVE que afecta y se descarta) o si la precisión baja del 90 %.

## Consecuencias
- Los informes dicen con qué confianza afecta cada CVE y por qué. Las descartadas siguen a la vista, con su motivo.
- La precisión pasa de 46 % a 100 % en el corpus actual, sin descartes peligrosos.
- Sigue habiendo casos «por confirmar» cuando las fuentes no publican versiones. El próximo paso es leer los avisos de seguridad de Ubuntu y Debian, y a más largo plazo un sensor interno que lea los paquetes instalados.
