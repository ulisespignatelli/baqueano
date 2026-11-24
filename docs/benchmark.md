# Benchmark de precisión

Generado con `baqueano bench`. 46 casos reales: un servicio visto desde internet, una CVE que la fuente de exposición propone por la versión, y si de verdad lo afecta según el aviso del fabricante. Los registros son copias del repositorio oficial [cvelistV5](https://github.com/CVEProject/cvelistV5) (incluye los datos de CISA Vulnrichment). Esta corrida es **sin conexión y sin NVD**: es el piso, no el techo.

| Métrica | Sin verificar (v0.1) | Baqueano |
|---|---|---|
| Precisión (de lo que se informa como vulnerable, cuánto lo es) | 46 % | **100 %** |
| Falsos positivos | 25 | **0** |
| Descartes peligrosos (afectada pero descartada) | 0 | **0** |
| Afectadas que se informan con confianza | 21 de 21 | 18 de 21 (86 %) |
| Descartadas correctamente (con datos estructurados) | 0 | 13 |
| «Improbables» (fuera de tramos en texto, prioridad mínima) | 0 | 6 (1 sí afectadas) |
| «Por confirmar» | 0 | 9 (2 sí afectadas) |

Solo se descarta con datos estructurados. Lo que no se puede afirmar queda **por confirmar** (baja un nivel de prioridad salvo que esté en KEV) y lo que cae fuera de tramos escritos en texto libre queda **improbable**, visible pero al final de la lista.

## Casos

| Resultado | Servicio | CVE | ¿Afectada? | Baqueano dijo | Motivo |
|---|---|---|---|---|---|
| ⚠️ improbable pero afectada | Apache Tomcat 9.0.30 | CVE-2020-1938 | sí — Ghostcat; el registro escribe «9.0.0.30» por 9.0.30 | improbable | La versión 9.0.30 queda fuera de los tramos publicados (desde 9.0.0.M1, hasta 9.0.0.30; desde 8.5.0, hasta 8.5.50; desde 7.0.0, hasta 7.0.99). Como esos tramos están en texto libre, no se descarta: queda con la prioridad más baja. |
| ⏳ por confirmar | OpenSSH 8.9p1 (paquete de Ubuntu) | CVE-2024-6387 | no — Ubuntu la corrigió en 1:8.9p1-3ubuntu0.10 (USN-6859-1) sin cambiar la versión de origen | por-confirmar | La versión 8.9p1 está dentro del rango afectado (desde 8.5p1, hasta 9.7p1) según registro CVE. Pero el servicio usa un paquete de Ubuntu (3ubuntu0.10): las distribuciones corrigen sin cambiar la versión de origen. Confirmalo con el aviso de seguridad de la distribución. |
| ⏳ por confirmar | OpenSSH 8.9p1 | CVE-2023-38408 | sí — ssh-agent, corregida en 9.3p2; el registro CVE no trae versiones (n/a) | por-confirmar | Los datos publicados no detallan qué versiones están afectadas. |
| ⏳ por confirmar | OpenSSH 9.6p1 | CVE-2023-38408 | no — corregida en 9.3p2 | por-confirmar | Los datos publicados no detallan qué versiones están afectadas. |
| ⏳ por confirmar | Apache httpd 2.4.51 | CVE-2021-41773 | no — corregida en 2.4.50/2.4.51 | por-confirmar | La versión 2.4.51 no figura en los rangos publicados (2.4; 2.4.49), pero parte de esos datos está en texto libre: no alcanza para descartarla. |
| ⏳ por confirmar | Apache httpd 2.4.48 | CVE-2021-42013 | no — anterior al cambio que introdujo el fallo | por-confirmar | La versión 2.4.48 no figura en los rangos publicados (2.4.49; 2.4.50), pero parte de esos datos está en texto libre: no alcanza para descartarla. |
| ⏳ por confirmar | BIG-IP 16.1.2.2 | CVE-2022-1388 | no — corregida en 16.1.2.2 | por-confirmar | La versión 16.1.2.2 no figura en los rangos publicados (rama 16.1.x, antes de 16.1.2.2; rama 15.1.x, antes de 15.1.5.1; rama 14.1.x, antes de 14.1.4.6; rama 13.1.x, antes de 13.1.5), pero parte de esos datos está en texto libre: no alcanza para descartarla. |
| ⏳ por confirmar | Exim smtpd 4.91 | CVE-2019-10149 | sí — afecta 4.87 a 4.91; el registro dice solo «4.92» | por-confirmar | La versión 4.91 no figura en los rangos publicados (4.92), pero parte de esos datos está en texto libre: no alcanza para descartarla. |
| ⏳ por confirmar | Exim smtpd 4.92 | CVE-2019-10149 | no — 4.92 es la versión corregida (el registro está mal cargado) | por-confirmar | El registro nombra solo la versión 4.92, sin aclarar si es la afectada o la que la corrige. |
| ⏳ por confirmar | Redis key-value store 6.0.9 | CVE-2022-0543 | no — fallo del empaquetado de Debian, no de Redis de origen | por-confirmar | Los datos publicados no detallan qué versiones están afectadas. |
| ✅ improbable | Apache httpd 2.4.39 | CVE-2019-0211 | no — corregida en 2.4.39 | improbable | La versión 2.4.39 queda fuera de los tramos publicados (desde 2.4.17, hasta 2.4.38). Como esos tramos están en texto libre, no se descarta: queda con la prioridad más baja. |
| ✅ improbable | Apache httpd 2.4.46 | CVE-2020-11984 | no — corregida en 2.4.46 | improbable | La versión 2.4.46 queda fuera de los tramos publicados (desde 2.4.32, hasta 2.4.44). Como esos tramos están en texto libre, no se descarta: queda con la prioridad más baja. |
| ✅ improbable | nginx 1.20.1 | CVE-2021-23017 | no — corregida en 1.20.1 | improbable | La versión 1.20.1 queda fuera de los tramos publicados (desde 0.6.18, hasta 1.20.0). Como esos tramos están en texto libre, no se descarta: queda con la prioridad más baja. |
| ✅ improbable | Apache Tomcat 9.0.31 | CVE-2020-1938 | no — corregida en 9.0.31 | improbable | La versión 9.0.31 queda fuera de los tramos publicados (desde 9.0.0.M1, hasta 9.0.0.30; desde 8.5.0, hasta 8.5.50; desde 7.0.0, hasta 7.0.99). Como esos tramos están en texto libre, no se descarta: queda con la prioridad más baja. |
| ✅ improbable | Fortinet FortiGate SSL VPN 6.0.5 | CVE-2018-13379 | no — corregida en 6.0.5 | improbable | La versión 6.0.5 queda fuera de los tramos publicados (desde 6.0.0, hasta 6.0.4; desde 5.6.3, hasta 5.6.7; desde 5.4.6, hasta 5.4.12; desde 1.2.0, hasta 1.2.8). Como esos tramos están en texto libre, no se descarta: queda con la prioridad más baja. |
| ✅ | OpenSSH 8.9p1 | CVE-2024-6387 | sí — regreSSHion afecta 8.5p1 a 9.7p1 | probable | La versión 8.9p1 está dentro del rango afectado (desde 8.5p1, hasta 9.7p1) según registro CVE. |
| ✅ | OpenSSH 9.8p1 | CVE-2024-6387 | no — corregida en 9.8p1 | descartada | La versión 9.8p1 no está en ningún rango afectado (desde 8.5p1, hasta 9.7p1). |
| ✅ | OpenSSH 7.4p1 | CVE-2024-6387 | no — 7.4p1 es anterior a la regresión de 8.5p1 | descartada | La versión 7.4p1 no está en ningún rango afectado (desde 8.5p1, hasta 9.7p1). |
| ✅ | Apache httpd 2.4.49 | CVE-2021-41773 | sí — path traversal, solo 2.4.49 | probable | La versión 2.4.49 está dentro del rango afectado (2.4.49) según registro CVE. El rango se interpretó de texto libre. |
| ✅ | Apache httpd 2.4.50 | CVE-2021-42013 | sí — afecta 2.4.49 y 2.4.50 | probable | La versión 2.4.50 está dentro del rango afectado (2.4.50) según registro CVE. El rango se interpretó de texto libre. |
| ✅ | Apache httpd 2.4.55 | CVE-2023-25690 | sí — afecta 2.4.0 a 2.4.55 | probable | La versión 2.4.55 está dentro del rango afectado (desde 2.4.0, hasta 2.4.55) según registro CVE. |
| ✅ | Apache httpd 2.4.57 | CVE-2023-25690 | no — corregida en 2.4.56 | descartada | La versión 2.4.57 no está en ningún rango afectado (desde 2.4.0, hasta 2.4.55). |
| ✅ | Apache httpd 2.4.59 | CVE-2024-38476 | sí — afecta hasta 2.4.59 | probable | La versión 2.4.59 está dentro del rango afectado (desde 2.4.0, hasta 2.4.59) según registro CVE. |
| ✅ | Apache httpd 2.4.62 | CVE-2024-38476 | no — corregida en 2.4.60 | descartada | La versión 2.4.62 no está en ningún rango afectado (desde 2.4.0, hasta 2.4.59; hasta 2.4.59). |
| ✅ | Apache httpd 2.4.51 | CVE-2021-44790 | sí — mod_lua, hasta 2.4.51 | probable | La versión 2.4.51 está dentro del rango afectado (rama 2.4.x, hasta 2.4.51) según registro CVE. |
| ✅ | Apache httpd 2.4.52 | CVE-2021-44790 | no — corregida en 2.4.52 | descartada | La versión 2.4.52 no está en ningún rango afectado (rama 2.4.x, hasta 2.4.51). |
| ✅ | Apache httpd 2.4.48 | CVE-2021-40438 | sí — SSRF en mod_proxy, hasta 2.4.48 | probable | La versión 2.4.48 está dentro del rango afectado (rama 2.4.x, hasta 2.4.48) según registro CVE. |
| ✅ | Apache httpd 2.4.49 | CVE-2021-40438 | no — corregida en 2.4.49 | descartada | La versión 2.4.49 no está en ningún rango afectado (rama 2.4.x, hasta 2.4.48). |
| ✅ | Apache httpd 2.4.38 | CVE-2019-0211 | sí — escalada local, 2.4.17 a 2.4.38 | probable | La versión 2.4.38 está dentro del rango afectado (desde 2.4.17, hasta 2.4.38) según registro CVE. El rango se interpretó de texto libre. |
| ✅ | Apache httpd 2.4.44 | CVE-2020-11984 | sí — mod_proxy_uwsgi, 2.4.32 a 2.4.44 | probable | La versión 2.4.44 está dentro del rango afectado (desde 2.4.32, hasta 2.4.44) según registro CVE. El rango se interpretó de texto libre. |
| ✅ | nginx 1.18.0 | CVE-2021-23017 | sí — resolver, 0.6.18 a 1.20.0 | probable | La versión 1.18.0 está dentro del rango afectado (desde 0.6.18, hasta 1.20.0) según registro CVE. El rango se interpretó de texto libre. |
| ✅ | nginx 1.25.3 | CVE-2024-24989 | sí — HTTP/3, solo 1.25.3 | probable | La versión 1.25.3 está dentro del rango afectado (desde 1.25.3, antes de 1.25.4) según registro CVE. |
| ✅ | nginx 1.24.0 | CVE-2024-24989 | no — la rama 1.24 no tiene el módulo afectado | descartada | La versión 1.24.0 no está en ningún rango afectado (desde 1.25.3, antes de 1.25.4). |
| ✅ | PHP 7.3.10 | CVE-2019-11043 | sí — PHP-FPM, 7.3.x antes de 7.3.11 | probable | La versión 7.3.10 está dentro del rango afectado (rama 7.3.x, antes de 7.3.11) según registro CVE. |
| ✅ | PHP 7.3.11 | CVE-2019-11043 | no — corregida en 7.3.11 | descartada | La versión 7.3.11 no está en ningún rango afectado (rama 7.1.x, antes de 7.1.33; rama 7.2.x, antes de 7.2.24; rama 7.3.x, antes de 7.3.11). |
| ✅ | PHP 7.4.0 | CVE-2019-11043 | no — 7.4.0 salió con la corrección | descartada | La versión 7.4.0 no está en ningún rango afectado (rama 7.1.x, antes de 7.1.33; rama 7.2.x, antes de 7.2.24; rama 7.3.x, antes de 7.3.11). |
| ✅ | PHP 8.1.28 | CVE-2024-4577 | sí — CGI en Windows, 8.1.x antes de 8.1.29 | probable | La versión 8.1.28 está dentro del rango afectado (rama 8.1.x, antes de 8.1.29) según registro CVE. |
| ✅ | PHP 8.1.29 | CVE-2024-4577 | no — corregida en 8.1.29 | descartada | La versión 8.1.29 no está en ningún rango afectado (rama 8.1.x, antes de 8.1.29; rama 8.2.x, antes de 8.2.20; rama 8.3.x, antes de 8.3.8; desde 8.1.0, antes de 8.1.29). |
| ✅ | PHP 8.3.8 | CVE-2024-4577 | no — corregida en 8.3.8 | descartada | La versión 8.3.8 no está en ningún rango afectado (rama 8.1.x, antes de 8.1.29; rama 8.2.x, antes de 8.2.20; rama 8.3.x, antes de 8.3.8; desde 8.1.0, antes de 8.1.29). |
| ✅ | Apache Tomcat 8.5.50 | CVE-2020-1938 | sí — Ghostcat, 8.5.0 a 8.5.50 | probable | La versión 8.5.50 está dentro del rango afectado (desde 8.5.0, hasta 8.5.50) según registro CVE. El rango se interpretó de texto libre. |
| ✅ | Apache ActiveMQ 5.18.2 | CVE-2023-46604 | sí — OpenWire, 5.18.x antes de 5.18.3 | probable | La versión 5.18.2 está dentro del rango afectado (desde 5.18.0, antes de 5.18.3) según registro CVE. |
| ✅ | Apache ActiveMQ 5.18.3 | CVE-2023-46604 | no — corregida en 5.18.3 | descartada | La versión 5.18.3 no está en ningún rango afectado (desde 5.18.0, antes de 5.18.3; desde 5.17.0, antes de 5.17.6; desde 5.16.0, antes de 5.16.7; antes de 5.15.16). |
| ✅ | BIG-IP 16.1.2 | CVE-2022-1388 | sí — iControl REST, 16.1.x antes de 16.1.2.2 | probable | La versión 16.1.2 está dentro del rango afectado (rama 16.1.x, antes de 16.1.2.2) según registro CVE. El rango se interpretó de texto libre. |
| ✅ | PAN-OS 10.2.5 | CVE-2024-3400 | sí — GlobalProtect, 10.2 antes de 10.2.9-h1 | probable | La versión 10.2.5 está dentro del rango afectado (desde 10.2.0, antes de 10.2.9-h1) según registro CVE. |
| ✅ | PAN-OS 10.2.9-h1 | CVE-2024-3400 | no — hotfix que la corrige | descartada | La versión 10.2.9-h1 no está en ningún rango afectado (desde 10.2.0, antes de 10.2.9-h1; desde 11.0.0, antes de 11.0.4-h1; desde 11.1.0, antes de 11.1.2-h3; desde 10.2.0, antes de 10.2.9-h1). |
| ✅ | Fortinet FortiGate SSL VPN 6.0.4 | CVE-2018-13379 | sí — lectura de archivos en el portal SSL VPN, 6.0.0 a 6.0.4 | probable | La versión 6.0.4 está dentro del rango afectado (desde 6.0.0, hasta 6.0.4) según registro CVE. El rango se interpretó de texto libre. |

## Qué muestran los errores

- Los casos «por confirmar» con CVE de OpenSSH vienen de registros sin versiones (`n/a`). Con la NVD (o con `NVD_API_KEY`) esos rangos se completan.
- Exim CVE-2019-10149: el registro oficial dice «4.92», que es justamente la versión corregida. Por eso los datos de texto libre nunca alcanzan para descartar.
- Tomcat CVE-2020-1938: el registro escribe «9.0.0.30» en lugar de 9.0.30, así que 9.0.30 queda como improbable aunque está afectada. Sigue en la lista, y como está en KEV conserva la marca de explotación activa.
