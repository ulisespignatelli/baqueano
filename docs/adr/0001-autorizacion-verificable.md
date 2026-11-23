# ADR 0001 — Alcance con responsable declarado y verificación DNS opcional

**Estado:** aceptada (reemplaza la primera versión, que exigía la verificación DNS) · **Fecha:** 2026-11

## Contexto
Una herramienta de superficie de ataque puede usarse para mirar organizaciones ajenas. La primera versión exigía que el dueño publicara un registro TXT, pero eso dejaba afuera casos legítimos muy comunes: el consultor con un contrato, el analista de una empresa donde el DNS lo maneja otra área, la auditoría con permiso por escrito. Además, Baqueano solo usa datos públicos (Certificate Transparency, DNS, lo que Shodan ya indexó): exigir más que esas mismas fuentes era desproporcionado.

## Decisión
- **Alcance declarado (por defecto):** quien carga una organización acepta una declaración de responsabilidad con su nombre ("soy responsable de estos activos o tengo autorización de su dueño"). Queda con fecha en el **historial de auditoría** de la organización, y cada escaneo registra con qué autorización se hizo.
- **Verificación DNS (opcional):** si el dueño publica `baqueano-verify=<token>` como TXT, el dominio figura como "verificado". Se vuelve a comprobar antes de cada escaneo; si el registro se retira, la verificación se pierde y queda registrado.
- Sin declaración ni verificación, no se analiza nada.

### Límites que no cambian
Son los que hacen que la herramienta no sirva para mirar todo internet:
- Solo subdominios de los dominios cargados; un nombre parecido (`acme.example.evil.test`) no entra.
- No se consultan IP de servicios de terceros (CDN, SaaS).
- Redes públicas de hasta un /20; las privadas o reservadas se rechazan.
- Hasta 20 dominios y 16 redes por organización.
- Solo datos pasivos: ni escaneos ni tráfico hacia los equipos ([ADR 0002](0002-solo-pasivo-sin-terceros.md)).

## Consecuencias
- Se usa como las plataformas comerciales: con un responsable identificado y un registro de qué se hizo y cuándo.
- La verificación DNS sigue disponible para quien quiera una constancia verificable por terceros.
