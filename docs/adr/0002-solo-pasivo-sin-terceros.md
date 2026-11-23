# ADR 0002 — Solo datos pasivos, y nunca IP de terceros

**Estado:** aceptada · **Fecha:** 2026-11

## Decisión
- **No se escanea.** Los subdominios salen de Certificate Transparency y los servicios, de datos que Shodan ya recolectó. Baqueano no envía tráfico a los equipos analizados; solo consulta DNS público.
- **No se consultan IP de terceros.** Si un subdominio es un CNAME a una CDN o un SaaS conocido (Cloudflare, CloudFront, Shopify, Heroku…), su IP pertenece al proveedor: no se consulta en Shodan. El informe dice cuántas se omitieron.
- Las vulnerabilidades que Shodan **infiere por la versión** del banner se marcan «por confirmar» y bajan un nivel de severidad, salvo que estén en el catálogo KEV.

## Consecuencias
- Hay servicios que Baqueano no ve (los que Shodan no indexó). Es una vista "desde afuera", no un escaneo de vulnerabilidades.
- Los hallazgos son prudentes: lo confirmado se distingue de lo inferido.
