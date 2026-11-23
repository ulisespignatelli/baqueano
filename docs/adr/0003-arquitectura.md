# ADR 0003 — Arquitectura

**Estado:** aceptada · **Fecha:** 2026-11

Es la misma base que en cryptoinv: un monorepo con backend en Go (hexagonal y solo con biblioteca estándar), un panel en React embebido en el binario, un contrato OpenAPI del que se generan los tipos, y una demo en GitHub Pages que usa el mismo panel con datos estáticos.

```
domain      modelo puro (Organization, Asset, Service, Finding, Snapshot, puntaje)
scope       qué se puede analizar: validación de dominios y redes, verificación DNS opcional
discovery   Certificate Transparency + DNS; proveedores de terceros conocidos
exposure    fuentes: Shodan (API REST) e InternetDB (gratuita), detrás de una interfaz
rules       hallazgos: lógica pura y explicada
app         casos de uso: organizaciones, verificación, escaneo en segundo plano, cambios
adapters    store (JSON atómico), httpapi (API + panel + demo estática)
demodata    escenario ficticio que pasa por el pipeline real (tests y demo)
```

Los escaneos con Shodan tardan minutos (≈ 1 consulta por segundo), por eso la API los lanza en segundo plano y el panel consulta el avance.
