# ADR 0006 — Contexto, reglas y estados se aplican al mostrar

**Estado:** aceptada · **Fecha:** 2026-11

## Contexto
La severidad de Baqueano es genérica: un RDP abierto es crítico en cualquier lado. Pero no es lo mismo en un servidor de desarrollo que en
el de la planta, y cada organización tiene su propia política. Además, los equipos necesitan registrar decisiones: «lo estamos
corrigiendo», «aceptamos el riesgo hasta marzo», «es un falso positivo».

## Decisión
- La organización guarda su **contexto** (ambiente, criticidad y responsable por nombre, comodín, IP o red), sus **reglas** de severidad y el
  **estado** de cada hallazgo (por su identificador estable).
- Todo eso se aplica **al mostrar**, no al escanear: un cambio vale al instante y también para el historial, sin volver a escanear.
- La severidad original queda en `base_severity` y cada ajuste dice por qué (`adjustments`). Nada se oculta.
- El contexto ajusta un nivel (desarrollo y pruebas bajan, criticidad alta sube); lo que está en KEV o es P1 **no baja nunca** por contexto.
  Las reglas fijan la severidad y exigen un motivo.
- Aceptar un riesgo exige motivo, responsable y **vencimiento** (máximo un año). Al vencer, el hallazgo vuelve a contar y dice que venció.
  Los aceptados vigentes y los falsos positivos no cuentan para el puntaje.
- Cada cambio queda en el historial de auditoría.

## Consecuencias
- El puntaje y las alertas reflejan la realidad de la organización, con la decisión y su autor a la vista.
- Mostrar un escaneo cuesta leer la organización; para el historial de puntajes se recalculan hasta 20 escaneos por organización.
