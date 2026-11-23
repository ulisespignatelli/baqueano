# ADR 0004 — La clave de Shodan nunca sale del equipo

**Estado:** aceptada · **Fecha:** 2026-11

- Se lee de `SHODAN_API_KEY` o de un `.env` local (en `.gitignore`). No se guarda en los datos, en la API ni en el panel.
- Los errores de red de Go incluyen la URL completa, que lleva la clave. El cliente **nunca** devuelve el error original: lo reemplaza por un mensaje genérico. Un test lo verifica con un servidor caído.
- Al iniciar, `serve` muestra solo los últimos 4 caracteres de la clave.
- El CSV exportado escapa las celdas que empiezan con `=`, `+`, `-` o `@` para que una hoja de cálculo no las ejecute como fórmulas (inyección CSV): los títulos de las páginas vienen de internet.
