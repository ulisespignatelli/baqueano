import { Card } from "@/shared/ui";

export function AboutPage() {
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Cómo funciona</h1>
          <p>Qué hace Baqueano, de dónde saca los datos y qué no hace nunca.</p>
        </div>
      </div>
      <div className="grid grid--2">
        <Card title="1 · Alcance con responsable">
          <p>
            Quien carga una organización declara que es responsable de sus dominios y redes, o que tiene autorización del dueño. La declaración
            queda con nombre y fecha en el historial, y cada informe dice con qué autorización se analizó. Como constancia extra, el dueño puede
            verificar el dominio publicando un TXT <code>baqueano-verify=…</code>. Solo se analizan subdominios de los dominios cargados y redes
            públicas de hasta un /20.
          </p>
        </Card>
        <Card title="2 · Descubrimiento pasivo">
          <p>
            Los subdominios salen de <b>Certificate Transparency</b> (crt.sh) y se resuelven con DNS público. Si un subdominio apunta a un servicio
            de terceros (CDN, SaaS), sus IP <b>no se consultan</b>: pertenecen al proveedor, no a la organización.
          </p>
        </Card>
        <Card title="3 · Exposición con datos de Shodan">
          <p>
            Lo que internet ve de cada IP propia sale de datos que <b>Shodan ya recolectó</b>. Baqueano no escanea ni envía tráfico a los equipos.
            Con una cuenta de Shodan, la consulta por IP no consume créditos; sin cuenta se usa InternetDB, la API gratuita.
          </p>
        </Card>
        <Card title="4 · Vulnerabilidades verificadas, no copiadas">
          <p>
            Cada CVE se contrasta con los rangos de versiones del <b>registro CVE oficial</b>, <b>CISA Vulnrichment</b> y la <b>NVD</b>. Si la versión
            no está afectada se descarta (con el motivo a la vista); si el banner muestra un paquete de Ubuntu, Debian o RHEL queda «por confirmar»,
            porque las distros corrigen sin cambiar la versión. Además, la NVD encuentra CVE que la fuente no informó.
          </p>
        </Card>
        <Card title="5 · Prioridad por riesgo real">
          <p>
            Primero lo que se está explotando (<b>KEV</b> de CISA, uso en ransomware, <b>SSVC</b>), después la probabilidad de explotación
            (<b>EPSS</b>) y la severidad técnica (CVSS) al final. Cada CVE queda en P1 (hoy), P2 (esta semana), P3 (este mes) o P4 (planificar),
            con la explicación. «Reevaluar» vuelve a juzgar el último escaneo con la inteligencia nueva sin gastar créditos.
          </p>
        </Card>
        <Card title="6 · Precisión medida">
          <p>
            El motor se prueba en cada build contra casos reales con la respuesta del fabricante: precisión, falsos positivos y, sobre todo,
            <b> cero descartes peligrosos</b> (una CVE que afecta y se descarta). El informe está en <code>docs/benchmark.md</code>.
          </p>
        </Card>
        <Card title="7 · Hallazgos explicados">
          <p>
            Además de las CVE: servicios que no deberían estar en internet (RDP, bases de datos, protocolos industriales…), software sin soporte,
            certificados vencidos, subdominios tomables y paneles de administración públicos. Cada hallazgo dice qué es, por qué importa y cómo se
            corrige.
          </p>
        </Card>
      </div>
    </>
  );
}
