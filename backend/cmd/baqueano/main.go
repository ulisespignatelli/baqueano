// Comando baqueano: vigilancia de la superficie externa de ataque de organizaciones que lo autorizaron.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/ulisespignatelli/baqueano/backend/internal/adapters/httpapi"
	"github.com/ulisespignatelli/baqueano/backend/internal/adapters/store"
	"github.com/ulisespignatelli/baqueano/backend/internal/app"
	"github.com/ulisespignatelli/baqueano/backend/internal/config"
	"github.com/ulisespignatelli/baqueano/backend/internal/demodata"
	"github.com/ulisespignatelli/baqueano/backend/internal/discovery"
	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
	"github.com/ulisespignatelli/baqueano/backend/internal/exposure"
)

var version = "dev"

const usage = `baqueano — superficie externa de ataque, con autorización verificada

Uso:
  baqueano org add NOMBRE DOMINIO [DOMINIO…] --responsable "Tu Nombre" [--red 203.0.113.0/24]
                                               crea una organización y registra tu declaración de responsabilidad
                                               (sin --responsable, solo se analizan los dominios verificados en DNS)
  baqueano org list                            organizaciones y estado de verificación
  baqueano org verify ID                       comprueba los registros DNS (verificación opcional)
  baqueano scan ID                             analiza una organización (dominios verificados)
  baqueano serve                               levanta la API y el panel en http://127.0.0.1:8080
  baqueano demo --out DIR                      genera los datos de la demo (organizaciones ficticias)
  baqueano version

Opciones comunes:
  --data CARPETA    carpeta de datos (por defecto .baqueano)
  --source FUENTE   shodan | internetdb | none (por defecto: shodan si hay SHODAN_API_KEY, si no internetdb)
  --addr DIR        (serve) dónde escuchar, por defecto 127.0.0.1:8080
  --token TOKEN     (serve) exige este token para modificar datos; obligatorio fuera de localhost

La clave de Shodan se lee de la variable SHODAN_API_KEY o de un archivo .env en la carpeta actual.
`

func main() {
	config.LoadDotEnv(".env")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	code, err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	os.Exit(code)
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

type opts struct {
	data, source, addr, token, out, responsible string
	networks                                    multi
	fs                                          *flag.FlagSet
}

func parse(args []string, stderr io.Writer) (*opts, []string, error) {
	o := &opts{fs: flag.NewFlagSet("baqueano", flag.ContinueOnError)}
	o.fs.SetOutput(stderr)
	o.fs.Usage = func() { fmt.Fprint(stderr, usage) }
	o.fs.StringVar(&o.data, "data", ".baqueano", "")
	o.fs.StringVar(&o.source, "source", "", "")
	o.fs.StringVar(&o.addr, "addr", "127.0.0.1:8080", "")
	o.fs.StringVar(&o.token, "token", os.Getenv("BAQUEANO_TOKEN"), "")
	o.fs.StringVar(&o.out, "out", "", "")
	o.fs.StringVar(&o.responsible, "responsable", "", "")
	o.fs.Var(&o.networks, "red", "")
	var pos, flags []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flags = append(flags, args[i])
			if !strings.Contains(args[i], "=") && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
		} else {
			pos = append(pos, args[i])
		}
	}
	if err := o.fs.Parse(flags); err != nil {
		return nil, nil, err
	}
	return o, pos, nil
}

func (o *opts) service() (*app.Service, string, error) {
	repo, err := store.Open(o.data)
	if err != nil {
		return nil, "", err
	}
	src, name, err := exposureSource(o.source)
	if err != nil {
		return nil, "", err
	}
	return &app.Service{Repo: repo, DNS: net.DefaultResolver, Discovery: discovery.New(), Exposure: src}, name, nil
}

func exposureSource(choice string) (exposure.Source, string, error) {
	key := strings.TrimSpace(os.Getenv("SHODAN_API_KEY"))
	if choice == "" {
		choice = "internetdb"
		if key != "" {
			choice = "shodan"
		}
	}
	switch choice {
	case "shodan":
		if key == "" {
			return nil, "", errors.New("falta SHODAN_API_KEY (en el entorno o en un archivo .env)")
		}
		return exposure.NewShodan(key), "shodan", nil
	case "internetdb":
		return exposure.NewInternetDB(), "internetdb", nil
	case "none":
		return nil, "none", nil
	}
	return nil, "", fmt.Errorf("fuente desconocida %q (shodan, internetdb o none)", choice)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2, nil
	}
	cmd := args[0]
	o, pos, err := parse(args[1:], stderr)
	if err != nil {
		return 2, nil
	}
	switch cmd {
	case "version", "--version":
		fmt.Fprintln(stdout, "baqueano", version)
		return 0, nil
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0, nil
	case "org":
		return orgCmd(ctx, o, pos, stdout)
	case "scan":
		if len(pos) != 1 {
			return 2, errors.New("uso: baqueano scan ID")
		}
		svc, src, err := o.service()
		if err != nil {
			return 1, err
		}
		fmt.Fprintf(stderr, "fuente de exposición: %s\n", src)
		if sh, ok := svc.Exposure.(*exposure.Shodan); ok {
			plan, credits, err := sh.APIInfo(ctx)
			if err != nil {
				return 1, err
			}
			fmt.Fprintf(stderr, "Shodan: plan %s, %d créditos de consulta disponibles (la consulta por IP no los usa)\n", plan, credits)
		}
		snap, err := svc.Scan(ctx, pos[0], func(m string) { fmt.Fprintln(stderr, "·", m) })
		if err != nil {
			return 1, err
		}
		printSummary(stdout, snap)
		return 0, nil
	case "serve":
		return serve(ctx, o, stderr)
	case "demo":
		if o.out == "" {
			return 2, errors.New("falta --out")
		}
		repo, err := store.Open(o.data)
		if err != nil {
			return 1, err
		}
		if _, err := demodata.Build(ctx, repo, time.Date(2026, 11, 16, 14, 0, 0, 0, time.UTC)); err != nil {
			return 1, err
		}
		if err := httpapi.WriteSnapshot(ctx, &app.Service{Repo: repo}, o.out); err != nil {
			return 1, err
		}
		fmt.Fprintln(stderr, "demo escrita en", o.out)
		return 0, nil
	}
	fmt.Fprint(stderr, usage)
	return 2, fmt.Errorf("comando desconocido %q", cmd)
}

func orgCmd(ctx context.Context, o *opts, pos []string, stdout io.Writer) (int, error) {
	if len(pos) == 0 {
		return 2, errors.New("uso: baqueano org add|list|verify")
	}
	repo, err := store.Open(o.data)
	if err != nil {
		return 1, err
	}
	svc := &app.Service{Repo: repo, DNS: net.DefaultResolver}
	switch pos[0] {
	case "add":
		if len(pos) < 3 {
			return 2, errors.New("uso: baqueano org add NOMBRE DOMINIO [DOMINIO…]")
		}
		org, err := svc.CreateOrg(ctx, app.NewOrg{Name: pos[1], Domains: pos[2:], Networks: o.networks, DeclaredBy: o.responsible})
		if err != nil {
			return 1, err
		}
		fmt.Fprintf(stdout, "Organización %q creada (ID %s).\n", org.Name, org.ID)
		if org.Attestation != nil {
			fmt.Fprintf(stdout, "\nDeclaración registrada a nombre de %s:\n  «%s»\n\nYa podés escanear: baqueano scan %s\n", org.Attestation.By, domain.AttestationText, org.ID)
		} else {
			fmt.Fprintf(stdout, "\nSin --responsable, solo se analizan los dominios verificados en DNS. Publicá estos TXT y corré `baqueano org verify %s`:\n\n", org.ID)
		}
		fmt.Fprintln(stdout, "\nVerificación DNS (opcional, deja constancia de que el dueño autoriza):")
		for _, d := range org.Domains {
			fmt.Fprintf(stdout, "  %s  TXT  \"%s\"\n", d.Name, d.TXTRecord())
		}
		return 0, nil
	case "list":
		orgs, err := repo.ListOrgs(ctx)
		if err != nil {
			return 1, err
		}
		for _, org := range orgs {
			fmt.Fprintf(stdout, "%s  %s\n", org.ID, org.Name)
			if org.Attestation != nil {
				fmt.Fprintf(stdout, "    declarado por %s el %s\n", org.Attestation.By, org.Attestation.At.Format("2006-01-02"))
			}
			for _, d := range org.Domains {
				state := "sin autorización"
				switch {
				case d.Verified():
					state = "verificado en DNS"
				case org.Authorized(d):
					state = "declarado"
				}
				fmt.Fprintf(stdout, "    %-32s %s  %s\n", d.Name, state, strings.Join(d.Networks, ", "))
			}
		}
		return 0, nil
	case "verify":
		if len(pos) != 2 {
			return 2, errors.New("uso: baqueano org verify ID")
		}
		org, err := svc.VerifyDomains(ctx, pos[1])
		if err != nil {
			return 1, err
		}
		for _, d := range org.Domains {
			if d.Verified() {
				fmt.Fprintf(stdout, "✓ %s verificado%s\n", d.Name, map[bool]string{true: " · redes: " + strings.Join(d.Networks, ", "), false: ""}[len(d.Networks) > 0])
			} else {
				fmt.Fprintf(stdout, "✗ %s: %s. Registro esperado: TXT \"%s\"\n", d.Name, d.CheckError, d.TXTRecord())
			}
			if d.Verified() && d.CheckError != "" {
				fmt.Fprintf(stdout, "  aviso: %s\n", d.CheckError)
			}
		}
		return 0, nil
	}
	return 2, fmt.Errorf("subcomando desconocido %q", pos[0])
}

func printSummary(w io.Writer, s domain.Snapshot) {
	m := app.Meta(s)
	fmt.Fprintf(w, "\n%s · puntaje %d/100 · %d activos · %d IP · %d servicios · %d hallazgos\n", s.OrgName, m.Score, m.Assets, m.IPs, m.Services, m.Findings)
	for _, sev := range []domain.Severity{domain.SevCritical, domain.SevHigh, domain.SevMedium, domain.SevLow} {
		if n := m.BySeverity[string(sev)]; n > 0 {
			fmt.Fprintf(w, "  %-7s %d\n", sev, n)
		}
	}
	for i, f := range s.Findings {
		if i == 10 {
			fmt.Fprintf(w, "  … y %d más (ver el panel: baqueano serve)\n", len(s.Findings)-10)
			break
		}
		fmt.Fprintf(w, "  [%s] %s — %s\n", strings.ToUpper(string(f.Severity)), f.Title, f.Asset)
	}
	for _, n := range s.Notes {
		fmt.Fprintln(w, "  nota:", n)
	}
}

func serve(ctx context.Context, o *opts, stderr io.Writer) (int, error) {
	host, _, err := net.SplitHostPort(o.addr)
	if err != nil {
		return 2, fmt.Errorf("--addr inválido: %w", err)
	}
	ip := net.ParseIP(host)
	loopback := host == "localhost" || (ip != nil && ip.IsLoopback())
	if !loopback && o.token == "" {
		return 2, errors.New("escuchar fuera de localhost exige --token (o BAQUEANO_TOKEN)")
	}
	svc, src, err := o.service()
	if err != nil {
		return 1, err
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	h := httpapi.New(svc, httpapi.Config{Token: o.token, Loopback: loopback, Version: version, Source: src, Logger: log})
	srv := &http.Server{Addr: o.addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	ln, err := net.Listen("tcp", o.addr)
	if err != nil {
		return 1, err
	}
	keyInfo := ""
	if k := os.Getenv("SHODAN_API_KEY"); k != "" && src == "shodan" {
		keyInfo = " (clave " + config.Mask(k) + ")"
	}
	fmt.Fprintf(stderr, "baqueano %s · panel en http://%s · fuente %s%s · datos en %s\n", version, ln.Addr(), src, keyInfo, o.data)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
		return 0, nil
	case err := <-errc:
		return 1, err
	}
}
