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
	"path/filepath"
	"strconv"
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
	"github.com/ulisespignatelli/baqueano/backend/internal/intel"
	"github.com/ulisespignatelli/baqueano/backend/internal/notify"
)

var version = "dev"

const usage = `baqueano — superficie externa de ataque e inteligencia de vulnerabilidades

Uso:
  baqueano org add NOMBRE DOMINIO [DOMINIO…] --responsable "Tu Nombre" [--red 203.0.113.0/24]
                                               crea una organización y registra tu declaración de responsabilidad
                                               (sin --responsable, solo se analizan los dominios verificados en DNS)
  baqueano org list                            organizaciones y estado de verificación
  baqueano org verify ID                       comprueba los registros DNS (verificación opcional)
  baqueano scan ID                             analiza una organización y evalúa sus vulnerabilidades
  baqueano reassess ID                         vuelve a evaluar el último escaneo con la inteligencia actual (sin Shodan)
  baqueano schedule ID --cada 24h [--modo reevaluar]   programa escaneos (o reevaluaciones) periódicos
  baqueano schedule ID --off                   desactiva la programación
  baqueano prune --dias 365 [--conservar 3]    borra escaneos viejos (conserva siempre los últimos de cada organización)
  baqueano run-due                             ejecuta lo programado que esté pendiente (para cron o el
                                               Programador de tareas de Windows; serve lo hace solo)
  baqueano intel update                        descarga el catálogo KEV y refresca EPSS
  baqueano intel status                        estado de la base de inteligencia
  baqueano intel cve CVE-AAAA-NNNN             lo que se sabe de una CVE (versiones afectadas, KEV, EPSS, SSVC)
  baqueano bench [--corpus DIR] [--out F]      benchmark de precisión del motor (casos reales)
  baqueano serve                               levanta la API y el panel en http://127.0.0.1:8080
  baqueano demo --out DIR                      genera los datos de la demo (organizaciones ficticias)
  baqueano version

Opciones comunes:
  --data CARPETA    carpeta de datos (por defecto .baqueano)
  --source FUENTES  shodan | internetdb | censys | none, combinables: shodan,censys
                    (por defecto: shodan si hay SHODAN_API_KEY, si no internetdb; más censys si hay CENSYS_API_TOKEN)
  --addr DIR        (serve) dónde escuchar, por defecto 127.0.0.1:8080
  --token TOKEN     (serve) exige este token para modificar datos; obligatorio fuera de localhost
  --offline         no consulta fuentes de inteligencia: usa solo la base guardada

La clave de Shodan se lee de SHODAN_API_KEY y la de la NVD (opcional, acelera las consultas) de
NVD_API_KEY, en el entorno o en un archivo .env en la carpeta actual.
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
	corpus, every, mode                         string
	days, keep                                  int
	offline, off                                bool
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
	o.fs.StringVar(&o.corpus, "corpus", "../bench", "")
	o.fs.BoolVar(&o.offline, "offline", false, "")
	o.fs.BoolVar(&o.off, "off", false, "")
	o.fs.StringVar(&o.every, "cada", "24h", "")
	o.fs.IntVar(&o.days, "dias", 365, "")
	o.fs.IntVar(&o.keep, "conservar", 3, "")
	o.fs.StringVar(&o.mode, "modo", "escanear", "")
	var pos, flags []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flags = append(flags, args[i])
			name := strings.TrimLeft(args[i], "-")
			if !strings.Contains(args[i], "=") && i+1 < len(args) && name != "offline" && name != "off" {
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

// intel abre la base de inteligencia de la carpeta de datos.
func (o *opts) intel() (*intel.Engine, error) {
	e, err := intel.Open(filepath.Join(o.data, "intel", "intel.json.gz"))
	if err != nil {
		return nil, err
	}
	if !o.offline {
		c := intel.NewClient()
		c.NVDKey = strings.TrimSpace(os.Getenv("NVD_API_KEY"))
		e.Client = c
	}
	e.UseNVD = !strings.EqualFold(os.Getenv("BAQUEANO_NVD"), "off")
	return e, nil
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
	eng, err := o.intel()
	if err != nil {
		return nil, "", err
	}
	return &app.Service{Repo: repo, DNS: net.DefaultResolver, Discovery: discovery.New(), Exposure: src, Intel: eng, Notifier: notify.FromEnv()}, name, nil
}

func exposureSource(choice string) (exposure.Source, string, error) {
	key := strings.TrimSpace(os.Getenv("SHODAN_API_KEY"))
	censysToken := strings.TrimSpace(os.Getenv("CENSYS_API_TOKEN"))
	if choice == "" {
		choice = "internetdb"
		if key != "" {
			choice = "shodan"
		}
		if censysToken != "" {
			choice += ",censys"
		}
	}
	if choice == "none" {
		return nil, "none", nil
	}
	var srcs []exposure.Source
	for _, c := range strings.Split(choice, ",") {
		switch strings.TrimSpace(c) {
		case "shodan":
			if key == "" {
				return nil, "", errors.New("falta SHODAN_API_KEY (en el entorno o en un archivo .env)")
			}
			srcs = append(srcs, exposure.NewShodan(key))
		case "internetdb":
			srcs = append(srcs, exposure.NewInternetDB())
		case "censys":
			if censysToken == "" {
				return nil, "", errors.New("falta CENSYS_API_TOKEN (en el entorno o en un archivo .env)")
			}
			cz := exposure.NewCensys(censysToken, strings.TrimSpace(os.Getenv("CENSYS_ORG_ID")))
			if n, err := strconv.Atoi(os.Getenv("CENSYS_MAX_LOOKUPS")); err == nil && n > 0 {
				cz.MaxLookups = n
			}
			srcs = append(srcs, cz)
		default:
			return nil, "", fmt.Errorf("fuente desconocida %q (shodan, internetdb, censys o none; se pueden combinar: shodan,censys)", c)
		}
	}
	src := exposure.NewMulti(srcs...)
	return src, src.Name(), nil
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
	case "reassess":
		if len(pos) != 1 {
			return 2, errors.New("uso: baqueano reassess ID")
		}
		svc, _, err := o.service()
		if err != nil {
			return 1, err
		}
		snap, err := svc.Reassess(ctx, pos[0], func(m string) { fmt.Fprintln(stderr, "·", m) })
		if err != nil {
			return 1, err
		}
		printSummary(stdout, snap)
		return 0, nil
	case "intel":
		return intelCmd(ctx, o, pos, stdout, stderr)
	case "schedule":
		if len(pos) != 1 {
			return 2, errors.New("uso: baqueano schedule ID --cada 24h [--modo escanear|reevaluar] | --off")
		}
		svc, _, err := o.service()
		if err != nil {
			return 1, err
		}
		d, err := time.ParseDuration(o.every)
		if err != nil {
			return 2, fmt.Errorf("--cada inválido (ejemplos: 24h, 168h): %w", err)
		}
		org, err := svc.SetSchedule(ctx, pos[0], domain.Schedule{Enabled: !o.off, Hours: int(d.Hours()), Mode: o.mode})
		if err != nil {
			return 1, err
		}
		if sc := org.Schedule; sc != nil && sc.Enabled {
			fmt.Fprintf(stdout, "%s: %s cada %d h. Próxima corrida: %s.\n", org.Name, sc.Mode, sc.Hours, sc.NextRun.Local().Format("2006-01-02 15:04"))
			fmt.Fprintln(stdout, "Se ejecuta mientras corra «baqueano serve», o programá «baqueano run-due» en cron o en el Programador de tareas.")
		} else {
			fmt.Fprintln(stdout, org.Name+": programación desactivada.")
		}
		return 0, nil
	case "prune":
		svc, _, err := o.service()
		if err != nil {
			return 1, err
		}
		n, err := svc.Prune(ctx, o.days, o.keep)
		if err != nil {
			return 1, err
		}
		fmt.Fprintf(stdout, "%d escaneo(s) de más de %d días borrado(s); se conservan siempre los %d más recientes de cada organización.\n", n, o.days, o.keep)
		return 0, nil
	case "run-due":
		svc, _, err := o.service()
		if err != nil {
			return 1, err
		}
		n, err := svc.RunDue(ctx, func(m string) { fmt.Fprintln(stderr, "·", m) })
		if err != nil {
			return 1, err
		}
		fmt.Fprintf(stdout, "%d corrida(s) programada(s) ejecutada(s).\n", n)
		return 0, nil
	case "bench":
		c, db, err := intel.LoadBench(o.corpus)
		if err != nil {
			return 1, fmt.Errorf("no se pudo leer el benchmark en %s: %w", o.corpus, err)
		}
		r := intel.RunBench(c, db)
		md := r.Markdown()
		if o.out != "" {
			if err := os.WriteFile(o.out, []byte(md), 0o644); err != nil {
				return 1, err
			}
			fmt.Fprintln(stderr, "informe escrito en", o.out)
		}
		fmt.Fprintf(stdout, "%d casos · precisión %.0f %% (sin verificar %.0f %%) · falsos positivos %d · descartes peligrosos %d · afectadas informadas %d de %d · por confirmar %d · improbables %d\n",
			len(r.Cases), r.Precision()*100, r.BaselinePrecision()*100, r.FP, r.FNHard, r.TP, r.Positives, r.Pending, r.Unlikely)
		if r.FNHard > 0 {
			return 1, errors.New("hay descartes peligrosos")
		}
		return 0, nil
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
		eng := intel.NewMemory(demodata.Intel())
		eng.Now = func() time.Time { return time.Date(2026, 11, 23, 14, 0, 0, 0, time.UTC) }
		if err := httpapi.WriteSnapshot(ctx, &app.Service{Repo: repo}, o.out, eng); err != nil {
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
	eng, _ := svc.Intel.(*intel.Engine)
	h := httpapi.New(svc, httpapi.Config{Token: o.token, Loopback: loopback, Version: version, Source: src, Logger: log, Intel: eng})
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
	go func() { // corridas programadas
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				svc.StartDue(ctx)
			}
		}
	}()
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

func intelCmd(ctx context.Context, o *opts, pos []string, stdout, stderr io.Writer) (int, error) {
	if len(pos) == 0 {
		return 2, errors.New("uso: baqueano intel update|status|cve ID")
	}
	e, err := o.intel()
	if err != nil {
		return 1, err
	}
	switch pos[0] {
	case "update":
		if err := e.Update(ctx, func(m string) { fmt.Fprintln(stderr, "·", m) }); err != nil {
			return 1, err
		}
		fallthrough
	case "status":
		st := e.Status()
		fmt.Fprintf(stdout, "Base de inteligencia en %s · %d CVE con datos · %s\n", filepath.Join(o.data, "intel"), st.Records,
			map[bool]string{true: "con conexión", false: "sin conexión"}[st.Online])
		for _, s := range st.Sources {
			when := "nunca"
			if s.Updated != nil {
				when = s.Updated.Format("2006-01-02 15:04")
			}
			fmt.Fprintf(stdout, "  %-34s %6d datos · actualizado: %s", s.Name, s.Items, when)
			if s.Error != "" {
				fmt.Fprintf(stdout, " · último error: %s", s.Error)
			}
			fmt.Fprintln(stdout)
		}
		if os.Getenv("NVD_API_KEY") == "" {
			fmt.Fprintln(stdout, "  Sugerencia: con una clave gratuita de la NVD (NVD_API_KEY) las consultas son 10 veces más rápidas.")
		}
		return 0, nil
	case "cve":
		if len(pos) != 2 {
			return 2, errors.New("uso: baqueano intel cve CVE-AAAA-NNNN")
		}
		info, err := e.Lookup(ctx, pos[1])
		if err != nil {
			return 1, err
		}
		if r := info.Record; r != nil {
			fmt.Fprintf(stdout, "%s · publicada %s · CVSS %.1f · fuentes: %s\n", r.CVE, r.Published, r.CVSS, strings.Join(r.Sources, ", "))
			if r.Summary != "" {
				fmt.Fprintln(stdout, " ", r.Summary)
			}
			if s := r.SSVC; s != nil {
				fmt.Fprintf(stdout, "  SSVC (CISA): explotación %s · automatizable %s · impacto técnico %s\n", s.Exploitation, s.Automatable, s.TechnicalImpact)
			}
			for _, a := range r.Affected {
				var rs []string
				for _, x := range a.Ranges {
					rs = append(rs, x.String())
				}
				switch {
				case a.NotAffected:
					rs = []string{"no afectado"}
				case a.AllVersions && len(rs) == 0:
					rs = []string{"sin detalle de versiones"}
				}
				fmt.Fprintf(stdout, "  afectado: %s [%s, datos %s] %s\n", a.Name, a.Source, a.Quality, strings.Join(rs, "; "))
			}
		}
		if k := info.KEV; k != nil {
			fmt.Fprintf(stdout, "  KEV: agregada %s, plazo %s%s\n", k.Added, k.Due, map[bool]string{true: ", usada en ransomware", false: ""}[k.Ransomware])
		}
		if x := info.EPSS; x != nil {
			fmt.Fprintf(stdout, "  EPSS: %.4f (percentil %.0f) al %s\n", x.Score, x.Percentile*100, x.Date)
		}
		return 0, nil
	}
	return 2, fmt.Errorf("subcomando desconocido %q", pos[0])
}
