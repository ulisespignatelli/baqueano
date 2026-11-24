// Package notify envia avisos de Baqueano a webhooks, Slack, Microsoft Teams, correo y Jira. Las
// credenciales (SMTP, Jira, firma de webhooks) se leen del entorno: nunca se guardan con los datos.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

// Item es un elemento de un aviso (casi siempre, un hallazgo).
type Item struct {
	FindingID string          `json:"finding_id,omitempty"`
	Rule      string          `json:"rule,omitempty"`
	Severity  domain.Severity `json:"severity"`
	Title     string          `json:"title"`
	Asset     string          `json:"asset"`
	Detail    string          `json:"detail,omitempty"`
	Change    string          `json:"change"` // nuevo | sube-severidad | servicio-nuevo | kev | actual
	KEV       bool            `json:"kev,omitempty"`
}

// Message es un aviso listo para enviar.
type Message struct {
	Event      string    `json:"event"` // baqueano.scan
	OrgID      string    `json:"org_id"`
	Org        string    `json:"org"`
	SnapshotID string    `json:"snapshot_id"`
	Title      string    `json:"title"`
	Summary    string    `json:"summary"`
	Score      int       `json:"score"`
	Items      []Item    `json:"items"`
	Link       string    `json:"link,omitempty"`
	At         time.Time `json:"at"`
	Test       bool      `json:"test,omitempty"`
}

// Sender envia avisos. Devuelve los tickets creados (Jira) por hallazgo.
type Sender struct {
	HTTP          *http.Client
	SMTPAddr      string // host:puerto
	SMTPUser      string
	SMTPPassword  string
	SMTPFrom      string
	JiraURL       string // https://miempresa.atlassian.net
	JiraEmail     string
	JiraToken     string
	JiraIssueType string
	WebhookSecret string // firma HMAC-SHA256 de los webhooks genericos
	MaxTickets    int
}

// FromEnv arma el emisor con las credenciales del entorno.
func FromEnv() *Sender {
	return &Sender{
		HTTP: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("el destino respondió con una redirección: configurá la URL final")
		}},
		SMTPAddr: os.Getenv("SMTP_ADDR"), SMTPUser: os.Getenv("SMTP_USER"), SMTPPassword: os.Getenv("SMTP_PASSWORD"), SMTPFrom: os.Getenv("SMTP_FROM"),
		JiraURL: strings.TrimRight(os.Getenv("JIRA_URL"), "/"), JiraEmail: os.Getenv("JIRA_EMAIL"), JiraToken: os.Getenv("JIRA_API_TOKEN"),
		JiraIssueType: envOr("JIRA_ISSUE_TYPE", "Task"), WebhookSecret: os.Getenv("BAQUEANO_WEBHOOK_SECRET"), MaxTickets: 10,
	}
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// Canales.
var Channels = []string{"webhook", "slack", "teams", "email", "jira"}

// ValidateTarget revisa el destino de un canal. Las URL tienen que ser https (http solo hacia el propio
// equipo, para receptores locales).
func ValidateTarget(channel, target string) error {
	target = strings.TrimSpace(target)
	switch channel {
	case "webhook", "slack", "teams":
		u, err := url.Parse(target)
		if err != nil || u.Host == "" {
			return errors.New("la URL del webhook no es válida")
		}
		host := u.Hostname()
		local := host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
		if u.Scheme != "https" && !(u.Scheme == "http" && local) {
			return errors.New("la URL tiene que usar https")
		}
		if u.User != nil {
			return errors.New("no pongas usuario y contraseña en la URL")
		}
	case "email":
		list, err := mail.ParseAddressList(target)
		if err != nil || len(list) == 0 || len(list) > 10 {
			return errors.New("indicá entre 1 y 10 direcciones de correo separadas por coma")
		}
	case "jira":
		if len(target) < 2 || len(target) > 20 || strings.ToUpper(target) != target || strings.ContainsAny(target, " /") {
			return errors.New("indicá la clave del proyecto de Jira (por ejemplo SEC)")
		}
	default:
		return fmt.Errorf("canal desconocido %q (%s)", channel, strings.Join(Channels, ", "))
	}
	return nil
}

// Mask oculta la parte secreta de un destino (las URL de webhook son credenciales).
func Mask(channel, target string) string {
	switch channel {
	case "webhook", "slack", "teams":
		u, err := url.Parse(target)
		if err != nil || u.Host == "" {
			return "…"
		}
		tail := ""
		if len(target) > 12 {
			tail = target[len(target)-4:]
		}
		return u.Scheme + "://" + u.Host + "/…" + tail
	}
	return target
}

// IsMasked dice si un destino es la version enmascarada (el panel lo devuelve sin cambios).
func IsMasked(target string) bool { return strings.Contains(target, "/…") }

// Send envia un aviso por el canal de la alerta.
func (s *Sender) Send(ctx context.Context, a domain.Alert, m Message) (map[string]string, error) {
	switch a.Channel {
	case "webhook":
		return nil, s.webhook(ctx, a.Target, m)
	case "slack":
		return nil, s.postJSON(ctx, a.Target, slackPayload(m), nil)
	case "teams":
		return nil, s.postJSON(ctx, a.Target, teamsPayload(m), nil)
	case "email":
		return nil, s.email(a.Target, m)
	case "jira":
		return s.jira(ctx, a, m)
	}
	return nil, fmt.Errorf("canal desconocido %q", a.Channel)
}

func (s *Sender) postJSON(ctx context.Context, u string, body any, hdr map[string]string) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return errors.New("URL inválida")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "baqueano")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("no se pudo enviar a %s: %v", hostOf(u), ue.Err)
		}
		return fmt.Errorf("no se pudo enviar a %s", hostOf(u))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s respondió %d", hostOf(u), resp.StatusCode)
	}
	return nil
}

func hostOf(u string) string {
	if p, err := url.Parse(u); err == nil && p.Host != "" {
		return p.Host
	}
	return "el destino"
}

// webhook generico: el JSON del aviso, firmado con HMAC-SHA256 si hay secreto configurado.
func (s *Sender) webhook(ctx context.Context, u string, m Message) error {
	b, _ := json.Marshal(m)
	hdr := map[string]string{}
	if s.WebhookSecret != "" {
		mac := hmac.New(sha256.New, []byte(s.WebhookSecret))
		mac.Write(b)
		hdr["X-Baqueano-Signature"] = "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}
	return s.postJSON(ctx, u, json.RawMessage(b), hdr)
}

var sevIcon = map[domain.Severity]string{domain.SevCritical: "🔴", domain.SevHigh: "🟠", domain.SevMedium: "🟡", domain.SevLow: "🔵", domain.SevInfo: "⚪"}

var changeLabel = map[string]string{"nuevo": "nuevo", "sube-severidad": "subió de severidad", "servicio-nuevo": "servicio nuevo", "kev": "en KEV", "actual": ""}

func itemLine(it Item) string {
	l := fmt.Sprintf("%s %s — %s", sevIcon[it.Severity], it.Title, it.Asset)
	if c := changeLabel[it.Change]; c != "" {
		l += " (" + c + ")"
	}
	return l
}

func slackPayload(m Message) map[string]any {
	var lines []string
	for i, it := range m.Items {
		if i == 15 {
			lines = append(lines, fmt.Sprintf("…y %d más", len(m.Items)-15))
			break
		}
		lines = append(lines, "• "+itemLine(it))
	}
	blocks := []map[string]any{
		{"type": "header", "text": map[string]any{"type": "plain_text", "text": clip(m.Title, 140)}},
		{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": clip(m.Summary, 2900)}},
	}
	if len(lines) > 0 {
		blocks = append(blocks, map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": clip(strings.Join(lines, "\n"), 2900)}})
	}
	if m.Link != "" {
		blocks = append(blocks, map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": "<" + m.Link + "|Abrir en Baqueano>"}})
	}
	return map[string]any{"text": m.Title, "blocks": blocks}
}

// teamsPayload: tarjeta adaptable para los webhooks de flujos de trabajo de Teams.
func teamsPayload(m Message) map[string]any {
	body := []map[string]any{
		{"type": "TextBlock", "text": m.Title, "weight": "Bolder", "size": "Medium", "wrap": true},
		{"type": "TextBlock", "text": m.Summary, "wrap": true},
	}
	for i, it := range m.Items {
		if i == 15 {
			body = append(body, map[string]any{"type": "TextBlock", "text": fmt.Sprintf("…y %d más", len(m.Items)-15), "wrap": true})
			break
		}
		body = append(body, map[string]any{"type": "TextBlock", "text": itemLine(it), "wrap": true, "spacing": "Small"})
	}
	card := map[string]any{"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": body}
	if m.Link != "" {
		card["actions"] = []map[string]any{{"type": "Action.OpenUrl", "title": "Abrir en Baqueano", "url": m.Link}}
	}
	return map[string]any{"type": "message", "attachments": []map[string]any{{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}}}
}

func plainText(m Message) string {
	var b strings.Builder
	b.WriteString(m.Summary + "\n\n")
	for _, it := range m.Items {
		b.WriteString("- " + itemLine(it) + "\n")
		if it.Detail != "" {
			b.WriteString("  " + clip(it.Detail, 400) + "\n")
		}
	}
	if m.Link != "" {
		b.WriteString("\n" + m.Link + "\n")
	}
	b.WriteString("\n— Baqueano\n")
	return b.String()
}

func (s *Sender) email(to string, m Message) error {
	if s.SMTPAddr == "" || s.SMTPFrom == "" {
		return errors.New("falta configurar SMTP_ADDR y SMTP_FROM para enviar correos")
	}
	list, err := mail.ParseAddressList(to)
	if err != nil {
		return errors.New("direcciones de correo inválidas")
	}
	var rcpt, hdrTo []string
	for _, a := range list {
		rcpt = append(rcpt, a.Address)
		hdrTo = append(hdrTo, a.String())
	}
	subject := strings.NewReplacer("\r", " ", "\n", " ").Replace(m.Title)
	msg := "From: " + s.SMTPFrom + "\r\nTo: " + strings.Join(hdrTo, ", ") + "\r\nSubject: " + mimeWord(subject) +
		"\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" +
		strings.ReplaceAll(plainText(m), "\n", "\r\n")
	var auth smtp.Auth
	if s.SMTPUser != "" {
		host, _, _ := net.SplitHostPort(s.SMTPAddr)
		auth = smtp.PlainAuth("", s.SMTPUser, s.SMTPPassword, host) // net/smtp exige TLS para enviar la clave
	}
	if err := smtp.SendMail(s.SMTPAddr, auth, addrOnly(s.SMTPFrom), rcpt, []byte(msg)); err != nil {
		return fmt.Errorf("el servidor de correo rechazó el envío: %v", redact(err.Error(), s.SMTPPassword))
	}
	return nil
}

func addrOnly(from string) string {
	if a, err := mail.ParseAddress(from); err == nil {
		return a.Address
	}
	return from
}

func mimeWord(s string) string {
	for _, r := range s {
		if r > 127 {
			return "=?UTF-8?B?" + b64(s) + "?="
		}
	}
	return s
}

func redact(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "***")
}

// jira crea un ticket por hallazgo nuevo (sin duplicar los que ya tienen ticket).
func (s *Sender) jira(ctx context.Context, a domain.Alert, m Message) (map[string]string, error) {
	if s.JiraURL == "" || s.JiraEmail == "" || s.JiraToken == "" {
		return nil, errors.New("falta configurar JIRA_URL, JIRA_EMAIL y JIRA_API_TOKEN")
	}
	if !strings.HasPrefix(s.JiraURL, "https://") {
		return nil, errors.New("JIRA_URL tiene que usar https")
	}
	out := map[string]string{}
	created := 0
	for _, it := range m.Items {
		if it.FindingID == "" || a.Tickets[it.FindingID] != "" {
			continue
		}
		if created >= s.MaxTickets {
			break
		}
		desc := it.Detail
		if m.Link != "" {
			desc += "\n\n" + m.Link
		}
		body := map[string]any{"fields": map[string]any{
			"project":     map[string]string{"key": a.Target},
			"issuetype":   map[string]string{"name": s.JiraIssueType},
			"summary":     clip(fmt.Sprintf("[%s] %s — %s", strings.ToUpper(string(it.Severity)), it.Title, it.Asset), 250),
			"labels":      []string{"baqueano", "sev-" + string(it.Severity)},
			"description": adf(fmt.Sprintf("%s\n\nOrganización: %s\nActivo: %s\nControl: %s\nHallazgo: %s\n\n%s", it.Title, m.Org, it.Asset, it.Rule, it.FindingID, desc)),
		}}
		b, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.JiraURL+"/rest/api/3/issue", bytes.NewReader(b))
		if err != nil {
			return out, errors.New("JIRA_URL inválida")
		}
		req.SetBasicAuth(s.JiraEmail, s.JiraToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		resp, err := s.HTTP.Do(req)
		if err != nil {
			return out, fmt.Errorf("no se pudo conectar con %s", hostOf(s.JiraURL))
		}
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			return out, fmt.Errorf("Jira respondió %d al crear el ticket", resp.StatusCode)
		}
		var r struct {
			Key string `json:"key"`
		}
		if json.Unmarshal(rb, &r) == nil && r.Key != "" {
			out[it.FindingID] = r.Key
			created++
		}
	}
	return out, nil
}

// adf convierte texto en el formato de documento de Atlassian (un parrafo por linea).
func adf(text string) map[string]any {
	var content []map[string]any
	for _, l := range strings.Split(text, "\n") {
		p := map[string]any{"type": "paragraph"}
		if l != "" {
			p["content"] = []map[string]any{{"type": "text", "text": clip(l, 4000)}}
		}
		content = append(content, p)
	}
	return map[string]any{"type": "doc", "version": 1, "content": content}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut] + "…"
}
