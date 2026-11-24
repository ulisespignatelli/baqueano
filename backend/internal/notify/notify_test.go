package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ulisespignatelli/baqueano/backend/internal/domain"
)

var msg = Message{Event: "baqueano.scan", Org: "Acme", Title: "Baqueano · Acme: 2 novedades", Summary: "Puntaje 40/100",
	Items: []Item{{FindingID: "f1", Rule: "PX-RDP", Severity: domain.SevCritical, Title: "RDP accesible desde internet", Asset: "203.0.113.10:3389", Change: "nuevo"},
		{FindingID: "f2", Rule: "VU-01", Severity: domain.SevHigh, Title: "CVE-2099-0102 en Grafana", Asset: "198.51.100.40:3000", Change: "kev", KEV: true}}}

func capture(t *testing.T) (*httptest.Server, func() (http.Header, []byte)) {
	var mu sync.Mutex
	var hdr http.Header
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		hdr, body = r.Header.Clone(), must(io.ReadAll(r.Body))
	}))
	t.Cleanup(srv.Close)
	return srv, func() (http.Header, []byte) { mu.Lock(); defer mu.Unlock(); return hdr, body }
}

func must(b []byte, _ error) []byte { return b }

func TestChannels(t *testing.T) {
	s := FromEnv()
	s.WebhookSecret = "secreto"
	srv, got := capture(t)
	ctx := context.Background()

	if _, err := s.Send(ctx, domain.Alert{Channel: "webhook", Target: srv.URL}, msg); err != nil {
		t.Fatal(err)
	}
	h, b := got()
	mac := hmac.New(sha256.New, []byte("secreto"))
	mac.Write(b)
	if h.Get("X-Baqueano-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Error("firma HMAC incorrecta")
	}
	var m Message
	if json.Unmarshal(b, &m) != nil || len(m.Items) != 2 {
		t.Errorf("webhook: %s", b)
	}

	if _, err := s.Send(ctx, domain.Alert{Channel: "slack", Target: srv.URL}, msg); err != nil {
		t.Fatal(err)
	}
	_, b = got()
	if !strings.Contains(string(b), `"blocks"`) || !strings.Contains(string(b), "RDP accesible") {
		t.Errorf("slack: %s", b)
	}
	if _, err := s.Send(ctx, domain.Alert{Channel: "teams", Target: srv.URL}, msg); err != nil {
		t.Fatal(err)
	}
	_, b = got()
	if !strings.Contains(string(b), "application/vnd.microsoft.card.adaptive") || !strings.Contains(string(b), "AdaptiveCard") {
		t.Errorf("teams: %s", b)
	}
	if _, err := s.Send(ctx, domain.Alert{Channel: "email", Target: "seguridad@acme.example"}, msg); err == nil || !strings.Contains(err.Error(), "SMTP_ADDR") {
		t.Errorf("correo sin SMTP debía explicar qué falta: %v", err)
	}
}

func TestJira(t *testing.T) {
	var mu sync.Mutex
	n := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "bot@acme.example" || pass != "token" || r.URL.Path != "/rest/api/3/issue" {
			w.WriteHeader(401)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f := body["fields"].(map[string]any)
		if f["project"].(map[string]any)["key"] != "SEC" || f["description"].(map[string]any)["type"] != "doc" {
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		n++
		k := n
		mu.Unlock()
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"id":"1","key":"SEC-` + string(rune('0'+k)) + `"}`))
	}))
	defer srv.Close()
	s := FromEnv()
	s.HTTP = srv.Client()
	s.JiraURL, s.JiraEmail, s.JiraToken = srv.URL, "bot@acme.example", "token"
	tk, err := s.Send(context.Background(), domain.Alert{Channel: "jira", Target: "SEC", Tickets: map[string]string{"f1": "SEC-0"}}, msg)
	if err != nil || len(tk) != 1 || tk["f2"] != "SEC-1" {
		t.Fatalf("solo debía crear el ticket que falta: %v %v", tk, err)
	}
}

func TestValidateAndMask(t *testing.T) {
	bad := map[string]string{"webhook": "http://hooks.example.com/x", "slack": "https://user:pass@hooks.slack.com/x", "email": "no-es-correo", "jira": "sec mal", "fax": "x"}
	for ch, tg := range bad {
		if ValidateTarget(ch, tg) == nil {
			t.Errorf("%s %q debía rechazarse", ch, tg)
		}
	}
	for ch, tg := range map[string]string{"webhook": "http://127.0.0.1:9000/hook", "slack": "https://hooks.slack.com/services/T/B/abcdef123456", "email": "a@b.example, c@d.example", "jira": "SEC"} {
		if err := ValidateTarget(ch, tg); err != nil {
			t.Errorf("%s %q: %v", ch, tg, err)
		}
	}
	m := Mask("slack", "https://hooks.slack.com/services/T000/B000/secretoSuperLargo")
	if strings.Contains(m, "secretoSuper") || !IsMasked(m) || !strings.HasPrefix(m, "https://hooks.slack.com/…") {
		t.Errorf("máscara: %s", m)
	}
}
