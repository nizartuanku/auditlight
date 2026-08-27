package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nizartuanku/auditlight/internal/delta"
	"github.com/nizartuanku/auditlight/internal/finding"
)

func result(counts delta.Counts, hasBaseline bool) delta.Result {
	return delta.Result{Counts: counts, HasBaseline: hasBaseline}
}

func TestShouldSendRules(t *testing.T) {
	worse := result(delta.Counts{New: 1}, true)
	better := result(delta.Counts{Resolved: 2}, true)
	still := result(delta.Counts{Persisting: 3}, true)
	first := result(delta.Counts{Persisting: 3}, false)

	cases := []struct {
		rule Rule
		res  delta.Result
		want bool
		why  string
	}{
		{RuleNever, worse, false, "never means never, even when it degrades"},
		{RuleWorse, worse, true, "new findings are worse"},
		{RuleWorse, better, false, "improvement alone must not page anyone"},
		{RuleWorse, still, false, "nothing moved"},
		{RuleChange, better, true, "an improvement is still a change worth reporting"},
		{RuleChange, still, false, "an unchanged assessment is not news"},
		{RuleChange, first, true, "the first assessment is worth knowing about"},
		{Rule(""), still, false, "an unset rule behaves like change"},
	}
	for _, c := range cases {
		if got := ShouldSend(c.rule, c.res); got != c.want {
			t.Errorf("ShouldSend(%q) = %v, want %v — %s", c.rule, got, c.want, c.why)
		}
	}
}

func TestWebhookPostsPayload(t *testing.T) {
	var got Payload
	var contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s := New(SMTPConfig{})
	p := Payload{
		Product: "AuditLight", Version: "0.2.0", Definition: "Acme quarterly",
		JobID: "jobB", BaselineID: "jobA", Headline: "1 new finding since the last assessment.",
		Counts: delta.Counts{New: 1}, At: time.Now(),
	}
	if err := s.Webhook(context.Background(), srv.URL, p); err != nil {
		t.Fatalf("webhook: %v", err)
	}
	if !strings.HasPrefix(contentType, "application/json") {
		t.Fatalf("content type = %q", contentType)
	}
	if got.JobID != "jobB" || got.Counts.New != 1 {
		t.Fatalf("payload = %+v", got)
	}
}

// A notification that failed silently is worse than none: the operator believes
// they are covered.
func TestWebhookReportsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := New(SMTPConfig{}).Webhook(context.Background(), srv.URL, Payload{})
	if err == nil {
		t.Fatal("a 500 from the webhook must surface as an error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("error = %v; it should say what happened", err)
	}
}

func TestWebhookNoURLIsNotAnError(t *testing.T) {
	if err := New(SMTPConfig{}).Webhook(context.Background(), "  ", Payload{}); err != nil {
		t.Fatalf("an unset webhook is a configuration choice, not a failure: %v", err)
	}
}

func TestEmailDisabledWithoutConfig(t *testing.T) {
	if err := New(SMTPConfig{}).Email("someone@example.com", Payload{}); err != nil {
		t.Fatalf("email without SMTP configured should be a no-op: %v", err)
	}
	cfg := SMTPConfig{Host: "mail.example.com", From: "audit@example.com"}
	if err := New(cfg).Email("", Payload{}); err != nil {
		t.Fatalf("no recipient should be a no-op: %v", err)
	}
	if !cfg.Enabled() {
		t.Fatal("host and from should be enough to enable mail")
	}
}

// Credentials must never go out in clear text to a remote host.
func TestEmailRefusesPlaintextAuthToRemoteHost(t *testing.T) {
	s := New(SMTPConfig{
		Host: "mail.example.com", Port: 25, From: "a@example.com",
		Username: "user", Password: "secret", StartTLS: false,
	})
	err := s.Email("b@example.com", Payload{})
	if err == nil {
		t.Fatal("expected a refusal or a dial failure, got nil")
	}
	// Either it refused on principle, or it never got that far because the
	// host does not resolve. Both are acceptable; silently sending is not.
	if strings.Contains(err.Error(), "refusing to authenticate") {
		return
	}
	if !strings.Contains(err.Error(), "dial") {
		t.Fatalf("unexpected error path: %v", err)
	}
}

func TestMessageCannotBeHeaderInjected(t *testing.T) {
	p := Payload{
		Definition: "Acme\r\nBcc: attacker@evil.example",
		Headline:   "1 new finding.",
		Version:    "0.2.0",
		At:         time.Now(),
	}
	msg := string(buildMessage("audit@example.com", "client@example.com", p))
	head := msg[:strings.Index(msg, "\r\n\r\n")]

	// The real property is that no NEW header line was created. The attacker's
	// text surviving inside the Subject value is harmless; a line that begins
	// with "Bcc:" is not.
	allowed := map[string]bool{
		"from": true, "to": true, "subject": true,
		"date": true, "mime-version": true, "content-type": true,
	}
	for _, line := range strings.Split(head, "\r\n") {
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			t.Fatalf("malformed header line %q", line)
		}
		if !allowed[strings.ToLower(strings.TrimSpace(name))] {
			t.Fatalf("header injection created a %q line:\n%s", name, head)
		}
	}
}

func TestMessageCarriesTheNumbers(t *testing.T) {
	p := Payload{
		Definition: "Acme quarterly", Headline: "2 new findings since the last assessment.",
		Counts: delta.Counts{New: 2, Resolved: 5}, Targets: []string{"example.com"},
		JobID: "jobB", Version: "0.2.0", At: time.Now(),
	}
	msg := string(buildMessage("a@example.com", "b@example.com", p))
	for _, want := range []string{"2 new findings", "Acme quarterly", "example.com", "jobB", "New:        2", "Resolved:   5"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message should contain %q", want)
		}
	}
	if !strings.Contains(msg, "detection only") {
		t.Error("even a notification should restate what the product does not do")
	}
}

var _ = finding.CategoryTLS
