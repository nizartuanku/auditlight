// Package notify delivers the outcome of a re-assessment.
//
// Two transports, both on the standard library: an HTTP webhook and plain SMTP.
// There is no third-party notification service, because a product that promises
// air-gapped operation cannot quietly depend on somebody's cloud to tell you
// what it found.
//
// Notification is deliberately per-assessment, not per-finding. AuditLight
// re-assesses on a schedule measured in weeks; a stream of individual alerts
// would be noise pretending to be monitoring.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/nizartuanku/auditlight/internal/delta"
)

// Rule decides whether a comparison is worth telling someone about.
type Rule string

const (
	// RuleChange notifies whenever anything moved.
	RuleChange Rule = "change"
	// RuleWorse notifies only when something new or regressed appeared.
	RuleWorse Rule = "worse"
	// RuleNever stays silent.
	RuleNever Rule = "never"
)

// ShouldSend applies the rule to a comparison.
func ShouldSend(rule Rule, r delta.Result) bool {
	switch rule {
	case RuleNever:
		return false
	case RuleWorse:
		return r.Counts.Worse()
	default:
		// A first assessment is worth knowing about; an unchanged one is not.
		if !r.HasBaseline {
			return true
		}
		return r.Counts.Changed()
	}
}

// Payload is what a webhook receives.
type Payload struct {
	Product      string       `json:"product"`
	Version      string       `json:"version"`
	Definition   string       `json:"definition"`
	DefinitionID string       `json:"definition_id"`
	JobID        string       `json:"job_id"`
	BaselineID   string       `json:"baseline_job_id,omitempty"`
	At           time.Time    `json:"at"`
	Targets      []string     `json:"targets"`
	Headline     string       `json:"headline"`
	Counts       delta.Counts `json:"counts"`
	Severity     any          `json:"severity_after"`
	ConsoleURL   string       `json:"console_url,omitempty"`
}

// SMTPConfig is the mail transport. Zero value means email is disabled.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// StartTLS upgrades the connection. Plain submission without it is refused
	// unless the host is loopback, so credentials cannot leave the machine in
	// clear text by accident.
	StartTLS bool
}

// Enabled reports whether mail can be sent.
func (c SMTPConfig) Enabled() bool { return c.Host != "" && c.From != "" }

// Sender delivers notifications.
type Sender struct {
	client *http.Client
	smtp   SMTPConfig
}

// New builds a sender.
func New(cfg SMTPConfig) *Sender {
	return &Sender{
		client: &http.Client{Timeout: 15 * time.Second},
		smtp:   cfg,
	}
}

// Webhook posts the payload. It returns an error the caller records in the job
// rather than swallowing: a notification that silently failed is worse than no
// notification, because the operator believes they are covered.
func (s *Sender) Webhook(ctx context.Context, url string, p Payload) error {
	if strings.TrimSpace(url) == "" {
		return nil
	}
	body, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("notify: encode payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AuditLight/"+p.Version)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("notify: webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("notify: webhook returned %s", resp.Status)
	}
	return nil
}

// Email sends a plain-text summary.
func (s *Sender) Email(to string, p Payload) error {
	if strings.TrimSpace(to) == "" || !s.smtp.Enabled() {
		return nil
	}
	addr := net.JoinHostPort(s.smtp.Host, itoa(s.smtp.Port))

	msg := buildMessage(s.smtp.From, to, p)

	c, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("notify: smtp dial: %w", err)
	}
	defer c.Close()

	if s.smtp.StartTLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(nil); err != nil {
				return fmt.Errorf("notify: starttls: %w", err)
			}
		} else {
			return fmt.Errorf("notify: server does not offer STARTTLS")
		}
	} else if s.smtp.Username != "" && !isLoopback(s.smtp.Host) {
		// Refuse to put credentials on the wire in clear text.
		return fmt.Errorf("notify: refusing to authenticate without STARTTLS to %s", s.smtp.Host)
	}

	if s.smtp.Username != "" {
		auth := smtp.PlainAuth("", s.smtp.Username, s.smtp.Password, s.smtp.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("notify: smtp auth: %w", err)
		}
	}
	if err := c.Mail(s.smtp.From); err != nil {
		return fmt.Errorf("notify: smtp from: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("notify: smtp rcpt: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("notify: smtp data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("notify: smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("notify: smtp close: %w", err)
	}
	return c.Quit()
}

func buildMessage(from, to string, p Payload) []byte {
	var b bytes.Buffer
	subject := fmt.Sprintf("AuditLight: %s — %s", p.Definition, p.Headline)
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", sanitiseHeader(subject))
	fmt.Fprintf(&b, "Date: %s\r\n", p.At.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: text/plain; charset=utf-8\r\n\r\n")

	fmt.Fprintf(&b, "%s\r\n\r\n", p.Headline)
	fmt.Fprintf(&b, "Assessment: %s\r\n", p.Definition)
	fmt.Fprintf(&b, "Targets:    %s\r\n", strings.Join(p.Targets, ", "))
	fmt.Fprintf(&b, "Run:        %s\r\n", p.JobID)
	if p.BaselineID != "" {
		fmt.Fprintf(&b, "Compared to: %s\r\n", p.BaselineID)
	}
	fmt.Fprintf(&b, "\r\nNew:        %d\r\nRegressed:  %d\r\nPersisting: %d\r\nImproved:   %d\r\nResolved:   %d\r\n",
		p.Counts.New, p.Counts.Regressed, p.Counts.Persisting, p.Counts.Improved, p.Counts.Resolved)
	if p.ConsoleURL != "" {
		fmt.Fprintf(&b, "\r\nChange report: %s\r\n", p.ConsoleURL)
	}
	fmt.Fprintf(&b, "\r\n-- \r\nAuditLight %s — detection only, no exploitation was attempted.\r\n", p.Version)
	return b.Bytes()
}

// sanitiseHeader strips CR and LF so a definition name cannot inject headers.
func sanitiseHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func itoa(n int) string {
	if n <= 0 {
		return "25"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
