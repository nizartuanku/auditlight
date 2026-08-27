package authz

import (
	"strings"
	"testing"
	"time"
)

func goodRequest() Request {
	return Request{
		Operator:  "Nizar",
		Statement: Affirmation,
		Targets:   []string{"example.com", "app.example.com"},
		Confirm:   []string{"app.example.com", "example.com"}, // order must not matter
		Confirmed: true,
	}
}

func TestGateAllowsAWellFormedRequest(t *testing.T) {
	l := NewLog()
	d := l.Gate(goodRequest(), time.Now())
	if !d.Allowed {
		t.Fatalf("expected allow, got refusal: %s", d.Reason)
	}
	if len(d.Accepted) != 2 {
		t.Fatalf("accepted = %v", d.Accepted)
	}
	if d.Record.EntryHash == "" {
		t.Fatal("an allowed request must produce an audit record")
	}
}

func TestGateRefusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Request)
		want   string
	}{
		{"no targets", func(r *Request) { r.Targets = nil }, "no targets"},
		{"no operator", func(r *Request) { r.Operator = "  " }, "operator name is required"},
		{"not confirmed", func(r *Request) { r.Confirmed = false }, "not accepted"},
		{"confirmation mismatch", func(r *Request) { r.Confirm = []string{"example.com"} }, "does not match"},
		{"confirmation empty", func(r *Request) { r.Confirm = nil }, "does not match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := goodRequest()
			tc.mutate(&req)
			d := NewLog().Gate(req, time.Now())
			if d.Allowed {
				t.Fatal("expected refusal")
			}
			if !strings.Contains(strings.ToLower(d.Reason), tc.want) {
				t.Fatalf("reason %q should mention %q", d.Reason, tc.want)
			}
		})
	}
}

// Invariant I1: a target that is not assessed is reported, never dropped.
func TestScopeGuardSkipsWithReason(t *testing.T) {
	req := Request{
		Operator: "Nizar", Statement: Affirmation, Confirmed: true,
		Targets: []string{"example.com", "notmine.test"},
		Confirm: []string{"example.com", "notmine.test"},
		Scope:   []string{"example.com"},
	}
	d := NewLog().Gate(req, time.Now())
	if !d.Allowed {
		t.Fatalf("in-scope target should still run: %s", d.Reason)
	}
	if len(d.Accepted) != 1 || d.Accepted[0] != "example.com" {
		t.Fatalf("accepted = %v", d.Accepted)
	}
	if len(d.Skipped) != 1 {
		t.Fatalf("skipped = %v; the out-of-scope target must be reported", d.Skipped)
	}
	if !strings.Contains(d.Skipped[0].Reason, "scope") {
		t.Fatalf("skip reason = %q", d.Skipped[0].Reason)
	}
}

func TestScopeAcceptsSubdomainsAndCIDR(t *testing.T) {
	req := Request{
		Operator: "Nizar", Statement: Affirmation, Confirmed: true,
		Targets: []string{"api.example.com", "192.0.2.10", "198.51.100.7"},
		Confirm: []string{"api.example.com", "192.0.2.10", "198.51.100.7"},
		Scope:   []string{"example.com", "192.0.2.0/24"},
	}
	d := NewLog().Gate(req, time.Now())
	if len(d.Accepted) != 2 {
		t.Fatalf("accepted = %v; subdomain and in-range IP should pass", d.Accepted)
	}
	if len(d.Skipped) != 1 || d.Skipped[0].Target != "198.51.100.7" {
		t.Fatalf("skipped = %v; the out-of-range IP should be refused", d.Skipped)
	}
}

func TestEveryTargetOutOfScopeIsARefusal(t *testing.T) {
	req := Request{
		Operator: "Nizar", Statement: Affirmation, Confirmed: true,
		Targets: []string{"notmine.test"}, Confirm: []string{"notmine.test"},
		Scope: []string{"example.com"},
	}
	d := NewLog().Gate(req, time.Now())
	if d.Allowed {
		t.Fatal("a job with nothing left to assess must not start")
	}
	if len(d.Skipped) != 1 {
		t.Fatal("the refused target must still be reported")
	}
}

// Loopback and private addresses are legitimate targets: auditing your own
// machine is a first-class use case.
func TestLocalTargetsAreAllowedAndFlagged(t *testing.T) {
	for _, target := range []string{"127.0.0.1", "localhost", "192.168.1.10", "myserver"} {
		req := Request{
			Operator: "Nizar", Statement: Affirmation, Confirmed: true,
			Targets: []string{target}, Confirm: []string{target},
		}
		d := NewLog().Gate(req, time.Now())
		if !d.Allowed {
			t.Fatalf("%s should be assessable: %s", target, d.Reason)
		}
	}
	for _, local := range []string{"127.0.0.1", "localhost", "192.168.1.10"} {
		if !IsLocal(local) {
			t.Fatalf("%s should be reported as local", local)
		}
	}
	if IsLocal("example.com") {
		t.Fatal("a public domain must not be flagged local")
	}
}

func TestUnassessableTargetsAreSkipped(t *testing.T) {
	req := Request{
		Operator: "Nizar", Statement: Affirmation, Confirmed: true,
		Targets: []string{"example.com", "0.0.0.0", "224.0.0.1", "bad host!"},
		Confirm: []string{"example.com", "0.0.0.0", "224.0.0.1", "bad host!"},
	}
	d := NewLog().Gate(req, time.Now())
	if !d.Allowed {
		t.Fatalf("the valid target should still run: %s", d.Reason)
	}
	if len(d.Skipped) != 3 {
		t.Fatalf("skipped = %v, want three refusals with reasons", d.Skipped)
	}
	for _, s := range d.Skipped {
		if s.Reason == "" {
			t.Fatalf("target %q was skipped with no reason", s.Target)
		}
	}
}

func TestAuditChainDetectsTampering(t *testing.T) {
	l := NewLog()
	for i := 0; i < 3; i++ {
		if d := l.Gate(goodRequest(), time.Now()); !d.Allowed {
			t.Fatalf("gate refused: %s", d.Reason)
		}
	}
	if err := l.Verify(); err != nil {
		t.Fatalf("a clean chain must verify: %v", err)
	}
	if len(l.entries) != 3 {
		t.Fatalf("entries = %d", len(l.entries))
	}
	if l.entries[0].PrevHash != "" {
		t.Fatal("the first entry has no predecessor")
	}
	if l.entries[1].PrevHash != l.entries[0].EntryHash {
		t.Fatal("entries must be linked")
	}

	// Rewriting history must break verification.
	l.entries[1].Operator = "Someone Else"
	if err := l.Verify(); err == nil {
		t.Fatal("an altered entry must break the chain")
	}
}

func TestEntriesReturnsACopy(t *testing.T) {
	l := NewLog()
	l.Gate(goodRequest(), time.Now())
	got := l.Entries()
	got[0].Operator = "tampered"
	if l.Entries()[0].Operator == "tampered" {
		t.Fatal("Entries must not expose the internal slice")
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"https://example.com/path?q=1": "example.com",
		"http://example.com:8080/":     "example.com",
		"EXAMPLE.com.":                 "example.com",
		"user@example.com":             "example.com",
		"[2001:db8::1]":                "2001:db8::1",
		"192.0.2.1:443":                "192.0.2.1",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
