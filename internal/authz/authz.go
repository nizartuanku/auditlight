// Package authz implements the authorisation gate.
//
// AuditLight touches assets that belong to someone, so authorisation is a hard
// precondition, not a checkbox. No job reaches the orchestrator until the
// operator has stated authority over every target, the targets have passed the
// scope guard, and the whole statement has been appended to a hash-chained
// audit log that the Process Report renders as evidence.
//
// The gate is present in every edition, including Free. It is a safety
// mechanism, not a paid feature.
package authz

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Request is what an operator submits to open a job.
type Request struct {
	Operator  string   // who is running this
	Statement string   // the affirmation text shown in the UI
	Targets   []string // targets to assess
	Confirm   []string // targets re-entered by hand, must match Targets
	Scope     []string // allowed domains / CIDRs; empty means "targets are the scope"
	Confirmed bool     // the affirmation checkbox
}

// Decision is the gate's verdict.
type Decision struct {
	Allowed  bool
	Reason   string
	Accepted []string        // targets cleared to run
	Skipped  []SkippedTarget // targets refused, each with a reason
	Record   Record
}

// SkippedTarget is a target the gate refused, with the reason recorded.
// Invariant I1: nothing is dropped silently.
type SkippedTarget struct {
	Target string
	Reason string
}

// Record is the audit-log entry for one authorisation event.
type Record struct {
	Operator  string
	Statement string
	Targets   []string
	Scope     []string
	At        time.Time
	PrevHash  string
	EntryHash string
}

// The affirmation an operator must accept. Kept here so the UI, the API and the
// report all quote exactly the same words.
const Affirmation = "I am authorised to assess the targets listed below, and I accept responsibility for this assessment."

// Log is an append-only, hash-chained record of authorisation events. Chaining
// means an entry cannot be altered or removed without breaking every entry
// after it, which is what makes the log usable as evidence.
type Log struct {
	entries []Record
}

// NewLog returns an empty log.
func NewLog() *Log { return &Log{} }

// Entries returns a copy of the log.
func (l *Log) Entries() []Record {
	out := make([]Record, len(l.entries))
	copy(out, l.entries)
	return out
}

// Append adds a record, linking it to the previous entry.
func (l *Log) Append(r Record) Record {
	prev := ""
	if n := len(l.entries); n > 0 {
		prev = l.entries[n-1].EntryHash
	}
	r.PrevHash = prev
	r.EntryHash = hashRecord(r)
	l.entries = append(l.entries, r)
	return r
}

// Verify walks the chain and reports the first broken link, if any.
func (l *Log) Verify() error {
	prev := ""
	for i, r := range l.entries {
		if r.PrevHash != prev {
			return fmt.Errorf("authz: chain broken at entry %d: prev hash mismatch", i)
		}
		want := hashRecord(r)
		if r.EntryHash != want {
			return fmt.Errorf("authz: chain broken at entry %d: entry hash mismatch", i)
		}
		prev = r.EntryHash
	}
	return nil
}

func hashRecord(r Record) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%d\x00%s",
		r.Operator, r.Statement,
		strings.Join(r.Targets, ","), strings.Join(r.Scope, ","),
		r.At.UTC().UnixNano(), r.PrevHash)
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// Gate evaluates a request. It returns a decision rather than an error: a
// refusal is a normal, reportable outcome, not a crash.
func (l *Log) Gate(req Request, now time.Time) Decision {
	targets := normaliseList(req.Targets)

	if len(targets) == 0 {
		return Decision{Reason: "No targets were supplied."}
	}
	if strings.TrimSpace(req.Operator) == "" {
		return Decision{Reason: "An operator name is required, so the assessment can be attributed."}
	}
	if !req.Confirmed {
		return Decision{Reason: "The authorisation statement was not accepted."}
	}

	// The re-entered list must match exactly. Typing the targets again is what
	// turns the affirmation from a reflex click into a deliberate act.
	confirm := normaliseList(req.Confirm)
	if !equalLists(targets, confirm) {
		return Decision{Reason: "The re-entered target list does not match the targets to be assessed."}
	}

	scope := normaliseList(req.Scope)
	var accepted []string
	var skipped []SkippedTarget
	for _, t := range targets {
		if err := validTarget(t); err != nil {
			skipped = append(skipped, SkippedTarget{Target: t, Reason: err.Error()})
			continue
		}
		if len(scope) > 0 && !inScope(t, scope) {
			skipped = append(skipped, SkippedTarget{
				Target: t,
				Reason: "outside the declared scope",
			})
			continue
		}
		accepted = append(accepted, t)
	}

	if len(accepted) == 0 {
		return Decision{
			Reason:  "No target survived the scope guard.",
			Skipped: skipped,
		}
	}

	rec := l.Append(Record{
		Operator:  strings.TrimSpace(req.Operator),
		Statement: strings.TrimSpace(req.Statement),
		Targets:   accepted,
		Scope:     scope,
		At:        now.UTC(),
	})

	return Decision{
		Allowed:  true,
		Accepted: accepted,
		Skipped:  skipped,
		Record:   rec,
	}
}

// validTarget rejects things that are not assessable hostnames, IPs or URLs.
//
// Loopback, private and single-label hosts are deliberately allowed: auditing
// your own machine or an internal asset is a first-class use case, and it is
// the safest thing anyone can scan. The control against scanning what you do
// not own is the affirmation plus the scope guard, not a blanket address ban.
// Only addresses that cannot name a real asset are refused.
func validTarget(t string) error {
	if t == "" {
		return fmt.Errorf("empty target")
	}
	host := hostOf(t)
	if host == "" {
		return fmt.Errorf("target could not be parsed")
	}
	if ip := net.ParseIP(host); ip != nil {
		switch {
		case ip.IsUnspecified():
			return fmt.Errorf("unspecified addresses do not name an asset")
		case ip.IsMulticast():
			return fmt.Errorf("multicast addresses do not name an asset")
		}
		return nil
	}
	for _, r := range host {
		if r > 127 {
			return fmt.Errorf("hostname contains non-ASCII characters; use the punycode form")
		}
		if !(r == '-' || r == '.' || r == '_' ||
			(r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return fmt.Errorf("hostname contains characters that are not valid in a host name")
		}
	}
	return nil
}

// IsLocal reports whether a target names a loopback or private address. It is
// used to annotate the report, not to refuse the target.
func IsLocal(t string) bool {
	host := hostOf(t)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// hostOf strips scheme, path, port and trailing dot from a target.
func hostOf(t string) string {
	s := strings.TrimSpace(strings.ToLower(t))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	// Bracketed IPv6, optionally with a port.
	if strings.HasPrefix(s, "[") {
		if j := strings.Index(s, "]"); j > 0 {
			return s[1:j]
		}
		return ""
	}
	// Strip a trailing :port, but leave bare IPv6 alone.
	if i := strings.LastIndex(s, ":"); i >= 0 && strings.Count(s, ":") == 1 {
		s = s[:i]
	}
	return strings.TrimSuffix(s, ".")
}

// inScope reports whether target falls inside any scope entry. A scope entry is
// a CIDR, an exact host, or a domain that the target may be a subdomain of.
func inScope(target string, scope []string) bool {
	host := hostOf(target)
	ip := net.ParseIP(host)
	for _, s := range scope {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" {
			continue
		}
		if _, netw, err := net.ParseCIDR(s); err == nil {
			if ip != nil && netw.Contains(ip) {
				return true
			}
			continue
		}
		sh := hostOf(s)
		if sh == "" {
			continue
		}
		if host == sh || strings.HasSuffix(host, "."+sh) {
			return true
		}
	}
	return false
}

func normaliseList(in []string) []string {
	seen := make(map[string]bool, len(in))
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func equalLists(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
