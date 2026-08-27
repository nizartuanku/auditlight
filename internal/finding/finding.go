// Package finding defines the canonical finding model that every adapter result
// is normalised into. It is the contract shared by the whole pipeline:
// adapters produce findings, correlation merges them, scoring ranks them and
// reports render them.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Category groups findings by the domain they came from.
type Category string

const (
	CategoryDiscovery Category = "discovery"
	CategoryNetwork   Category = "network"
	CategoryWeb       Category = "web"
	CategoryTLS       Category = "tls"
	CategoryDNSEmail  Category = "dns_email"
	CategoryVuln      Category = "vuln"
	CategorySecret    Category = "secret"
	CategoryHardening Category = "hardening"
)

// AllCategories is the closed set of valid categories.
func AllCategories() []Category {
	return []Category{
		CategoryDiscovery, CategoryNetwork, CategoryWeb, CategoryTLS,
		CategoryDNSEmail, CategoryVuln, CategorySecret, CategoryHardening,
	}
}

// Valid reports whether c is a known category.
func (c Category) Valid() bool {
	for _, k := range AllCategories() {
		if k == c {
			return true
		}
	}
	return false
}

// Severity expresses how serious the condition is if real.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Rank returns a sort weight; higher is more severe.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool { return s.Rank() > 0 }

// Confidence expresses how certain we are that the condition is real.
//
// AuditLight never exploits, so it can rarely prove exploitability. Confidence
// is the honest expression of that limit.
type Confidence string

const (
	// ConfidenceConfirmed means the condition was observed directly and
	// unambiguously (an expired certificate, a missing DMARC record).
	ConfidenceConfirmed Confidence = "confirmed"
	// ConfidenceLikely means strong evidence, but inference is involved
	// (a version banner matching a known-vulnerable range).
	ConfidenceLikely Confidence = "likely"
	// ConfidencePotential means the signal is suggestive only.
	ConfidencePotential Confidence = "potential"
)

// Rank returns a sort weight; higher is more certain.
func (c Confidence) Rank() int {
	switch c {
	case ConfidenceConfirmed:
		return 3
	case ConfidenceLikely:
		return 2
	case ConfidencePotential:
		return 1
	default:
		return 0
	}
}

// Valid reports whether c is a known confidence level.
func (c Confidence) Valid() bool { return c.Rank() > 0 }

// promote raises confidence by exactly one step, never past confirmed.
// Invariant I4: corroboration may only ever raise confidence one step.
func (c Confidence) promote() Confidence {
	switch c {
	case ConfidencePotential:
		return ConfidenceLikely
	case ConfidenceLikely:
		return ConfidenceConfirmed
	default:
		return c
	}
}

// Status marks how a finding should be treated by the reader.
type Status string

const (
	// StatusOpen is an actionable finding.
	StatusOpen Status = "open"
	// StatusManualReview means AuditLight detected something it cannot
	// classify automatically. Invariant I2: we say so rather than guess.
	StatusManualReview Status = "manual_review"
	// StatusInformational carries context, not a defect.
	StatusInformational Status = "informational"
)

// Evidence is raw, verifiable material supporting a finding. It is what lets
// an auditor check our work instead of trusting it.
type Evidence struct {
	Kind  string `json:"kind"`            // banner, header, record, certificate, config, match
	Label string `json:"label,omitempty"` // human label for the value
	Value string `json:"value"`           // the raw observed value, truncated safely
}

// Control is a compliance control a finding maps to. Paid tiers only.
type Control struct {
	Framework string `json:"framework"` // ISO 27001:2022, CIS v8, NIST CSF 2.0, UU PDP
	ID        string `json:"id"`        // A.8.8, 7, ID.RA, Pasal 35
	Title     string `json:"title,omitempty"`
}

// Finding is the canonical normalised result.
type Finding struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Target      string     `json:"target"`
	Port        int        `json:"port,omitempty"`
	Category    Category   `json:"category"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	CVSS        float64    `json:"cvss,omitempty"`
	CVE         []string   `json:"cve,omitempty"`
	CWE         []string   `json:"cwe,omitempty"`
	Evidence    []Evidence `json:"evidence,omitempty"`
	SourceTools []string   `json:"source_tools"`
	Description string     `json:"description"`
	Remediation string     `json:"remediation,omitempty"`
	Compliance  []Control  `json:"compliance,omitempty"`
	Status      Status     `json:"status"`

	// signature is the adapter-supplied discriminator that, together with
	// target/port/category, gives the finding its stable identity. It is not
	// serialised: ID is derived from it and ID is what persists.
	signature string
}

// Signature returns the discriminator used to compute the finding's identity.
func (f *Finding) Signature() string { return f.signature }

// SetSignature sets the discriminator and recomputes the deterministic ID.
func (f *Finding) SetSignature(sig string) {
	f.signature = sig
	f.ID = ComputeID(f.Target, f.Port, f.Category, sig)
}

// ComputeID derives the stable identity of a finding.
//
// Invariant I3: the same condition on the same target must yield the same ID on
// every run, so that findings can be diffed across assessments.
func ComputeID(target string, port int, category Category, signature string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%d\x00%s\x00%s",
		strings.ToLower(strings.TrimSpace(target)), port, category, signature)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// New builds a finding with a deterministic ID. It is the only constructor
// adapters should use, so that identity rules stay in one place.
func New(target string, port int, cat Category, sev Severity, conf Confidence, signature, title, description string, tool string) *Finding {
	f := &Finding{
		Title:       title,
		Target:      target,
		Port:        port,
		Category:    cat,
		Severity:    sev,
		Confidence:  conf,
		SourceTools: []string{tool},
		Description: description,
		Status:      StatusOpen,
	}
	f.SetSignature(signature)
	return f
}

// Clone returns a deep copy.
//
// A shallow copy is not enough: the slices would still share backing arrays
// with the original, so a reader serialising the copy can race a writer
// appending to the source. That race was real and is what this exists to
// prevent.
func (f *Finding) Clone() *Finding {
	if f == nil {
		return nil
	}
	cp := *f
	cp.SourceTools = append([]string(nil), f.SourceTools...)
	cp.CVE = append([]string(nil), f.CVE...)
	cp.CWE = append([]string(nil), f.CWE...)
	cp.Evidence = append([]Evidence(nil), f.Evidence...)
	cp.Compliance = append([]Control(nil), f.Compliance...)
	return &cp
}

// CloneAll deep-copies a slice of findings.
func CloneAll(fs []*Finding) []*Finding {
	if fs == nil {
		return nil
	}
	out := make([]*Finding, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Clone())
	}
	return out
}

// AddEvidence appends evidence, truncating oversized values so that a hostile
// or broken endpoint cannot bloat a report.
const maxEvidenceValue = 2048

func (f *Finding) AddEvidence(kind, label, value string) {
	if len(value) > maxEvidenceValue {
		value = value[:maxEvidenceValue] + fmt.Sprintf("… [truncated, %d bytes total]", len(value))
	}
	f.Evidence = append(f.Evidence, Evidence{Kind: kind, Label: label, Value: value})
}

// Validate checks the finding against the schema. It is applied at the pipeline
// boundary so malformed adapter output never reaches a report.
func (f *Finding) Validate() error {
	switch {
	case f.ID == "":
		return fmt.Errorf("finding: empty id")
	case strings.TrimSpace(f.Title) == "":
		return fmt.Errorf("finding %s: empty title", f.ID)
	case strings.TrimSpace(f.Target) == "":
		return fmt.Errorf("finding %s: empty target", f.ID)
	case !f.Category.Valid():
		return fmt.Errorf("finding %s: invalid category %q", f.ID, f.Category)
	case !f.Severity.Valid():
		return fmt.Errorf("finding %s: invalid severity %q", f.ID, f.Severity)
	case !f.Confidence.Valid():
		return fmt.Errorf("finding %s: invalid confidence %q", f.ID, f.Confidence)
	case len(f.SourceTools) == 0:
		return fmt.Errorf("finding %s: no source tool", f.ID)
	case f.Port < 0 || f.Port > 65535:
		return fmt.Errorf("finding %s: port %d out of range", f.ID, f.Port)
	case f.CVSS < 0 || f.CVSS > 10:
		return fmt.Errorf("finding %s: cvss %v out of range", f.ID, f.CVSS)
	}
	return nil
}

// Merge folds other into f, treating them as the same underlying condition.
//
// Invariant I4: corroboration by a distinct tool raises confidence by at most
// one step. Merging results from the same tool never raises it.
func (f *Finding) Merge(other *Finding) {
	newTool := false
	for _, t := range other.SourceTools {
		if !containsString(f.SourceTools, t) {
			f.SourceTools = append(f.SourceTools, t)
			newTool = true
		}
	}
	sort.Strings(f.SourceTools)

	// Keep the most severe assessment of the two.
	if other.Severity.Rank() > f.Severity.Rank() {
		f.Severity = other.Severity
	}
	// Keep the higher stated confidence, then apply at most one promotion.
	if other.Confidence.Rank() > f.Confidence.Rank() {
		f.Confidence = other.Confidence
	}
	if newTool {
		f.Confidence = f.Confidence.promote()
	}

	// CVSS: keep any real score; never invent one. Invariant I2.
	if f.CVSS == 0 && other.CVSS > 0 {
		f.CVSS = other.CVSS
	}
	f.CVE = mergeUnique(f.CVE, other.CVE)
	f.CWE = mergeUnique(f.CWE, other.CWE)
	f.Evidence = append(f.Evidence, other.Evidence...)

	if f.Remediation == "" {
		f.Remediation = other.Remediation
	}
	// A condition needing human judgement stays flagged even if the other
	// copy looked routine.
	if other.Status == StatusManualReview {
		f.Status = StatusManualReview
	}
}

// Sort orders findings for presentation: severity, then confidence, then
// category, then target, then id. The final key keeps the order total and
// therefore stable across runs.
func Sort(fs []*Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Confidence.Rank() != b.Confidence.Rank() {
			return a.Confidence.Rank() > b.Confidence.Rank()
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		return a.ID < b.ID
	})
}

// Counts summarises findings by severity, for executive summaries and badges.
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// Count tallies findings by severity.
func Count(fs []*Finding) Counts {
	var c Counts
	for _, f := range fs {
		switch f.Severity {
		case SeverityCritical:
			c.Critical++
		case SeverityHigh:
			c.High++
		case SeverityMedium:
			c.Medium++
		case SeverityLow:
			c.Low++
		case SeverityInfo:
			c.Info++
		}
		c.Total++
	}
	return c
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func mergeUnique(a, b []string) []string {
	for _, s := range b {
		if !containsString(a, s) {
			a = append(a, s)
		}
	}
	sort.Strings(a)
	return a
}
