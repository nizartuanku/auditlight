package finding

import "testing"

// Invariant I3: identity is deterministic and stable across runs.
func TestComputeIDIsDeterministic(t *testing.T) {
	a := ComputeID("Example.COM ", 443, CategoryTLS, "cert-expired")
	b := ComputeID("example.com", 443, CategoryTLS, "cert-expired")
	if a != b {
		t.Fatalf("id should ignore case and surrounding space: %s != %s", a, b)
	}
	if c := ComputeID("example.com", 443, CategoryTLS, "cert-expiring"); c == a {
		t.Fatal("different signatures must not collide")
	}
	if c := ComputeID("example.com", 8443, CategoryTLS, "cert-expired"); c == a {
		t.Fatal("different ports must not collide")
	}
	if len(a) != 16 {
		t.Fatalf("id length = %d, want 16", len(a))
	}
}

func TestNewSetsIdentityAndDefaults(t *testing.T) {
	f := New("example.com", 443, CategoryTLS, SeverityHigh, ConfidenceConfirmed,
		"cert-expired", "Certificate has expired", "It expired.", "tlsaudit")
	if f.ID == "" {
		t.Fatal("constructor must set an id")
	}
	if f.Status != StatusOpen {
		t.Fatalf("status = %q, want open", f.Status)
	}
	if got := f.Signature(); got != "cert-expired" {
		t.Fatalf("signature = %q", got)
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("constructed finding should validate: %v", err)
	}
}

// Invariant I4: a distinct corroborating tool raises confidence by exactly one
// step, and never past confirmed.
func TestMergePromotesConfidenceOnceOnly(t *testing.T) {
	mk := func(tool string, conf Confidence) *Finding {
		return New("example.com", 443, CategoryTLS, SeverityMedium, conf,
			"weak-cipher", "Weak cipher", "d", tool)
	}

	a := mk("tlsaudit", ConfidencePotential)
	a.Merge(mk("testssl", ConfidencePotential))
	if a.Confidence != ConfidenceLikely {
		t.Fatalf("one corroboration: got %q, want likely", a.Confidence)
	}

	// A second finding from a tool already credited must not promote again.
	a.Merge(mk("testssl", ConfidencePotential))
	if a.Confidence != ConfidenceLikely {
		t.Fatalf("same tool twice must not promote again: got %q", a.Confidence)
	}

	// A third distinct tool promotes once more, to the ceiling.
	a.Merge(mk("nuclei", ConfidencePotential))
	if a.Confidence != ConfidenceConfirmed {
		t.Fatalf("second distinct tool: got %q, want confirmed", a.Confidence)
	}

	// Confirmed is the ceiling.
	a.Merge(mk("nmap", ConfidenceConfirmed))
	if a.Confidence != ConfidenceConfirmed {
		t.Fatalf("confidence must not exceed confirmed: got %q", a.Confidence)
	}
}

func TestMergeKeepsHighestSeverityAndUnionsIdentifiers(t *testing.T) {
	a := New("h", 0, CategoryVuln, SeverityLow, ConfidenceLikely, "s", "t", "d", "one")
	a.CVE = []string{"CVE-2020-1"}
	b := New("h", 0, CategoryVuln, SeverityCritical, ConfidenceLikely, "s", "t", "d", "two")
	b.CVE = []string{"CVE-2021-2", "CVE-2020-1"}
	b.CVSS = 9.1

	a.Merge(b)
	if a.Severity != SeverityCritical {
		t.Fatalf("severity = %q, want critical", a.Severity)
	}
	if len(a.CVE) != 2 {
		t.Fatalf("cve = %v, want two unique entries", a.CVE)
	}
	if a.CVSS != 9.1 {
		t.Fatalf("cvss = %v, want the real score carried over", a.CVSS)
	}
}

// Invariant I2: a score is never invented.
func TestMergeNeverInventsCVSS(t *testing.T) {
	a := New("h", 0, CategoryVuln, SeverityHigh, ConfidenceLikely, "s", "t", "d", "one")
	a.Merge(New("h", 0, CategoryVuln, SeverityHigh, ConfidenceLikely, "s", "t", "d", "two"))
	if a.CVSS != 0 {
		t.Fatalf("cvss = %v, want 0 when neither source supplied one", a.CVSS)
	}
}

func TestMergePreservesManualReview(t *testing.T) {
	a := New("h", 0, CategoryVuln, SeverityLow, ConfidenceLikely, "s", "t", "d", "one")
	b := New("h", 0, CategoryVuln, SeverityLow, ConfidenceLikely, "s", "t", "d", "two")
	b.Status = StatusManualReview
	a.Merge(b)
	if a.Status != StatusManualReview {
		t.Fatalf("status = %q, want manual_review to survive a merge", a.Status)
	}
}

func TestValidateRejectsMalformed(t *testing.T) {
	cases := map[string]func(*Finding){
		"empty title":       func(f *Finding) { f.Title = "" },
		"empty target":      func(f *Finding) { f.Target = "" },
		"bad category":      func(f *Finding) { f.Category = "nonsense" },
		"bad severity":      func(f *Finding) { f.Severity = "urgent" },
		"bad confidence":    func(f *Finding) { f.Confidence = "certain" },
		"no source tool":    func(f *Finding) { f.SourceTools = nil },
		"port out of range": func(f *Finding) { f.Port = 70000 },
		"cvss out of range": func(f *Finding) { f.CVSS = 11 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := New("h", 1, CategoryWeb, SeverityLow, ConfidenceLikely, "s", "t", "d", "tool")
			mutate(f)
			if err := f.Validate(); err == nil {
				t.Fatalf("expected %s to be rejected", name)
			}
		})
	}
}

func TestAddEvidenceTruncatesHostileInput(t *testing.T) {
	f := New("h", 0, CategoryNetwork, SeverityInfo, ConfidenceConfirmed, "s", "t", "d", "tool")
	huge := make([]byte, 10_000)
	for i := range huge {
		huge[i] = 'A'
	}
	f.AddEvidence("banner", "flood", string(huge))
	if got := len(f.Evidence[0].Value); got > maxEvidenceValue+64 {
		t.Fatalf("evidence length %d; oversized input must be truncated", got)
	}
}

func TestSortIsTotalAndStable(t *testing.T) {
	fs := []*Finding{
		New("b", 0, CategoryWeb, SeverityLow, ConfidenceLikely, "s1", "low", "d", "t"),
		New("a", 0, CategoryWeb, SeverityCritical, ConfidencePotential, "s2", "crit", "d", "t"),
		New("c", 0, CategoryWeb, SeverityCritical, ConfidenceConfirmed, "s3", "crit2", "d", "t"),
	}
	Sort(fs)
	if fs[0].Title != "crit2" {
		t.Fatalf("first = %q; critical+confirmed should lead", fs[0].Title)
	}
	if fs[2].Title != "low" {
		t.Fatalf("last = %q; low severity should trail", fs[2].Title)
	}
}

func TestCount(t *testing.T) {
	fs := []*Finding{
		New("a", 0, CategoryWeb, SeverityCritical, ConfidenceConfirmed, "1", "t", "d", "x"),
		New("b", 0, CategoryWeb, SeverityCritical, ConfidenceConfirmed, "2", "t", "d", "x"),
		New("c", 0, CategoryWeb, SeverityInfo, ConfidenceConfirmed, "3", "t", "d", "x"),
	}
	c := Count(fs)
	if c.Critical != 2 || c.Info != 1 || c.Total != 3 {
		t.Fatalf("counts = %+v", c)
	}
}
