package score

import (
	"strings"
	"testing"

	"github.com/nizartuanku/auditlight/internal/finding"
)

func mk(sev finding.Severity, sig string) *finding.Finding {
	return finding.New("example.com", 443, finding.CategoryTLS, sev,
		finding.ConfidenceConfirmed, sig, "Title "+sig, "Description.", "tlsaudit")
}

// Invariant I1: a cap is always reported, never applied silently.
func TestApplyCapReportsWhatItHid(t *testing.T) {
	fs := []*finding.Finding{
		mk(finding.SeverityCritical, "a"), mk(finding.SeverityHigh, "b"),
		mk(finding.SeverityMedium, "c"), mk(finding.SeverityLow, "d"),
	}
	c := ApplyCap(fs, 2)
	if len(c.Shown) != 2 {
		t.Fatalf("shown = %d, want 2", len(c.Shown))
	}
	if c.Total != 4 {
		t.Fatalf("total = %d, want the real count", c.Total)
	}
	if c.Withheld != 2 {
		t.Fatalf("withheld = %d, want 2", c.Withheld)
	}
	if c.Notice == "" {
		t.Fatal("a cap must produce a notice the reader can see")
	}
	for _, want := range []string{"4", "2"} {
		if !strings.Contains(c.Notice, want) {
			t.Fatalf("notice %q should state the numbers", c.Notice)
		}
	}
}

func TestApplyCapNoOpWhenUnderLimit(t *testing.T) {
	fs := []*finding.Finding{mk(finding.SeverityLow, "a")}
	for _, limit := range []int{0, 1, 10} {
		c := ApplyCap(fs, limit)
		if c.Withheld != 0 || c.Notice != "" {
			t.Fatalf("limit %d should withhold nothing, got %+v", limit, c)
		}
		if len(c.Shown) != 1 {
			t.Fatalf("limit %d dropped a finding", limit)
		}
	}
}

func TestRankPutsSeverityFirst(t *testing.T) {
	fs := []*finding.Finding{
		mk(finding.SeverityLow, "low"), mk(finding.SeverityCritical, "crit"),
		mk(finding.SeverityMedium, "med"),
	}
	ranked := Rank(fs)
	if ranked[0].Severity != finding.SeverityCritical {
		t.Fatalf("first severity = %q", ranked[0].Severity)
	}
	if ranked[2].Severity != finding.SeverityLow {
		t.Fatalf("last severity = %q", ranked[2].Severity)
	}
	// Rank must not reorder the caller's slice.
	if fs[0].Severity != finding.SeverityLow {
		t.Fatal("Rank mutated its input")
	}
}

func TestSummarisePostureWording(t *testing.T) {
	cases := []struct {
		name string
		fs   []*finding.Finding
		want string
	}{
		{"critical", []*finding.Finding{mk(finding.SeverityCritical, "a")}, "Critical findings are present"},
		{"high", []*finding.Finding{mk(finding.SeverityHigh, "a")}, "high-severity issues"},
		{"medium", []*finding.Finding{mk(finding.SeverityMedium, "a")}, "medium-severity"},
		{"low", []*finding.Finding{mk(finding.SeverityLow, "a")}, "hardening opportunities"},
		{"none", nil, "not the same as an absence of risk"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := Summarise(tc.fs)
			if !strings.Contains(s.Posture, tc.want) {
				t.Fatalf("posture = %q, should contain %q", s.Posture, tc.want)
			}
		})
	}
}

// An empty result must never be described as "secure".
func TestEmptySummaryDoesNotClaimSafety(t *testing.T) {
	s := Summarise(nil)
	for _, forbidden := range []string{"secure", "safe", "clean bill"} {
		if strings.Contains(strings.ToLower(s.Posture), forbidden) {
			t.Fatalf("posture %q must not imply safety", s.Posture)
		}
	}
}

func TestSummariseCountsCategories(t *testing.T) {
	a := mk(finding.SeverityHigh, "a")
	a.SourceTools = []string{"tlsaudit", "testssl"}
	b := mk(finding.SeverityMedium, "b")
	b.Status = finding.StatusManualReview
	c := mk(finding.SeverityInfo, "c")
	c.Status = finding.StatusInformational

	s := Summarise([]*finding.Finding{a, b, c})
	if s.Corroborated != 1 {
		t.Fatalf("corroborated = %d", s.Corroborated)
	}
	if s.NeedsReview != 1 {
		t.Fatalf("needs review = %d", s.NeedsReview)
	}
	if s.Actionable != 1 {
		t.Fatalf("actionable = %d; only the open finding counts", s.Actionable)
	}
	if len(s.TopRisks) != 1 {
		t.Fatalf("top risks = %v", s.TopRisks)
	}
}

func TestTopRisksCapsAtThree(t *testing.T) {
	var fs []*finding.Finding
	for _, s := range []string{"a", "b", "c", "d", "e"} {
		fs = append(fs, mk(finding.SeverityCritical, s))
	}
	if got := len(Summarise(fs).TopRisks); got != 3 {
		t.Fatalf("top risks = %d, want at most 3", got)
	}
}
