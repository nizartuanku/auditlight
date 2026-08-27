package compliance

import (
	"strings"
	"testing"

	"github.com/nizartuanku/auditlight/internal/finding"
)

func mk(cat finding.Category, sig string) *finding.Finding {
	return finding.New("example.com", 443, cat, finding.SeverityMedium,
		finding.ConfidenceConfirmed, sig, "Title", "Description.", "tool")
}

func TestAnnotateRespectsFrameworkEntitlement(t *testing.T) {
	f := mk(finding.CategoryTLS, "a")
	Annotate([]*finding.Finding{f}, []string{ISO27001, CISv8})
	if len(f.Compliance) != 2 {
		t.Fatalf("controls = %d, want only the two entitled frameworks", len(f.Compliance))
	}
	for _, c := range f.Compliance {
		if c.Framework == NISTCSF || c.Framework == UUPDP {
			t.Fatalf("framework %q is not entitled and must not appear", c.Framework)
		}
	}
}

func TestAnnotateAllFrameworks(t *testing.T) {
	f := mk(finding.CategorySecret, "a")
	Annotate([]*finding.Finding{f}, AllFrameworks())
	if len(f.Compliance) != 4 {
		t.Fatalf("controls = %d, want one per framework", len(f.Compliance))
	}
	var sawPDP bool
	for _, c := range f.Compliance {
		if c.Framework == UUPDP && strings.HasPrefix(c.ID, "Pasal") {
			sawPDP = true
		}
		if c.Title == "" {
			t.Fatalf("control %s %s has no title", c.Framework, c.ID)
		}
	}
	if !sawPDP {
		t.Fatal("a secret exposure should map to a UU PDP article")
	}
}

// Invariant I2: an unmapped category is flagged for a human, never guessed at.
func TestUnmappedCategoryBecomesManualReview(t *testing.T) {
	f := mk(finding.Category("something-new"), "a")
	Annotate([]*finding.Finding{f}, AllFrameworks())
	if len(f.Compliance) != 0 {
		t.Fatal("an unmapped category must not receive invented controls")
	}
	if f.Status != finding.StatusManualReview {
		t.Fatalf("status = %q, want manual_review", f.Status)
	}
}

func TestInformationalFindingsAreNotControlEvidence(t *testing.T) {
	f := mk(finding.CategoryNetwork, "a")
	f.Status = finding.StatusInformational
	Annotate([]*finding.Finding{f}, AllFrameworks())
	if len(f.Compliance) != 0 {
		t.Fatal("inventory records are not control evidence")
	}
	if f.Status != finding.StatusInformational {
		t.Fatal("annotation must not change an informational status")
	}
}

func TestSummariseGroupsAndOrders(t *testing.T) {
	a := mk(finding.CategoryTLS, "a")
	b := mk(finding.CategoryTLS, "b")
	c := mk(finding.CategorySecret, "c")
	fs := []*finding.Finding{a, b, c}
	Annotate(fs, []string{ISO27001})

	cov := Summarise(fs)
	if len(cov) != 2 {
		t.Fatalf("coverage rows = %d, want one per distinct control", len(cov))
	}
	for _, row := range cov {
		if row.Framework != ISO27001 {
			t.Fatalf("unexpected framework %q", row.Framework)
		}
		if row.ID == "A.8.24" && row.Findings != 2 {
			t.Fatalf("A.8.24 findings = %d, want 2", row.Findings)
		}
	}
}

func TestDisclaimerRefusesToOverclaim(t *testing.T) {
	low := strings.ToLower(Disclaimer)
	for _, must := range []string{"not a statement of compliance", "certification", "legal opinion", "principle-based"} {
		if !strings.Contains(low, strings.ToLower(must)) {
			t.Fatalf("the disclaimer must mention %q", must)
		}
	}
}

func TestEveryFindingCategoryIsMapped(t *testing.T) {
	for _, cat := range finding.AllCategories() {
		if _, ok := byCategory[cat]; !ok {
			t.Errorf("category %q has no control mapping", cat)
		}
	}
}
