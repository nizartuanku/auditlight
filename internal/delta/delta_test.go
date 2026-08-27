package delta

import (
	"strings"
	"testing"
	"time"

	"github.com/nizartuanku/auditlight/internal/finding"
)

func mk(sev finding.Severity, sig string) *finding.Finding {
	return finding.New("example.com", 443, finding.CategoryTLS, sev,
		finding.ConfidenceConfirmed, sig, "Title "+sig, "Body.", "tlsaudit")
}

func TestCompareClassifiesEveryFinding(t *testing.T) {
	base := []*finding.Finding{
		mk(finding.SeverityHigh, "gone"),
		mk(finding.SeverityMedium, "worse"),
		mk(finding.SeverityHigh, "better"),
		mk(finding.SeverityLow, "same"),
	}
	cur := []*finding.Finding{
		mk(finding.SeverityCritical, "worse"),
		mk(finding.SeverityLow, "better"),
		mk(finding.SeverityLow, "same"),
		mk(finding.SeverityHigh, "fresh"),
	}
	r := Compare(base, cur, "jobA", "jobB", time.Now().AddDate(0, -3, 0), time.Now())

	if !r.HasBaseline {
		t.Fatal("a comparison with a baseline id must report having one")
	}
	want := Counts{New: 1, Resolved: 1, Regressed: 1, Improved: 1, Persisting: 1}
	if r.Counts != want {
		t.Fatalf("counts = %+v, want %+v", r.Counts, want)
	}
	if r.Counts.Total() != 5 {
		t.Fatalf("total = %d; every finding from both runs must be placed", r.Counts.Total())
	}
	if !r.Counts.Worse() || !r.Counts.Changed() {
		t.Fatal("new findings and a regression mean the result got worse")
	}

	// The regression must carry what it used to be, or a reader cannot judge it.
	reg := r.Of(ChangeRegressed)
	if len(reg) != 1 || reg[0].WasSev != finding.SeverityMedium {
		t.Fatalf("regression entry = %+v; must record the previous severity", reg)
	}
	imp := r.Of(ChangeImproved)
	if len(imp) != 1 || imp[0].WasSev != finding.SeverityHigh {
		t.Fatalf("improvement entry = %+v", imp)
	}
}

// A first run has no history. Calling everything "new" would imply a comparison
// that never happened.
func TestFirstRunIsNotAllNew(t *testing.T) {
	cur := []*finding.Finding{mk(finding.SeverityHigh, "a"), mk(finding.SeverityLow, "b")}
	r := Compare(nil, cur, "", "jobA", time.Time{}, time.Now())

	if r.HasBaseline {
		t.Fatal("no baseline id means no baseline")
	}
	if r.Counts.New != 0 {
		t.Fatalf("new = %d; a first run cannot have new findings", r.Counts.New)
	}
	if r.Counts.Persisting != 2 {
		t.Fatalf("persisting = %d, want 2", r.Counts.Persisting)
	}
	if r.Counts.Worse() {
		t.Fatal("a first run has not become worse than anything")
	}
	if !strings.Contains(r.Headline(), "First assessment") {
		t.Fatalf("headline = %q", r.Headline())
	}
}

func TestNoChangeIsReportedAsNoChange(t *testing.T) {
	fs := []*finding.Finding{mk(finding.SeverityHigh, "a")}
	same := []*finding.Finding{mk(finding.SeverityHigh, "a")}
	r := Compare(fs, same, "jobA", "jobB", time.Now(), time.Now())
	if r.Counts.Changed() || r.Counts.Worse() {
		t.Fatalf("counts = %+v, want no movement", r.Counts)
	}
	if r.Headline() != "No change since the last assessment." {
		t.Fatalf("headline = %q", r.Headline())
	}
}

func TestSeverityTrendIsCarried(t *testing.T) {
	base := []*finding.Finding{mk(finding.SeverityCritical, "a"), mk(finding.SeverityCritical, "b")}
	cur := []*finding.Finding{mk(finding.SeverityCritical, "a")}
	r := Compare(base, cur, "jobA", "jobB", time.Now(), time.Now())
	if r.SeverityBefore.Critical != 2 || r.SeverityAfter.Critical != 1 {
		t.Fatalf("trend before=%d after=%d", r.SeverityBefore.Critical, r.SeverityAfter.Critical)
	}
}

func TestEntriesOrderWorstFirst(t *testing.T) {
	base := []*finding.Finding{mk(finding.SeverityLow, "resolved")}
	cur := []*finding.Finding{mk(finding.SeverityLow, "fresh")}
	r := Compare(base, cur, "jobA", "jobB", time.Now(), time.Now())
	if r.Entries[0].Change != ChangeNew {
		t.Fatalf("first entry = %q; what got worse must lead", r.Entries[0].Change)
	}
	if r.Entries[len(r.Entries)-1].Change != ChangeResolved {
		t.Fatalf("last entry = %q", r.Entries[len(r.Entries)-1].Change)
	}
}

func TestHeadlineNeverOverclaims(t *testing.T) {
	// Resolved findings alongside new ones must not read as pure progress.
	base := []*finding.Finding{mk(finding.SeverityHigh, "gone")}
	cur := []*finding.Finding{mk(finding.SeverityHigh, "fresh")}
	r := Compare(base, cur, "jobA", "jobB", time.Now(), time.Now())
	h := strings.ToLower(r.Headline())
	if !strings.Contains(h, "new finding") {
		t.Fatalf("headline %q must lead with what got worse", r.Headline())
	}
	if strings.Contains(h, "resolved") {
		t.Fatalf("headline %q should not advertise resolution while new findings exist", r.Headline())
	}
}

func TestPluralWording(t *testing.T) {
	one := Compare(
		[]*finding.Finding{},
		[]*finding.Finding{mk(finding.SeverityHigh, "a")},
		"jobA", "jobB", time.Now(), time.Now())
	if !strings.Contains(one.Headline(), "1 new finding ") {
		t.Fatalf("singular headline = %q", one.Headline())
	}
	two := Compare(
		[]*finding.Finding{},
		[]*finding.Finding{mk(finding.SeverityHigh, "a"), mk(finding.SeverityHigh, "b")},
		"jobA", "jobB", time.Now(), time.Now())
	if !strings.Contains(two.Headline(), "2 new findings") {
		t.Fatalf("plural headline = %q", two.Headline())
	}
}
