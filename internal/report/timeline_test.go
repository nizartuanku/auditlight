package report

import (
	"strings"
	"testing"
	"time"

	"github.com/nizartuanku/auditlight/internal/finding"
	"github.com/nizartuanku/auditlight/internal/store"
)

func snap(day int, fs []*finding.Finding, targets ...store.TargetOutcome) RunSnapshot {
	return RunSnapshot{
		JobID:    "j" + string(rune('0'+day)),
		At:       time.Date(2026, 8, day, 9, 0, 0, 0, time.UTC),
		Findings: fs,
		Targets:  targets,
	}
}

// One run is not a trend, and a chart of one point invites the reader to see
// one anyway.
func TestTimelineNeedsTwoRuns(t *testing.T) {
	svg, cap := Timeline([]RunSnapshot{snap(1, nil, ok("example.com"))})
	if svg != "" || cap != "" {
		t.Fatalf("a single run produced a timeline")
	}
}

// This is the distinction the whole picture exists to preserve.
func TestAssessedAndClearIsNotTheSameAsNotAssessed(t *testing.T) {
	first := snap(1, []*finding.Finding{
		mkFinding("api.example.com", 443, finding.SeverityHigh, "a", "x"),
	}, ok("example.com"))
	// Second run: the target was assessed and the finding is gone.
	second := snap(8, nil, ok("example.com"))
	// Third run: the target was skipped, so nothing can be concluded.
	third := snap(15, nil, store.TargetOutcome{Target: "example.com", Reason: "out of scope"})

	svg, _ := Timeline([]RunSnapshot{first, second, third})
	s := string(svg)
	if !strings.Contains(s, "c-clear") {
		t.Errorf("no cell marked assessed-and-clear")
	}
	if !strings.Contains(s, "c-absent") {
		t.Errorf("no cell marked not-assessed")
	}
	if !strings.Contains(s, "assessed, nothing found") || !strings.Contains(s, "not assessed") {
		t.Errorf("the key does not name both states:\n%s", s)
	}
	if !strings.Contains(s, "assessed on 8 Aug 2026, nothing recorded") {
		t.Errorf("cell tooltip does not say which state it is:\n%s", s)
	}
}

func TestTimelineEscapesHostNames(t *testing.T) {
	bad := `<img src=x onerror=1>.example.com`
	svg, _ := Timeline([]RunSnapshot{
		snap(1, []*finding.Finding{mkFinding(bad, 80, finding.SeverityLow, "a", "x")}, ok("example.com")),
		snap(8, nil, ok("example.com")),
	})
	if strings.Contains(string(svg), "<img") {
		t.Fatalf("hostile host name reached the document unescaped")
	}
}

func TestTimelineCaptionStatesWhatIsNotDrawn(t *testing.T) {
	var snaps []RunSnapshot
	for i := 1; i <= tlMaxRuns+3; i++ {
		snaps = append(snaps, snap(i, []*finding.Finding{
			mkFinding("api.example.com", 443, finding.SeverityLow, "a", "x"),
		}, ok("example.com")))
	}
	_, cap := Timeline(snaps)
	if !strings.Contains(cap, "earlier run") {
		t.Fatalf("dropped runs not stated: %s", cap)
	}
}

func TestTimelineOrdersRunsByTimeNotByArrival(t *testing.T) {
	a := snap(1, []*finding.Finding{mkFinding("h.example.com", 1, finding.SeverityLow, "a", "x")}, ok("example.com"))
	b := snap(9, []*finding.Finding{mkFinding("h.example.com", 1, finding.SeverityCritical, "a", "x")}, ok("example.com"))
	svg, _ := Timeline([]RunSnapshot{b, a})
	s := string(svg)
	i, j := strings.Index(s, "1 Aug"), strings.Index(s, "9 Aug")
	if i < 0 || j < 0 || i > j {
		t.Fatalf("columns are not in chronological order")
	}
}

// Three columns all reading "27 Aug" tell the reader nothing. When every run
// lands on one day the clock is the informative label.
func TestSameDayRunsAreLabelledByTime(t *testing.T) {
	base := time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC)
	mk := func(h, m int) RunSnapshot {
		return RunSnapshot{
			JobID: "j", At: base.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute),
			Findings: []*finding.Finding{mkFinding("h.example.com", 1, finding.SeverityLow, "a", "x")},
			Targets:  []store.TargetOutcome{ok("example.com")},
		}
	}
	svg, _ := Timeline([]RunSnapshot{mk(0, 0), mk(1, 30)})
	s := string(svg)
	if !strings.Contains(s, "09:00") || !strings.Contains(s, "10:30") {
		t.Fatalf("same-day runs were not labelled by time:\n%s", s)
	}
	// The tooltips still carry the full date; it is the column headings that
	// must not be three copies of one day.
	for _, part := range strings.Split(s, `class="hdr"`)[1:] {
		head := part[:strings.Index(part, "</text>")]
		if strings.Contains(head, "27 Aug") {
			t.Fatalf("column heading %q repeats a date that carries no information", head)
		}
	}
}
