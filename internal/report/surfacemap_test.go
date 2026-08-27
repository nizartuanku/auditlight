package report

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nizartuanku/auditlight/internal/finding"
	"github.com/nizartuanku/auditlight/internal/store"
	"github.com/nizartuanku/auditlight/internal/surface"
)

func mkFinding(target string, port int, sev finding.Severity, sig, title string) *finding.Finding {
	return finding.New(target, port, finding.CategoryNetwork, sev,
		finding.ConfidenceConfirmed, sig, title, "d", "unit")
}

func mkJob(targets ...store.TargetOutcome) *store.Job {
	return &store.Job{ID: "job1", Targets: targets, Started: time.Now()}
}

func ok(t string) store.TargetOutcome { return store.TargetOutcome{Target: t, Processed: true} }

func TestSurfaceMapIsSelfContainedSVG(t *testing.T) {
	g := surface.Build(mkJob(ok("example.com")), []*finding.Finding{
		mkFinding("api.example.com", 443, finding.SeverityCritical, "a", "x"),
		mkFinding("api.example.com", 22, finding.SeverityLow, "b", "y"),
	})
	out := string(SurfaceMap(g))
	if !strings.HasPrefix(out, "<svg") || !strings.HasSuffix(out, "</svg>") {
		t.Fatalf("not a single svg element: %.80s…", out)
	}
	for _, bad := range []string{"http://", "https://", "<script", "url(", "xlink:href"} {
		if strings.Contains(out, bad) && !strings.Contains(bad, "www.w3.org") {
			if bad == "http://" && strings.Count(out, "http://") == 1 &&
				strings.Contains(out, "http://www.w3.org/2000/svg") {
				continue // the SVG namespace is a name, not a fetch
			}
			t.Errorf("map reaches outside the document: contains %q", bad)
		}
	}
	if !strings.Contains(out, "api.example.com") {
		t.Errorf("host label missing from the map")
	}
	if !strings.Contains(out, "443/tcp") {
		t.Errorf("service label missing from the map")
	}
}

func TestSurfaceMapEscapesLabels(t *testing.T) {
	g := surface.Build(mkJob(ok("example.com")), []*finding.Finding{
		mkFinding(`<script>alert(1)</script>.example.com`, 80, finding.SeverityLow, "a", "x"),
	})
	out := string(SurfaceMap(g))
	if strings.Contains(out, "<script>") {
		t.Fatalf("a hostile hostname reached the document unescaped")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatalf("label was dropped rather than escaped")
	}
}

// Two renders of one assessment must be byte-identical, or the same report
// printed twice would not be comparable by eye.
func TestSurfaceMapIsDeterministic(t *testing.T) {
	fs := []*finding.Finding{
		mkFinding("b.example.com", 80, finding.SeverityLow, "x", "1"),
		mkFinding("a.example.com", 443, finding.SeverityHigh, "y", "2"),
	}
	j := mkJob(ok("example.com"))
	first := string(SurfaceMap(surface.Build(j, fs)))
	second := string(SurfaceMap(surface.Build(j, []*finding.Finding{fs[1], fs[0]})))
	if first != second {
		t.Fatalf("map output depends on input order")
	}
}

func TestSurfaceMapDrawsNothingWhenThereIsNothingObserved(t *testing.T) {
	if got := SurfaceMap(surface.Build(nil, nil)); got != "" {
		t.Fatalf("an empty assessment produced a picture: %q", got)
	}
	if got := SurfaceCaption(surface.Build(nil, nil)); got != "" {
		t.Fatalf("caption written for an empty graph: %q", got)
	}
}

// A skipped target must read as skipped in the picture, not as a clean host.
func TestSurfaceMapShowsSkipReasons(t *testing.T) {
	g := surface.Build(mkJob(
		ok("example.com"),
		store.TargetOutcome{Target: "denied.test", Reason: "outside the declared scope"},
	), nil)
	out := string(SurfaceMap(g))
	if !strings.Contains(out, "skipped — outside the declared scope") {
		t.Fatalf("skip reason not drawn:\n%s", out)
	}
	if !strings.Contains(SurfaceCaption(g), "skipped") {
		t.Fatalf("caption does not mention the skipped target: %s", SurfaceCaption(g))
	}
}

func TestSurfaceCaptionStatesTruncation(t *testing.T) {
	var fs []*finding.Finding
	for i := 0; i < surface.MaxServicesPerHost+5; i++ {
		fs = append(fs, mkFinding("example.com", 1000+i, finding.SeverityLow,
			string(rune('a'+i)), "t"))
	}
	c := SurfaceCaption(surface.Build(mkJob(ok("example.com")), fs))
	if !strings.Contains(c, "folded") {
		t.Fatalf("truncation not stated in the caption: %s", c)
	}
}

// The map goes into the Assessment Report, so it must survive the template.
func TestAssessmentReportCarriesTheMap(t *testing.T) {
	j := mkJob(ok("example.com"))
	j.Profile = "perimeter"
	j.FindingsTotal, j.FindingsShown = 1, 1
	html, err := Assessment(Input{
		Job:      j,
		Findings: []*finding.Finding{mkFinding("api.example.com", 443, finding.SeverityHigh, "a", "x")},
		Version:  "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(html)
	if !strings.Contains(s, "Attack surface") {
		t.Fatalf("assessment report has no surface section")
	}
	if !strings.Contains(s, `class="smap"`) {
		t.Fatalf("assessment report has no map")
	}
	if !strings.Contains(s, "does not know how these hosts reach one another") {
		t.Fatalf("the report draws a graph without stating what it does not claim")
	}
}

// A declared target that is itself a host carries its services one level down.
// Those services still belong in the service column: a reader scanning the
// "host observed" column must never find a port number in it.
func TestServicesSitInTheServiceColumnEvenUnderARoot(t *testing.T) {
	g := surface.Build(mkJob(ok("example.com")), []*finding.Finding{
		mkFinding("example.com", 3306, finding.SeverityMedium, "a", "x"),
		mkFinding("api.example.com", 0, finding.SeverityLow, "b", "y"),
	})
	out := string(SurfaceMap(g))
	svcX, hostX := -1.0, -1.0
	for _, line := range strings.Split(out, "<text class=\"lbl\"") {
		if strings.Contains(line, "3306/tcp") {
			svcX = xAttr(t, line)
		}
		if strings.Contains(line, "api.example.com") {
			hostX = xAttr(t, line)
		}
	}
	if svcX < 0 || hostX < 0 {
		t.Fatalf("labels missing from the map:\n%s", out)
	}
	if svcX <= hostX {
		t.Fatalf("service label at x=%v is not right of the host column at x=%v", svcX, hostX)
	}
}

func xAttr(t *testing.T, s string) float64 {
	t.Helper()
	i := strings.Index(s, `x="`)
	if i < 0 {
		t.Fatalf("no x attribute in %q", s)
	}
	rest := s[i+3:]
	j := strings.Index(rest, `"`)
	var f float64
	if _, err := fmt.Sscanf(rest[:j], "%f", &f); err != nil {
		t.Fatalf("bad x attribute %q", rest[:j])
	}
	return f
}
