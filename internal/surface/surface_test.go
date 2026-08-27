package surface

import (
	"reflect"
	"testing"

	"github.com/nizartuanku/auditlight/internal/finding"
	"github.com/nizartuanku/auditlight/internal/store"
)

func f(target string, port int, sev finding.Severity, sig string) *finding.Finding {
	return finding.New(target, port, finding.CategoryNetwork, sev,
		finding.ConfidenceConfirmed, sig, "t "+sig, "d", "unit")
}

func job(targets ...store.TargetOutcome) *store.Job {
	return &store.Job{ID: "job1", Targets: targets}
}

func processed(t string) store.TargetOutcome {
	return store.TargetOutcome{Target: t, Processed: true}
}

func TestHostsAttachToTheDeclaredTargetTheyBelongTo(t *testing.T) {
	g := Build(job(processed("example.com"), processed("other.test")), []*finding.Finding{
		f("api.example.com", 443, finding.SeverityHigh, "a"),
		f("other.test", 22, finding.SeverityLow, "b"),
	})
	root := findNode(t, g, "root:example.com")
	if len(root.Children) != 1 || root.Children[0].Label != "api.example.com" {
		t.Fatalf("api.example.com did not attach under example.com: %+v", root.Children)
	}
	// other.test is its own declared target, so no second host node is invented
	// for a name identical to the root.
	other := findNode(t, g, "root:other.test")
	for _, c := range other.Children {
		if c.Kind == KindHost {
			t.Fatalf("host node invented for a name identical to its root: %s", c.Label)
		}
	}
}

// A finding whose target matches no declared root must not be quietly filed
// under one that happens to sort first. Invariant I2: no invented structure.
func TestUnmatchedHostIsGroupedNotGuessed(t *testing.T) {
	g := Build(job(processed("example.com")), []*finding.Finding{
		f("stray.invalid", 80, finding.SeverityMedium, "a"),
	})
	if g.Unplaced != 1 {
		t.Fatalf("unplaced = %d, want 1", g.Unplaced)
	}
	declared := findNode(t, g, "root:example.com")
	if len(declared.Children) != 0 {
		t.Fatalf("stray host was attached to a declared target it does not belong to")
	}
	if n := findNode(t, g, "root:__unplaced"); n.Label != MaxUnattributedRoot {
		t.Fatalf("unplaced group mislabelled: %q", n.Label)
	}
}

// Invariant I1: a target that was never assessed is shown, with its reason.
func TestSkippedTargetSurvivesIntoTheGraph(t *testing.T) {
	g := Build(job(
		processed("example.com"),
		store.TargetOutcome{Target: "denied.test", Reason: "outside the declared scope"},
	), nil)
	n := findNode(t, g, "root:denied.test")
	if !n.Skipped || n.Reason != "outside the declared scope" {
		t.Fatalf("skip not recorded: %+v", n)
	}
	if g.SkippedTargets != 1 {
		t.Fatalf("SkippedTargets = %d, want 1", g.SkippedTargets)
	}
}

func TestCountsRollUpAndSeverityIsTheWorstBelow(t *testing.T) {
	g := Build(job(processed("example.com")), []*finding.Finding{
		f("api.example.com", 443, finding.SeverityCritical, "a"),
		f("api.example.com", 443, finding.SeverityLow, "b"),
		f("api.example.com", 22, finding.SeverityMedium, "c"),
	})
	root := findNode(t, g, "root:example.com")
	if root.Total.Total != 3 {
		t.Fatalf("root total = %d, want 3", root.Total.Total)
	}
	if root.Severity != finding.SeverityCritical {
		t.Fatalf("root severity = %q, want critical", root.Severity)
	}
	host := findNode(t, g, "host:api.example.com")
	if host.Own.Total != 0 {
		t.Fatalf("findings on a port should sit on the service, not the host: %+v", host.Own)
	}
	if g.Services != 2 {
		t.Fatalf("services = %d, want 2", g.Services)
	}
}

// A port of zero is a finding about the host itself, not about a service.
func TestPortlessFindingSitsOnTheHost(t *testing.T) {
	g := Build(job(processed("example.com")), []*finding.Finding{
		f("example.com", 0, finding.SeverityHigh, "a"),
	})
	root := findNode(t, g, "root:example.com")
	if root.Own.Total != 1 {
		t.Fatalf("portless finding did not land on the root: %+v", root.Own)
	}
	if g.Services != 0 {
		t.Fatalf("a service was invented for a portless finding")
	}
}

func TestTruncationIsCountedNotDropped(t *testing.T) {
	var fs []*finding.Finding
	for i := 0; i < MaxServicesPerHost+6; i++ {
		fs = append(fs, f("example.com", 1000+i, finding.SeverityLow, string(rune('a'+i))))
	}
	g := Build(job(processed("example.com")), fs)
	root := findNode(t, g, "root:example.com")
	if len(root.Children) != MaxServicesPerHost {
		t.Fatalf("children = %d, want %d", len(root.Children), MaxServicesPerHost)
	}
	last := root.Children[len(root.Children)-1]
	if last.Kind != KindMore {
		t.Fatalf("tail is not a KindMore node: %+v", last)
	}
	if last.Hidden != 7 || g.Truncated != 7 {
		t.Fatalf("hidden = %d, truncated = %d, want 7 and 7", last.Hidden, g.Truncated)
	}
	// Everything hidden is still counted in the totals.
	if root.Total.Total != len(fs) {
		t.Fatalf("root total = %d, want %d — folding a node must not lose its findings",
			root.Total.Total, len(fs))
	}
}

// The picture has to be reproducible or two prints of one run will not match.
func TestLayoutIsDeterministicUnderInputReordering(t *testing.T) {
	fs := []*finding.Finding{
		f("b.example.com", 80, finding.SeverityLow, "x"),
		f("a.example.com", 443, finding.SeverityHigh, "y"),
		f("a.example.com", 22, finding.SeverityCritical, "z"),
	}
	first := shape(Build(job(processed("example.com")), fs))
	rev := []*finding.Finding{fs[2], fs[0], fs[1]}
	second := shape(Build(job(processed("example.com")), rev))
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("graph shape depends on input order:\n%v\n%v", first, second)
	}
}

func TestHostKeyNormalisation(t *testing.T) {
	cases := map[string]string{
		"https://Example.COM/path?q=1": "example.com",
		"example.com:8443":             "example.com",
		"example.com.":                 "example.com",
		"user@example.com":             "example.com",
		"[2001:db8::1]":                "[2001:db8::1]",
		"192.0.2.10":                   "192.0.2.10",
		"  ":                           "",
	}
	for in, want := range cases {
		if got := HostKey(in); got != want {
			t.Errorf("HostKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEmptyJobProducesNothingToDraw(t *testing.T) {
	if g := Build(nil, nil); !g.Empty() {
		t.Fatalf("nil job produced a graph: %+v", g)
	}
}

// shape reduces a graph to its drawn skeleton, which is what has to be stable.
func shape(g *Graph) []string {
	var out []string
	var walk func(n *Node, d int)
	walk = func(n *Node, d int) {
		out = append(out, string(rune('0'+d))+":"+n.ID+":"+string(n.Severity))
		for _, c := range n.Children {
			walk(c, d+1)
		}
	}
	for _, r := range g.Roots {
		walk(r, 0)
	}
	return out
}

func findNode(t *testing.T, g *Graph, id string) *Node {
	t.Helper()
	var found *Node
	var walk func(n *Node)
	walk = func(n *Node) {
		if n.ID == id {
			found = n
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, r := range g.Roots {
		walk(r)
	}
	if found == nil {
		t.Fatalf("node %q not in graph", id)
	}
	return found
}
