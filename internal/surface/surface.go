// Package surface derives the attack-surface graph of an assessment.
//
// The graph is built strictly from what was observed. AuditLight performs no
// traceroute, no routing discovery and no adjacency probing, so it does not
// know how hosts are connected to each other — and therefore never draws it.
// Invariant I2 applies here as much as anywhere else in the product: a picture
// that invents structure is worse than no picture, because a diagram is
// believed more readily than a sentence.
//
// What the graph does assert, and can defend:
//
//   - a declared target is a root, whether it was processed or skipped
//     (invariant I1: a skipped target is shown, with its reason, never dropped);
//   - a host sits under a root when its name is that root or a DNS-suffix of
//     it — a fact about the names as observed, not an inferred network path;
//   - a service sits under a host when a finding recorded an observed port on
//     that host;
//   - a node's severity is the worst severity actually recorded at or below it.
//
// Ordering is total and deterministic, so the same assessment always produces
// the same picture. That matters for the same reason deterministic finding IDs
// matter: two reports of the same run must be comparable by eye.
package surface

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nizartuanku/auditlight/internal/finding"
	"github.com/nizartuanku/auditlight/internal/store"
)

// Kind labels what a node represents.
type Kind string

const (
	// KindRoot is a target the operator declared and authorised.
	KindRoot Kind = "root"
	// KindHost is a name or address findings were recorded against, sitting
	// under the declared target it is a DNS-suffix of.
	KindHost Kind = "host"
	// KindService is an observed open port on a host.
	KindService Kind = "service"
	// KindMore stands for children that were not drawn. It exists so that
	// truncation is stated rather than silently applied.
	KindMore Kind = "more"
)

// Limits bound the drawn graph. Anything beyond them is aggregated into a
// KindMore node and counted, never dropped.
const (
	MaxHostsPerRoot     = 24
	MaxServicesPerHost  = 14
	MaxUnattributedRoot = "(outside the declared targets)"
)

// Node is one element of the surface.
type Node struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Kind   Kind   `json:"kind"`
	Parent string `json:"parent,omitempty"`
	Port   int    `json:"port,omitempty"`

	// Severity is the worst severity recorded at or below this node. Empty
	// when nothing was recorded there at all.
	Severity finding.Severity `json:"severity,omitempty"`
	// Own counts findings recorded exactly at this node.
	Own finding.Counts `json:"own"`
	// Total counts findings at this node and everything under it.
	Total finding.Counts `json:"total"`
	// FindingIDs are the identities recorded at this node, sorted.
	FindingIDs []string `json:"finding_ids,omitempty"`

	// Skipped marks a declared target that was not assessed, with the reason.
	Skipped bool   `json:"skipped,omitempty"`
	Reason  string `json:"reason,omitempty"`

	// Hidden is the number of siblings a KindMore node stands in for.
	Hidden int `json:"hidden,omitempty"`

	Children []*Node `json:"children,omitempty"`
}

// Leaves counts the drawable rows this node occupies: itself when it has no
// children, otherwise the sum of its children.
func (n *Node) Leaves() int {
	if len(n.Children) == 0 {
		return 1
	}
	t := 0
	for _, c := range n.Children {
		t += c.Leaves()
	}
	return t
}

// Graph is the whole surface for one job.
type Graph struct {
	JobID string  `json:"job_id"`
	Roots []*Node `json:"roots"`

	// Counted totals, before any drawing limit.
	Hosts    int `json:"hosts"`
	Services int `json:"services"`
	// Truncated is how many nodes the drawing limits folded into KindMore.
	Truncated int `json:"truncated"`
	// SkippedTargets is how many declared targets were never assessed.
	SkippedTargets int `json:"skipped_targets"`
	// Unplaced counts findings whose target matched no declared root; they are
	// grouped rather than discarded.
	Unplaced int `json:"unplaced"`
}

// Empty reports whether there is nothing worth drawing.
func (g *Graph) Empty() bool { return g == nil || len(g.Roots) == 0 }

// Rows is the number of dendrogram rows the graph needs.
func (g *Graph) Rows() int {
	t := 0
	for _, r := range g.Roots {
		t += r.Leaves()
	}
	return t
}

// Build derives the graph from a job and its findings.
func Build(job *store.Job, fs []*finding.Finding) *Graph {
	g := &Graph{}
	if job != nil {
		g.JobID = job.ID
	}

	// Roots: every declared target, processed or not.
	declared := declaredTargets(job)
	roots := make([]*Node, 0, len(declared))
	byKey := map[string]*Node{}
	for _, d := range declared {
		key := hostOf(d.Target)
		if key == "" {
			continue
		}
		if _, dup := byKey[key]; dup {
			continue
		}
		n := &Node{
			ID:      "root:" + key,
			Label:   d.Target,
			Kind:    KindRoot,
			Skipped: !d.Processed,
			Reason:  d.Reason,
		}
		if n.Skipped {
			g.SkippedTargets++
		}
		byKey[key] = n
		roots = append(roots, n)
	}

	// Index roots longest-first so the most specific declared target wins.
	rootKeys := make([]string, 0, len(byKey))
	for k := range byKey {
		rootKeys = append(rootKeys, k)
	}
	sort.Slice(rootKeys, func(i, j int) bool {
		if len(rootKeys[i]) != len(rootKeys[j]) {
			return len(rootKeys[i]) > len(rootKeys[j])
		}
		return rootKeys[i] < rootKeys[j]
	})

	var unplaced *Node
	hosts := map[string]*Node{}    // rootKey\x00hostKey -> node
	services := map[string]*Node{} // hostNodeID\x00port -> node

	for _, f := range fs {
		if f == nil {
			continue
		}
		hk := hostOf(f.Target)
		if hk == "" {
			continue
		}

		// Which declared root does this host belong under?
		var root *Node
		for _, rk := range rootKeys {
			if hk == rk || strings.HasSuffix(hk, "."+rk) {
				root = byKey[rk]
				break
			}
		}
		if root == nil {
			if unplaced == nil {
				unplaced = &Node{
					ID:    "root:__unplaced",
					Label: MaxUnattributedRoot,
					Kind:  KindRoot,
				}
				roots = append(roots, unplaced)
			}
			root = unplaced
			g.Unplaced++
		}

		// The host node. When the host is the declared target itself, the
		// root doubles as the host: inventing a second identical node would
		// pad the picture without adding a fact.
		holder := root
		if strings.TrimPrefix(root.ID, "root:") != hk {
			key := root.ID + "\x00" + hk
			h := hosts[key]
			if h == nil {
				h = &Node{
					ID:     "host:" + hk,
					Label:  hk,
					Kind:   KindHost,
					Parent: root.ID,
				}
				hosts[key] = h
				root.Children = append(root.Children, h)
				g.Hosts++
			}
			holder = h
		}

		// The service node, when a port was actually observed.
		target := holder
		if f.Port > 0 {
			key := holder.ID + "\x00" + fmt.Sprint(f.Port)
			s := services[key]
			if s == nil {
				s = &Node{
					ID:     fmt.Sprintf("svc:%s:%d", hk, f.Port),
					Label:  fmt.Sprintf("%d/tcp", f.Port),
					Kind:   KindService,
					Parent: holder.ID,
					Port:   f.Port,
				}
				services[key] = s
				holder.Children = append(holder.Children, s)
				g.Services++
			}
			target = s
		}

		target.Own = addCount(target.Own, f.Severity)
		target.FindingIDs = append(target.FindingIDs, f.ID)
	}

	for _, r := range roots {
		normalise(r)
	}
	sortNodes(roots)
	for _, r := range roots {
		g.Truncated += trim(r)
	}
	for _, r := range roots {
		rollUp(r)
	}
	g.Roots = roots
	return g
}

// declaredTargets returns the operator's targets with their outcome, falling
// back to the authorisation record when the job never got as far as recording
// per-target outcomes.
func declaredTargets(job *store.Job) []store.TargetOutcome {
	if job == nil {
		return nil
	}
	if len(job.Targets) > 0 {
		out := append([]store.TargetOutcome(nil), job.Targets...)
		sort.SliceStable(out, func(i, j int) bool { return out[i].Target < out[j].Target })
		return out
	}
	out := make([]store.TargetOutcome, 0, len(job.Authz.Targets))
	for _, t := range job.Authz.Targets {
		out = append(out, store.TargetOutcome{Target: t})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

// normalise sorts finding ids and recurses.
func normalise(n *Node) {
	sort.Strings(n.FindingIDs)
	for _, c := range n.Children {
		normalise(c)
	}
	sortNodes(n.Children)
}

// sortNodes imposes a total order: worst severity first so the eye lands on
// the problem, then by port, then by label, then by id. The trailing keys keep
// it total, which is what makes the drawing reproducible.
func sortNodes(ns []*Node) {
	sort.SliceStable(ns, func(i, j int) bool {
		a, b := ns[i], ns[j]
		if a.Kind == KindMore != (b.Kind == KindMore) {
			return b.Kind == KindMore // KindMore always last
		}
		as, bs := worstOwn(a), worstOwn(b)
		if as != bs {
			return as > bs
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Label != b.Label {
			return a.Label < b.Label
		}
		return a.ID < b.ID
	})
}

// worstOwn is the severity rank recorded directly at a node, used only for
// ordering before roll-up has happened.
func worstOwn(n *Node) int {
	switch {
	case n.Own.Critical > 0:
		return 5
	case n.Own.High > 0:
		return 4
	case n.Own.Medium > 0:
		return 3
	case n.Own.Low > 0:
		return 2
	case n.Own.Info > 0:
		return 1
	}
	// A node with nothing of its own still ranks by its worst descendant.
	best := 0
	for _, c := range n.Children {
		if r := worstOwn(c); r > best {
			best = r
		}
	}
	return best
}

// trim enforces the drawing limits, replacing the tail with a KindMore node
// that says how many were folded away. It returns how many were hidden.
func trim(n *Node) int {
	// The limit follows what the children are, not what the parent is: a
	// declared target that is itself a host carries services directly, and
	// capping those at the host limit would let one noisy host fill the page.
	limit := MaxServicesPerHost
	for _, c := range n.Children {
		if c.Kind == KindHost {
			limit = MaxHostsPerRoot
			break
		}
	}
	hidden := 0
	if limit > 0 && len(n.Children) > limit {
		rest := n.Children[limit-1:]
		n.Children = n.Children[:limit-1]
		more := &Node{
			ID:     n.ID + "/more",
			Label:  fmt.Sprintf("+%d more", len(rest)),
			Kind:   KindMore,
			Parent: n.ID,
			Hidden: len(rest),
		}
		for _, r := range rest {
			rollUp(r)
			more.Own = sumCounts(more.Own, r.Total)
		}
		hidden += len(rest)
		n.Children = append(n.Children, more)
	}
	for _, c := range n.Children {
		hidden += trim(c)
	}
	return hidden
}

// rollUp computes Total and Severity bottom-up.
func rollUp(n *Node) {
	total := n.Own
	for _, c := range n.Children {
		rollUp(c)
		total = sumCounts(total, c.Total)
	}
	n.Total = total
	n.Severity = worstOf(total)
}

func addCount(c finding.Counts, s finding.Severity) finding.Counts {
	switch s {
	case finding.SeverityCritical:
		c.Critical++
	case finding.SeverityHigh:
		c.High++
	case finding.SeverityMedium:
		c.Medium++
	case finding.SeverityLow:
		c.Low++
	case finding.SeverityInfo:
		c.Info++
	default:
		return c
	}
	c.Total++
	return c
}

func sumCounts(a, b finding.Counts) finding.Counts {
	a.Critical += b.Critical
	a.High += b.High
	a.Medium += b.Medium
	a.Low += b.Low
	a.Info += b.Info
	a.Total += b.Total
	return a
}

func worstOf(c finding.Counts) finding.Severity {
	switch {
	case c.Critical > 0:
		return finding.SeverityCritical
	case c.High > 0:
		return finding.SeverityHigh
	case c.Medium > 0:
		return finding.SeverityMedium
	case c.Low > 0:
		return finding.SeverityLow
	case c.Info > 0:
		return finding.SeverityInfo
	}
	return ""
}

// HostKey reduces whatever the operator typed to a comparable host key. It is
// exported because anything that groups findings by host — the timeline, the
// explorer — must group them exactly the way the map does, or two views of the
// same run will disagree with each other.
func HostKey(s string) string { return hostOf(s) }

// hostOf reduces whatever the operator typed to a comparable host key. It
// accepts the same shapes the rest of the product does: bare names, addresses,
// URLs, and host:port.
func hostOf(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	// IPv6 in brackets keeps its colons; everything else loses a trailing port.
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i >= 0 {
			return s[:i+1]
		}
		return s
	}
	if i := strings.LastIndex(s, ":"); i >= 0 && strings.Count(s, ":") == 1 {
		s = s[:i]
	}
	return strings.TrimSuffix(s, ".")
}
