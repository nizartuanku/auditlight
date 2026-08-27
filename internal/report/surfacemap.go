package report

import (
	"fmt"
	"html/template"
	"strings"

	"github.com/nizartuanku/auditlight/internal/finding"
	"github.com/nizartuanku/auditlight/internal/surface"
)

// Attack Surface Map.
//
// The report gets a left-to-right dendrogram rather than the radial graph the
// dashboard draws in 3D, and the difference is deliberate. This picture is
// printed. It cannot be rotated, so it must not rely on depth or parallax to
// stay readable, and it must never let one label sit on top of another. A tree
// laid out along one axis satisfies both: every row has its own line, the
// ordering is total, and it survives being turned into a PDF page.

const (
	smapWidth   = 1000.0
	smapRowH    = 22.0
	smapTop     = 40.0
	smapBottom  = 14.0
	smapColRoot = 20.0
	smapColHost = 258.0
	smapColSvc  = 476.0
	smapBarX    = 700.0
	smapBarW    = 210.0
	smapMaxRows = 80
)

type smapRow struct {
	node  *surface.Node
	depth int
	x     float64
	y     float64
}

// SurfaceMap renders the graph as a self-contained inline SVG. It returns an
// empty string when there is nothing observed to draw — an empty picture would
// imply an assessment found a surface of nothing, which is a different claim
// from having nothing to show.
func SurfaceMap(g *surface.Graph) template.HTML {
	if g.Empty() {
		return ""
	}

	rows := make([]*smapRow, 0, 64)
	var walk func(n *surface.Node, depth int)
	walk = func(n *surface.Node, depth int) {
		if len(rows) >= smapMaxRows {
			return
		}
		r := &smapRow{node: n, depth: depth}
		rows = append(rows, r)
		for _, c := range n.Children {
			walk(c, depth+1)
		}
	}
	for _, root := range g.Roots {
		walk(root, 0)
	}
	if len(rows) == 0 {
		return ""
	}

	for i, r := range rows {
		r.y = smapTop + float64(i)*smapRowH + smapRowH/2
		r.x = smapColOf(r.node)
	}
	height := smapTop + float64(len(rows))*smapRowH + smapBottom

	// Connectors run down from the parent's own row and then across, which is
	// how every file tree anyone has ever read is drawn. It costs a little
	// elegance against a balanced dendrogram and buys back the thing that
	// matters on paper: no row is ever ambiguous about whose child it is.
	yOf := map[string]float64{}
	xOf := map[string]float64{}
	for _, r := range rows {
		yOf[r.node.ID] = r.y
		xOf[r.node.ID] = r.x
	}

	var b strings.Builder
	fmt.Fprintf(&b,
		`<svg class="smap" viewBox="0 0 %.0f %.0f" width="%.0f" height="%.0f" role="img" `+
			`aria-label="Attack surface map" xmlns="http://www.w3.org/2000/svg">`,
		smapWidth, height, smapWidth, height)

	// Column headings.
	smapHeading(&b, smapColRoot, "Declared target")
	smapHeading(&b, smapColHost, "Host observed")
	smapHeading(&b, smapColSvc, "Service observed")
	smapHeading(&b, smapBarX, "Findings recorded")
	fmt.Fprintf(&b, `<line class="rule" x1="%.0f" y1="%.0f" x2="%.0f" y2="%.0f"/>`,
		smapColRoot, smapTop-14, smapWidth-20, smapTop-14)

	// Connectors first so nodes sit on top of them.
	for _, r := range rows {
		if r.depth == 0 {
			continue
		}
		py, ok := yOf[r.node.Parent]
		if !ok {
			continue
		}
		px := xOf[r.node.Parent]
		cx := r.x
		fmt.Fprintf(&b,
			`<path class="lnk" d="M%.1f %.1f H%.1f V%.1f H%.1f"/>`,
			px, py, px+14, r.y, cx-6)
	}

	for _, r := range rows {
		x := r.x
		n := r.node
		cls := "skip"
		if !n.Skipped {
			cls = ""
		}
		fmt.Fprintf(&b, `<g class="nd %s">`, cls)
		fmt.Fprintf(&b, `<circle class="dot d-%s" cx="%.1f" cy="%.1f" r="%.1f"/>`,
			smapSevClass(n.Severity), x, r.y, smapRadius(n.Kind))

		label := smapElide(n.Label, smapLabelChars(x))
		fmt.Fprintf(&b, `<text class="lbl" x="%.1f" y="%.1f">%s</text>`,
			x+12, r.y+4, template.HTMLEscapeString(label))

		switch {
		case n.Skipped:
			reason := n.Reason
			if reason == "" {
				reason = "not assessed"
			}
			fmt.Fprintf(&b, `<text class="sub" x="%.1f" y="%.1f">skipped — %s</text>`,
				smapBarX, r.y+4, template.HTMLEscapeString(smapElide(reason, 46)))
		case n.Total.Total == 0:
			fmt.Fprintf(&b, `<text class="sub" x="%.1f" y="%.1f">no findings recorded</text>`,
				smapBarX, r.y+4)
		default:
			smapBar(&b, r.y, n.Total)
		}
		b.WriteString(`</g>`)
	}

	b.WriteString(`</svg>`)
	return template.HTML(b.String()) //nolint:gosec // every dynamic value is escaped above
}

// smapColOf places a node by what it IS, not by how deep it sits. A declared
// target that is itself a host carries its services one level down, and those
// services belong in the service column with every other service — not in the
// host column merely because of where they hang.
func smapColOf(n *surface.Node) float64 {
	switch n.Kind {
	case surface.KindRoot:
		return smapColRoot
	case surface.KindHost:
		return smapColHost
	case surface.KindService:
		return smapColSvc
	case surface.KindMore:
		// A fold stands where the siblings it replaces stood.
		if n.Parent != "" && strings.HasPrefix(n.Parent, "host:") {
			return smapColSvc
		}
		return smapColHost
	}
	return smapColHost
}

func smapLabelChars(x float64) int {
	switch x {
	case smapColRoot:
		return 30
	case smapColHost:
		return 29
	default:
		return 26
	}
}

func smapRadius(k surface.Kind) float64 {
	switch k {
	case surface.KindRoot:
		return 5.5
	case surface.KindHost:
		return 4.5
	case surface.KindMore:
		return 3
	default:
		return 4
	}
}

func smapHeading(b *strings.Builder, x float64, s string) {
	fmt.Fprintf(b, `<text class="hdr" x="%.1f" y="%.1f">%s</text>`, x, smapTop-24, s)
}

// smapBar draws the severity mix as one stacked bar. Every non-zero class gets
// at least a visible sliver: a count of one that renders as nothing would be a
// silent drop, and this product does not do those.
func smapBar(b *strings.Builder, y float64, c finding.Counts) {
	type seg struct {
		n   int
		cls string
	}
	segs := []seg{
		{c.Critical, "crit"}, {c.High, "high"}, {c.Medium, "med"},
		{c.Low, "low"}, {c.Info, "info"},
	}
	const minW = 4.0
	nonZero := 0
	for _, s := range segs {
		if s.n > 0 {
			nonZero++
		}
	}
	avail := smapBarW - float64(nonZero)*minW
	if avail < 0 {
		avail = 0
	}
	x := smapBarX
	for _, s := range segs {
		if s.n == 0 {
			continue
		}
		w := minW + avail*float64(s.n)/float64(c.Total)
		fmt.Fprintf(b, `<rect class="seg s-%s" x="%.1f" y="%.1f" width="%.1f" height="10" rx="2"/>`,
			s.cls, x, y-5, w)
		x += w
	}
	fmt.Fprintf(b, `<text class="cnt" x="%.1f" y="%.1f">%d</text>`, smapBarX+smapBarW+10, y+4, c.Total)
}

func smapSevClass(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "crit"
	case finding.SeverityHigh:
		return "high"
	case finding.SeverityMedium:
		return "med"
	case finding.SeverityLow:
		return "low"
	case finding.SeverityInfo:
		return "info"
	}
	return "none"
}

func smapElide(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max < 2 {
		return string(r[:max])
	}
	return string(r[:max-1]) + "…"
}

// SurfaceCaption is the sentence printed under the map. It states the limit of
// the picture in the picture's own words, so a client reading the report
// unaccompanied gets the same caveat an assessor would give them aloud.
func SurfaceCaption(g *surface.Graph) string {
	if g.Empty() {
		return ""
	}
	var parts []string
	parts = append(parts, fmt.Sprintf("%d declared target(s), %d host(s) and %d observed service(s)",
		len(g.Roots), g.Hosts, g.Services))
	if g.SkippedTargets > 0 {
		parts = append(parts, fmt.Sprintf("%d target(s) skipped and shown as such", g.SkippedTargets))
	}
	if g.Truncated > 0 {
		parts = append(parts, fmt.Sprintf("%d node(s) folded into “+n more” to keep the page readable", g.Truncated))
	}
	if g.Rows() > smapMaxRows {
		parts = append(parts, fmt.Sprintf("only the first %d rows are drawn", smapMaxRows))
	}
	return strings.Join(parts, "; ") + "."
}
