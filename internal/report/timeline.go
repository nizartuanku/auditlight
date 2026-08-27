package report

import (
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"

	"github.com/nizartuanku/auditlight/internal/finding"
	"github.com/nizartuanku/auditlight/internal/store"
	"github.com/nizartuanku/auditlight/internal/surface"
)

// Assessment timeline.
//
// Once a saved assessment has run more than twice there is finally a real
// third axis in this product's data — host, severity and time — and it is
// worth drawing. It is drawn as a grid rather than as a surface in perspective
// because a reader has to be able to answer "which cell is that, exactly?"
// and a grid answers that; a landscape does not.
//
// The distinction the grid must never blur is between "assessed and clear" and
// "not assessed". They look the same in a naive heatmap and they mean opposite
// things, so they get different colours and the key says which is which.

// RunSnapshot is one past run of a saved assessment.
type RunSnapshot struct {
	JobID    string
	At       time.Time
	Findings []*finding.Finding
	Targets  []store.TargetOutcome
}

const (
	tlMaxRuns  = 12
	tlMaxHosts = 20
	// Pitch is wider than the square so a date label fits above a column
	// without colliding with its neighbour.
	tlPitch  = 46.0
	tlCell   = 26.0
	tlGapTop = 30.0
	tlLabelW = 240.0
)

// tlKey is the legend, declared once so the layout can measure it before it
// draws it.
var tlKey = []struct{ cls, label string }{
	{"crit", "critical"}, {"high", "high"}, {"med", "medium"},
	{"low", "low"}, {"info", "info"}, {"clear", "assessed, nothing found"},
	{"absent", "not assessed"},
}

type tlState struct {
	sev      finding.Severity
	assessed bool
}

// Timeline renders the host × run grid. It returns an empty string when there
// are fewer than two runs: a timeline of one point is a chart that implies a
// trend nobody measured.
func Timeline(snaps []RunSnapshot) (template.HTML, string) {
	if len(snaps) < 2 {
		return "", ""
	}
	sort.SliceStable(snaps, func(i, j int) bool { return snaps[i].At.Before(snaps[j].At) })
	droppedRuns := 0
	if len(snaps) > tlMaxRuns {
		droppedRuns = len(snaps) - tlMaxRuns
		snaps = snaps[len(snaps)-tlMaxRuns:]
	}

	// Collect every host seen in any run, and its state per run.
	grid := map[string][]tlState{}
	worst := map[string]int{}
	for i, s := range snaps {
		for _, f := range s.Findings {
			if f == nil {
				continue
			}
			h := surface.HostKey(f.Target)
			if h == "" {
				continue
			}
			row, ok := grid[h]
			if !ok {
				row = make([]tlState, len(snaps))
				grid[h] = row
			}
			row[i].assessed = true
			if f.Severity.Rank() > row[i].sev.Rank() {
				row[i].sev = f.Severity
			}
			if f.Severity.Rank() > worst[h] {
				worst[h] = f.Severity.Rank()
			}
		}
	}
	// A host with no findings in a given run was still assessed if a declared
	// target covering it was processed in that run. Anything else is absent,
	// and absent is not the same as clean.
	for h, row := range grid {
		for i, s := range snaps {
			if row[i].assessed {
				continue
			}
			for _, t := range s.Targets {
				if !t.Processed {
					continue
				}
				tk := surface.HostKey(t.Target)
				if tk != "" && (h == tk || strings.HasSuffix(h, "."+tk)) {
					row[i].assessed = true
					break
				}
			}
		}
	}
	if len(grid) == 0 {
		return "", ""
	}

	hosts := make([]string, 0, len(grid))
	for h := range grid {
		hosts = append(hosts, h)
	}
	sort.Slice(hosts, func(i, j int) bool {
		if worst[hosts[i]] != worst[hosts[j]] {
			return worst[hosts[i]] > worst[hosts[j]]
		}
		return hosts[i] < hosts[j]
	})
	droppedHosts := 0
	if len(hosts) > tlMaxHosts {
		droppedHosts = len(hosts) - tlMaxHosts
		hosts = hosts[:tlMaxHosts]
	}

	// The key is part of the picture, not decoration around it: a grid whose
	// legend runs off the edge is a grid the reader has to guess at. Widen the
	// canvas to whichever of the two actually needs the room.
	keyW := 0.0
	for _, k := range tlKey {
		keyW += 17 + float64(len(k.label))*5.6 + 16
	}
	w := tlLabelW + float64(len(snaps))*tlPitch + 24
	if keyW+24 > w {
		w = keyW + 24
	}
	h := tlGapTop + float64(len(hosts))*tlCell + 40

	var b strings.Builder
	fmt.Fprintf(&b,
		`<svg class="tl" viewBox="0 0 %.0f %.0f" width="%.0f" height="%.0f" role="img" `+
			`aria-label="Assessment timeline" xmlns="http://www.w3.org/2000/svg">`, w, h, w, h)

	// Runs are normally weeks apart, so the date is the useful label. When they
	// all fall on one day — which is what happens the first time somebody tries
	// the feature — a column of identical dates tells the reader nothing, so
	// the clock is used instead.
	stamp := "2 Jan"
	if sameDay(snaps[0].At, snaps[len(snaps)-1].At) {
		stamp = "15:04"
	}
	for i, s := range snaps {
		x := tlLabelW + float64(i)*tlPitch + tlPitch/2
		fmt.Fprintf(&b, `<text class="hdr" x="%.1f" y="%.1f" text-anchor="middle">%s</text>`,
			x, tlGapTop-10, template.HTMLEscapeString(s.At.Format(stamp)))
	}

	for r, host := range hosts {
		y := tlGapTop + float64(r)*tlCell
		fmt.Fprintf(&b, `<text class="lbl" x="0" y="%.1f">%s</text>`,
			y+tlCell/2+4, template.HTMLEscapeString(smapElide(host, 34)))
		for c, st := range grid[host] {
			x := tlLabelW + float64(c)*tlPitch + (tlPitch-tlCell)/2
			cls := "absent"
			switch {
			case st.sev != "":
				cls = smapSevClass(st.sev)
			case st.assessed:
				cls = "clear"
			}
			tlCellShape(&b, cls, x, y+1, template.HTMLEscapeString(host)+" — "+tlCellTitle(st, snaps[c].At))
		}
	}

	// Key. Two of these entries mean opposite things and look adjacent, so
	// they are named rather than left to the reader's assumption.
	keyY := tlGapTop + float64(len(hosts))*tlCell + 22
	kx := 0.0
	for _, k := range tlKey {
		tlKeySwatch(&b, k.cls, kx, keyY-9)
		fmt.Fprintf(&b, `<text class="key" x="%.1f" y="%.1f">%s</text>`, kx+17, keyY, k.label)
		kx += 17 + float64(len(k.label))*5.6 + 16
	}

	b.WriteString(`</svg>`)

	caption := fmt.Sprintf("%d runs across %d host(s)", len(snaps), len(hosts))
	if droppedRuns > 0 {
		caption += fmt.Sprintf("; the %d earlier run(s) are not drawn", droppedRuns)
	}
	if droppedHosts > 0 {
		caption += fmt.Sprintf("; %d further host(s) are not drawn", droppedHosts)
	}
	return template.HTML(b.String()), caption + "." //nolint:gosec // escaped above
}

// tlCellShape draws one cell. "Not assessed" gets a slash through it as well
// as its own colour: two greys side by side is exactly the confusion this
// picture exists to prevent, and a shape difference survives a black-and-white
// printer where a colour difference does not.
func tlCellShape(b *strings.Builder, cls string, x, y float64, title string) {
	fmt.Fprintf(b, `<rect class="cell c-%s" x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="4">`,
		cls, x, y, tlCell-2, tlCell-2)
	fmt.Fprintf(b, `<title>%s</title></rect>`, title)
	if cls == "absent" {
		fmt.Fprintf(b, `<path class="na" d="M%.1f %.1f L%.1f %.1f"/>`,
			x+6, y+tlCell-8, x+tlCell-8, y+6)
	}
}

func tlKeySwatch(b *strings.Builder, cls string, x, y float64) {
	fmt.Fprintf(b, `<rect class="cell c-%s" x="%.1f" y="%.1f" width="12" height="12" rx="3"/>`,
		cls, x, y)
	if cls == "absent" {
		fmt.Fprintf(b, `<path class="na" d="M%.1f %.1f L%.1f %.1f"/>`, x+2.5, y+9.5, x+9.5, y+2.5)
	}
}

func sameDay(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

func tlCellTitle(st tlState, at time.Time) string {
	d := at.Format("2 Jan 2006")
	switch {
	case st.sev != "":
		return template.HTMLEscapeString(string(st.sev)) + " on " + d
	case st.assessed:
		return "assessed on " + d + ", nothing recorded"
	default:
		return "not assessed on " + d
	}
}
