// Package report renders the two audit documents.
//
// Both are self-contained HTML: inline CSS, inline SVG, no external request of
// any kind. They must open from a USB stick on an air-gapped machine, and they
// must print to PDF without a browser plugin.
package report

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/nizartuanku/auditlight/internal/compliance"
	"github.com/nizartuanku/auditlight/internal/finding"
	"github.com/nizartuanku/auditlight/internal/license"
	"github.com/nizartuanku/auditlight/internal/score"
	"github.com/nizartuanku/auditlight/internal/store"
	"github.com/nizartuanku/auditlight/internal/surface"
)

// Branding customises the report for the firm delivering it. Paid tiers only.
type Branding struct {
	Firm    string
	Contact string
	// WhiteLabel removes the AuditLight name from the header. Team tier only.
	WhiteLabel bool
}

// Input is everything a report needs.
type Input struct {
	Job          *store.Job
	Findings     []*finding.Finding
	Capabilities []Capability
	Licence      license.State
	Branding     Branding
	Version      string
	// Watermark marks a preview rendered under a licence that does not include
	// the full Assessment Report.
	Watermark string
}

// Capability mirrors the adapter capability row, kept local so the report
// package does not depend on the adapter package.
type Capability struct {
	Name      string
	Kind      string
	Describe  string
	Available bool
	Reason    string
}

var funcs = template.FuncMap{
	"sevClass": func(s finding.Severity) string {
		switch s {
		case finding.SeverityCritical:
			return "crit"
		case finding.SeverityHigh:
			return "high"
		case finding.SeverityMedium:
			return "med"
		case finding.SeverityLow:
			return "low"
		default:
			return "info"
		}
	},
	"upper":  strings.ToUpper,
	"join":   func(s []string) string { return strings.Join(s, ", ") },
	"inc":    func(i int) int { return i + 1 },
	"hasSuf": strings.HasSuffix,
	"dur": func(d time.Duration) string {
		if d <= 0 {
			return "—"
		}
		if d < time.Second {
			return fmt.Sprintf("%dms", d.Milliseconds())
		}
		return d.Round(100 * time.Millisecond).String()
	},
	"ts": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.UTC().Format("2 Jan 2006, 15:04:05 UTC")
	},
	"dateOnly": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.UTC().Format("2 January 2006")
	},
	"para": func(s string) template.HTML {
		var b strings.Builder
		for _, p := range strings.Split(s, "\n\n") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			b.WriteString("<p>" + template.HTMLEscapeString(p) + "</p>")
		}
		return template.HTML(b.String()) //nolint:gosec // content escaped above
	},
	"svg":   func() template.HTML { return template.HTML(hexMark) }, //nolint:gosec // constant asset
	"css":   func() template.CSS { return template.CSS(baseCSS) },
	"trend": newTrend,
}

// TrendCell is one severity column of the change report's trend row.
type TrendCell struct {
	Label  string
	Before int
	After  int
	Delta  string
	Arrow  string
	Class  string
}

// newTrend builds a trend cell. More of a severity is bad, less is good, and
// the wording says which without editorialising.
func newTrend(label string, before, after int) TrendCell {
	c := TrendCell{Label: label, Before: before, After: after}
	switch {
	case after > before:
		c.Arrow, c.Class = "▲ ", "up"
		c.Delta = fmt.Sprintf("+%d", after-before)
	case after < before:
		c.Arrow, c.Class = "▼ ", "down"
		c.Delta = fmt.Sprintf("−%d", before-after)
	default:
		c.Class = "same"
	}
	return c
}

func render(name, text string, data any) ([]byte, error) {
	t, err := template.New(name).Funcs(funcs).Parse(text)
	if err != nil {
		return nil, fmt.Errorf("report: parse %s: %w", name, err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("report: render %s: %w", name, err)
	}
	return buf.Bytes(), nil
}

// --- Process Report -------------------------------------------------------

type processData struct {
	In           Input
	Title        string
	Generated    time.Time
	ProfileTitle string
	Skipped      []store.TargetOutcome
	Processed    []store.TargetOutcome
	NativeCount  int
	ToolCount    int
	MissingTools []Capability
}

// Process renders the Process Report: what actually ran, what did not, and why.
func Process(in Input) ([]byte, error) {
	d := processData{
		In: in, Title: "Process Report",
		Generated: time.Now(),
	}
	for _, t := range in.Job.Targets {
		if t.Processed {
			d.Processed = append(d.Processed, t)
		} else {
			d.Skipped = append(d.Skipped, t)
		}
	}
	for _, c := range in.Capabilities {
		if c.Kind == "native" {
			d.NativeCount++
			continue
		}
		if c.Available {
			d.ToolCount++
		} else {
			d.MissingTools = append(d.MissingTools, c)
		}
	}
	return render("process", processTmpl, d)
}

const processTmpl = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Process Report — {{.In.Job.ID}}</title>
<style>{{css}}</style></head><body><div class="wrap">

<header class="doc">
  <div class="brand">{{svg}}<div>
    <div class="brandname">{{if .In.Branding.WhiteLabel}}{{.In.Branding.Firm}}{{else}}AuditLight{{end}}</div>
    <div class="brandsub">Process Report</div>
  </div></div>
  <div class="docmeta">
    <div>Job <b>{{.In.Job.ID}}</b></div>
    <div>Generated <b>{{ts .Generated}}</b></div>
    <div>Profile <b>{{.In.Job.Profile}}</b> · Tier <b>{{.In.Job.Tier}}</b></div>
    {{if and .In.Branding.Firm (not .In.Branding.WhiteLabel)}}<div>Prepared by <b>{{.In.Branding.Firm}}</b></div>{{end}}
  </div>
</header>

<h1>What this assessment actually did</h1>
<p class="lede">This document records the mechanics of the run: the authorisation given, the checks
attempted, which succeeded, which did not, and what was left out. It exists so that the findings
report can be read in context, and so that gaps in coverage are visible rather than assumed away.</p>

<h2>Authorisation</h2>
<div class="panel">
{{if .In.Job.Authz.Confirmed}}
  <dl class="kv">
    <dt>Operator</dt><dd>{{.In.Job.Authz.Operator}}</dd>
    <dt>Accepted at</dt><dd>{{ts .In.Job.Authz.At}}</dd>
    <dt>Targets authorised</dt><dd>{{join .In.Job.Authz.Targets}}</dd>
    <dt>Declared scope</dt><dd>{{if .In.Job.Authz.Scope}}{{join .In.Job.Authz.Scope}}{{else}}<span class="muted">the target list itself</span>{{end}}</dd>
  </dl>
  <p class="small muted" style="margin-top:14px;margin-bottom:6px">Statement accepted:</p>
  <p class="small" style="margin:0">“{{.In.Job.Authz.Statement}}”</p>
  <div class="ev">
    <div class="ev-h">Audit chain</div>
    <div class="ev-row"><span class="ev-k">entry</span> <span class="hash">{{.In.Job.Authz.EntryHash}}</span></div>
    <div class="ev-row"><span class="ev-k">previous</span> <span class="hash">{{if .In.Job.Authz.PrevHash}}{{.In.Job.Authz.PrevHash}}{{else}}— first entry{{end}}</span></div>
  </div>
{{else}}
  <div class="note"><b>Refused.</b> {{if .In.Job.Error}}{{.In.Job.Error}}{{else}}The authorisation gate did not pass, so no check was run.{{end}}</div>
{{end}}
</div>

<h2>Targets</h2>
<div class="panel"><div class="tblwrap"><table>
<thead><tr><th>Target</th><th>Status</th><th>Findings</th><th>Note</th></tr></thead><tbody>
{{range .Processed}}<tr>
  <td><code>{{.Target}}</code></td>
  <td><span class="chip ok">processed</span></td>
  <td>{{.Findings}}</td>
  <td class="muted small">{{if .Reason}}{{.Reason}}{{else}}—{{end}}</td>
</tr>{{end}}
{{range .Skipped}}<tr>
  <td><code>{{.Target}}</code></td>
  <td><span class="chip no">skipped</span></td>
  <td>—</td>
  <td class="muted small">{{.Reason}}</td>
</tr>{{end}}
</tbody></table></div>
{{if .Skipped}}<p class="small muted" style="margin:10px 0 0">Skipped targets are listed rather than dropped:
a target that was never assessed must not read as a target that came back clean.</p>{{end}}
</div>

<h2>Checks run</h2>
<div class="panel"><div class="tblwrap"><table>
<thead><tr><th>Check</th><th>Kind</th><th>Result</th><th>Findings</th><th>Duration</th><th>Detail</th></tr></thead><tbody>
{{range .In.Job.Adapters}}<tr>
  <td><code>{{.Name}}</code></td>
  <td class="small muted">{{.Kind}}</td>
  <td>{{if .Skipped}}<span class="chip">skipped</span>{{else if .OK}}<span class="chip ok">ok</span>{{else}}<span class="chip no">failed</span>{{end}}</td>
  <td>{{if .Skipped}}—{{else}}{{.Findings}}{{end}}</td>
  <td class="small muted">{{dur .Duration}}</td>
  <td class="small muted">{{if .Reason}}{{.Reason}}{{else}}—{{end}}</td>
</tr>{{end}}
</tbody></table></div></div>

<h2>Capabilities of this installation</h2>
<div class="panel">
<p class="small muted" style="margin-top:0">AuditLight completes an assessment using its built-in checks alone.
External tools add depth when they are installed. This table states which were available for this run,
so that the absence of a check is never mistaken for the absence of a problem.</p>
<div class="tblwrap"><table>
<thead><tr><th>Check</th><th>Kind</th><th>Available</th><th>What it adds</th></tr></thead><tbody>
{{range .In.Capabilities}}<tr>
  <td><code>{{.Name}}</code></td>
  <td class="small muted">{{.Kind}}</td>
  <td>{{if .Available}}<span class="chip ok">yes</span>{{else}}<span class="chip no">no</span>{{end}}</td>
  <td class="small">{{.Describe}}{{if .Reason}} <span class="muted">— {{.Reason}}</span>{{end}}</td>
</tr>{{end}}
</tbody></table></div>
</div>

{{if .In.Job.Adapters}}
<h2>Safe-mode enforcement</h2>
<div class="panel">
<p class="small" style="margin-top:0">AuditLight has no aggressive mode. Where an external tool was used,
these arguments were imposed by AuditLight and could not be overridden.</p>
<div class="tblwrap"><table>
<thead><tr><th>Tool</th><th>Path</th><th>Enforced arguments</th></tr></thead><tbody>
{{$any := false}}
{{range .In.Job.Adapters}}{{if .SafeFlags}}{{$any = true}}<tr>
  <td><code>{{.Name}}</code></td>
  <td class="small muted"><code>{{if .ToolPath}}{{.ToolPath}}{{else}}—{{end}}</code></td>
  <td class="small"><code>{{join .SafeFlags}}</code></td>
</tr>{{end}}{{end}}
{{if not $any}}<tr><td colspan="3" class="muted small">No external tool was used in this run; only built-in checks ran.</td></tr>{{end}}
</tbody></table></div>
</div>
{{end}}

<h2>Timing</h2>
<div class="panel"><dl class="kv">
  <dt>Created</dt><dd>{{ts .In.Job.Created}}</dd>
  <dt>Started</dt><dd>{{ts .In.Job.Started}}</dd>
  <dt>Finished</dt><dd>{{ts .In.Job.Finished}}</dd>
  <dt>Final state</dt><dd>{{.In.Job.State}}</dd>
  <dt>Findings produced</dt><dd>{{.In.Job.FindingsTotal}}{{if lt .In.Job.FindingsShown .In.Job.FindingsTotal}} — {{.In.Job.FindingsShown}} shown under this licence{{end}}</dd>
</dl></div>

<footer class="doc">
  <p><b>AuditLight {{.In.Version}}</b> — self-hosted security assessment, detection only.
  No exploitation, brute force, denial of service or offensive fuzzing was attempted at any point in this run.</p>
  {{if .In.Branding.Contact}}<p>{{.In.Branding.Contact}}</p>{{end}}
</footer>
</div></body></html>`

// --- Assessment Report ----------------------------------------------------

type assessData struct {
	In         Input
	Generated  time.Time
	Summary    score.Summary
	Coverage   []compliance.Coverage
	Disclaimer string
	Withheld   int
	Notice     string
	Actionable []*finding.Finding
	Context    []*finding.Finding
	Map        template.HTML
	MapCaption string
}

// Assessment renders the findings report.
func Assessment(in Input) ([]byte, error) {
	g := surface.Build(in.Job, in.Findings)
	d := assessData{
		In: in, Generated: time.Now(),
		Map:        SurfaceMap(g),
		MapCaption: SurfaceCaption(g),
		Summary:    score.Summarise(in.Findings),
		Coverage:   compliance.Summarise(in.Findings),
		Disclaimer: compliance.Disclaimer,
	}
	if in.Job.FindingsTotal > in.Job.FindingsShown {
		d.Withheld = in.Job.FindingsTotal - in.Job.FindingsShown
		d.Notice = fmt.Sprintf(
			"%d findings were produced by this assessment. This licence displays the %d highest-ranked; %d are not shown.",
			in.Job.FindingsTotal, in.Job.FindingsShown, d.Withheld)
	}
	for _, f := range in.Findings {
		if f.Status == finding.StatusInformational {
			d.Context = append(d.Context, f)
			continue
		}
		d.Actionable = append(d.Actionable, f)
	}
	return render("assessment", assessTmpl, d)
}

const assessTmpl = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Assessment Report — {{.In.Job.ID}}</title>
<style>{{css}}</style></head><body>
{{if .In.Watermark}}<div class="wm"><span>{{.In.Watermark}}</span></div>{{end}}
<div class="wrap">

<header class="doc">
  <div class="brand">{{svg}}<div>
    <div class="brandname">{{if .In.Branding.WhiteLabel}}{{.In.Branding.Firm}}{{else}}AuditLight{{end}}</div>
    <div class="brandsub">Security Assessment Report</div>
  </div></div>
  <div class="docmeta">
    <div>Job <b>{{.In.Job.ID}}</b></div>
    <div>Generated <b>{{ts .Generated}}</b></div>
    <div>Profile <b>{{.In.Job.Profile}}</b></div>
    {{if and .In.Branding.Firm (not .In.Branding.WhiteLabel)}}<div>Prepared by <b>{{.In.Branding.Firm}}</b></div>{{end}}
  </div>
</header>

<h1>Security assessment</h1>
<p class="lede">
{{if .In.Job.Authz.Targets}}Targets: <b>{{join .In.Job.Authz.Targets}}</b>. {{end}}
Assessed on {{dateOnly .In.Job.Started}} using detection-only checks. No exploitation was attempted.</p>

{{if .In.Watermark}}
<div class="note"><b>Preview.</b> This report is watermarked because the current licence does not include
the full Assessment Report. Findings are shown in summary; evidence and remediation detail are part of the
paid editions.</div>
{{end}}

<h2>Executive summary</h2>
<div class="tiles">
  <div class="tile crit"><div class="n">{{.Summary.Counts.Critical}}</div><div class="l">Critical</div></div>
  <div class="tile high"><div class="n">{{.Summary.Counts.High}}</div><div class="l">High</div></div>
  <div class="tile med"><div class="n">{{.Summary.Counts.Medium}}</div><div class="l">Medium</div></div>
  <div class="tile low"><div class="n">{{.Summary.Counts.Low}}</div><div class="l">Low</div></div>
  <div class="tile info"><div class="n">{{.Summary.Counts.Info}}</div><div class="l">Info</div></div>
</div>
<div class="panel">
  <p>{{.Summary.Posture}}</p>
  {{if .Summary.TopRisks}}
  <h3 style="margin-top:16px">What to look at first</h3>
  <ul class="clean">{{range .Summary.TopRisks}}<li>{{.}}</li>{{end}}</ul>
  {{end}}
  <dl class="kv" style="margin-top:16px">
    <dt>Actionable findings</dt><dd>{{.Summary.Actionable}}</dd>
    <dt>Corroborated by 2+ checks</dt><dd>{{.Summary.Corroborated}}</dd>
    <dt>Needing human judgement</dt><dd>{{.Summary.NeedsReview}}</dd>
    <dt>Contextual records</dt><dd>{{len .Context}}</dd>
  </dl>
  {{if .Notice}}<div class="note" style="margin-bottom:0"><b>Not all findings are shown.</b> {{.Notice}}</div>{{end}}
</div>

{{if .Map}}
<h2>Attack surface</h2>
<p class="lede">Every declared target, every host observed beneath it, and every service a check
actually reached — with the findings recorded against each.</p>
<div class="smapwrap">{{.Map}}</div>
<p class="small muted" style="margin-top:8px">{{.MapCaption}}</p>
<div class="note"><b>What this picture does not claim.</b> AuditLight performs no traceroute and no
adjacency probing, so it does not know how these hosts reach one another and does not draw it. A host
appears under a target because its name is that target or a DNS-suffix of it; a service appears under a
host because a check observed that port. Nothing here is inferred network topology.</div>
{{end}}

{{if .Actionable}}
<h2>Findings</h2>
{{range $i, $f := .Actionable}}
<div class="f">
  <div class="f-head">
    <div class="f-num">{{inc $i}}</div>
    <div class="f-title">{{$f.Title}}</div>
    <span class="badge b-{{sevClass $f.Severity}}">{{upper (printf "%s" $f.Severity)}}</span>
  </div>
  <div class="f-meta">
    <span class="chip">{{$f.Target}}{{if $f.Port}}:{{$f.Port}}{{end}}</span>
    <span class="chip">{{$f.Category}}</span>
    <span class="chip">confidence: {{$f.Confidence}}</span>
    {{if gt (len $f.SourceTools) 1}}<span class="chip ok">{{len $f.SourceTools}} checks agree</span>{{else}}<span class="chip">{{join $f.SourceTools}}</span>{{end}}
    {{if $f.CVSS}}<span class="chip">CVSS {{printf "%.1f" $f.CVSS}}</span>{{end}}
    {{range $f.CVE}}<span class="chip">{{.}}</span>{{end}}
    {{range $f.CWE}}<span class="chip">{{.}}</span>{{end}}
    {{if eq (printf "%s" $f.Status) "manual_review"}}<span class="badge b-med">NEEDS REVIEW</span>{{end}}
  </div>
  <div class="f-body">{{para $f.Description}}</div>
  {{if and $f.Evidence (not $.In.Watermark)}}
  <div class="ev"><div class="ev-h">Evidence</div>
    {{range $f.Evidence}}<div class="ev-row"><span class="ev-k">{{if .Label}}{{.Label}}{{else}}{{.Kind}}{{end}}:</span> {{.Value}}</div>{{end}}
  </div>{{end}}
  {{if and $f.Remediation (not $.In.Watermark)}}
  <div class="fix"><b>Remediation</b>{{$f.Remediation}}</div>{{end}}
  {{if $f.Compliance}}
  <div class="ev"><div class="ev-h">Related controls</div>
    <div class="ev-row">{{range $f.Compliance}}<span class="chip">{{.Framework}} {{.ID}}</span> {{end}}</div>
  </div>{{end}}
</div>
{{end}}
{{else}}
<h2>Findings</h2>
<div class="panel"><p style="margin:0">No actionable finding was produced. That is not a statement that the
targets are secure: it means these checks, within this scope, detected nothing that warranted action.</p></div>
{{end}}

{{if .Coverage}}
<h2>Control mapping</h2>
<div class="panel">
<div class="tblwrap"><table>
<thead><tr><th>Framework</th><th>Control</th><th>Title</th><th>Findings</th></tr></thead><tbody>
{{range .Coverage}}<tr>
  <td class="small">{{.Framework}}</td>
  <td><code>{{.ID}}</code></td>
  <td class="small">{{.Title}}</td>
  <td>{{.Findings}}</td>
</tr>{{end}}
</tbody></table></div>
<div class="note" style="margin-bottom:0"><b>Read this carefully.</b> {{.Disclaimer}}</div>
</div>
{{end}}

{{if .Context}}
<h2>Context and inventory</h2>
<div class="panel">
<p class="small muted" style="margin-top:0">Records that are not defects. They describe what exists, which is
what makes an asset inventory useful and a future comparison possible.</p>
<div class="tblwrap"><table>
<thead><tr><th>Item</th><th>Target</th><th>Detail</th></tr></thead><tbody>
{{range .Context}}<tr>
  <td class="small">{{.Title}}</td>
  <td class="small"><code>{{.Target}}{{if .Port}}:{{.Port}}{{end}}</code></td>
  <td class="small muted">{{range .Evidence}}{{.Value}} {{end}}</td>
</tr>{{end}}
</tbody></table></div>
</div>
{{end}}

<h2>Methodology and limits</h2>
<div class="panel">
<p><b>Detection only.</b> Every check in this assessment observes; none exploits. No credential was guessed,
no payload was sent to alter state, and no denial-of-service condition was induced. This is what makes the
assessment safe to run against production, and it is also its main limitation.</p>
<p><b>What that means for these findings.</b> Because nothing was exploited, exploitability is not proven.
A finding marked <i>confirmed</i> was observed directly. One marked <i>likely</i> rests on inference, most often
a version string — and distributions routinely back-port fixes without changing it. One marked <i>potential</i>
is a signal worth checking, not a conclusion.</p>
<p><b>Not a penetration test.</b> There is no business-logic testing here, no chaining of weaknesses, and no
human creativity. Automated assessment finds the recurring, mechanical problems well; it does not replace a
tester who thinks about your application.</p>
<p><b>Coverage is the visible surface.</b> Anything behind authentication was not examined. The Process Report
lists every check that ran, failed or was unavailable — read the two documents together.</p>
{{if .Withheld}}<p><b>Findings withheld.</b> {{.Withheld}} finding(s) were produced but are not displayed under
the current licence. They exist; they are simply not in this document.</p>{{end}}
</div>

<footer class="doc">
  <p><b>AuditLight {{.In.Version}}</b> — self-hosted, offline, detection-only security assessment.</p>
  <p>Report generated {{ts .Generated}} from job {{.In.Job.ID}}.
  {{if .In.Licence.Licensee}}Licensed to {{.In.Licence.Licensee}}. {{end}}</p>
  {{if .In.Branding.Contact}}<p>{{.In.Branding.Contact}}</p>{{end}}
</footer>
</div></body></html>`
