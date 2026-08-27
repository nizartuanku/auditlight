package report

import (
	"html/template"
	"time"

	"github.com/nizartuanku/auditlight/internal/delta"
	"github.com/nizartuanku/auditlight/internal/store"
)

// DeltaInput is what the Delta Report needs.
type DeltaInput struct {
	Job        *store.Job
	Baseline   *store.Job
	Definition *store.Definition
	Result     delta.Result
	// History is every completed run of this saved assessment, oldest first.
	// It is what the timeline is drawn from.
	History   []RunSnapshot
	Branding  Branding
	Version   string
	Watermark string
}

type deltaData struct {
	In              DeltaInput
	Generated       time.Time
	New             []delta.Entry
	Regressed       []delta.Entry
	Resolved        []delta.Entry
	Improved        []delta.Entry
	Persisting      []delta.Entry
	Timeline        template.HTML
	TimelineCaption string
}

// Delta renders the comparison between this assessment and the previous one.
func Delta(in DeltaInput) ([]byte, error) {
	d := deltaData{In: in, Generated: time.Now()}
	d.New = in.Result.Of(delta.ChangeNew)
	d.Regressed = in.Result.Of(delta.ChangeRegressed)
	d.Resolved = in.Result.Of(delta.ChangeResolved)
	d.Improved = in.Result.Of(delta.ChangeImproved)
	d.Persisting = in.Result.Of(delta.ChangePersisting)
	d.Timeline, d.TimelineCaption = Timeline(in.History)
	return render("delta", deltaTmpl, d)
}

const deltaTmpl = `{{define "trendcell"}}
<div class="tr">
  <div class="l">{{.Label}}</div>
  <div class="v">{{.After}}</div>
  <div class="d {{.Class}}">{{.Arrow}}{{if .Delta}}{{.Delta}}{{else}}no change{{end}}</div>
</div>
{{end -}}
{{define "dentry"}}
<div class="f">
  <div class="f-head">
    <div class="f-title">{{.Finding.Title}}</div>
    <span class="badge b-{{sevClass .Finding.Severity}}">{{upper (printf "%s" .Finding.Severity)}}</span>
  </div>
  <div class="f-meta">
    <span class="chip">{{.Finding.Target}}{{if .Finding.Port}}:{{.Finding.Port}}{{end}}</span>
    <span class="chip">{{.Finding.Category}}</span>
    <span class="chip">confidence: {{.Finding.Confidence}}</span>
    {{if .WasSev}}<span class="arrow">was {{.WasSev}} → now {{.Finding.Severity}}</span>{{end}}
  </div>
  <div class="f-body">{{para .Finding.Description}}</div>
  {{if .Finding.Remediation}}<div class="fix"><b>Remediation</b>{{.Finding.Remediation}}</div>{{end}}
</div>
{{end -}}
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Change Report — {{.In.Job.ID}}</title>
<style>{{css}}
.dtiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(112px,1fr));gap:10px;margin:4px 0 10px}
.chg{display:inline-block;padding:2.5px 9px;border-radius:999px;font-size:11px;
  font-weight:660;text-transform:uppercase;letter-spacing:.055em;white-space:nowrap}
.c-new{background:var(--crit-bg);color:var(--crit)}
.c-reg{background:var(--high-bg);color:var(--high)}
.c-per{background:var(--info-bg);color:var(--info)}
.c-imp{background:var(--low-bg);color:var(--low)}
.c-res{background:var(--low-bg);color:var(--low)}
.arrow{font-family:var(--mono);font-size:12px;color:var(--muted)}
.trend{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:6px}
.tr{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:13px 10px;text-align:center}
.tr .l{font-size:10.5px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-bottom:7px}
.tr .v{font-size:19px;font-weight:700;font-variant-numeric:tabular-nums}
.tr .d{font-size:12px;margin-top:4px;font-variant-numeric:tabular-nums}
.up{color:var(--crit)} .down{color:var(--low)} .same{color:var(--muted)}
</style></head><body>
{{if .In.Watermark}}<div class="wm"><span>{{.In.Watermark}}</span></div>{{end}}
<div class="wrap">

<header class="doc">
  <div class="brand">{{svg}}<div>
    <div class="brandname">{{if .In.Branding.WhiteLabel}}{{.In.Branding.Firm}}{{else}}AuditLight{{end}}</div>
    <div class="brandsub">Change Report</div>
  </div></div>
  <div class="docmeta">
    <div>This run <b>{{.In.Job.ID}}</b></div>
    {{if .In.Result.HasBaseline}}<div>Compared to <b>{{.In.Result.BaselineJobID}}</b></div>{{end}}
    <div>Generated <b>{{ts .Generated}}</b></div>
    {{if and .In.Branding.Firm (not .In.Branding.WhiteLabel)}}<div>Prepared by <b>{{.In.Branding.Firm}}</b></div>{{end}}
  </div>
</header>

<h1>What changed since the last assessment</h1>
<p class="lede">
{{if .In.Definition}}<b>{{.In.Definition.Name}}</b> · {{end}}
{{if .In.Result.HasBaseline}}Comparing {{dateOnly .In.Result.CurrentAt}} against {{dateOnly .In.Result.BaselineAt}}.{{else}}First assessment of these targets.{{end}}
Detection only — nothing was exploited in either run.</p>

{{if not .In.Result.HasBaseline}}
<div class="note"><b>No baseline yet.</b> This is the first completed assessment for this definition,
so there is nothing to compare against. Run it again later and this report will show what moved.</div>
{{else}}

<h2>Summary</h2>
<div class="panel">
<p style="font-size:16px;margin-bottom:16px"><b>{{.In.Result.Headline}}</b></p>
<div class="dtiles">
  <div class="tile crit"><div class="n">{{.In.Result.Counts.New}}</div><div class="l">New</div></div>
  <div class="tile high"><div class="n">{{.In.Result.Counts.Regressed}}</div><div class="l">Regressed</div></div>
  <div class="tile info"><div class="n">{{.In.Result.Counts.Persisting}}</div><div class="l">Persisting</div></div>
  <div class="tile low"><div class="n">{{.In.Result.Counts.Improved}}</div><div class="l">Improved</div></div>
  <div class="tile low"><div class="n">{{.In.Result.Counts.Resolved}}</div><div class="l">Resolved</div></div>
</div>

<h3 style="margin-top:20px">Severity trend</h3>
<div class="trend">
  {{template "trendcell" trend "Critical" .In.Result.SeverityBefore.Critical .In.Result.SeverityAfter.Critical}}
  {{template "trendcell" trend "High" .In.Result.SeverityBefore.High .In.Result.SeverityAfter.High}}
  {{template "trendcell" trend "Medium" .In.Result.SeverityBefore.Medium .In.Result.SeverityAfter.Medium}}
  {{template "trendcell" trend "Low" .In.Result.SeverityBefore.Low .In.Result.SeverityAfter.Low}}
  {{template "trendcell" trend "Info" .In.Result.SeverityBefore.Info .In.Result.SeverityAfter.Info}}
</div>
</div>

{{if .Timeline}}
<h2>Assessment timeline</h2>
<p class="lede">Every run of this saved assessment, host by host. This is the picture a client asks
for when they want to know whether the work is holding, rather than what today's list looks like.</p>
<div class="tlwrap">{{.Timeline}}</div>
<p class="small muted" style="margin-top:8px">{{.TimelineCaption}}</p>
<div class="note"><b>Grey is not green.</b> A cell is grey when that host was not assessed in that run —
the target was skipped, or it had not been discovered yet. It is not a record of a clean result, and the
key names both states separately for exactly that reason.</div>
{{end}}

{{if .New}}
<h2>New findings</h2>
<p class="small muted" style="margin-top:-6px">Not present in the previous assessment.</p>
{{range $i, $e := .New}}{{template "dentry" $e}}{{end}}
{{end}}

{{if .Regressed}}
<h2>Regressions</h2>
<p class="small muted" style="margin-top:-6px">Present before, and more severe now.</p>
{{range $i, $e := .Regressed}}{{template "dentry" $e}}{{end}}
{{end}}

{{if .Resolved}}
<h2>No longer detected</h2>
<p class="small muted" style="margin-top:-6px">Present in the previous assessment, absent from this one.
Read this with the Process Report: a finding also disappears when the check that produced it could not run.</p>
{{range $i, $e := .Resolved}}{{template "dentry" $e}}{{end}}
{{end}}

{{if .Improved}}
<h2>Improved</h2>
<p class="small muted" style="margin-top:-6px">Still present, but less severe than before.</p>
{{range $i, $e := .Improved}}{{template "dentry" $e}}{{end}}
{{end}}

{{if .Persisting}}
<h2>Unchanged</h2>
<p class="small muted" style="margin-top:-6px">Present in both assessments at the same severity.</p>
<div class="panel"><div class="tblwrap"><table>
<thead><tr><th>Finding</th><th>Target</th><th>Severity</th><th>Confidence</th></tr></thead><tbody>
{{range .Persisting}}<tr>
  <td class="small">{{.Finding.Title}}</td>
  <td class="small"><code>{{.Finding.Target}}{{if .Finding.Port}}:{{.Finding.Port}}{{end}}</code></td>
  <td><span class="badge b-{{sevClass .Finding.Severity}}">{{upper (printf "%s" .Finding.Severity)}}</span></td>
  <td class="small muted">{{.Finding.Confidence}}</td>
</tr>{{end}}
</tbody></table></div></div>
{{end}}

{{end}}

<h2>How to read this</h2>
<div class="panel">
<p><b>"No longer detected" is not the same as "fixed."</b> A finding leaves the results when the condition
is gone — but also when the check that found it did not run this time, or when a target was skipped. The
Process Report for this run lists every check attempted and every target skipped, with reasons. Compare the
two before telling a client something was remediated.</p>
<p><b>Findings are matched by identity, not by text.</b> Each finding's identity is derived from its target,
port, category and the specific condition detected, so the same problem on the same host is recognised across
runs even if its wording changes. A finding that moves to a different port or host is correctly treated as a
different finding.</p>
<p><b>Severity can change without the world changing.</b> Corroboration from an additional check raises
confidence, and some findings carry a severity that depends on what else was observed. A regression is always
worth reading rather than assuming.</p>
</div>

<footer class="doc">
  <p><b>AuditLight {{.In.Version}}</b> — self-hosted, offline, detection-only security assessment.</p>
  <p>Change report generated {{ts .Generated}}{{if .In.Result.HasBaseline}} comparing job {{.In.Result.CurrentJobID}} against {{.In.Result.BaselineJobID}}{{end}}.</p>
  {{if .In.Branding.Contact}}<p>{{.In.Branding.Contact}}</p>{{end}}
</footer>
</div></body></html>`
