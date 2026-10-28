// Package siemexport sends AuditLight results to a SIEM as Hexward Finding
// Schema events (github.com/nizartuanku/hexward-core), the shape every
// Hexward tool emits, so one Wazuh rule set or Splunk search covers them all.
//
// AuditLight works in runs rather than in a continuous stream, so a run is
// turned into transitions by its delta against the previous run of the same
// definition: new and regressed findings are "opened", resolved ones are
// "resolved", and unchanged ones are not repeated. A run with no previous
// run to compare against (a one-off assessment, or the first run of a saved
// one) sends every finding as "opened".
package siemexport

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/nizartuanku/hexward-core/hfs"
	"github.com/nizartuanku/hexward-core/sink"

	"github.com/nizartuanku/auditlight/internal/delta"
	"github.com/nizartuanku/auditlight/internal/finding"
)

// Exporter fans a run's events out to every configured sink.
type Exporter struct {
	Sinks   []sink.Sink
	Meta    hfs.Meta
	Options hfs.Options
}

// Events turns a delta into HFS events, most severe first as delta orders them.
func (x *Exporter) Events(res delta.Result, at time.Time) []hfs.Event {
	if at.IsZero() {
		at = time.Now()
	}
	var out []hfs.Event
	for _, e := range res.Entries {
		if e.Finding == nil {
			continue
		}
		change := e.Change
		if !res.HasBaseline {
			// A first run lists everything as present, not new, because no
			// comparison happened. The SIEM has never seen any of it, so for
			// the SIEM every finding opens here.
			change = delta.ChangeNew
		}
		switch change {
		case delta.ChangeNew, delta.ChangeRegressed:
			out = append(out, hfs.New(hfs.KindOpened, x.Meta, Source(e.Finding, e.FirstSeen, at), at, x.Options))
		case delta.ChangeResolved:
			out = append(out, hfs.New(hfs.KindResolved, x.Meta, Source(e.Finding, e.FirstSeen, at), at, x.Options))
		}
	}
	return out
}

// Run sends one run's events to every sink. Every sink is tried; the errors
// of those that failed are joined.
func (x *Exporter) Run(ctx context.Context, res delta.Result, at time.Time) error {
	evs := x.Events(res, at)
	if len(evs) == 0 {
		return nil
	}
	var errs []error
	for _, s := range x.Sinks {
		if err := s.Send(ctx, evs); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// Source maps an AuditLight finding onto the schema's input. The finding ID
// is AuditLight's stable identity (target, port, category, signature), so it
// doubles as the fingerprint; the check is the category.
func Source(f *finding.Finding, firstSeen, lastSeen time.Time) hfs.Source {
	target := f.Target
	if f.Port > 0 {
		target += ":" + strconv.Itoa(f.Port)
	}
	ev := map[string]any{"confidence": string(f.Confidence)}
	if f.CVSS > 0 {
		ev["cvss"] = f.CVSS
	}
	if len(f.CVE) > 0 {
		ev["cve"] = f.CVE
	}
	if len(f.CWE) > 0 {
		ev["cwe"] = f.CWE
	}
	if len(f.SourceTools) > 0 {
		ev["source_tools"] = f.SourceTools
	}
	if len(f.Compliance) > 0 {
		controls := make([]string, 0, len(f.Compliance))
		for _, c := range f.Compliance {
			controls = append(controls, c.Framework+" "+c.ID)
		}
		ev["compliance"] = controls
	}
	if len(f.Evidence) > 0 {
		// Plain maps, so the schema's redaction walks them like any other
		// evidence (it only descends into maps and lists).
		items := make([]any, 0, len(f.Evidence))
		for _, e := range f.Evidence {
			item := map[string]any{"kind": e.Kind, "label": e.Label}
			// A secret finding's value is already masked by the scanner,
			// but it still carries the first and last characters of a
			// live credential. That never leaves for a SIEM: the label
			// (file and line) is enough to find it.
			if f.Category != finding.CategorySecret {
				item["value"] = e.Value
			}
			items = append(items, item)
		}
		ev["observed"] = items
	}
	remediation := f.Remediation
	if remediation == "" {
		remediation = f.Description
	}
	if firstSeen.IsZero() {
		firstSeen = lastSeen
	}
	return hfs.Source{
		ID:          f.ID,
		Fingerprint: f.ID,
		Check:       "auditlight." + string(f.Category),
		Title:       f.Title,
		Target:      target,
		Severity:    string(f.Severity),
		Status:      string(f.Status),
		Remediation: remediation,
		FirstSeen:   firstSeen,
		LastSeen:    lastSeen,
		Evidence:    ev,
	}
}
