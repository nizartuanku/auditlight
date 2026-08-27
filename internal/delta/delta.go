// Package delta compares two assessments of the same targets.
//
// This is the difference between a scanner and an audit trail. The first
// assessment tells a client what is wrong. Every assessment after it answers
// the only question they actually care about: did the things we paid to fix
// stay fixed?
//
// The comparison is possible because finding identity is deterministic
// (finding invariant I3): the same condition on the same target produces the
// same ID on every run. Nothing here re-derives identity or matches on text.
package delta

import (
	"sort"
	"time"

	"github.com/nizartuanku/auditlight/internal/finding"
)

// Change classifies what happened to one finding between two runs.
type Change string

const (
	// ChangeNew appeared in the current run and was not in the baseline.
	ChangeNew Change = "new"
	// ChangeResolved was in the baseline and is gone. Note the honest wording:
	// gone from the results, which is not always the same as fixed — the
	// Process Report says whether the check that found it even ran.
	ChangeResolved Change = "resolved"
	// ChangeRegressed is present in both, but more severe now.
	ChangeRegressed Change = "regressed"
	// ChangeImproved is present in both, but less severe now.
	ChangeImproved Change = "improved"
	// ChangePersisting is present in both at the same severity.
	ChangePersisting Change = "persisting"
)

// Entry is one finding placed in the comparison.
type Entry struct {
	Change    Change             `json:"change"`
	Finding   *finding.Finding   `json:"finding"`
	WasSev    finding.Severity   `json:"was_severity,omitempty"`
	WasConf   finding.Confidence `json:"was_confidence,omitempty"`
	FirstSeen time.Time          `json:"first_seen,omitempty"`
}

// Counts summarise a comparison.
type Counts struct {
	New        int `json:"new"`
	Resolved   int `json:"resolved"`
	Regressed  int `json:"regressed"`
	Improved   int `json:"improved"`
	Persisting int `json:"persisting"`
}

// Total is how many findings the comparison touched.
func (c Counts) Total() int {
	return c.New + c.Resolved + c.Regressed + c.Improved + c.Persisting
}

// Worse reports whether anything got worse: new findings or regressions. It is
// what a "only tell me when it degrades" notification rule keys on.
func (c Counts) Worse() bool { return c.New > 0 || c.Regressed > 0 }

// Changed reports whether anything moved at all.
func (c Counts) Changed() bool {
	return c.New > 0 || c.Resolved > 0 || c.Regressed > 0 || c.Improved > 0
}

// Result is a full comparison between a baseline run and a current run.
type Result struct {
	CurrentJobID  string    `json:"current_job_id"`
	BaselineJobID string    `json:"baseline_job_id"`
	CurrentAt     time.Time `json:"current_at"`
	BaselineAt    time.Time `json:"baseline_at"`

	Entries []Entry `json:"entries"`
	Counts  Counts  `json:"counts"`

	// SeverityBefore and SeverityAfter give the headline trend.
	SeverityBefore finding.Counts `json:"severity_before"`
	SeverityAfter  finding.Counts `json:"severity_after"`

	// HasBaseline is false for a first run, where there is nothing to compare
	// against. Callers must not present an empty comparison as "no changes".
	HasBaseline bool `json:"has_baseline"`
}

// Compare places every finding from both runs into the comparison.
func Compare(baseline, current []*finding.Finding, baselineID, currentID string, baselineAt, currentAt time.Time) Result {
	r := Result{
		CurrentJobID:   currentID,
		BaselineJobID:  baselineID,
		CurrentAt:      currentAt,
		BaselineAt:     baselineAt,
		HasBaseline:    baselineID != "",
		SeverityBefore: finding.Count(baseline),
		SeverityAfter:  finding.Count(current),
	}

	if !r.HasBaseline {
		// A first run has no history. Every finding is simply present; calling
		// them all "new" would imply a comparison that never happened.
		for _, f := range current {
			r.Entries = append(r.Entries, Entry{Change: ChangePersisting, Finding: f})
		}
		r.Counts.Persisting = len(current)
		sortEntries(r.Entries)
		return r
	}

	base := make(map[string]*finding.Finding, len(baseline))
	for _, f := range baseline {
		base[f.ID] = f
	}

	seen := make(map[string]bool, len(current))
	for _, f := range current {
		seen[f.ID] = true
		prev, existed := base[f.ID]
		if !existed {
			r.Entries = append(r.Entries, Entry{Change: ChangeNew, Finding: f})
			r.Counts.New++
			continue
		}
		e := Entry{Finding: f, WasSev: prev.Severity, WasConf: prev.Confidence}
		switch {
		case f.Severity.Rank() > prev.Severity.Rank():
			e.Change = ChangeRegressed
			r.Counts.Regressed++
		case f.Severity.Rank() < prev.Severity.Rank():
			e.Change = ChangeImproved
			r.Counts.Improved++
		default:
			e.Change = ChangePersisting
			r.Counts.Persisting++
		}
		r.Entries = append(r.Entries, e)
	}

	for _, f := range baseline {
		if seen[f.ID] {
			continue
		}
		r.Entries = append(r.Entries, Entry{Change: ChangeResolved, Finding: f, WasSev: f.Severity})
		r.Counts.Resolved++
	}

	sortEntries(r.Entries)
	return r
}

// changeRank orders the sections of a delta report: what got worse first,
// because that is what needs action, then what improved, then the rest.
func changeRank(c Change) int {
	switch c {
	case ChangeNew:
		return 5
	case ChangeRegressed:
		return 4
	case ChangePersisting:
		return 3
	case ChangeImproved:
		return 2
	case ChangeResolved:
		return 1
	default:
		return 0
	}
}

func sortEntries(es []Entry) {
	sort.SliceStable(es, func(i, j int) bool {
		a, b := es[i], es[j]
		if ra, rb := changeRank(a.Change), changeRank(b.Change); ra != rb {
			return ra > rb
		}
		if a.Finding.Severity.Rank() != b.Finding.Severity.Rank() {
			return a.Finding.Severity.Rank() > b.Finding.Severity.Rank()
		}
		if a.Finding.Confidence.Rank() != b.Finding.Confidence.Rank() {
			return a.Finding.Confidence.Rank() > b.Finding.Confidence.Rank()
		}
		return a.Finding.ID < b.Finding.ID
	})
}

// Of returns the entries with a given change class.
func (r Result) Of(c Change) []Entry {
	var out []Entry
	for _, e := range r.Entries {
		if e.Change == c {
			out = append(out, e)
		}
	}
	return out
}

// Headline is a one-sentence summary for a notification or an inbox preview.
// It never claims progress that the numbers do not support.
func (r Result) Headline() string {
	if !r.HasBaseline {
		return "First assessment — no previous run to compare against."
	}
	switch {
	case r.Counts.New > 0 && r.Counts.Regressed > 0:
		return plural(r.Counts.New, "new finding", "new findings") + " and " +
			plural(r.Counts.Regressed, "regression", "regressions") + " since the last assessment."
	case r.Counts.New > 0:
		return plural(r.Counts.New, "new finding", "new findings") + " since the last assessment."
	case r.Counts.Regressed > 0:
		return plural(r.Counts.Regressed, "finding has", "findings have") + " become more severe since the last assessment."
	case r.Counts.Resolved > 0 && r.Counts.Improved > 0:
		return plural(r.Counts.Resolved, "finding resolved", "findings resolved") + " and " +
			plural(r.Counts.Improved, "improved", "improved") + ", nothing new."
	case r.Counts.Resolved > 0:
		return plural(r.Counts.Resolved, "finding resolved", "findings resolved") + ", nothing new."
	case r.Counts.Improved > 0:
		return plural(r.Counts.Improved, "finding improved", "findings improved") + ", nothing new."
	default:
		return "No change since the last assessment."
	}
}

func plural(n int, one, many string) string {
	word := many
	if n == 1 {
		word = one
	}
	return itoa(n) + " " + word
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
