// Package score ranks findings and applies tier caps.
//
// The ranking is deliberately transparent: severity first, then confidence,
// with corroboration as a tiebreak. There is no opaque composite number, because
// an auditor has to be able to explain to a client why one finding sits above
// another.
package score

import (
	"fmt"

	"github.com/nizartuanku/auditlight/internal/finding"
)

// Capped is the outcome of applying a tier limit.
type Capped struct {
	Shown []*finding.Finding
	Total int
	// Withheld is how many findings the licence hid. It is always reported,
	// never silently applied — honesty invariant I1.
	Withheld int
	// Notice is the sentence a report or UI shows when findings were withheld.
	Notice string
}

// Rank orders findings for presentation.
func Rank(fs []*finding.Finding) []*finding.Finding {
	out := append([]*finding.Finding(nil), fs...)
	finding.Sort(out)
	return out
}

// ApplyCap limits how many findings are shown, reporting exactly what it hid.
// A limit of zero means unlimited.
func ApplyCap(fs []*finding.Finding, limit int) Capped {
	c := Capped{Shown: fs, Total: len(fs)}
	if limit <= 0 || len(fs) <= limit {
		return c
	}
	c.Shown = fs[:limit]
	c.Withheld = len(fs) - limit
	c.Notice = fmt.Sprintf(
		"%d findings were produced; this licence displays the %d highest-ranked. %d are not shown.",
		c.Total, limit, c.Withheld)
	return c
}

// Summary is the executive view of an assessment.
type Summary struct {
	Counts       finding.Counts `json:"counts"`
	Corroborated int            `json:"corroborated"`
	NeedsReview  int            `json:"needs_review"`
	Actionable   int            `json:"actionable"`
	TopRisks     []string       `json:"top_risks"`
	Posture      string         `json:"posture"`
}

// Summarise builds the executive summary. Posture wording is restrained on
// purpose: an assessment that never exploits anything cannot honestly declare a
// host "secure", only describe what was and was not found.
func Summarise(fs []*finding.Finding) Summary {
	s := Summary{Counts: finding.Count(fs)}
	for _, f := range fs {
		if len(f.SourceTools) > 1 {
			s.Corroborated++
		}
		if f.Status == finding.StatusManualReview {
			s.NeedsReview++
		}
		if f.Status == finding.StatusOpen {
			s.Actionable++
		}
	}
	for _, f := range fs {
		if len(s.TopRisks) >= 3 {
			break
		}
		if f.Severity == finding.SeverityCritical || f.Severity == finding.SeverityHigh {
			s.TopRisks = append(s.TopRisks, f.Title)
		}
	}

	switch {
	case s.Counts.Critical > 0:
		s.Posture = "Critical findings are present and should be addressed before anything else on this list."
	case s.Counts.High > 0:
		s.Posture = "No critical findings, but high-severity issues are present that warrant prompt attention."
	case s.Counts.Medium > 0:
		s.Posture = "No critical or high-severity findings. The medium-severity items are worth scheduling into routine work."
	case s.Counts.Low > 0:
		s.Posture = "Only low-severity findings were detected. These are hardening opportunities rather than urgent defects."
	case s.Counts.Total > 0:
		s.Posture = "No defects were detected by these checks; the findings recorded are informational."
	default:
		s.Posture = "These checks produced no findings. That is not the same as an absence of risk: it means nothing was detected within the scope and methods used."
	}
	return s
}
