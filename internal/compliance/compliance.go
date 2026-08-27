// Package compliance maps findings to control frameworks.
//
// The mapping is supporting evidence, not a verdict. A finding that touches a
// control tells an auditor where to look; it does not certify compliance, and
// nothing in this package should ever be worded as if it did.
package compliance

import (
	"sort"

	"github.com/nizartuanku/auditlight/internal/finding"
)

// Framework identifiers, as they appear in reports.
const (
	ISO27001 = "ISO 27001:2022"
	CISv8    = "CIS v8"
	NISTCSF  = "NIST CSF 2.0"
	UUPDP    = "UU PDP"
)

// AllFrameworks lists every framework this build can map to.
func AllFrameworks() []string { return []string{ISO27001, CISv8, NISTCSF, UUPDP} }

type mapping struct {
	framework string
	id        string
	title     string
}

// byCategory is the mapping table. Categories are the join key because they are
// what the finding model guarantees; mapping on free text would be guesswork.
var byCategory = map[finding.Category][]mapping{
	finding.CategoryVuln: {
		{ISO27001, "A.8.8", "Management of technical vulnerabilities"},
		{CISv8, "7", "Continuous vulnerability management"},
		{NISTCSF, "ID.RA", "Risk assessment"},
		{UUPDP, "Pasal 35", "Technical measures to protect personal data"},
	},
	finding.CategoryHardening: {
		{ISO27001, "A.8.9", "Configuration management"},
		{CISv8, "4", "Secure configuration of enterprise assets and software"},
		{NISTCSF, "PR.PS", "Platform security"},
		{UUPDP, "Pasal 35", "Technical and organisational measures"},
	},
	finding.CategoryTLS: {
		{ISO27001, "A.8.24", "Use of cryptography"},
		{CISv8, "3", "Data protection"},
		{NISTCSF, "PR.DS", "Data security, data in transit"},
		{UUPDP, "Pasal 36", "Protection against unauthorised access"},
	},
	finding.CategoryDiscovery: {
		{ISO27001, "A.5.9", "Inventory of information and other associated assets"},
		{CISv8, "1", "Inventory and control of enterprise assets"},
		{NISTCSF, "ID.AM", "Asset management"},
		{UUPDP, "Pasal 31", "Accountability for processing"},
	},
	finding.CategoryNetwork: {
		{ISO27001, "A.8.20", "Networks security"},
		{CISv8, "2", "Inventory and control of software assets"},
		{NISTCSF, "ID.AM", "Asset management"},
		{UUPDP, "Pasal 31", "Accountability for processing"},
	},
	finding.CategorySecret: {
		{ISO27001, "A.8.12", "Data leakage prevention"},
		{CISv8, "3", "Data protection"},
		{NISTCSF, "PR.DS", "Data security"},
		{UUPDP, "Pasal 46", "Breach notification readiness"},
	},
	finding.CategoryDNSEmail: {
		{ISO27001, "A.8.21", "Security of network services"},
		{CISv8, "9", "Email and web browser protections"},
		{NISTCSF, "PR.PS", "Platform security"},
		{UUPDP, "Pasal 35", "Technical measures"},
	},
	finding.CategoryWeb: {
		{ISO27001, "A.8.26", "Application security requirements"},
		{CISv8, "16", "Application software security"},
		{NISTCSF, "PR.PS", "Platform security"},
		{UUPDP, "Pasal 35", "Technical measures"},
	},
}

// Annotate attaches control mappings to findings, restricted to the frameworks
// the licence permits.
//
// A finding whose category has no mapping is marked for manual review rather
// than left blank or guessed at — invariant I2.
func Annotate(fs []*finding.Finding, frameworks []string) {
	allowed := make(map[string]bool, len(frameworks))
	for _, f := range frameworks {
		allowed[f] = true
	}
	for _, f := range fs {
		// Informational records are inventory, not control evidence.
		if f.Status == finding.StatusInformational {
			continue
		}
		maps, ok := byCategory[f.Category]
		if !ok {
			f.Status = finding.StatusManualReview
			continue
		}
		var controls []finding.Control
		for _, m := range maps {
			if !allowed[m.framework] {
				continue
			}
			controls = append(controls, finding.Control{
				Framework: m.framework, ID: m.id, Title: m.title,
			})
		}
		if len(controls) == 0 {
			continue
		}
		sort.Slice(controls, func(i, j int) bool {
			if controls[i].Framework != controls[j].Framework {
				return controls[i].Framework < controls[j].Framework
			}
			return controls[i].ID < controls[j].ID
		})
		f.Compliance = controls
	}
}

// Coverage counts how many findings touch each control, for the report's
// compliance section.
type Coverage struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
	Title     string `json:"title"`
	Findings  int    `json:"findings"`
}

// Summarise builds the coverage table.
func Summarise(fs []*finding.Finding) []Coverage {
	type key struct{ fw, id string }
	counts := map[key]*Coverage{}
	for _, f := range fs {
		for _, c := range f.Compliance {
			k := key{c.Framework, c.ID}
			if cur, ok := counts[k]; ok {
				cur.Findings++
				continue
			}
			counts[k] = &Coverage{Framework: c.Framework, ID: c.ID, Title: c.Title, Findings: 1}
		}
	}
	out := make([]Coverage, 0, len(counts))
	for _, c := range counts {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Framework != out[j].Framework {
			return out[i].Framework < out[j].Framework
		}
		if out[i].Findings != out[j].Findings {
			return out[i].Findings > out[j].Findings
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Disclaimer is the wording every report carries beside a compliance table. It
// is deliberately blunt: overselling this is the fastest way to make the whole
// report untrustworthy.
const Disclaimer = "This mapping indicates which controls the findings relate to. It is supporting evidence for an audit, " +
	"not a statement of compliance, a certification, or a legal opinion. UU PDP in particular is principle-based rather " +
	"than a technical checklist: these findings can help demonstrate that technical measures were taken, and nothing more."
