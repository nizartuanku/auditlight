// Package correlate folds duplicate findings together.
//
// Different adapters routinely observe the same condition. Reporting it three
// times inflates the count and buries the findings that matter; reporting it
// once, noting that three independent checks agreed, is both shorter and more
// informative.
package correlate

import (
	"github.com/nizartuanku/auditlight/internal/finding"
)

// Stats describe what a correlation pass did, so the Process Report can state
// it rather than leave the reader wondering where findings went.
type Stats struct {
	In           int `json:"in"`
	Out          int `json:"out"`
	Merged       int `json:"merged"`
	Corroborated int `json:"corroborated"` // findings confirmed by more than one adapter
}

// Merge collapses findings that share an identity.
//
// Identity is the finding ID, which is derived from target, port, category and
// the adapter's signature. Two adapters that describe the same condition
// therefore have to agree on the signature to be merged — deliberately strict,
// because wrongly merging two distinct findings loses information, while
// failing to merge only costs a duplicate line.
func Merge(in []*finding.Finding) ([]*finding.Finding, Stats) {
	st := Stats{In: len(in)}
	index := make(map[string]*finding.Finding, len(in))
	order := make([]string, 0, len(in))

	for _, f := range in {
		if cur, ok := index[f.ID]; ok {
			cur.Merge(f)
			st.Merged++
			continue
		}
		cp := *f
		// Copy the slices so that merging cannot mutate the caller's data.
		cp.SourceTools = append([]string(nil), f.SourceTools...)
		cp.Evidence = append([]finding.Evidence(nil), f.Evidence...)
		index[f.ID] = &cp
		order = append(order, f.ID)
	}

	out := make([]*finding.Finding, 0, len(order))
	for _, id := range order {
		f := index[id]
		if len(f.SourceTools) > 1 {
			st.Corroborated++
		}
		out = append(out, f)
	}
	st.Out = len(out)
	return out, st
}
