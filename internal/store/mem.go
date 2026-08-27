package store

import (
	"fmt"
	"sync"

	"github.com/nizartuanku/auditlight/internal/finding"
)

// Mem is an in-memory Store. It is the reference implementation: the file
// backend must behave identically, which the contract test enforces.
type Mem struct {
	mu       sync.RWMutex
	jobs     map[string]*Job
	findings map[string][]*finding.Finding
	order    []string
	defs     map[string]*Definition
	defOrder []string
}

// NewMem returns an empty in-memory store.
func NewMem() *Mem {
	return &Mem{
		jobs:     make(map[string]*Job),
		findings: make(map[string][]*finding.Finding),
		defs:     make(map[string]*Definition),
	}
}

func (m *Mem) CreateJob(j *Job) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.jobs[j.ID]; ok {
		return errDuplicate(j.ID)
	}
	m.jobs[j.ID] = j.Clone()
	m.order = append(m.order, j.ID)
	return nil
}

func (m *Mem) UpdateJob(j *Job) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.jobs[j.ID]; !ok {
		return ErrNotFound
	}
	m.jobs[j.ID] = j.Clone()
	return nil
}

func (m *Mem) GetJob(id string) (*Job, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, ok := m.jobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return j.Clone(), nil
}

func (m *Mem) ListJobs(workspace string) ([]*Job, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Job, 0, len(m.order))
	// Newest first.
	for i := len(m.order) - 1; i >= 0; i-- {
		j := m.jobs[m.order[i]]
		if workspace != "" && j.Workspace != workspace {
			continue
		}
		out = append(out, j.Clone())
	}
	return out, nil
}

func (m *Mem) AddFindings(jobID string, fs []*finding.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.jobs[jobID]; !ok {
		return ErrNotFound
	}
	m.findings[jobID] = mergeInto(m.findings[jobID], fs)
	return nil
}

func (m *Mem) GetFindings(jobID string) ([]*finding.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.jobs[jobID]; !ok {
		return nil, ErrNotFound
	}
	return finding.CloneAll(m.findings[jobID]), nil
}

func (m *Mem) ActiveJobs() (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, j := range m.jobs {
		if !j.State.Terminal() {
			n++
		}
	}
	return n, nil
}

func (m *Mem) Close() error { return nil }

// mergeInto appends findings, folding duplicates by ID into the existing entry.
// Both backends share this so de-duplication semantics cannot drift.
func mergeInto(existing []*finding.Finding, incoming []*finding.Finding) []*finding.Finding {
	index := make(map[string]*finding.Finding, len(existing))
	for _, f := range existing {
		index[f.ID] = f
	}
	for _, f := range incoming {
		if cur, ok := index[f.ID]; ok {
			cur.Merge(f)
			continue
		}
		cp := f.Clone()
		existing = append(existing, cp)
		index[cp.ID] = cp
	}
	return existing
}

// --- definitions ----------------------------------------------------------

func (m *Mem) CreateDefinition(d *Definition) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.defs == nil {
		m.defs = make(map[string]*Definition)
	}
	if _, ok := m.defs[d.ID]; ok {
		return fmt.Errorf("store: definition %s already exists", d.ID)
	}
	m.defs[d.ID] = d.Clone()
	m.defOrder = append(m.defOrder, d.ID)
	return nil
}

func (m *Mem) UpdateDefinition(d *Definition) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.defs[d.ID]; !ok {
		return ErrNotFound
	}
	m.defs[d.ID] = d.Clone()
	return nil
}

func (m *Mem) GetDefinition(id string) (*Definition, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.defs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return d.Clone(), nil
}

func (m *Mem) ListDefinitions(workspace string) ([]*Definition, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Definition, 0, len(m.defOrder))
	for _, id := range m.defOrder {
		d, ok := m.defs[id]
		if !ok || (workspace != "" && d.Workspace != workspace) {
			continue
		}
		out = append(out, d.Clone())
	}
	return out, nil
}

func (m *Mem) DeleteDefinition(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.defs[id]; !ok {
		return ErrNotFound
	}
	delete(m.defs, id)
	for i, x := range m.defOrder {
		if x == id {
			m.defOrder = append(m.defOrder[:i], m.defOrder[i+1:]...)
			break
		}
	}
	return nil
}

func (m *Mem) LastCompletedJob(definitionID, excludeID string) (*Job, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return lastCompleted(m.jobs, m.order, definitionID, excludeID)
}
