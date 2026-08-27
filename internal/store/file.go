package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/nizartuanku/auditlight/internal/finding"
)

// File is a file-backed Store. Each job is one JSON document under
// <dir>/jobs/<id>.json and its findings under <dir>/findings/<id>.json.
//
// Writes are atomic: content goes to a temporary file in the same directory and
// is then renamed over the target, so a crash mid-write cannot leave a
// half-written job behind.
type File struct {
	mu  sync.RWMutex
	dir string

	// cache mirrors disk so reads stay cheap and ordering stays stable.
	jobs     map[string]*Job
	order    []string
	defs     map[string]*Definition
	defOrder []string
}

// NewFile opens (creating if needed) a file-backed store rooted at dir.
func NewFile(dir string) (*File, error) {
	for _, sub := range []string{"jobs", "findings", "definitions"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o750); err != nil {
			return nil, fmt.Errorf("store: create %s: %w", sub, err)
		}
	}
	f := &File{dir: dir, jobs: make(map[string]*Job), defs: make(map[string]*Definition)}
	if err := f.load(); err != nil {
		return nil, err
	}
	if err := f.loadDefinitions(); err != nil {
		return nil, err
	}
	return f, nil
}

func (s *File) load() error {
	entries, err := os.ReadDir(filepath.Join(s.dir, "jobs"))
	if err != nil {
		return fmt.Errorf("store: read jobs: %w", err)
	}
	type dated struct {
		id string
		j  *Job
	}
	var all []dated
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.dir, "jobs", e.Name()))
		if err != nil {
			return fmt.Errorf("store: read job %s: %w", e.Name(), err)
		}
		var j Job
		if err := json.Unmarshal(b, &j); err != nil {
			// A corrupt job must not take the whole store down; skip it and
			// keep serving the rest.
			continue
		}
		all = append(all, dated{id: j.ID, j: &j})
	}
	// Oldest first, so that ListJobs' reverse walk yields newest first.
	sort.Slice(all, func(i, k int) bool {
		if all[i].j.Created.Equal(all[k].j.Created) {
			return all[i].id < all[k].id
		}
		return all[i].j.Created.Before(all[k].j.Created)
	})
	for _, d := range all {
		s.jobs[d.id] = d.j
		s.order = append(s.order, d.id)
	}
	return nil
}

func writeAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("store: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("store: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("store: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: close: %w", err)
	}
	if err := os.Chmod(tmpName, 0o640); err != nil {
		return fmt.Errorf("store: chmod: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("store: rename: %w", err)
	}
	return nil
}

// safeID rejects identifiers that could escape the store directory. Job IDs are
// generated internally, but this keeps a future caller from turning an ID into
// a path traversal.
func safeID(id string) error {
	if id == "" || strings.ContainsAny(id, `/\.`) {
		return fmt.Errorf("store: unsafe id %q", id)
	}
	return nil
}

func (s *File) jobPath(id string) string { return filepath.Join(s.dir, "jobs", id+".json") }
func (s *File) findPath(id string) string {
	return filepath.Join(s.dir, "findings", id+".json")
}

func (s *File) CreateJob(j *Job) error {
	if err := safeID(j.ID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.jobs[j.ID]; ok {
		return errDuplicate(j.ID)
	}
	if err := writeAtomic(s.jobPath(j.ID), j); err != nil {
		return err
	}
	s.jobs[j.ID] = j.Clone()
	s.order = append(s.order, j.ID)
	return nil
}

func (s *File) UpdateJob(j *Job) error {
	if err := safeID(j.ID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.jobs[j.ID]; !ok {
		return ErrNotFound
	}
	if err := writeAtomic(s.jobPath(j.ID), j); err != nil {
		return err
	}
	s.jobs[j.ID] = j.Clone()
	return nil
}

func (s *File) GetJob(id string) (*Job, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.jobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return j.Clone(), nil
}

func (s *File) ListJobs(workspace string) ([]*Job, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Job, 0, len(s.order))
	for i := len(s.order) - 1; i >= 0; i-- {
		j := s.jobs[s.order[i]]
		if workspace != "" && j.Workspace != workspace {
			continue
		}
		out = append(out, j.Clone())
	}
	return out, nil
}

func (s *File) AddFindings(jobID string, fs []*finding.Finding) error {
	if err := safeID(jobID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.jobs[jobID]; !ok {
		return ErrNotFound
	}
	existing, err := s.readFindings(jobID)
	if err != nil {
		return err
	}
	merged := mergeInto(existing, fs)
	if err := writeAtomic(s.findPath(jobID), merged); err != nil {
		return err
	}
	return nil
}

// readFindings loads findings from disk. Callers must hold the lock.
func (s *File) readFindings(jobID string) ([]*finding.Finding, error) {
	b, err := os.ReadFile(s.findPath(jobID))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: read findings: %w", err)
	}
	var fs []*finding.Finding
	if err := json.Unmarshal(b, &fs); err != nil {
		return nil, fmt.Errorf("store: decode findings: %w", err)
	}
	return fs, nil
}

func (s *File) GetFindings(jobID string) ([]*finding.Finding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.jobs[jobID]; !ok {
		return nil, ErrNotFound
	}
	return s.readFindings(jobID)
}

func (s *File) ActiveJobs() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, j := range s.jobs {
		if !j.State.Terminal() {
			n++
		}
	}
	return n, nil
}

func (s *File) Close() error { return nil }

func errDuplicate(id string) error { return fmt.Errorf("store: job %s already exists", id) }

// --- definitions ----------------------------------------------------------

func (s *File) defPath(id string) string {
	return filepath.Join(s.dir, "definitions", id+".json")
}

func (s *File) loadDefinitions() error {
	dir := filepath.Join(s.dir, "definitions")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("store: read definitions: %w", err)
	}
	var all []*Definition
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var d Definition
		if err := json.Unmarshal(b, &d); err != nil {
			continue
		}
		all = append(all, &d)
	}
	sort.Slice(all, func(i, k int) bool {
		if all[i].Created.Equal(all[k].Created) {
			return all[i].ID < all[k].ID
		}
		return all[i].Created.Before(all[k].Created)
	})
	for _, d := range all {
		s.defs[d.ID] = d
		s.defOrder = append(s.defOrder, d.ID)
	}
	return nil
}

func (s *File) CreateDefinition(d *Definition) error {
	if err := safeID(d.ID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.defs[d.ID]; ok {
		return fmt.Errorf("store: definition %s already exists", d.ID)
	}
	if err := writeAtomic(s.defPath(d.ID), d); err != nil {
		return err
	}
	s.defs[d.ID] = d.Clone()
	s.defOrder = append(s.defOrder, d.ID)
	return nil
}

func (s *File) UpdateDefinition(d *Definition) error {
	if err := safeID(d.ID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.defs[d.ID]; !ok {
		return ErrNotFound
	}
	if err := writeAtomic(s.defPath(d.ID), d); err != nil {
		return err
	}
	s.defs[d.ID] = d.Clone()
	return nil
}

func (s *File) GetDefinition(id string) (*Definition, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.defs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return d.Clone(), nil
}

func (s *File) ListDefinitions(workspace string) ([]*Definition, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Definition, 0, len(s.defOrder))
	for _, id := range s.defOrder {
		d, ok := s.defs[id]
		if !ok || (workspace != "" && d.Workspace != workspace) {
			continue
		}
		out = append(out, d.Clone())
	}
	return out, nil
}

func (s *File) DeleteDefinition(id string) error {
	if err := safeID(id); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.defs[id]; !ok {
		return ErrNotFound
	}
	if err := os.Remove(s.defPath(id)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("store: delete definition: %w", err)
	}
	delete(s.defs, id)
	for i, x := range s.defOrder {
		if x == id {
			s.defOrder = append(s.defOrder[:i], s.defOrder[i+1:]...)
			break
		}
	}
	return nil
}

func (s *File) LastCompletedJob(definitionID, excludeID string) (*Job, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return lastCompleted(s.jobs, s.order, definitionID, excludeID)
}
