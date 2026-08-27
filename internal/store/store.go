// Package store persists jobs and findings.
//
// Two backends implement the same interface: an in-memory store used by tests
// and ephemeral runs, and a file-backed JSON store used in production. A shared
// contract test asserts the two behave identically, so callers never depend on
// which one is mounted.
//
// The product-build standard specifies SQLite. No SQLite driver is reachable
// without CGO or a module proxy, so v0.1.0 ships the file backend behind this
// interface. Adding a SQLite backend later requires no change above this line.
package store

import (
	"errors"
	"time"

	"github.com/nizartuanku/auditlight/internal/finding"
)

// ErrNotFound is returned when a job does not exist.
var ErrNotFound = errors.New("store: not found")

// JobState is the lifecycle of an assessment job.
type JobState string

const (
	StateQueued    JobState = "queued"
	StateRunning   JobState = "running"
	StateCompleted JobState = "completed"
	StateFailed    JobState = "failed"
	StateRefused   JobState = "refused" // authorisation gate rejected it
)

// Terminal reports whether no further transition is expected.
func (s JobState) Terminal() bool {
	return s == StateCompleted || s == StateFailed || s == StateRefused
}

// AdapterRun records what one adapter actually did. This is the raw material of
// the Process Report: successes and failures are recorded with equal weight.
type AdapterRun struct {
	Name      string        `json:"name"`
	Kind      string        `json:"kind"` // native | subprocess
	Started   time.Time     `json:"started"`
	Duration  time.Duration `json:"duration"`
	OK        bool          `json:"ok"`
	Findings  int           `json:"findings"`
	Skipped   bool          `json:"skipped"`
	Reason    string        `json:"reason,omitempty"` // why it failed or was skipped
	ToolName  string        `json:"tool_name,omitempty"`
	ToolPath  string        `json:"tool_path,omitempty"`
	SafeFlags []string      `json:"safe_flags,omitempty"`
}

// TargetOutcome records per-target disposition, including skips with reasons.
// Invariant I1: a skipped target is reported, never dropped silently.
type TargetOutcome struct {
	Target    string `json:"target"`
	Processed bool   `json:"processed"`
	Reason    string `json:"reason,omitempty"`
	Verified  bool   `json:"verified"` // ownership proof succeeded
	InScope   bool   `json:"in_scope"` // passed the scope guard
	Findings  int    `json:"findings"`
}

// AuthzRecord is the authorisation evidence captured before a job runs.
type AuthzRecord struct {
	Operator  string    `json:"operator"`
	Statement string    `json:"statement"`
	Targets   []string  `json:"targets"`
	Scope     []string  `json:"scope"`
	Confirmed bool      `json:"confirmed"`
	At        time.Time `json:"at"`
	EntryHash string    `json:"entry_hash"`
	PrevHash  string    `json:"prev_hash"`
}

// Definition is a saved assessment that can be re-run, on a schedule or on
// demand. It is what turns AuditLight from a one-off scanner into something
// that tracks whether findings actually get fixed.
type Definition struct {
	ID        string `json:"id"`
	Workspace string `json:"workspace"`
	Name      string `json:"name"`
	Profile   string `json:"profile"`

	Targets  []string `json:"targets"`
	Scope    []string `json:"scope,omitempty"`
	ScanPath string   `json:"scan_path,omitempty"`

	// Authorisation is captured once and then EXPIRES. A permission that never
	// lapses is not a permission, it is a checkbox someone clicked in March.
	// When the window closes, scheduled runs stop and wait for a human.
	Operator      string    `json:"operator"`
	Statement     string    `json:"statement"`
	AuthorisedAt  time.Time `json:"authorised_at"`
	AuthorisedFor int       `json:"authorised_for_days"`

	// IntervalDays of 0 means the definition only runs when asked.
	IntervalDays int       `json:"interval_days"`
	NextRunAt    time.Time `json:"next_run_at,omitempty"`
	LastRunID    string    `json:"last_run_id,omitempty"`
	LastRunAt    time.Time `json:"last_run_at,omitempty"`
	// LastSkipReason records why a due run did not happen, so a definition
	// that quietly stopped running is visible rather than silently dead.
	LastSkipReason string `json:"last_skip_reason,omitempty"`

	WebhookURL  string `json:"webhook_url,omitempty"`
	NotifyEmail string `json:"notify_email,omitempty"`
	// NotifyOn: "change" (default) notifies when the delta is non-empty,
	// "worse" only when something new or regressed appears, "never" is silent.
	NotifyOn string `json:"notify_on,omitempty"`

	Enabled bool      `json:"enabled"`
	Created time.Time `json:"created"`
}

// AuthorisationExpires returns when the recorded authorisation lapses.
func (d *Definition) AuthorisationExpires() time.Time {
	days := d.AuthorisedFor
	if days <= 0 {
		days = DefaultAuthorisationDays
	}
	return d.AuthorisedAt.AddDate(0, 0, days)
}

// AuthorisationValid reports whether the authorisation still holds at t.
func (d *Definition) AuthorisationValid(t time.Time) bool {
	return !d.AuthorisedAt.IsZero() && t.Before(d.AuthorisationExpires())
}

// DefaultAuthorisationDays is how long a recorded authorisation stands before
// a human has to affirm it again.
const DefaultAuthorisationDays = 90

// Clone returns a deep copy of the definition.
func (d *Definition) Clone() *Definition {
	if d == nil {
		return nil
	}
	cp := *d
	cp.Targets = append([]string(nil), d.Targets...)
	cp.Scope = append([]string(nil), d.Scope...)
	return &cp
}

// Job is one assessment run.
type Job struct {
	ID        string `json:"id"`
	Workspace string `json:"workspace"`
	Profile   string `json:"profile"`
	// DefinitionID links a run back to the saved assessment it came from, and
	// is how the delta engine finds the previous run to compare against.
	DefinitionID string `json:"definition_id,omitempty"`
	// BaselineJobID is the run this one was compared against, if any.
	BaselineJobID string `json:"baseline_job_id,omitempty"`
	// Trigger records who or what started the run: "manual" or "schedule".
	Trigger  string    `json:"trigger,omitempty"`
	State    JobState  `json:"state"`
	Created  time.Time `json:"created"`
	Started  time.Time `json:"started,omitempty"`
	Finished time.Time `json:"finished,omitempty"`
	Error    string    `json:"error,omitempty"`

	Authz    AuthzRecord     `json:"authz"`
	Targets  []TargetOutcome `json:"targets"`
	Adapters []AdapterRun    `json:"adapters"`

	// Progress is 0..100, updated as adapters complete.
	Progress int `json:"progress"`
	// Phase is a short human label for what is happening now.
	Phase string `json:"phase,omitempty"`

	// FindingsTotal is how many findings the job actually produced, before any
	// tier cap. FindingsShown is how many the current licence exposes.
	// Invariant I1: both are recorded so truncation can be stated, not hidden.
	FindingsTotal int `json:"findings_total"`
	FindingsShown int `json:"findings_shown"`

	// Tier the job ran under, recorded for the report.
	Tier string `json:"tier"`
}

// Clone returns a deep copy of the job.
//
// The slices matter here. A shallow copy shares their backing arrays, so an
// HTTP handler serialising a "copy" while the runner appends to the original is
// a data race — one the race detector caught during the end-to-end tests.
func (j *Job) Clone() *Job {
	if j == nil {
		return nil
	}
	cp := *j
	cp.Targets = append([]TargetOutcome(nil), j.Targets...)
	cp.Adapters = make([]AdapterRun, len(j.Adapters))
	for i, a := range j.Adapters {
		ac := a
		ac.SafeFlags = append([]string(nil), a.SafeFlags...)
		cp.Adapters[i] = ac
	}
	cp.Authz.Targets = append([]string(nil), j.Authz.Targets...)
	cp.Authz.Scope = append([]string(nil), j.Authz.Scope...)
	return &cp
}

// Store is the persistence contract.
type Store interface {
	CreateJob(j *Job) error
	UpdateJob(j *Job) error
	GetJob(id string) (*Job, error)
	ListJobs(workspace string) ([]*Job, error)

	// AddFindings appends findings to a job. Implementations must de-duplicate
	// by finding ID, merging duplicates rather than storing them twice.
	AddFindings(jobID string, fs []*finding.Finding) error
	GetFindings(jobID string) ([]*finding.Finding, error)

	// ActiveJobs counts jobs not in a terminal state, for concurrency caps.
	ActiveJobs() (int, error)

	CreateDefinition(d *Definition) error
	UpdateDefinition(d *Definition) error
	GetDefinition(id string) (*Definition, error)
	ListDefinitions(workspace string) ([]*Definition, error)
	DeleteDefinition(id string) error

	// LastCompletedJob returns the most recent completed run of a definition,
	// excluding excludeID. It is the baseline a delta is measured against.
	LastCompletedJob(definitionID, excludeID string) (*Job, error)

	Close() error
}

// lastCompleted walks insertion order backwards to find the most recent
// completed run of a definition. Shared by both backends so "which run is the
// baseline" cannot mean two different things.
func lastCompleted(jobs map[string]*Job, order []string, definitionID, excludeID string) (*Job, error) {
	if definitionID == "" {
		return nil, ErrNotFound
	}
	for i := len(order) - 1; i >= 0; i-- {
		j, ok := jobs[order[i]]
		if !ok || j.ID == excludeID {
			continue
		}
		if j.DefinitionID == definitionID && j.State == StateCompleted {
			return j.Clone(), nil
		}
	}
	return nil, ErrNotFound
}
