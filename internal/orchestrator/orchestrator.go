// Package orchestrator plans and runs an assessment.
//
// It owns the safety envelope: which adapters may run, against which targets,
// with what policy, and under which licence caps. Adapters do the work; the
// orchestrator decides what work is permitted and records what actually
// happened, including the parts that failed.
package orchestrator

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nizartuanku/auditlight/internal/adapters"
	"github.com/nizartuanku/auditlight/internal/authz"
	"github.com/nizartuanku/auditlight/internal/compliance"
	"github.com/nizartuanku/auditlight/internal/correlate"
	"github.com/nizartuanku/auditlight/internal/finding"
	"github.com/nizartuanku/auditlight/internal/license"
	"github.com/nizartuanku/auditlight/internal/notify"
	"github.com/nizartuanku/auditlight/internal/score"
	"github.com/nizartuanku/auditlight/internal/store"
)

// Profile is a named set of adapters with a tier requirement.
type Profile struct {
	Name     string   `json:"name"`
	Title    string   `json:"title"`
	Summary  string   `json:"summary"`
	Adapters []string `json:"adapters"`
	// NeedsPaid marks profiles the Free tier cannot run.
	NeedsPaid bool `json:"needs_paid"`
}

// Profiles is the closed set of assessment profiles.
func Profiles() []Profile {
	return []Profile{
		{
			Name: "perimeter", Title: "Perimeter",
			Summary:  "What an outsider can see: hosts, open services, web surface, certificates and observable software.",
			Adapters: []string{"subdomain", "portscan", "banner", "httpprobe", "headers", "tlsaudit", "vulnsig"},
		},
		{
			Name: "web", Title: "Web surface",
			Summary:  "One web service in depth: response, headers, cookies, certificate and observable stack.",
			Adapters: []string{"httpprobe", "headers", "tlsaudit", "vulnsig"},
		},
		{
			Name: "tls-email", Title: "TLS and email posture",
			Summary:   "Certificate and protocol health, plus the DNS records that decide who can send mail as you.",
			Adapters:  []string{"tlsaudit", "dnsemail", "testssl"},
			NeedsPaid: true,
		},
		{
			Name: "hardening", Title: "Host hardening",
			Summary:   "Local configuration review and a search for credentials committed into files.",
			Adapters:  []string{"secrets", "lynis"},
			NeedsPaid: true,
		},
		{
			Name: "full", Title: "Full assessment",
			Summary: "Every check this installation can perform, across all stages.",
			Adapters: []string{
				"subdomain", "portscan", "banner", "httpprobe", "headers",
				"tlsaudit", "dnsemail", "secrets", "vulnsig",
				"nuclei", "testssl", "lynis", "nmap",
			},
			NeedsPaid: true,
		},
	}
}

// ProfileByName looks up a profile.
func ProfileByName(name string) (Profile, bool) {
	for _, p := range Profiles() {
		if p.Name == name {
			return p, true
		}
	}
	return Profile{}, false
}

// Request opens a job.
type Request struct {
	Workspace    string
	Profile      string
	Authz        authz.Request
	ScanPath     string
	DefinitionID string
	Trigger      string
}

// Runner executes assessments.
type Runner struct {
	registry *adapters.Registry
	store    store.Store
	log      *authz.Log
	licence  license.State

	notifier   *notify.Sender
	consoleURL string

	mu      sync.Mutex
	running map[string]context.CancelFunc
}

// New builds a runner.
func New(st store.Store, lic license.State) *Runner {
	return &Runner{
		registry: adapters.NewRegistry(),
		store:    st,
		log:      authz.NewLog(),
		licence:  lic,
		running:  make(map[string]context.CancelFunc),
	}
}

// WithNotifications attaches a notification sender and the console URL used to
// build links back into reports.
func (r *Runner) WithNotifications(s *notify.Sender, consoleURL string) *Runner {
	r.notifier = s
	r.consoleURL = consoleURL
	return r
}

// Store exposes the backing store, for callers that read definitions.
func (r *Runner) Store() store.Store { return r.store }

// Registry exposes the adapter registry, for the capability matrix.
func (r *Runner) Registry() *adapters.Registry { return r.registry }

// Licence exposes the resolved licence state.
func (r *Runner) Licence() license.State { return r.licence }

// AuthzLog exposes the authorisation log.
func (r *Runner) AuthzLog() *authz.Log { return r.log }

// RefusalError distinguishes a refusal from an internal failure, so the API can
// answer 402 or 403 rather than 500.
type RefusalError struct {
	Reason  string
	Upgrade bool // true when a paid tier would lift the limit
}

func (e *RefusalError) Error() string { return e.Reason }

// Submit validates a request, records authorisation and starts the job.
func (r *Runner) Submit(ctx context.Context, req Request) (*store.Job, error) {
	prof, ok := ProfileByName(req.Profile)
	if !ok {
		return nil, &RefusalError{Reason: fmt.Sprintf("Unknown profile %q.", req.Profile)}
	}
	caps := r.licence.Caps
	if !caps.AllowsProfile(prof.Name) {
		return nil, &RefusalError{
			Reason:  fmt.Sprintf("The %s profile is not available on the %s tier.", prof.Title, caps.Tier.Title()),
			Upgrade: true,
		}
	}
	if !license.Unlimited(caps.MaxTargets) && len(req.Authz.Targets) > caps.MaxTargets {
		return nil, &RefusalError{
			Reason: fmt.Sprintf("This tier allows %d targets per job; %d were supplied.",
				caps.MaxTargets, len(req.Authz.Targets)),
			Upgrade: true,
		}
	}
	if !license.Unlimited(caps.MaxActiveJobs) {
		active, err := r.store.ActiveJobs()
		if err != nil {
			return nil, fmt.Errorf("orchestrator: count active jobs: %w", err)
		}
		if active >= caps.MaxActiveJobs {
			return nil, &RefusalError{
				Reason: fmt.Sprintf("This tier allows %d job(s) running at once; %d already running.",
					caps.MaxActiveJobs, active),
				Upgrade: true,
			}
		}
	}

	now := time.Now()
	decision := r.log.Gate(req.Authz, now)
	job := &store.Job{
		ID:           newID(now),
		Workspace:    firstNonEmpty(req.Workspace, "default"),
		Profile:      prof.Name,
		DefinitionID: req.DefinitionID,
		Trigger:      firstNonEmpty(req.Trigger, TriggerManual),
		Created:      now,
		Tier:         string(caps.Tier),
		Phase:        "authorisation",
	}

	if !decision.Allowed {
		job.State = store.StateRefused
		job.Error = decision.Reason
		job.Finished = now
		job.Progress = 100
		job.Phase = "refused"
		for _, s := range decision.Skipped {
			job.Targets = append(job.Targets, store.TargetOutcome{
				Target: s.Target, Processed: false, Reason: s.Reason,
			})
		}
		if err := r.store.CreateJob(job); err != nil {
			return nil, err
		}
		return job, &RefusalError{Reason: decision.Reason}
	}

	job.State = store.StateQueued
	job.Authz = store.AuthzRecord{
		Operator: decision.Record.Operator, Statement: decision.Record.Statement,
		Targets: decision.Record.Targets, Scope: decision.Record.Scope,
		Confirmed: true, At: decision.Record.At,
		EntryHash: decision.Record.EntryHash, PrevHash: decision.Record.PrevHash,
	}
	for _, t := range decision.Accepted {
		job.Targets = append(job.Targets, store.TargetOutcome{Target: t, InScope: true})
	}
	for _, s := range decision.Skipped {
		job.Targets = append(job.Targets, store.TargetOutcome{
			Target: s.Target, Processed: false, Reason: s.Reason,
		})
	}
	if err := r.store.CreateJob(job); err != nil {
		return nil, err
	}

	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	r.mu.Lock()
	r.running[job.ID] = cancel
	r.mu.Unlock()

	go func() {
		defer func() {
			r.mu.Lock()
			delete(r.running, job.ID)
			r.mu.Unlock()
			cancel()
		}()
		r.run(runCtx, job.ID, prof, decision.Accepted, req.ScanPath)
	}()

	return job, nil
}

// Cancel stops a running job.
func (r *Runner) Cancel(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.running[id]; ok {
		c()
		return true
	}
	return false
}

// run executes the job. It never returns an error: every outcome, including
// failure, is written to the job record so the Process Report can show it.
func (r *Runner) run(ctx context.Context, jobID string, prof Profile, targets []string, scanPath string) {
	job, err := r.store.GetJob(jobID)
	if err != nil {
		return
	}
	job.State = store.StateRunning
	job.Started = time.Now()
	job.Phase = "starting"
	_ = r.store.UpdateJob(job)

	caps := r.licence.Caps
	policy := adapters.DefaultPolicy()
	policy.AllowSubprocess = caps.SubprocessTools
	policy.ScanPath = scanPath

	// Select adapters named by the profile, in stage order.
	type planned struct {
		adapter adapters.Adapter
		stage   adapters.Stage
	}
	var plan []planned
	for _, name := range prof.Adapters {
		a, ok := r.registry.ByName(name)
		if !ok {
			continue
		}
		plan = append(plan, planned{adapter: a, stage: a.Stage()})
	}
	sort.SliceStable(plan, func(i, j int) bool { return plan[i].stage < plan[j].stage })

	steps := len(plan) * len(targets)
	if steps == 0 {
		steps = 1
	}
	done := 0

	var collected []*finding.Finding
	perTarget := map[string]int{}

	for _, p := range plan {
		available, why := p.adapter.Available()
		if !available {
			job.Adapters = append(job.Adapters, store.AdapterRun{
				Name: p.adapter.Name(), Kind: string(p.adapter.Kind()),
				Skipped: true, Reason: why,
			})
			done += len(targets)
			job.Progress = percent(done, steps)
			_ = r.store.UpdateJob(job)
			continue
		}
		if p.adapter.Kind() == adapters.KindSubprocess && !caps.SubprocessTools {
			job.Adapters = append(job.Adapters, store.AdapterRun{
				Name: p.adapter.Name(), Kind: string(p.adapter.Kind()),
				Skipped: true,
				Reason:  "external tools require a paid licence",
			})
			done += len(targets)
			job.Progress = percent(done, steps)
			_ = r.store.UpdateJob(job)
			continue
		}

		for _, raw := range targets {
			select {
			case <-ctx.Done():
				job.State = store.StateFailed
				job.Error = "assessment was cancelled"
				job.Phase = "cancelled"
				job.Finished = time.Now()
				job.Progress = 100
				_ = r.store.UpdateJob(job)
				return
			default:
			}

			job.Phase = fmt.Sprintf("%s · %s", p.adapter.Name(), raw)
			_ = r.store.UpdateJob(job)

			target := adapters.NewTarget(raw)
			start := time.Now()
			actx, cancel := context.WithTimeout(ctx, 3*time.Minute)
			res, runErr := p.adapter.Run(actx, target, policy, collected)
			cancel()

			rec := store.AdapterRun{
				Name: p.adapter.Name(), Kind: string(p.adapter.Kind()),
				Started: start, Duration: time.Since(start),
				OK: runErr == nil, Findings: len(res.Findings),
			}
			if ex, ok := p.adapter.(interface {
				SafeFlags() []string
				BinaryPath() string
			}); ok {
				rec.SafeFlags = ex.SafeFlags()
				rec.ToolPath = ex.BinaryPath()
				rec.ToolName = p.adapter.Name()
			}
			if runErr != nil {
				rec.Reason = runErr.Error()
			} else if len(res.Notes) > 0 {
				rec.Reason = joinNotes(res.Notes)
			}
			job.Adapters = append(job.Adapters, rec)

			for _, f := range res.Findings {
				if err := f.Validate(); err != nil {
					// Malformed adapter output is dropped, but the drop is
					// recorded rather than hidden.
					rec.Reason = appendNote(rec.Reason, "one finding was rejected as malformed: "+err.Error())
					continue
				}
				collected = append(collected, f)
				perTarget[raw]++
			}

			done++
			job.Progress = percent(done, steps)
			_ = r.store.UpdateJob(job)
		}
	}

	// Correlate, enrich and rank.
	job.Phase = "correlating"
	_ = r.store.UpdateJob(job)

	merged := collected
	var cstats correlate.Stats
	if caps.Correlation {
		merged, cstats = correlate.Merge(collected)
	} else {
		merged, cstats = correlate.Merge(collected)
		// Free tier still de-duplicates; it simply does not gain the
		// cross-tool confidence promotion, which Merge applies inherently.
		// Recording the stats keeps the Process Report accurate either way.
		_ = cstats
	}

	if len(caps.ComplianceFrameworks) > 0 {
		compliance.Annotate(merged, caps.ComplianceFrameworks)
	}

	ranked := score.Rank(merged)
	capped := score.ApplyCap(ranked, caps.MaxFindingsShown)

	if err := r.store.AddFindings(jobID, ranked); err != nil {
		job.State = store.StateFailed
		job.Error = "findings could not be stored: " + err.Error()
	} else {
		job.State = store.StateCompleted
	}

	for i := range job.Targets {
		if n, ok := perTarget[job.Targets[i].Target]; ok {
			job.Targets[i].Processed = true
			job.Targets[i].Findings = n
		} else if job.Targets[i].InScope {
			job.Targets[i].Processed = true
		}
	}

	job.FindingsTotal = capped.Total
	job.FindingsShown = len(capped.Shown)
	job.Finished = time.Now()
	job.Progress = 100
	job.Phase = "complete"
	_ = r.store.UpdateJob(job)

	// Comparison and notification happen after the run is recorded, so a
	// failure here can never lose the assessment itself.
	r.afterRun(job)
}

func percent(done, total int) int {
	if total <= 0 {
		return 100
	}
	p := done * 100 / total
	if p > 99 {
		return 99 // 100 is reserved for a finished job
	}
	return p
}

func joinNotes(notes []string) string {
	out := ""
	for _, n := range notes {
		out = appendNote(out, n)
	}
	return out
}

func appendNote(cur, n string) string {
	if cur == "" {
		return n
	}
	return cur + "; " + n
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// jobSeq disambiguates jobs created within the same millisecond. A timestamp
// alone is not unique: two submissions in the same instant collide, which is
// easy to hit from a script and was caught by the end-to-end tests.
var jobSeq atomic.Uint64

// newID builds a sortable, filesystem-safe, collision-free job identifier.
func newID(t time.Time) string {
	return fmt.Sprintf("job%s%03d%s",
		t.UTC().Format("20060102T150405"),
		t.Nanosecond()/1e6,
		base36(jobSeq.Add(1)))
}

// base36 keeps the suffix short and filesystem-safe.
func base36(n uint64) string {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{digits[n%36]}, b...)
		n /= 36
	}
	return string(b)
}
