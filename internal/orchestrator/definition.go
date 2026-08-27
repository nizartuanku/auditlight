package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nizartuanku/auditlight/internal/authz"
	"github.com/nizartuanku/auditlight/internal/delta"
	"github.com/nizartuanku/auditlight/internal/finding"
	"github.com/nizartuanku/auditlight/internal/license"
	"github.com/nizartuanku/auditlight/internal/notify"
	"github.com/nizartuanku/auditlight/internal/store"
	"github.com/nizartuanku/auditlight/internal/version"
)

// TriggerManual and TriggerSchedule record what started a run.
const (
	TriggerManual   = "manual"
	TriggerSchedule = "schedule"
)

// SaveDefinition validates and stores a saved assessment.
//
// The authorisation statement is captured here, once, and it starts a clock:
// see Definition.AuthorisationExpires. Re-runs inherit that authorisation
// until it lapses, at which point a human has to affirm it again.
func (r *Runner) SaveDefinition(d *store.Definition, now time.Time) error {
	caps := r.licence.Caps
	if !caps.Reassessment {
		return &RefusalError{
			Reason:  "Saved assessments and scheduling are available on the Pro and Team tiers.",
			Upgrade: true,
		}
	}
	prof, ok := ProfileByName(d.Profile)
	if !ok {
		return &RefusalError{Reason: fmt.Sprintf("Unknown profile %q.", d.Profile)}
	}
	if !caps.AllowsProfile(prof.Name) {
		return &RefusalError{
			Reason:  fmt.Sprintf("The %s profile is not available on the %s tier.", prof.Title, caps.Tier.Title()),
			Upgrade: true,
		}
	}
	if strings.TrimSpace(d.Name) == "" {
		return &RefusalError{Reason: "Give the assessment a name, so its reports can be told apart."}
	}
	if len(d.Targets) == 0 {
		return &RefusalError{Reason: "No targets were supplied."}
	}
	if strings.TrimSpace(d.Operator) == "" {
		return &RefusalError{Reason: "An operator name is required, so the authorisation can be attributed."}
	}
	if !license.Unlimited(caps.MaxTargets) && len(d.Targets) > caps.MaxTargets {
		return &RefusalError{
			Reason:  fmt.Sprintf("This tier allows %d targets per assessment; %d were supplied.", caps.MaxTargets, len(d.Targets)),
			Upgrade: true,
		}
	}

	existing, err := r.store.ListDefinitions("")
	if err != nil {
		return fmt.Errorf("orchestrator: list definitions: %w", err)
	}
	if !license.Unlimited(caps.MaxDefinitions) && len(existing) >= caps.MaxDefinitions {
		return &RefusalError{
			Reason:  fmt.Sprintf("This tier allows %d saved assessments; %d already exist.", caps.MaxDefinitions, len(existing)),
			Upgrade: true,
		}
	}

	d.ID = newDefinitionID(now)
	d.Statement = authz.Affirmation
	d.AuthorisedAt = now.UTC()
	if d.AuthorisedFor <= 0 {
		d.AuthorisedFor = store.DefaultAuthorisationDays
	}
	if d.Workspace == "" {
		d.Workspace = "default"
	}
	if d.NotifyOn == "" {
		d.NotifyOn = string(notify.RuleChange)
	}
	d.Enabled = true
	d.Created = now.UTC()
	if d.IntervalDays > 0 {
		d.NextRunAt = now.UTC().AddDate(0, 0, d.IntervalDays)
	}
	return r.store.CreateDefinition(d)
}

// RunDefinition starts a run of a saved assessment.
func (r *Runner) RunDefinition(ctx context.Context, id, trigger string, now time.Time) (*store.Job, error) {
	d, err := r.store.GetDefinition(id)
	if err != nil {
		return nil, err
	}
	if !d.Enabled {
		return nil, &RefusalError{Reason: "This assessment is disabled."}
	}
	if !d.AuthorisationValid(now) {
		// The whole point of an expiring authorisation is that it stops things.
		return nil, &RefusalError{
			Reason: fmt.Sprintf(
				"The authorisation for this assessment lapsed on %s. Re-affirm it before running again.",
				d.AuthorisationExpires().UTC().Format("2 January 2006")),
		}
	}

	job, err := r.Submit(ctx, Request{
		Workspace: d.Workspace,
		Profile:   d.Profile,
		ScanPath:  d.ScanPath,
		Authz: authz.Request{
			Operator:  d.Operator,
			Statement: d.Statement,
			Targets:   d.Targets,
			// The operator typed these once, deliberately, when saving the
			// definition. Re-typing them on every scheduled run is not possible
			// and not the control: the expiry is.
			Confirm:   d.Targets,
			Scope:     d.Scope,
			Confirmed: true,
		},
		DefinitionID: d.ID,
		Trigger:      trigger,
	})
	if err != nil {
		return job, err
	}

	d.LastRunID = job.ID
	d.LastRunAt = now.UTC()
	d.LastSkipReason = ""
	if d.IntervalDays > 0 {
		d.NextRunAt = now.UTC().AddDate(0, 0, d.IntervalDays)
	}
	if err := r.store.UpdateDefinition(d); err != nil {
		return job, fmt.Errorf("orchestrator: update definition: %w", err)
	}
	return job, nil
}

// DeltaFor computes the comparison between a job and the previous completed run
// of the same definition.
func (r *Runner) DeltaFor(job *store.Job) (delta.Result, *store.Job, error) {
	current, err := r.store.GetFindings(job.ID)
	if err != nil {
		return delta.Result{}, nil, err
	}
	if job.DefinitionID == "" {
		return delta.Compare(nil, current, "", job.ID, time.Time{}, job.Finished), nil, nil
	}
	baseline, err := r.store.LastCompletedJob(job.DefinitionID, job.ID)
	if err != nil {
		// No previous run is a normal state, not a failure.
		return delta.Compare(nil, current, "", job.ID, time.Time{}, job.Finished), nil, nil
	}
	prev, err := r.store.GetFindings(baseline.ID)
	if err != nil {
		return delta.Result{}, nil, err
	}
	return delta.Compare(prev, current, baseline.ID, job.ID, baseline.Finished, job.Finished), baseline, nil
}

// afterRun computes the delta, records the baseline on the job, and notifies.
// It is called once a run reaches a terminal state.
func (r *Runner) afterRun(job *store.Job) {
	if job.DefinitionID == "" || job.State != store.StateCompleted {
		return
	}
	res, baseline, err := r.DeltaFor(job)
	if err != nil {
		return
	}
	if baseline != nil {
		job.BaselineJobID = baseline.ID
		_ = r.store.UpdateJob(job)
	}

	d, err := r.store.GetDefinition(job.DefinitionID)
	if err != nil || r.notifier == nil {
		return
	}
	rule := notify.Rule(d.NotifyOn)
	if !notify.ShouldSend(rule, res) {
		return
	}

	payload := notify.Payload{
		Product:      version.Product,
		Version:      version.Version,
		Definition:   d.Name,
		DefinitionID: d.ID,
		JobID:        job.ID,
		BaselineID:   res.BaselineJobID,
		At:           time.Now().UTC(),
		Targets:      d.Targets,
		Headline:     res.Headline(),
		Counts:       res.Counts,
		Severity:     res.SeverityAfter,
	}
	if r.consoleURL != "" {
		payload.ConsoleURL = fmt.Sprintf("%s/api/jobs/%s/report/delta", strings.TrimRight(r.consoleURL, "/"), job.ID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var problems []string
	if err := r.notifier.Webhook(ctx, d.WebhookURL, payload); err != nil {
		problems = append(problems, err.Error())
	}
	if err := r.notifier.Email(d.NotifyEmail, payload); err != nil {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		// A notification that failed silently is worse than none, because the
		// operator believes they are covered. Record it on the definition.
		d.LastSkipReason = "notification failed: " + strings.Join(problems, "; ")
		_ = r.store.UpdateDefinition(d)
	}
}

// unusedFinding keeps the finding import honest if the file evolves.
var _ = finding.CategoryVuln

func newDefinitionID(t time.Time) string {
	return fmt.Sprintf("def%s%s", t.UTC().Format("20060102T150405"), base36(jobSeq.Add(1)))
}
