// Package schedule re-runs saved assessments when they fall due.
//
// This is not a monitoring loop. AuditLight re-assesses on a cadence measured
// in weeks, because that is how audit works: you fix things, then you check
// whether they stayed fixed. Continuous watching of live assets is a different
// product's job, and conflating the two would make this one dishonest about
// what it does.
package schedule

import (
	"context"
	"log"
	"time"

	"github.com/nizartuanku/auditlight/internal/orchestrator"
	"github.com/nizartuanku/auditlight/internal/store"
)

// Runner is the subset of the orchestrator the scheduler needs.
type Runner interface {
	RunDefinition(ctx context.Context, id, trigger string, now time.Time) (*store.Job, error)
	Store() store.Store
}

// Scheduler fires due assessments.
type Scheduler struct {
	runner Runner
	tick   time.Duration
	logger *log.Logger
	// now is injectable so tests do not have to wait for real days to pass.
	now func() time.Time
}

// New builds a scheduler. A tick of zero uses one minute.
func New(r Runner, tick time.Duration, logger *log.Logger) *Scheduler {
	if tick <= 0 {
		tick = time.Minute
	}
	return &Scheduler{runner: r, tick: tick, logger: logger, now: time.Now}
}

// Start runs until the context is cancelled.
func (s *Scheduler) Start(ctx context.Context) {
	t := time.NewTicker(s.tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.RunDue(ctx)
		}
	}
}

// RunDue starts every assessment that is due. It is exported so tests can drive
// it directly instead of waiting on a ticker.
func (s *Scheduler) RunDue(ctx context.Context) int {
	now := s.now()
	defs, err := s.runner.Store().ListDefinitions("")
	if err != nil {
		s.logf("schedule: list definitions: %v", err)
		return 0
	}

	started := 0
	for _, d := range defs {
		if !d.Enabled || d.IntervalDays <= 0 {
			continue
		}
		if d.NextRunAt.IsZero() || now.Before(d.NextRunAt) {
			continue
		}

		// An expired authorisation stops the schedule. It does not quietly
		// keep scanning, and it does not silently disable itself either — the
		// reason is recorded so somebody can see why the runs stopped.
		if !d.AuthorisationValid(now) {
			reason := "authorisation lapsed on " +
				d.AuthorisationExpires().UTC().Format("2 January 2006") +
				"; re-affirm it to resume scheduled runs"
			if d.LastSkipReason != reason {
				d.LastSkipReason = reason
				if err := s.runner.Store().UpdateDefinition(d); err != nil {
					s.logf("schedule: record lapse for %s: %v", d.ID, err)
				}
				s.logf("schedule: %s skipped — %s", d.Name, reason)
			}
			continue
		}

		if _, err := s.runner.RunDefinition(ctx, d.ID, orchestrator.TriggerSchedule, now); err != nil {
			// Push the next attempt out by one interval rather than retrying
			// every tick: a target that refuses today will refuse in a minute.
			d.LastSkipReason = "run refused: " + err.Error()
			d.NextRunAt = now.AddDate(0, 0, d.IntervalDays)
			if uerr := s.runner.Store().UpdateDefinition(d); uerr != nil {
				s.logf("schedule: record refusal for %s: %v", d.ID, uerr)
			}
			s.logf("schedule: %s refused — %v", d.Name, err)
			continue
		}
		started++
		s.logf("schedule: started %s", d.Name)
	}
	return started
}

func (s *Scheduler) logf(format string, args ...any) {
	if s.logger != nil {
		s.logger.Printf(format, args...)
	}
}
