package schedule

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nizartuanku/auditlight/internal/orchestrator"
	"github.com/nizartuanku/auditlight/internal/store"
)

// fakeRunner records what the scheduler asked for without running anything.
type fakeRunner struct {
	st      store.Store
	started []string
	fail    error
}

func (f *fakeRunner) Store() store.Store { return f.st }

func (f *fakeRunner) RunDefinition(_ context.Context, id, trigger string, now time.Time) (*store.Job, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	f.started = append(f.started, id+":"+trigger)
	d, err := f.st.GetDefinition(id)
	if err != nil {
		return nil, err
	}
	d.LastRunAt = now
	d.NextRunAt = now.AddDate(0, 0, d.IntervalDays)
	d.LastSkipReason = ""
	if err := f.st.UpdateDefinition(d); err != nil {
		return nil, err
	}
	return &store.Job{ID: "job-" + id}, nil
}

func harness(t *testing.T) (*fakeRunner, *Scheduler, store.Store) {
	t.Helper()
	st := store.NewMem()
	fr := &fakeRunner{st: st}
	s := New(fr, time.Minute, nil)
	return fr, s, st
}

func def(id string, interval int, authorisedAt time.Time) *store.Definition {
	return &store.Definition{
		ID: id, Name: "assessment " + id, Workspace: "default",
		Profile: "perimeter", Operator: "Nizar",
		Targets: []string{"example.com"}, IntervalDays: interval,
		AuthorisedAt: authorisedAt, AuthorisedFor: 90,
		Enabled: true, Created: authorisedAt,
	}
}

func TestRunsOnlyWhatIsDue(t *testing.T) {
	fr, s, st := harness(t)
	now := time.Now()
	s.now = func() time.Time { return now }

	due := def("due", 30, now.AddDate(0, 0, -10))
	due.NextRunAt = now.Add(-time.Hour)
	notYet := def("notyet", 30, now.AddDate(0, 0, -10))
	notYet.NextRunAt = now.Add(24 * time.Hour)
	manual := def("manual", 0, now.AddDate(0, 0, -10))
	disabled := def("disabled", 30, now.AddDate(0, 0, -10))
	disabled.NextRunAt = now.Add(-time.Hour)
	disabled.Enabled = false

	for _, d := range []*store.Definition{due, notYet, manual, disabled} {
		if err := st.CreateDefinition(d); err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	if n := s.RunDue(context.Background()); n != 1 {
		t.Fatalf("started %d, want 1", n)
	}
	if len(fr.started) != 1 || fr.started[0] != "due:"+orchestrator.TriggerSchedule {
		t.Fatalf("started = %v", fr.started)
	}
}

// The whole point of an expiring authorisation is that it stops things.
func TestLapsedAuthorisationStopsTheSchedule(t *testing.T) {
	fr, s, st := harness(t)
	now := time.Now()
	s.now = func() time.Time { return now }

	// Authorised 200 days ago for 90 days: long lapsed.
	d := def("lapsed", 30, now.AddDate(0, 0, -200))
	d.NextRunAt = now.Add(-time.Hour)
	if err := st.CreateDefinition(d); err != nil {
		t.Fatalf("create: %v", err)
	}

	if n := s.RunDue(context.Background()); n != 0 {
		t.Fatalf("started %d; a lapsed authorisation must not run", n)
	}
	if len(fr.started) != 0 {
		t.Fatalf("started = %v", fr.started)
	}

	// It must say why, rather than looking like nothing happened.
	got, err := st.GetDefinition("lapsed")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !strings.Contains(got.LastSkipReason, "authorisation lapsed") {
		t.Fatalf("skip reason = %q; a definition that stopped must explain itself", got.LastSkipReason)
	}

	// Re-affirming resumes it.
	got.AuthorisedAt = now
	if err := st.UpdateDefinition(got); err != nil {
		t.Fatalf("update: %v", err)
	}
	if n := s.RunDue(context.Background()); n != 1 {
		t.Fatalf("after re-authorisation started %d, want 1", n)
	}
}

// A refused run must back off, not hammer the target every tick.
func TestRefusalBacksOff(t *testing.T) {
	fr, s, st := harness(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	fr.fail = &orchestrator.RefusalError{Reason: "This tier allows 1 job at once."}

	d := def("busy", 7, now.AddDate(0, 0, -1))
	d.NextRunAt = now.Add(-time.Minute)
	if err := st.CreateDefinition(d); err != nil {
		t.Fatalf("create: %v", err)
	}

	if n := s.RunDue(context.Background()); n != 0 {
		t.Fatalf("started %d, want 0", n)
	}
	got, _ := st.GetDefinition("busy")
	if !strings.Contains(got.LastSkipReason, "refused") {
		t.Fatalf("skip reason = %q", got.LastSkipReason)
	}
	if !got.NextRunAt.After(now) {
		t.Fatalf("next run = %v; a refusal must push the next attempt out", got.NextRunAt)
	}

	// Immediately ticking again must not try once more.
	if n := s.RunDue(context.Background()); n != 0 {
		t.Fatalf("retried immediately after a refusal")
	}
}

func TestAuthorisationWindowMath(t *testing.T) {
	now := time.Now()
	d := def("w", 30, now.AddDate(0, 0, -89))
	if !d.AuthorisationValid(now) {
		t.Fatal("89 days into a 90-day window is still valid")
	}
	d.AuthorisedAt = now.AddDate(0, 0, -91)
	if d.AuthorisationValid(now) {
		t.Fatal("91 days into a 90-day window has lapsed")
	}
	// An unset window falls back to the default rather than never expiring.
	d.AuthorisedFor = 0
	d.AuthorisedAt = now.AddDate(0, 0, -store.DefaultAuthorisationDays-1)
	if d.AuthorisationValid(now) {
		t.Fatal("an unset window must default, not mean forever")
	}
	// A definition with no authorisation at all is not valid.
	d.AuthorisedAt = time.Time{}
	if d.AuthorisationValid(now) {
		t.Fatal("no recorded authorisation cannot be valid")
	}
}
