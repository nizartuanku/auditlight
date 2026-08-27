package store

import (
	"fmt"
	"testing"
	"time"

	"github.com/nizartuanku/auditlight/internal/finding"
)

// The contract test is what lets the rest of the code ignore which backend is
// mounted. Both implementations run the identical suite.
func eachBackend(t *testing.T, fn func(t *testing.T, s Store)) {
	t.Helper()
	t.Run("mem", func(t *testing.T) { fn(t, NewMem()) })
	t.Run("file", func(t *testing.T) {
		s, err := NewFile(t.TempDir())
		if err != nil {
			t.Fatalf("open file store: %v", err)
		}
		defer s.Close()
		fn(t, s)
	})
}

func job(id string, created time.Time) *Job {
	return &Job{
		ID: id, Workspace: "default", Profile: "perimeter",
		State: StateQueued, Created: created,
	}
}

func TestCreateGetUpdate(t *testing.T) {
	eachBackend(t, func(t *testing.T, s Store) {
		j := job("job1", time.Now())
		if err := s.CreateJob(j); err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := s.CreateJob(j); err == nil {
			t.Fatal("creating the same id twice must fail")
		}
		got, err := s.GetJob("job1")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Profile != "perimeter" {
			t.Fatalf("profile = %q", got.Profile)
		}

		// The returned job must be a copy: mutating it must not reach the store.
		got.Profile = "tampered"
		again, _ := s.GetJob("job1")
		if again.Profile != "perimeter" {
			t.Fatal("store returned a live reference; callers can corrupt it")
		}

		got.Profile = "web"
		if err := s.UpdateJob(got); err != nil {
			t.Fatalf("update: %v", err)
		}
		after, _ := s.GetJob("job1")
		if after.Profile != "web" {
			t.Fatalf("update did not persist: %q", after.Profile)
		}

		if _, err := s.GetJob("missing"); err != ErrNotFound {
			t.Fatalf("missing job error = %v, want ErrNotFound", err)
		}
		if err := s.UpdateJob(job("missing", time.Now())); err != ErrNotFound {
			t.Fatalf("update of missing job = %v, want ErrNotFound", err)
		}
	})
}

// Regression: the store used to return a shallow copy, so the returned job
// shared its slice backing arrays with the live one. A reader serialising that
// "copy" while the runner appended to it was a real data race.
func TestReturnedJobSlicesAreIsolated(t *testing.T) {
	eachBackend(t, func(t *testing.T, s Store) {
		j := job("iso", time.Now())
		j.Targets = []TargetOutcome{{Target: "example.com", InScope: true}}
		j.Adapters = []AdapterRun{{Name: "portscan", SafeFlags: []string{"-sT"}}}
		j.Authz.Targets = []string{"example.com"}
		if err := s.CreateJob(j); err != nil {
			t.Fatalf("create: %v", err)
		}

		// Mutating what we handed to the store must not change what it holds.
		j.Targets[0].Processed = true
		j.Adapters[0].SafeFlags[0] = "tampered"
		j.Authz.Targets[0] = "tampered"

		got, err := s.GetJob("iso")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Targets[0].Processed {
			t.Fatal("target slice was shared with the caller")
		}
		if got.Adapters[0].SafeFlags[0] != "-sT" {
			t.Fatal("adapter flag slice was shared with the caller")
		}
		if got.Authz.Targets[0] != "example.com" {
			t.Fatal("authz target slice was shared with the caller")
		}

		// And mutating what the store returned must not change it either.
		got.Targets[0].Processed = true
		again, _ := s.GetJob("iso")
		if again.Targets[0].Processed {
			t.Fatal("store handed out a live slice")
		}
	})
}

func TestReturnedFindingSlicesAreIsolated(t *testing.T) {
	eachBackend(t, func(t *testing.T, s Store) {
		if err := s.CreateJob(job("f", time.Now())); err != nil {
			t.Fatalf("create: %v", err)
		}
		src := finding.New("example.com", 443, finding.CategoryTLS, finding.SeverityLow,
			finding.ConfidenceConfirmed, "sig", "Title", "Body", "tlsaudit")
		src.AddEvidence("tls", "version", "TLS 1.0")
		src.CVE = []string{"CVE-2020-1"}
		if err := s.AddFindings("f", []*finding.Finding{src}); err != nil {
			t.Fatalf("add: %v", err)
		}

		src.Evidence[0].Value = "tampered"
		src.CVE[0] = "tampered"

		got, err := s.GetFindings("f")
		if err != nil || len(got) != 1 {
			t.Fatalf("get findings: %v (%d)", err, len(got))
		}
		if got[0].Evidence[0].Value != "TLS 1.0" {
			t.Fatal("evidence slice was shared with the caller")
		}
		if got[0].CVE[0] != "CVE-2020-1" {
			t.Fatal("cve slice was shared with the caller")
		}

		got[0].Evidence[0].Value = "tampered again"
		again, _ := s.GetFindings("f")
		if again[0].Evidence[0].Value != "TLS 1.0" {
			t.Fatal("store handed out a live evidence slice")
		}
	})
}

func TestListJobsNewestFirst(t *testing.T) {
	eachBackend(t, func(t *testing.T, s Store) {
		base := time.Now().Add(-time.Hour)
		for i := 0; i < 3; i++ {
			j := job(fmt.Sprintf("job%d", i), base.Add(time.Duration(i)*time.Minute))
			if err := s.CreateJob(j); err != nil {
				t.Fatalf("create: %v", err)
			}
		}
		list, err := s.ListJobs("")
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(list) != 3 {
			t.Fatalf("len = %d, want 3", len(list))
		}
		if list[0].ID != "job2" {
			t.Fatalf("first = %q, want newest (job2)", list[0].ID)
		}

		other := job("other", time.Now())
		other.Workspace = "client-a"
		_ = s.CreateJob(other)
		filtered, _ := s.ListJobs("client-a")
		if len(filtered) != 1 || filtered[0].ID != "other" {
			t.Fatalf("workspace filter returned %d job(s)", len(filtered))
		}
	})
}

func TestFindingsDeduplicateByID(t *testing.T) {
	eachBackend(t, func(t *testing.T, s Store) {
		if err := s.CreateJob(job("j", time.Now())); err != nil {
			t.Fatalf("create: %v", err)
		}
		mk := func(tool string) *finding.Finding {
			return finding.New("example.com", 443, finding.CategoryTLS,
				finding.SeverityMedium, finding.ConfidencePotential,
				"weak-cipher", "Weak cipher", "d", tool)
		}
		if err := s.AddFindings("j", []*finding.Finding{mk("tlsaudit")}); err != nil {
			t.Fatalf("add: %v", err)
		}
		if err := s.AddFindings("j", []*finding.Finding{mk("testssl")}); err != nil {
			t.Fatalf("add: %v", err)
		}
		fs, err := s.GetFindings("j")
		if err != nil {
			t.Fatalf("get findings: %v", err)
		}
		if len(fs) != 1 {
			t.Fatalf("len = %d; the same condition must be stored once", len(fs))
		}
		if len(fs[0].SourceTools) != 2 {
			t.Fatalf("source tools = %v; both tools should be credited", fs[0].SourceTools)
		}
		if fs[0].Confidence != finding.ConfidenceLikely {
			t.Fatalf("confidence = %q; corroboration should promote once", fs[0].Confidence)
		}

		if _, err := s.GetFindings("nope"); err != ErrNotFound {
			t.Fatalf("findings for missing job = %v, want ErrNotFound", err)
		}
	})
}

func TestActiveJobs(t *testing.T) {
	eachBackend(t, func(t *testing.T, s Store) {
		a := job("a", time.Now())
		b := job("b", time.Now())
		b.State = StateCompleted
		_ = s.CreateJob(a)
		_ = s.CreateJob(b)

		n, err := s.ActiveJobs()
		if err != nil {
			t.Fatalf("active: %v", err)
		}
		if n != 1 {
			t.Fatalf("active = %d, want 1", n)
		}
	})
}

func TestFileStoreSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFile(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	j := job("persist", time.Now())
	j.FindingsTotal = 7
	if err := s.CreateJob(j); err != nil {
		t.Fatalf("create: %v", err)
	}
	f := finding.New("example.com", 80, finding.CategoryWeb, finding.SeverityLow,
		finding.ConfidenceConfirmed, "sig", "Title", "Body", "httpprobe")
	if err := s.AddFindings("persist", []*finding.Finding{f}); err != nil {
		t.Fatalf("add: %v", err)
	}
	s.Close()

	reopened, err := NewFile(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	got, err := reopened.GetJob("persist")
	if err != nil {
		t.Fatalf("get after reopen: %v", err)
	}
	if got.FindingsTotal != 7 {
		t.Fatalf("findings total = %d, want 7", got.FindingsTotal)
	}
	fs, err := reopened.GetFindings("persist")
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings after reopen: %v (%d)", err, len(fs))
	}
	if fs[0].Title != "Title" {
		t.Fatalf("finding did not round-trip: %q", fs[0].Title)
	}
}

func TestFileStoreRejectsUnsafeID(t *testing.T) {
	s, err := NewFile(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	for _, id := range []string{"../escape", "a/b", "", "with.dot"} {
		if err := s.CreateJob(job(id, time.Now())); err == nil {
			t.Fatalf("id %q should have been rejected", id)
		}
	}
}

// --- definitions ----------------------------------------------------------

func definition(id string, created time.Time) *Definition {
	return &Definition{
		ID: id, Workspace: "default", Name: "assessment " + id,
		Profile: "perimeter", Operator: "Nizar",
		Targets:      []string{"example.com", "app.example.com"},
		Scope:        []string{"example.com"},
		IntervalDays: 30, AuthorisedAt: created, AuthorisedFor: 90,
		Enabled: true, Created: created,
	}
}

func TestDefinitionRoundTrip(t *testing.T) {
	eachBackend(t, func(t *testing.T, s Store) {
		d := definition("d1", time.Now())
		if err := s.CreateDefinition(d); err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := s.CreateDefinition(d); err == nil {
			t.Fatal("creating the same definition twice must fail")
		}
		got, err := s.GetDefinition("d1")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Name != d.Name || len(got.Targets) != 2 {
			t.Fatalf("definition did not round-trip: %+v", got)
		}

		got.IntervalDays = 7
		if err := s.UpdateDefinition(got); err != nil {
			t.Fatalf("update: %v", err)
		}
		after, _ := s.GetDefinition("d1")
		if after.IntervalDays != 7 {
			t.Fatalf("update did not persist: %d", after.IntervalDays)
		}

		if _, err := s.GetDefinition("nope"); err != ErrNotFound {
			t.Fatalf("missing definition = %v, want ErrNotFound", err)
		}
		if err := s.DeleteDefinition("d1"); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if _, err := s.GetDefinition("d1"); err != ErrNotFound {
			t.Fatal("delete did not remove the definition")
		}
		if err := s.DeleteDefinition("d1"); err != ErrNotFound {
			t.Fatal("deleting twice must report not found")
		}
	})
}

func TestDefinitionSlicesAreIsolated(t *testing.T) {
	eachBackend(t, func(t *testing.T, s Store) {
		d := definition("iso", time.Now())
		if err := s.CreateDefinition(d); err != nil {
			t.Fatalf("create: %v", err)
		}
		d.Targets[0] = "tampered"
		got, _ := s.GetDefinition("iso")
		if got.Targets[0] != "example.com" {
			t.Fatal("definition target slice was shared with the caller")
		}
		got.Targets[0] = "tampered again"
		again, _ := s.GetDefinition("iso")
		if again.Targets[0] != "example.com" {
			t.Fatal("store handed out a live target slice")
		}
	})
}

func TestListDefinitionsFiltersByWorkspace(t *testing.T) {
	eachBackend(t, func(t *testing.T, s Store) {
		base := time.Now().Add(-time.Hour)
		a := definition("a", base)
		b := definition("b", base.Add(time.Minute))
		b.Workspace = "client-x"
		_ = s.CreateDefinition(a)
		_ = s.CreateDefinition(b)

		all, err := s.ListDefinitions("")
		if err != nil || len(all) != 2 {
			t.Fatalf("list all: %v (%d)", err, len(all))
		}
		only, _ := s.ListDefinitions("client-x")
		if len(only) != 1 || only[0].ID != "b" {
			t.Fatalf("workspace filter returned %d", len(only))
		}
	})
}

// The baseline for a comparison is the most recent COMPLETED run of the same
// definition — not the most recent run, and not a run of something else.
func TestLastCompletedJobPicksTheRightBaseline(t *testing.T) {
	eachBackend(t, func(t *testing.T, s Store) {
		base := time.Now().Add(-10 * time.Hour)
		mk := func(id, defID string, state JobState, at time.Time) {
			j := job(id, at)
			j.DefinitionID = defID
			j.State = state
			if err := s.CreateJob(j); err != nil {
				t.Fatalf("create %s: %v", id, err)
			}
		}
		mk("old", "d1", StateCompleted, base)
		mk("newer", "d1", StateCompleted, base.Add(time.Hour))
		mk("failed", "d1", StateFailed, base.Add(2*time.Hour))
		mk("running", "d1", StateRunning, base.Add(3*time.Hour))
		mk("other", "d2", StateCompleted, base.Add(4*time.Hour))
		mk("current", "d1", StateCompleted, base.Add(5*time.Hour))

		got, err := s.LastCompletedJob("d1", "current")
		if err != nil {
			t.Fatalf("baseline: %v", err)
		}
		if got.ID != "newer" {
			t.Fatalf("baseline = %s; want the most recent completed run excluding the current one", got.ID)
		}

		if _, err := s.LastCompletedJob("nothing", ""); err != ErrNotFound {
			t.Fatalf("no history = %v, want ErrNotFound", err)
		}
		if _, err := s.LastCompletedJob("", ""); err != ErrNotFound {
			t.Fatal("a job with no definition has no baseline")
		}
	})
}

func TestFileStoreKeepsDefinitionsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFile(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.CreateDefinition(definition("persist", time.Now())); err != nil {
		t.Fatalf("create: %v", err)
	}
	s.Close()

	again, err := NewFile(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer again.Close()
	got, err := again.GetDefinition("persist")
	if err != nil {
		t.Fatalf("get after reopen: %v", err)
	}
	if got.IntervalDays != 30 || len(got.Targets) != 2 {
		t.Fatalf("definition did not survive reopen: %+v", got)
	}
}
