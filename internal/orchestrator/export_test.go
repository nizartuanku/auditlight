package orchestrator

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/nizartuanku/hexward-core/hfs"
	"github.com/nizartuanku/hexward-core/sink"

	"github.com/nizartuanku/auditlight/internal/finding"
	"github.com/nizartuanku/auditlight/internal/license"
	"github.com/nizartuanku/auditlight/internal/siemexport"
	"github.com/nizartuanku/auditlight/internal/store"
)

type capture struct {
	mu  sync.Mutex
	evs []hfs.Event
}

func (c *capture) Name() string { return "capture" }
func (c *capture) Send(_ context.Context, evs []hfs.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evs = append(c.evs, evs...)
	return nil
}

func job(t *testing.T, st store.Store, id, def string, at time.Time, fs ...*finding.Finding) *store.Job {
	t.Helper()
	j := &store.Job{ID: id, DefinitionID: def, State: store.StateCompleted, Created: at, Started: at, Finished: at}
	if err := st.CreateJob(j); err != nil {
		t.Fatal(err)
	}
	if err := st.AddFindings(id, fs); err != nil {
		t.Fatal(err)
	}
	return j
}

func f(id string, sev finding.Severity) *finding.Finding {
	return &finding.Finding{ID: id, Title: id, Target: "app.example.com", Port: 443,
		Category: finding.CategoryWeb, Severity: sev, Status: finding.StatusOpen}
}

func runner(st store.Store, c *capture) *Runner {
	x := &siemexport.Exporter{Sinks: []sink.Sink{c}, Meta: hfs.Meta{Product: "auditlight"}}
	return New(st, license.Resolve("")).WithExport(x)
}

func TestOneOffRunExportsEverythingAsOpened(t *testing.T) {
	st := store.NewMem()
	c := &capture{}
	r := runner(st, c)
	r.afterRun(job(t, st, "j1", "", time.Now(), f("a", finding.SeverityHigh), f("b", finding.SeverityLow)))
	if len(c.evs) != 2 {
		t.Fatalf("events = %d", len(c.evs))
	}
	for _, e := range c.evs {
		if e.Event != hfs.KindOpened {
			t.Fatalf("one-off run sent %s", e.Event)
		}
	}
}

func TestDefinitionRunExportsOnlyTransitions(t *testing.T) {
	st := store.NewMem()
	c := &capture{}
	r := runner(st, c)
	t0 := time.Now().Add(-48 * time.Hour)
	job(t, st, "base", "def1", t0, f("kept", finding.SeverityMedium), f("fixed", finding.SeverityHigh), f("worse", finding.SeverityLow))
	cur := job(t, st, "cur", "def1", time.Now(), f("kept", finding.SeverityMedium), f("worse", finding.SeverityCritical), f("fresh", finding.SeverityHigh))
	r.afterRun(cur)

	got := map[string]hfs.Kind{}
	for _, e := range c.evs {
		got[e.Finding.Fingerprint] = e.Event
	}
	want := map[string]hfs.Kind{"fixed": hfs.KindResolved, "worse": hfs.KindOpened, "fresh": hfs.KindOpened}
	if len(got) != len(want) {
		t.Fatalf("events %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestNoExportForFailedRunOrWithoutExporter(t *testing.T) {
	st := store.NewMem()
	c := &capture{}
	r := runner(st, c)
	j := job(t, st, "j1", "", time.Now(), f("a", finding.SeverityHigh))
	j.State = store.StateFailed
	r.afterRun(j)
	if len(c.evs) != 0 {
		t.Fatal("failed run exported")
	}
	plain := New(st, license.Resolve(""))
	j.State = store.StateCompleted
	plain.afterRun(j) // must not panic with no exporter
}
