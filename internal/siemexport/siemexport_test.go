package siemexport

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nizartuanku/hexward-core/hfs"
	"github.com/nizartuanku/hexward-core/sink"

	"github.com/nizartuanku/auditlight/internal/delta"
	"github.com/nizartuanku/auditlight/internal/finding"
)

var (
	t0 = time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	t1 = time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
)

func fnd(id string, sev finding.Severity, cat finding.Category, port int) *finding.Finding {
	return &finding.Finding{
		ID: id, Title: "Finding " + id, Target: "app.example.com", Port: port,
		Category: cat, Severity: sev, Confidence: finding.ConfidenceConfirmed,
		CVSS: 7.5, CVE: []string{"CVE-2026-0001"}, SourceTools: []string{"nuclei"},
		Description: "desc " + id, Remediation: "fix " + id, Status: finding.StatusOpen,
		Evidence:   []finding.Evidence{{Kind: "banner", Label: "Server", Value: "nginx/1.18.0"}},
		Compliance: []finding.Control{{Framework: "ISO 27001:2022", ID: "A.8.8"}},
	}
}

func result() delta.Result {
	return delta.Result{HasBaseline: true, Entries: []delta.Entry{
		{Change: delta.ChangeNew, Finding: fnd("a1", finding.SeverityCritical, finding.CategoryVuln, 443)},
		{Change: delta.ChangeRegressed, Finding: fnd("a2", finding.SeverityHigh, finding.CategoryWeb, 0), FirstSeen: t0},
		{Change: delta.ChangeResolved, Finding: fnd("a3", finding.SeverityMedium, finding.CategoryHardening, 22), FirstSeen: t0},
		{Change: delta.ChangePersisting, Finding: fnd("a4", finding.SeverityLow, finding.CategoryNetwork, 0)},
		{Change: delta.ChangeImproved, Finding: fnd("a5", finding.SeverityLow, finding.CategoryNetwork, 0)},
		{Change: delta.ChangeNew}, // no finding: skipped, never a panic
	}}
}

var meta = hfs.Meta{Product: "auditlight", Version: "0.3.3", Host: "audit-01"}

func TestEventsOnlyTransitions(t *testing.T) {
	x := &Exporter{Meta: meta}
	evs := x.Events(result(), t1)
	if len(evs) != 3 {
		t.Fatalf("events = %d, want 3 (new, regressed, resolved)", len(evs))
	}
	want := []struct {
		kind   hfs.Kind
		id     string
		target string
		sev    string
	}{
		{hfs.KindOpened, "a1", "app.example.com:443", "critical"},
		{hfs.KindOpened, "a2", "app.example.com", "high"},
		{hfs.KindResolved, "a3", "app.example.com:22", "medium"},
	}
	for i, w := range want {
		e := evs[i]
		if e.Event != w.kind || e.Finding.Fingerprint != w.id || e.Finding.Target != w.target || e.Finding.Severity != w.sev {
			t.Errorf("event %d = %s %s %s %s, want %+v", i, e.Event, e.Finding.Fingerprint, e.Finding.Target, e.Finding.Severity, w)
		}
		if e.Schema != hfs.SchemaV1 || e.Product != "auditlight" {
			t.Errorf("event %d header %+v", i, e)
		}
	}
	if evs[0].Finding.Check != "auditlight.vuln" {
		t.Errorf("check = %q", evs[0].Finding.Check)
	}
	if evs[2].Finding.Status != "resolved" {
		t.Errorf("resolved status = %q", evs[2].Finding.Status)
	}
	if evs[1].Finding.FirstSeen != t0.Format(time.RFC3339) {
		t.Errorf("first_seen = %q, want the baseline's", evs[1].Finding.FirstSeen)
	}
	b, _ := hfs.Marshal(evs[0])
	for _, s := range []string{"CVE-2026-0001", "nginx/1.18.0", "ISO 27001:2022 A.8.8", `"cvss":7.5`} {
		if !strings.Contains(string(b), s) {
			t.Errorf("missing %q in %s", s, b)
		}
	}
}

func TestFirstRunOpensEverything(t *testing.T) {
	first := delta.Result{Entries: []delta.Entry{
		{Change: delta.ChangePersisting, Finding: fnd("p1", finding.SeverityHigh, finding.CategoryWeb, 0)},
		{Change: delta.ChangePersisting, Finding: fnd("p2", finding.SeverityInfo, finding.CategoryDiscovery, 0)},
	}}
	evs := (&Exporter{Meta: meta}).Events(first, t1)
	if len(evs) != 2 || evs[0].Event != hfs.KindOpened || evs[1].Event != hfs.KindOpened {
		t.Fatalf("first run events: %+v", evs)
	}
}

func TestSecretValueNeverExported(t *testing.T) {
	f := fnd("s1", finding.SeverityHigh, finding.CategorySecret, 0)
	f.Evidence = []finding.Evidence{{Kind: "match", Label: "config/.env:12", Value: "AKIA••••••••XY"}}
	x := &Exporter{Meta: meta}
	evs := x.Events(delta.Result{Entries: []delta.Entry{{Change: delta.ChangeNew, Finding: f}}}, t1)
	b, _ := hfs.Marshal(evs[0])
	if strings.Contains(string(b), "AKIA") {
		t.Fatalf("masked secret exported: %s", b)
	}
	if !strings.Contains(string(b), "config/.env:12") {
		t.Fatalf("location dropped: %s", b)
	}
}

func TestEvidenceNone(t *testing.T) {
	x := &Exporter{Meta: meta, Options: hfs.Options{Evidence: hfs.EvidenceNone}}
	for _, e := range x.Events(result(), t1) {
		if e.Finding.Evidence != nil {
			t.Fatalf("evidence exported with none: %v", e.Finding.Evidence)
		}
	}
}

type failing struct{}

func (failing) Name() string                            { return "broken" }
func (failing) Send(context.Context, []hfs.Event) error { return errors.New("down") }

func TestRunTriesEverySink(t *testing.T) {
	p := filepath.Join(t.TempDir(), "auditlight.ndjson")
	file := &sink.File{Path: p}
	defer file.Close()
	x := &Exporter{Sinks: []sink.Sink{failing{}, file}, Meta: meta}
	err := x.Run(context.Background(), result(), t1)
	if err == nil || !strings.Contains(err.Error(), "broken: down") {
		t.Fatalf("err = %v", err)
	}
	fh, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	n := 0
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		var e hfs.Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != 3 {
		t.Fatalf("lines = %d, a failing sink must not stop the others", n)
	}
	if err := x.Run(context.Background(), delta.Result{}, t1); err != nil {
		t.Fatalf("empty run sent: %v", err)
	}
}

func build(t *testing.T, args ...string) (*Exporter, error) {
	t.Helper()
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	c := Register(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return c.Build(meta)
}

func TestFlags(t *testing.T) {
	if x, err := build(t); x != nil || err != nil {
		t.Fatalf("no flags: %v %v", x, err)
	}
	tok := filepath.Join(t.TempDir(), "tok")
	os.WriteFile(tok, []byte("abc\n"), 0o600)
	x, err := build(t, "-export-file", filepath.Join(t.TempDir(), "f.ndjson"), "-syslog", "127.0.0.1:5514",
		"-syslog-network", "tcp", "-syslog-format", "cef", "-hec-url", "https://splunk.example:8088",
		"-hec-token-file", tok, "-export-webhook", "https://hooks.example/x")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(x.Names(), ","); got != "file,syslog-cef,splunk-hec,webhook-v2" {
		t.Fatalf("sinks = %s", got)
	}
	for _, bad := range [][]string{
		{"-export-evidence", "all", "-export-file", "x"},
		{"-hec-url", "https://s:8088"},
		{"-hec-url", "ftp://s", "-hec-token-file", tok},
		{"-syslog", "nohost"},
		{"-syslog", "h:1", "-syslog-format", "kv"},
		{"-syslog", "h:1", "-syslog-network", "tls", "-syslog-ca-file", "/does/not/exist"},
	} {
		if _, err := build(t, bad...); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}
