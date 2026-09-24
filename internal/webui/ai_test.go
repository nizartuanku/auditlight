package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nizartuanku/auditlight/internal/finding"
	"github.com/nizartuanku/auditlight/internal/license"
	"github.com/nizartuanku/auditlight/internal/orchestrator"
	"github.com/nizartuanku/auditlight/internal/report"
	"github.com/nizartuanku/auditlight/internal/store"
)

// fakeSidecar answers like a grammar-constrained hexward-ai sidecar and
// records the last request it received.
type fakeSidecar struct {
	srv      *httptest.Server
	calls    atomic.Int32
	lastBody atomic.Value // string
	lastAuth atomic.Value // string
	status   int
}

func newFakeSidecar(t *testing.T) *fakeSidecar {
	t.Helper()
	f := &fakeSidecar{status: http.StatusOK}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		b := new(bytes.Buffer)
		_, _ = b.ReadFrom(r.Body)
		f.lastBody.Store(b.String())
		f.lastAuth.Store(r.Header.Get("Authorization"))
		if f.status != http.StatusOK {
			w.WriteHeader(f.status)
			return
		}
		content, _ := json.Marshal(map[string]any{
			"explanation":    "The response header on this target reveals a version.",
			"what_to_verify": []string{"Confirm who owns the target."},
			"disclaimer":     "model-authored text that must be overwritten",
		})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"role": "assistant", "content": string(content)}}},
		})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// aiHarness is the product wired to an in-memory store with one completed
// job holding one finding, plus (when withDelta) a saved assessment whose
// previous run held three more findings that are absent from the current
// run for three different recorded reasons.
type aiHarness struct {
	api     *httptest.Server
	store   store.Store
	jobID   string
	prevID  string
	finding *finding.Finding
	gone    map[string]*finding.Finding // by scenario
}

const aiTestSecret = "SECRET-DO-NOT-SEND"

func newAIHarness(t *testing.T, tier license.Tier, ai *AIAssist, withDelta bool) *aiHarness {
	t.Helper()
	st := store.NewMem()
	lic := license.State{Tier: tier, Caps: license.CapsFor(tier), Notice: "test licence", Valid: tier != license.TierFree}
	runner := orchestrator.New(st, lic)
	srv := New(runner, st, report.Branding{}).WithAI(ai)
	api := httptest.NewServer(srv.Handler())
	t.Cleanup(api.Close)

	h := &aiHarness{api: api, store: st, gone: map[string]*finding.Finding{}}

	f := finding.New("127.0.0.1", 8080, finding.CategoryWeb, finding.SeverityMedium, finding.ConfidenceConfirmed,
		"server-header", "Server header reveals version", "The Server response header reveals nginx/1.14.0.\n\nSecond paragraph.", "web")
	f.Remediation = "Remove or generalise the Server header."
	f.AddEvidence("header", "Server", "nginx/1.14.0")
	f.AddEvidence("header", "Set-Cookie", "sid="+aiTestSecret)
	f.AddEvidence("match", "config/app.env:3", "AWS_KEY="+aiTestSecret)
	f.AddEvidence("headers", "response headers", "Set-Cookie: sid="+aiTestSecret)
	h.finding = f

	now := time.Now()
	defID := ""
	if withDelta {
		d := &store.Definition{ID: "def-1", Name: "acme", Workspace: "default", Profile: "web", Targets: []string{"127.0.0.1", "10.0.0.9"},
			Operator: "Tester", AuthorisedAt: now, AuthorisedFor: 90, Enabled: true, Created: now}
		if err := st.CreateDefinition(d); err != nil {
			t.Fatal(err)
		}
		defID = d.ID

		skipped := finding.New("10.0.0.9", 443, finding.CategoryTLS, finding.SeverityHigh, finding.ConfidenceConfirmed,
			"cert-expired", "Certificate has expired", "Expired.", "tlsaudit")
		failed := finding.New("127.0.0.1", 8080, finding.CategoryVuln, finding.SeverityHigh, finding.ConfidenceLikely,
			"cve-x", "Known vulnerable version", "Banner matches a vulnerable range.", "nuclei")
		undetected := finding.New("127.0.0.1", 8080, finding.CategoryWeb, finding.SeverityLow, finding.ConfidenceConfirmed,
			"dir-listing", "Directory listing enabled", "Index page lists files.", "web")
		h.gone["target_skipped"], h.gone["check_failed"], h.gone["no_longer_detected"] = skipped, failed, undetected

		prev := &store.Job{ID: "job-prev", Workspace: "default", Profile: "web", DefinitionID: defID, State: store.StateCompleted,
			Created: now.Add(-time.Hour), Started: now.Add(-time.Hour), Finished: now.Add(-time.Hour),
			Targets:  []store.TargetOutcome{{Target: "127.0.0.1", Processed: true, InScope: true}, {Target: "10.0.0.9", Processed: true, InScope: true}},
			Adapters: []store.AdapterRun{{Name: "web", OK: true}, {Name: "tlsaudit", OK: true}, {Name: "nuclei", OK: true}}}
		if err := st.CreateJob(prev); err != nil {
			t.Fatal(err)
		}
		if err := st.AddFindings(prev.ID, []*finding.Finding{f.Clone(), skipped, failed, undetected}); err != nil {
			t.Fatal(err)
		}
		h.prevID = prev.ID
	}

	cur := &store.Job{ID: "job-cur", Workspace: "default", Profile: "web", DefinitionID: defID, State: store.StateCompleted,
		Created: now, Started: now, Finished: now,
		Targets: []store.TargetOutcome{
			{Target: "127.0.0.1", Processed: true, InScope: true, Findings: 1},
			{Target: "10.0.0.9", Processed: false, Reason: "outside the declared scope"},
		},
		Adapters: []store.AdapterRun{
			{Name: "web", OK: true, Findings: 1},
			{Name: "tlsaudit", OK: true},
			{Name: "nuclei", Skipped: true, Reason: "external tools require a paid licence"},
		}}
	if err := st.CreateJob(cur); err != nil {
		t.Fatal(err)
	}
	if err := st.AddFindings(cur.ID, []*finding.Finding{f}); err != nil {
		t.Fatal(err)
	}
	h.jobID = cur.ID
	return h
}

func (h *aiHarness) post(t *testing.T, path, body string) (int, explainResponse) {
	t.Helper()
	resp, err := http.Post(h.api.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out explainResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (h *aiHarness) explain(t *testing.T, id string) (int, explainResponse) {
	t.Helper()
	return h.post(t, "/api/jobs/"+h.jobID+"/findings/explain", `{"finding_id":"`+id+`"}`)
}

func (h *aiHarness) whyGone(t *testing.T, id string) (int, explainResponse) {
	t.Helper()
	return h.post(t, "/api/jobs/"+h.jobID+"/delta/explain", `{"finding_id":"`+id+`"}`)
}

func TestAI_OffByDefault(t *testing.T) {
	ai, err := NewAIAssist(AIConfig{})
	if err != nil || ai != nil {
		t.Fatalf("empty URL must mean AI off, got %v, %v", ai, err)
	}
	h := newAIHarness(t, license.TierPro, nil, true)
	code, out := h.explain(t, h.finding.ID)
	if code != http.StatusOK || out.Available || out.Reason == "" {
		t.Fatalf("AI off: want 200 available=false with a reason, got %d %+v", code, out)
	}
	code, out = h.whyGone(t, h.gone["no_longer_detected"].ID)
	if code != http.StatusOK || out.Available || out.Reason == "" {
		t.Fatalf("AI off (delta): want 200 available=false with a reason, got %d %+v", code, out)
	}
	resp, err := http.Get(h.api.URL + "/api/ai")
	if err != nil {
		t.Fatal(err)
	}
	var st aiStatusResponse
	_ = json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if st.Enabled {
		t.Error("/api/ai must report enabled=false when AI Assist is off")
	}
}

func TestAI_RejectsBadURLAndEmptyKey(t *testing.T) {
	if _, err := NewAIAssist(AIConfig{URL: "127.0.0.1:8435"}); err == nil {
		t.Error("URL without scheme must be rejected")
	}
	empty := filepath.Join(t.TempDir(), "k")
	_ = os.WriteFile(empty, []byte("  \n"), 0o600)
	if _, err := NewAIAssist(AIConfig{URL: "http://127.0.0.1:8435", KeyFile: empty}); err == nil {
		t.Error("empty key file must be rejected")
	}
	if _, err := NewAIAssist(AIConfig{URL: "http://127.0.0.1:8435", KeyFile: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Error("missing key file must be rejected")
	}
}

func TestAI_ExplainHappyPathSanitisesEvidence(t *testing.T) {
	side := newFakeSidecar(t)
	ai, err := NewAIAssist(AIConfig{URL: side.srv.URL, Language: "id"})
	if err != nil {
		t.Fatal(err)
	}
	h := newAIHarness(t, license.TierFree, ai, false)
	code, out := h.explain(t, h.finding.ID)
	if code != http.StatusOK || !out.Available {
		t.Fatalf("want available explanation, got %d %+v", code, out)
	}
	if out.Disclaimer != "AI-generated summary — verify against raw findings" {
		t.Errorf("disclaimer not canonical: %q", out.Disclaimer)
	}
	if out.Status != "" {
		t.Errorf("a plain explanation carries no coverage status, got %q", out.Status)
	}
	body, _ := side.lastBody.Load().(string)
	if strings.Contains(body, aiTestSecret) || strings.Contains(body, "Set-Cookie") || strings.Contains(body, "app.env") {
		t.Error("secret-like evidence reached the sidecar")
	}
	for _, want := range []string{"hexward.explain_finding", "Server header reveals version", "nginx/1.14.0",
		"127.0.0.1:8080", `\"severity\":\"medium\"`, "Bahasa Indonesia", h.finding.ID} {
		if !strings.Contains(body, want) {
			t.Errorf("request to sidecar lacks %q", want)
		}
	}
	if strings.Contains(body, "Second paragraph") {
		t.Error("only the first paragraph of the description should be forwarded")
	}
}

func TestAI_KeyedEndpointNeedsPaidTier(t *testing.T) {
	side := newFakeSidecar(t)
	kf := filepath.Join(t.TempDir(), "ai_api_key")
	_ = os.WriteFile(kf, []byte("0123456789abcdef0123456789abcdef\n"), 0o600)
	ai, err := NewAIAssist(AIConfig{URL: side.srv.URL, KeyFile: kf})
	if err != nil {
		t.Fatal(err)
	}

	free := newAIHarness(t, license.TierFree, ai, false)
	code, out := free.explain(t, free.finding.ID)
	if code != http.StatusOK || out.Available || !strings.Contains(out.Reason, "Pro or Team") {
		t.Fatalf("free tier + keyed endpoint must be refused with a reason, got %d %+v", code, out)
	}
	if side.calls.Load() != 0 {
		t.Fatal("free tier must not send anything to a keyed endpoint")
	}
	resp, _ := http.Get(free.api.URL + "/api/ai")
	var st aiStatusResponse
	_ = json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if st.Enabled || !st.Keyed {
		t.Errorf("/api/ai on free + keyed: want enabled=false keyed=true, got %+v", st)
	}

	for _, tier := range []license.Tier{license.TierPro, license.TierTeam} {
		paid := newAIHarness(t, tier, ai, true)
		if _, out := paid.explain(t, paid.finding.ID); !out.Available {
			t.Fatalf("%s tier + keyed endpoint must work, got %+v", tier, out)
		}
		if _, out := paid.whyGone(t, paid.gone["no_longer_detected"].ID); !out.Available {
			t.Fatalf("%s tier + keyed endpoint (delta) must work, got %+v", tier, out)
		}
		if auth, _ := side.lastAuth.Load().(string); auth != "Bearer 0123456789abcdef0123456789abcdef" {
			t.Errorf("Authorization header = %q", auth)
		}
	}
}

func TestAI_SidecarDownDegradesQuietly(t *testing.T) {
	side := newFakeSidecar(t)
	side.status = http.StatusServiceUnavailable
	ai, _ := NewAIAssist(AIConfig{URL: side.srv.URL})
	h := newAIHarness(t, license.TierPro, ai, true)

	code, out := h.explain(t, h.finding.ID)
	if code != http.StatusOK || out.Available || out.Reason == "" {
		t.Fatalf("sidecar 503 must give 200 available=false, got %d %+v", code, out)
	}
	code, out = h.whyGone(t, h.gone["check_failed"].ID)
	if code != http.StatusOK || out.Available || out.Status != "check_failed" {
		t.Fatalf("sidecar 503 (delta) must give 200 available=false with the engine's status, got %d %+v", code, out)
	}

	fs, err := h.store.GetFindings(h.jobID)
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings after failure: %v %d", err, len(fs))
	}
	if fs[0].ID != h.finding.ID || fs[0].Severity != finding.SeverityMedium || fs[0].Status != finding.StatusOpen || len(fs[0].Evidence) != 4 {
		t.Fatalf("finding must be untouched after an AI failure, got %+v", fs[0])
	}
}

func TestAI_BadRequests(t *testing.T) {
	side := newFakeSidecar(t)
	ai, _ := NewAIAssist(AIConfig{URL: side.srv.URL})
	h := newAIHarness(t, license.TierPro, ai, true)

	if code, _ := h.explain(t, ""); code != http.StatusBadRequest {
		t.Errorf("missing finding_id: got %d, want 400", code)
	}
	if code, _ := h.post(t, "/api/jobs/"+h.jobID+"/findings/explain", `not json`); code != http.StatusBadRequest {
		t.Errorf("malformed body: got %d, want 400", code)
	}
	if code, _ := h.explain(t, "nope"); code != http.StatusNotFound {
		t.Errorf("unknown finding: got %d, want 404", code)
	}
	if code, _ := h.post(t, "/api/jobs/nope/findings/explain", `{"finding_id":"x"}`); code != http.StatusNotFound {
		t.Errorf("unknown job: got %d, want 404", code)
	}
	if code, _ := h.whyGone(t, "nope"); code != http.StatusNotFound {
		t.Errorf("unknown finding (delta): got %d, want 404", code)
	}
	// A finding that is still present has not disappeared, so there is
	// nothing for this feature to explain.
	if code, _ := h.whyGone(t, h.finding.ID); code != http.StatusBadRequest {
		t.Errorf("persisting finding on delta/explain: got %d, want 400", code)
	}
	if side.calls.Load() != 0 {
		t.Error("invalid requests must never reach the sidecar")
	}
}

// The pilot feature: the status sent to the model is AuditLight's own
// reading of its process record, never the model's guess, and "fixed" is
// never claimed because AuditLight never verifies a fix.
func TestAI_WhyDisappearedUsesEngineClassification(t *testing.T) {
	side := newFakeSidecar(t)
	ai, _ := NewAIAssist(AIConfig{URL: side.srv.URL})
	h := newAIHarness(t, license.TierPro, ai, true)

	cases := map[string]string{
		"target_skipped":     "outside the declared scope",
		"check_failed":       "external tools require a paid licence",
		"no_longer_detected": "does not verify fixes",
	}
	for status, wantDetail := range cases {
		f := h.gone[status]
		code, out := h.whyGone(t, f.ID)
		if code != http.StatusOK || !out.Available {
			t.Fatalf("%s: want available explanation, got %d %+v", status, code, out)
		}
		if out.Status != status || !strings.Contains(out.Detail, wantDetail) {
			t.Errorf("%s: response status/detail = %q / %q", status, out.Status, out.Detail)
		}
		if out.Disclaimer != "AI-generated summary — verify against raw findings" {
			t.Errorf("%s: disclaimer not canonical: %q", status, out.Disclaimer)
		}
		body, _ := side.lastBody.Load().(string)
		for _, want := range []string{"auditlight.why_disappeared", `\"status\":\"` + status + `\"`, f.ID, f.Title, h.prevID, h.jobID} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: request to sidecar lacks %q", status, want)
			}
		}
		if strings.Contains(body, `\"status\":\"fixed\"`) {
			t.Errorf("%s: AuditLight must never claim a fix", status)
		}
	}

	// Change tracking is a paid capability, so the free edition gets the same
	// answer here as it does from the change report itself.
	free := newAIHarness(t, license.TierFree, ai, true)
	calls := side.calls.Load()
	if code, _ := free.whyGone(t, free.gone["no_longer_detected"].ID); code != http.StatusPaymentRequired {
		t.Errorf("free tier delta/explain: got %d, want 402", code)
	}
	if side.calls.Load() != calls {
		t.Error("a refused request must not reach the sidecar")
	}
}

func TestAI_ClassifyDisappearanceMatchesHosts(t *testing.T) {
	job := &store.Job{
		Targets:  []store.TargetOutcome{{Target: "https://app.example.com/login", Processed: false, Reason: "ownership not verified"}},
		Adapters: []store.AdapterRun{{Name: "web", OK: true}},
	}
	f := finding.New("app.example.com", 443, finding.CategoryWeb, finding.SeverityLow, finding.ConfidenceConfirmed, "x", "t", "d", "web")
	if st, detail := classifyDisappearance(job, f); st != "target_skipped" || !strings.Contains(detail, "ownership not verified") {
		t.Errorf("URL target vs host finding: %s %q", st, detail)
	}
	other := finding.New("other.example.com", 443, finding.CategoryWeb, finding.SeverityLow, finding.ConfidenceConfirmed, "x", "t", "d", "web")
	if st, _ := classifyDisappearance(job, other); st != "no_longer_detected" {
		t.Errorf("unrelated host must not inherit the skip: %s", st)
	}
	absent := finding.New("other.example.com", 443, finding.CategoryVuln, finding.SeverityLow, finding.ConfidenceLikely, "x", "t", "d", "nuclei")
	if st, detail := classifyDisappearance(job, absent); st != "check_failed" || !strings.Contains(detail, "not run") {
		t.Errorf("adapter absent from the run: %s %q", st, detail)
	}
}
