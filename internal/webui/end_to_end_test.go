package webui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nizartuanku/auditlight/internal/license"
	"github.com/nizartuanku/auditlight/internal/orchestrator"
	"github.com/nizartuanku/auditlight/internal/report"
	"github.com/nizartuanku/auditlight/internal/store"
)

// harness spins the whole product up in memory against a target we control, so
// the end-to-end path is exercised without touching anyone else's network.
type harness struct {
	api    *httptest.Server
	target *httptest.Server
	store  store.Store
	port   int
}

func newHarness(t *testing.T, tier license.Tier) *harness {
	t.Helper()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.14.0")
		w.Header().Set("X-Powered-By", "PHP/7.2.1")
		w.Header().Set("Set-Cookie", "sid=xyz; Path=/")
		_, _ = w.Write([]byte("<html><head><title>Demo</title></head><body>ok</body></html>"))
	}))

	st := store.NewMem()
	lic := license.State{
		Tier: tier, Caps: license.CapsFor(tier),
		Notice: "test licence", Valid: tier != license.TierFree,
	}
	runner := orchestrator.New(st, lic)
	srv := New(runner, st, report.Branding{Firm: "Test Firm"})
	api := httptest.NewServer(srv.Handler())

	t.Cleanup(func() { api.Close(); target.Close() })

	h := &harness{api: api, target: target, store: st}
	i := strings.LastIndex(target.URL, ":")
	_, _ = fmt.Sscanf(target.URL[i+1:], "%d", &h.port)
	return h
}

func (h *harness) post(t *testing.T, path string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(h.api.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (h *harness) get(t *testing.T, path string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(h.api.URL + path)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

func (h *harness) waitForJob(t *testing.T, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		code, body := h.get(t, "/api/jobs/"+id)
		if code != http.StatusOK {
			t.Fatalf("job status %d", code)
		}
		var j map[string]any
		if err := json.Unmarshal(body, &j); err != nil {
			t.Fatalf("decode job: %v", err)
		}
		switch j["state"] {
		case "completed", "failed", "refused":
			return j
		}
		time.Sleep(120 * time.Millisecond)
	}
	t.Fatal("job did not finish in time")
	return nil
}

func TestFullAssessmentProducesReports(t *testing.T) {
	h := newHarness(t, license.TierPro)
	targetURL := h.target.URL

	code, body := h.post(t, "/api/jobs", map[string]any{
		"profile":   "web",
		"operator":  "Tester",
		"targets":   []string{targetURL},
		"confirm":   []string{targetURL},
		"confirmed": true,
	})
	if code != http.StatusAccepted {
		t.Fatalf("create job: %d %v", code, body)
	}
	id, _ := body["id"].(string)
	if id == "" {
		t.Fatalf("no job id in %v", body)
	}

	job := h.waitForJob(t, id)
	if job["state"] != "completed" {
		t.Fatalf("state = %v, error = %v", job["state"], job["error"])
	}

	// Findings
	code, raw := h.get(t, "/api/jobs/"+id+"/findings")
	if code != http.StatusOK {
		t.Fatalf("findings: %d", code)
	}
	var fr struct {
		Total    int `json:"total"`
		Shown    int `json:"shown"`
		Findings []struct {
			Title      string `json:"title"`
			Severity   string `json:"severity"`
			Confidence string `json:"confidence"`
			Compliance []struct {
				Framework string `json:"framework"`
			} `json:"compliance"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &fr); err != nil {
		t.Fatalf("decode findings: %v", err)
	}
	if fr.Total == 0 {
		t.Fatal("a deliberately weak target should produce findings")
	}
	if fr.Shown != fr.Total {
		t.Fatalf("pro tier must not cap findings: shown %d of %d", fr.Shown, fr.Total)
	}
	var compliant bool
	for _, f := range fr.Findings {
		if len(f.Compliance) > 0 {
			compliant = true
		}
	}
	if !compliant {
		t.Fatal("pro tier should annotate findings with control mappings")
	}

	// Reports render and are self-contained.
	for _, path := range []string{"/report/process", "/report/assessment"} {
		code, html := h.get(t, "/api/jobs/"+id+path)
		if code != http.StatusOK {
			t.Fatalf("%s: status %d", path, code)
		}
		s := string(html)
		if !strings.HasPrefix(s, "<!doctype html>") {
			t.Fatalf("%s did not render a document", path)
		}
		for _, external := range []string{"http://fonts.", "https://cdn", "<script src=", "<link rel=\"stylesheet\" href="} {
			if strings.Contains(s, external) {
				t.Fatalf("%s references an external asset (%q); reports must be self-contained", path, external)
			}
		}
		if !strings.Contains(s, "AuditLight") {
			t.Fatalf("%s lost its identity", path)
		}
	}

	// The assessment report must state its limits.
	_, html := h.get(t, "/api/jobs/"+id+"/report/assessment")
	s := string(html)
	for _, must := range []string{"Detection only", "Not a penetration test", "exploitability is not proven"} {
		if !strings.Contains(s, must) {
			t.Fatalf("assessment report must state %q", must)
		}
	}
	if strings.Contains(s, "PREVIEW") {
		t.Fatal("a paid licence must not receive a watermarked report")
	}

	// Export is available on Pro.
	code, _ = h.get(t, "/api/jobs/"+id+"/export.json")
	if code != http.StatusOK {
		t.Fatalf("export on pro: %d", code)
	}
}

func TestFreeTierIsCappedAndWatermarked(t *testing.T) {
	h := newHarness(t, license.TierFree)
	targetURL := h.target.URL

	// A paid profile must be refused with 402, not 500 or a silent downgrade.
	code, body := h.post(t, "/api/jobs", map[string]any{
		"profile": "full", "operator": "Tester",
		"targets": []string{targetURL}, "confirm": []string{targetURL}, "confirmed": true,
	})
	if code != http.StatusPaymentRequired {
		t.Fatalf("paid profile on free tier: %d %v", code, body)
	}
	if body["upgrade"] != true {
		t.Fatalf("refusal should mark the upgrade path: %v", body)
	}

	// Too many targets is also a 402.
	many := []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"}
	code, _ = h.post(t, "/api/jobs", map[string]any{
		"profile": "web", "operator": "Tester",
		"targets": many, "confirm": many, "confirmed": true,
	})
	if code != http.StatusPaymentRequired {
		t.Fatalf("target cap on free tier: %d", code)
	}

	// A permitted run still works, but the report is a preview.
	code, body = h.post(t, "/api/jobs", map[string]any{
		"profile": "web", "operator": "Tester",
		"targets": []string{targetURL}, "confirm": []string{targetURL}, "confirmed": true,
	})
	if code != http.StatusAccepted {
		t.Fatalf("free run: %d %v", code, body)
	}
	id := body["id"].(string)
	job := h.waitForJob(t, id)
	if job["state"] != "completed" {
		t.Fatalf("state = %v", job["state"])
	}

	_, html := h.get(t, "/api/jobs/"+id+"/report/assessment")
	if !strings.Contains(string(html), "PREVIEW") {
		t.Fatal("the free tier report must be watermarked")
	}

	code, _ = h.get(t, "/api/jobs/"+id+"/export.json")
	if code != http.StatusPaymentRequired {
		t.Fatalf("export on free tier: %d, want 402", code)
	}
}

// A refused authorisation must be a 403 with an explanation, and must leave a
// recorded, refused job rather than nothing at all.
func TestAuthorisationRefusalIsRecorded(t *testing.T) {
	h := newHarness(t, license.TierPro)

	code, body := h.post(t, "/api/jobs", map[string]any{
		"profile": "web", "operator": "Tester",
		"targets": []string{"example.com"}, "confirm": []string{"different.com"},
		"confirmed": true,
	})
	if code != http.StatusForbidden {
		t.Fatalf("mismatched confirmation: %d %v", code, body)
	}
	if !strings.Contains(fmt.Sprint(body["error"]), "does not match") {
		t.Fatalf("the refusal must explain itself: %v", body)
	}

	code, body = h.post(t, "/api/jobs", map[string]any{
		"profile": "web", "operator": "Tester",
		"targets": []string{"example.com"}, "confirm": []string{"example.com"},
		"confirmed": false,
	})
	if code != http.StatusForbidden {
		t.Fatalf("unaccepted statement: %d %v", code, body)
	}
}

func TestStatusAndProfilesReflectLicence(t *testing.T) {
	h := newHarness(t, license.TierFree)

	code, raw := h.get(t, "/api/status")
	if code != http.StatusOK {
		t.Fatalf("status: %d", code)
	}
	var st struct {
		Product      string `json:"product"`
		Affirmation  string `json:"affirmation"`
		Capabilities []struct {
			Name      string `json:"name"`
			Kind      string `json:"kind"`
			Available bool   `json:"available"`
			Reason    string `json:"reason"`
		} `json:"capabilities"`
		Counts map[string]int `json:"counts"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if st.Product != "AuditLight" {
		t.Fatalf("product = %q", st.Product)
	}
	if st.Affirmation == "" {
		t.Fatal("the UI needs the exact affirmation text")
	}
	if st.Counts["native"] < 8 {
		t.Fatalf("native checks = %d", st.Counts["native"])
	}
	for _, c := range st.Capabilities {
		if c.Kind == "native" && !c.Available {
			t.Fatalf("native check %q reported unavailable", c.Name)
		}
		if !c.Available && c.Reason == "" {
			t.Fatalf("check %q unavailable with no reason", c.Name)
		}
	}

	code, raw = h.get(t, "/api/profiles")
	if code != http.StatusOK {
		t.Fatalf("profiles: %d", code)
	}
	var profiles []struct {
		Name    string `json:"name"`
		Allowed bool   `json:"allowed"`
	}
	if err := json.Unmarshal(raw, &profiles); err != nil {
		t.Fatalf("decode profiles: %v", err)
	}
	byName := map[string]bool{}
	for _, p := range profiles {
		byName[p.Name] = p.Allowed
	}
	if !byName["perimeter"] || !byName["web"] {
		t.Fatal("free tier must allow the two open profiles")
	}
	if byName["full"] || byName["hardening"] {
		t.Fatal("free tier must not allow paid profiles")
	}
}

func TestDashboardIsSelfContained(t *testing.T) {
	h := newHarness(t, license.TierFree)
	code, html := h.get(t, "/")
	if code != http.StatusOK {
		t.Fatalf("index: %d", code)
	}
	s := string(html)
	for _, external := range []string{"src=\"http", "href=\"http", "cdn.", "fonts.googleapis"} {
		if strings.Contains(s, external) {
			t.Fatalf("the dashboard must not reference %q", external)
		}
	}
	if !strings.Contains(s, "AuditLight") {
		t.Fatal("dashboard did not render")
	}
}

func TestSecurityHeadersAreSet(t *testing.T) {
	h := newHarness(t, license.TierFree)
	resp, err := http.Get(h.api.URL + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Error("the dashboard should ship the policy it would want on someone else's server")
	}
}

func TestUnknownJobIs404(t *testing.T) {
	h := newHarness(t, license.TierPro)
	if code, _ := h.get(t, "/api/jobs/nope"); code != http.StatusNotFound {
		t.Fatalf("unknown job: %d", code)
	}
}
