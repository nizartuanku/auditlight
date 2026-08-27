package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nizartuanku/auditlight/internal/license"
)

func (h *harness) delete(t *testing.T, path string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, h.api.URL+path, nil)
	if err != nil {
		t.Fatalf("build delete: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete %s: %v", path, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// The headline feature: run the same assessment twice and get a comparison
// that is genuinely derived from two real runs.
func TestReassessmentProducesARealDelta(t *testing.T) {
	h := newHarness(t, license.TierPro)

	code, body := h.post(t, "/api/definitions", map[string]any{
		"name": "Acme quarterly", "profile": "web", "operator": "Tester",
		"targets": []string{h.target.URL}, "interval_days": 90, "confirmed": true,
	})
	if code != http.StatusCreated {
		t.Fatalf("create definition: %d %v", code, body)
	}
	defID, _ := body["id"].(string)
	if defID == "" {
		t.Fatalf("no definition id in %v", body)
	}
	if body["authorisation_valid"] != true {
		t.Fatalf("a freshly saved definition must be authorised: %v", body)
	}

	// First run: no baseline.
	code, body = h.post(t, "/api/definitions/"+defID+"/run", nil)
	if code != http.StatusAccepted {
		t.Fatalf("first run: %d %v", code, body)
	}
	first := body["id"].(string)
	if job := h.waitForJob(t, first); job["state"] != "completed" {
		t.Fatalf("first run state = %v", job["state"])
	}

	code, raw := h.get(t, "/api/jobs/"+first+"/delta")
	if code != http.StatusOK {
		t.Fatalf("first delta: %d", code)
	}
	var d1 struct {
		HasBaseline bool                                    `json:"has_baseline"`
		Counts      struct{ New, Resolved, Persisting int } `json:"counts"`
	}
	if err := json.Unmarshal(raw, &d1); err != nil {
		t.Fatalf("decode delta: %v", err)
	}
	if d1.HasBaseline {
		t.Fatal("the first run has nothing to compare against")
	}
	if d1.Counts.New != 0 {
		t.Fatalf("new = %d; a first run cannot have new findings", d1.Counts.New)
	}
	if d1.Counts.Persisting == 0 {
		t.Fatal("the first run should still record its findings")
	}

	// Second run against the same unchanged target.
	code, body = h.post(t, "/api/definitions/"+defID+"/run", nil)
	if code != http.StatusAccepted {
		t.Fatalf("second run: %d %v", code, body)
	}
	second := body["id"].(string)
	job := h.waitForJob(t, second)
	if job["state"] != "completed" {
		t.Fatalf("second run state = %v", job["state"])
	}
	if job["baseline_job_id"] != first {
		t.Fatalf("baseline = %v, want the first run %s", job["baseline_job_id"], first)
	}
	if job["definition_id"] != defID {
		t.Fatalf("definition link lost: %v", job["definition_id"])
	}

	code, raw = h.get(t, "/api/jobs/"+second+"/delta")
	if code != http.StatusOK {
		t.Fatalf("second delta: %d", code)
	}
	var d2 struct {
		HasBaseline   bool                                                         `json:"has_baseline"`
		BaselineJobID string                                                       `json:"baseline_job_id"`
		Counts        struct{ New, Resolved, Regressed, Improved, Persisting int } `json:"counts"`
	}
	if err := json.Unmarshal(raw, &d2); err != nil {
		t.Fatalf("decode delta: %v", err)
	}
	if !d2.HasBaseline || d2.BaselineJobID != first {
		t.Fatalf("second run should compare against the first: %+v", d2)
	}
	// The target did not change between runs, so nothing should have moved.
	// This is the real proof that finding identity is stable across runs.
	if d2.Counts.New != 0 || d2.Counts.Resolved != 0 || d2.Counts.Regressed != 0 {
		t.Fatalf("counts = %+v; an unchanged target must produce no movement", d2.Counts)
	}
	if d2.Counts.Persisting == 0 {
		t.Fatal("an unchanged target should show its findings as persisting")
	}

	// The change report renders and is self-contained.
	code, html := h.get(t, "/api/jobs/"+second+"/report/delta")
	if code != http.StatusOK {
		t.Fatalf("change report: %d", code)
	}
	s := string(html)
	if !strings.HasPrefix(s, "<!doctype html>") {
		t.Fatalf("change report did not render a document")
	}
	for _, must := range []string{"What changed since the last assessment", "Acme quarterly", "No change since the last assessment."} {
		if !strings.Contains(s, must) {
			t.Errorf("change report should contain %q", must)
		}
	}
	// It must not let a reader assume "gone" means "fixed".
	if !strings.Contains(s, "is not the same as") {
		t.Error("the change report must warn that a disappeared finding is not proof of a fix")
	}
	for _, external := range []string{"https://cdn", "<script src=", "http://fonts."} {
		if strings.Contains(s, external) {
			t.Fatalf("change report references an external asset (%q)", external)
		}
	}
}

func TestDefinitionListAndDelete(t *testing.T) {
	h := newHarness(t, license.TierPro)
	code, body := h.post(t, "/api/definitions", map[string]any{
		"name": "Temp", "profile": "web", "operator": "Tester",
		"targets": []string{h.target.URL}, "confirmed": true,
	})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, body)
	}
	id := body["id"].(string)

	code, raw := h.get(t, "/api/definitions")
	if code != http.StatusOK {
		t.Fatalf("list: %d", code)
	}
	var list []map[string]any
	_ = json.Unmarshal(raw, &list)
	if len(list) != 1 || list[0]["name"] != "Temp" {
		t.Fatalf("list = %v", list)
	}

	if c := h.delete(t, "/api/definitions/"+id); c != http.StatusNoContent {
		t.Fatalf("delete: %d", c)
	}
	if c := h.delete(t, "/api/definitions/"+id); c != http.StatusNotFound {
		t.Fatalf("delete twice: %d", c)
	}
}

// Saving without accepting the statement must be refused, exactly like a job.
func TestDefinitionRequiresAffirmation(t *testing.T) {
	h := newHarness(t, license.TierPro)
	code, body := h.post(t, "/api/definitions", map[string]any{
		"name": "No consent", "profile": "web", "operator": "Tester",
		"targets": []string{h.target.URL}, "confirmed": false,
	})
	if code != http.StatusForbidden {
		t.Fatalf("unaffirmed definition: %d %v", code, body)
	}
}

func TestDefinitionValidation(t *testing.T) {
	h := newHarness(t, license.TierPro)
	cases := []struct {
		name string
		body map[string]any
		want string
	}{
		{"no name", map[string]any{"profile": "web", "operator": "T", "targets": []string{"example.com"}, "confirmed": true}, "name"},
		{"no targets", map[string]any{"name": "x", "profile": "web", "operator": "T", "confirmed": true}, "targets"},
		{"no operator", map[string]any{"name": "x", "profile": "web", "targets": []string{"example.com"}, "confirmed": true}, "operator"},
		{"bad profile", map[string]any{"name": "x", "profile": "nope", "operator": "T", "targets": []string{"example.com"}, "confirmed": true}, "profile"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, body := h.post(t, "/api/definitions", c.body)
			if code != http.StatusForbidden && code != http.StatusPaymentRequired {
				t.Fatalf("code = %d, want a refusal: %v", code, body)
			}
			if !strings.Contains(strings.ToLower(fmt.Sprint(body["error"])), c.want) {
				t.Fatalf("error %v should mention %q", body["error"], c.want)
			}
		})
	}
}

// Free tier must not get saved assessments at all — and the refusal must point
// at the upgrade rather than looking like a bug.
func TestFreeTierCannotSaveAssessments(t *testing.T) {
	h := newHarness(t, license.TierFree)
	code, body := h.post(t, "/api/definitions", map[string]any{
		"name": "Nope", "profile": "web", "operator": "Tester",
		"targets": []string{h.target.URL}, "confirmed": true,
	})
	if code != http.StatusPaymentRequired {
		t.Fatalf("free definition: %d %v", code, body)
	}
	if body["upgrade"] != true {
		t.Fatalf("refusal should mark the upgrade path: %v", body)
	}

	// And the change report is behind the same gate.
	code, body = h.post(t, "/api/jobs", map[string]any{
		"profile": "web", "operator": "T",
		"targets": []string{h.target.URL}, "confirm": []string{h.target.URL}, "confirmed": true,
	})
	if code != http.StatusAccepted {
		t.Fatalf("free job: %d %v", code, body)
	}
	id := body["id"].(string)
	h.waitForJob(t, id)
	if c, _ := h.get(t, "/api/jobs/"+id+"/report/delta"); c != http.StatusPaymentRequired {
		t.Fatalf("free change report = %d, want 402", c)
	}
	if c, _ := h.get(t, "/api/jobs/"+id+"/delta"); c != http.StatusPaymentRequired {
		t.Fatalf("free delta json = %d, want 402", c)
	}
}

// A lapsed authorisation must stop a run and be recoverable by a human.
func TestLapsedAuthorisationBlocksRunUntilReaffirmed(t *testing.T) {
	h := newHarness(t, license.TierPro)
	code, body := h.post(t, "/api/definitions", map[string]any{
		"name": "Lapsing", "profile": "web", "operator": "Tester",
		"targets": []string{h.target.URL}, "authorised_for_days": 1, "confirmed": true,
	})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, body)
	}
	id := body["id"].(string)

	// Age the authorisation past its window directly in the store.
	d, err := h.store.GetDefinition(id)
	if err != nil {
		t.Fatalf("get definition: %v", err)
	}
	d.AuthorisedAt = d.AuthorisedAt.AddDate(0, 0, -5)
	if err := h.store.UpdateDefinition(d); err != nil {
		t.Fatalf("update: %v", err)
	}

	code, body = h.post(t, "/api/definitions/"+id+"/run", nil)
	if code != http.StatusForbidden {
		t.Fatalf("lapsed run: %d %v", code, body)
	}
	if !strings.Contains(fmt.Sprint(body["error"]), "lapsed") {
		t.Fatalf("refusal should say the authorisation lapsed: %v", body["error"])
	}

	// Re-affirming must need a name and an explicit acceptance.
	code, _ = h.post(t, "/api/definitions/"+id+"/reauthorise", map[string]any{"confirmed": true})
	if code != http.StatusForbidden {
		t.Fatalf("re-authorise without a name: %d", code)
	}
	code, body = h.post(t, "/api/definitions/"+id+"/reauthorise",
		map[string]any{"operator": "Tester", "confirmed": true})
	if code != http.StatusOK {
		t.Fatalf("re-authorise: %d %v", code, body)
	}
	if body["authorisation_valid"] != true {
		t.Fatalf("re-authorisation should restore validity: %v", body)
	}

	code, body = h.post(t, "/api/definitions/"+id+"/run", nil)
	if code != http.StatusAccepted {
		t.Fatalf("run after re-authorisation: %d %v", code, body)
	}
}

func TestUnknownDefinitionIs404(t *testing.T) {
	h := newHarness(t, license.TierPro)
	if c, _ := h.get(t, "/api/definitions/nope"); c != http.StatusNotFound {
		t.Fatalf("unknown definition: %d", c)
	}
	if c, _ := h.post(t, "/api/definitions/nope/run", nil); c != http.StatusNotFound {
		t.Fatalf("run unknown definition: %d", c)
	}
}
