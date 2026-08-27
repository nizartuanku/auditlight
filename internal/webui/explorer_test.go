package webui

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nizartuanku/auditlight/internal/license"
)

// runOne drives a real assessment against the harness target and returns its id.
func runOne(t *testing.T, h *harness) string {
	t.Helper()
	u := h.target.URL
	code, body := h.post(t, "/api/jobs", map[string]any{
		"profile":   "web",
		"operator":  "Tester",
		"targets":   []string{u},
		"confirm":   []string{u},
		"confirmed": true,
	})
	if code != http.StatusAccepted {
		t.Fatalf("create job: %d %v", code, body)
	}
	id, _ := body["id"].(string)
	if job := h.waitForJob(t, id); job["state"] != "completed" {
		t.Fatalf("state = %v", job["state"])
	}
	return id
}

func surfaceOf(t *testing.T, h *harness, id string) map[string]any {
	t.Helper()
	code, raw := h.get(t, "/api/jobs/"+id+"/surface.json")
	if code != http.StatusOK {
		t.Fatalf("surface: %d — %s", code, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode surface: %v", err)
	}
	return out
}

// The explorer is part of the free edition on purpose: it is the demo, and the
// paid value in this product is the documents, not the ability to look at your
// own surface. If that ever changes it should change deliberately, so it is
// pinned by a test.
func TestSurfaceIsAvailableOnEveryTier(t *testing.T) {
	for _, tier := range []license.Tier{license.TierFree, license.TierPro, license.TierTeam} {
		t.Run(string(tier), func(t *testing.T) {
			h := newHarness(t, tier)
			id := runOne(t, h)
			out := surfaceOf(t, h, id)
			g, _ := out["graph"].(map[string]any)
			if g == nil {
				t.Fatalf("no graph in response: %v", out)
			}
			roots, _ := g["roots"].([]any)
			if len(roots) == 0 {
				t.Fatalf("graph has no roots: %v", g)
			}
		})
	}
}

// The picture and the findings list are two views of one thing. If a licence
// caps the list, it must cap the picture too, and say so.
func TestFreeSurfaceMatchesTheCappedFindingsList(t *testing.T) {
	h := newHarness(t, license.TierFree)
	id := runOne(t, h)

	code, raw := h.get(t, "/api/jobs/"+id+"/findings")
	if code != http.StatusOK {
		t.Fatalf("findings: %d", code)
	}
	var list struct {
		Total    int `json:"total"`
		Shown    int `json:"shown"`
		Findings []struct {
			ID string `json:"id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}

	out := surfaceOf(t, h, id)
	ids := map[string]bool{}
	for _, f := range list.Findings {
		ids[f.ID] = true
	}
	var walk func(n map[string]any)
	seen := 0
	walk = func(n map[string]any) {
		for _, raw := range toSlice(n["finding_ids"]) {
			s, _ := raw.(string)
			if !ids[s] {
				t.Errorf("the surface shows finding %q that the findings list withholds", s)
			}
			seen++
		}
		for _, c := range toSlice(n["children"]) {
			if m, okc := c.(map[string]any); okc {
				walk(m)
			}
		}
	}
	g, _ := out["graph"].(map[string]any)
	for _, r := range toSlice(g["roots"]) {
		if m, okr := r.(map[string]any); okr {
			walk(m)
		}
	}
	if seen == 0 {
		t.Fatal("the surface carried no findings at all")
	}
	if list.Total > list.Shown {
		if n, _ := out["notice"].(string); !strings.Contains(n, "partial") {
			t.Errorf("a capped surface did not say it was partial: %q", n)
		}
	}
}

// The renderer must reach the page, and it must not have dragged a library in
// with it.
func TestDashboardCarriesTheExplorerAndNoLibrary(t *testing.T) {
	h := newHarness(t, license.TierFree)
	code, html := h.get(t, "/")
	if code != http.StatusOK {
		t.Fatalf("index: %d", code)
	}
	s := string(html)
	for _, want := range []string{`id="sxc"`, "Surface explorer", "SX.load", "getContext"} {
		if !strings.Contains(s, want) {
			t.Errorf("dashboard is missing %q", want)
		}
	}
	for _, bad := range []string{"three.min.js", "THREE.", "webgl", "experimental-webgl", "import("} {
		if strings.Contains(strings.ToLower(s), strings.ToLower(bad)) {
			t.Errorf("the explorer pulled in %q — it is meant to be canvas 2D and nothing else", bad)
		}
	}
	if !strings.Contains(s, "does not probe how hosts connect") {
		t.Error("the explorer draws a graph without stating what it does not claim")
	}
}

func toSlice(v any) []any {
	s, _ := v.([]any)
	return s
}
