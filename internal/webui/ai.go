package webui

// AI Assist — the optional "Explain this finding" and "Why did this finding
// disappear?" buttons, backed by the hexward-ai sidecar
// (github.com/nizartuanku/hexward-ai).
//
// The rules this file exists to enforce:
//
//   - AuditLight's own engine stays the ONLY source of findings, severity and
//     change classification. Nothing here creates, edits, re-scores or closes
//     a finding, and nothing here decides why a finding disappeared: that
//     classification is read from the job's own process record (which
//     adapters ran, which targets were skipped) and the delta engine, then
//     handed to the model to put into words.
//   - AI Assist is off unless the operator starts the binary with
//     -ai-assist-url. Off, unreachable, slow, or answering garbage all look
//     the same to the dashboard: {"available": false} with HTTP 200, and the
//     findings are untouched.
//   - Only a bounded, sanitised copy of one finding leaves the process
//     (aiclient.NewFindingPacket drops secret-like evidence keys and caps
//     strings, lists and nesting). Matched-secret evidence and full response
//     header dumps are never forwarded at all.
//   - Edition gating: the free edition talks to a sidecar without an API
//     key (same host or same Docker network). An endpoint that needs a key
//     (a dedicated AI host serving several products, or your own
//     OpenAI-compatible endpoint) is a Pro/Team capability. The tier is read
//     from the runner on every request.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/nizartuanku/auditlight/internal/aiclient"
	"github.com/nizartuanku/auditlight/internal/delta"
	"github.com/nizartuanku/auditlight/internal/finding"
	"github.com/nizartuanku/auditlight/internal/license"
	"github.com/nizartuanku/auditlight/internal/store"
)

// AIConfig is what cmd/ passes in from its flags.
type AIConfig struct {
	URL        string // sidecar or endpoint base URL; "" = AI Assist off
	KeyFile    string // file holding an API key; set = keyed endpoint (Pro/Team)
	Language   string // "en" (default) or "id"
	NoThinking bool   // Qwen3 enterprise profiles: skip reasoning mode
}

// AIAssist is the resolved, ready-to-use AI configuration of a Server.
type AIAssist struct {
	Client   *aiclient.Client
	Endpoint string
	Keyed    bool
	Language string
}

// NewAIAssist validates cfg and builds the client. It returns (nil, nil)
// when cfg.URL is empty — AI Assist off is the default, not an error. It
// never dials: an absent sidecar is discovered per request and degrades
// quietly.
func NewAIAssist(cfg AIConfig) (*AIAssist, error) {
	raw := strings.TrimSpace(cfg.URL)
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("ai-assist-url must be an http(s) base URL such as http://127.0.0.1:8435, got %q", raw)
	}
	opts := []aiclient.Option{
		// CPU inference of a 3-8B model takes tens of seconds; measured
		// 13-53 s per explanation on a CPU-only VM (hexward-ai docs/TIERS.md).
		aiclient.WithTimeout(120 * time.Second),
		// No retries: a timed-out narration retried is another two minutes
		// of a person waiting, not a better answer.
		aiclient.WithMaxRetries(0),
		aiclient.WithMaxTokens(300),
	}
	a := &AIAssist{Endpoint: strings.TrimRight(raw, "/"), Language: aiclient.NormalizeLanguage(cfg.Language)}
	if cfg.KeyFile != "" {
		b, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("read ai-assist-key-file: %w", err)
		}
		key := strings.TrimSpace(string(b))
		if key == "" {
			return nil, fmt.Errorf("ai-assist-key-file %s is empty", cfg.KeyFile)
		}
		opts = append(opts, aiclient.WithAPIKey(key))
		a.Keyed = true
	}
	if cfg.NoThinking {
		opts = append(opts, aiclient.WithDisableThinking())
	}
	a.Client = aiclient.New(a.Endpoint, opts...)
	return a, nil
}

// WithAI attaches an AI Assist configuration. nil leaves AI Assist off.
func (s *Server) WithAI(a *AIAssist) *Server {
	s.ai = a
	return s
}

func (s *Server) registerAI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/ai", s.handleAIStatus)
	mux.HandleFunc("POST /api/jobs/{id}/findings/explain", s.handleExplainFinding)
	mux.HandleFunc("POST /api/jobs/{id}/delta/explain", s.handleExplainDisappearance)
}

// aiAllowed reports whether AI Assist may be used right now, and if not,
// the sentence the dashboard shows instead of the button.
func (s *Server) aiAllowed() (bool, string) {
	if s.ai == nil || s.ai.Client == nil {
		return false, "AI Assist is off. Start with -ai-assist-url to enable it."
	}
	if t := s.runner.Licence().Tier; s.ai.Keyed && t != license.TierPro && t != license.TierTeam {
		return false, "A dedicated AI host or your own endpoint (API key) needs a Pro or Team licence. The free edition works with a hexward-ai sidecar on the same host."
	}
	return true, ""
}

type aiStatusResponse struct {
	Enabled  bool   `json:"enabled"`
	Reason   string `json:"reason,omitempty"`
	Language string `json:"language,omitempty"`
	Keyed    bool   `json:"keyed,omitempty"`
}

func (s *Server) handleAIStatus(w http.ResponseWriter, _ *http.Request) {
	ok, reason := s.aiAllowed()
	resp := aiStatusResponse{Enabled: ok, Reason: reason}
	if s.ai != nil {
		resp.Language, resp.Keyed = s.ai.Language, s.ai.Keyed
	}
	writeJSON(w, http.StatusOK, resp)
}

type explainResponse struct {
	Available    bool     `json:"available"`
	Reason       string   `json:"reason,omitempty"`
	Explanation  string   `json:"explanation,omitempty"`
	WhatToVerify []string `json:"what_to_verify,omitempty"`
	Disclaimer   string   `json:"disclaimer,omitempty"`
	// Status is only set by the disappearance endpoint: it is AuditLight's
	// own classification of why the finding is gone, shown next to the
	// narrative so the reader sees the engine's word before the model's.
	Status string `json:"status,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// explainRequest is the body of both explain endpoints.
type explainRequest struct {
	FindingID string `json:"finding_id"`
}

func readExplainRequest(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req explainRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || strings.TrimSpace(req.FindingID) == "" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "finding_id is required."})
		return "", false
	}
	return strings.TrimSpace(req.FindingID), true
}

// shownFindings returns the findings this licence exposes for a job — the
// same cap the findings list applies, so a finding the dashboard cannot show
// cannot be explained either.
func (s *Server) shownFindings(jobID string) ([]*finding.Finding, error) {
	fs, err := s.store.GetFindings(jobID)
	if err != nil {
		return nil, err
	}
	caps := s.runner.Licence().Caps
	if !license.Unlimited(caps.MaxFindingsShown) && len(fs) > caps.MaxFindingsShown {
		fs = fs[:caps.MaxFindingsShown]
	}
	return fs, nil
}

// handleExplainFinding narrates one stored finding of a job. Every failure
// after the request itself is validated answers {"available": false} with
// HTTP 200 — the dashboard shows a quiet note and the finding is never
// affected.
func (s *Server) handleExplainFinding(w http.ResponseWriter, r *http.Request) {
	job, ok := s.job(w, r)
	if !ok {
		return
	}
	id, ok := readExplainRequest(w, r)
	if !ok {
		return
	}
	fs, err := s.shownFindings(job.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	var f *finding.Finding
	for _, c := range fs {
		if c.ID == id {
			f = c
			break
		}
	}
	if f == nil {
		writeJSON(w, http.StatusNotFound, apiError{Error: "No such finding in this job."})
		return
	}
	if ok, reason := s.aiAllowed(); !ok {
		writeJSON(w, http.StatusOK, explainResponse{Available: false, Reason: reason})
		return
	}
	packet, err := aiclient.NewFindingPacket(license.Product, s.ai.Language, coreFinding(f))
	if err != nil {
		writeJSON(w, http.StatusOK, explainResponse{Available: false, Reason: "This finding has no title or severity to explain."})
		return
	}
	exp, err := s.ai.Client.Explain(r.Context(), packet)
	if err != nil {
		writeJSON(w, http.StatusOK, explainResponse{Available: false, Reason: "The AI Assist sidecar did not answer. The finding is unaffected."})
		return
	}
	writeJSON(w, http.StatusOK, explainResponse{
		Available:    true,
		Explanation:  exp.ExplanationText,
		WhatToVerify: exp.WhatToVerify,
		Disclaimer:   exp.Disclaimer,
	})
}

// coreFinding maps an AuditLight finding onto the generic explain packet.
//
// Evidence is the engine's own record, minus two kinds that must never leave
// the process even redacted: "match" (a credential the secrets check found)
// and "headers" (a full HTTP response header dump, which can carry cookies).
// NewFindingPacket then drops secret-like keys and caps sizes on top.
func coreFinding(f *finding.Finding) aiclient.CoreFinding {
	ev := map[string]any{
		"category":     string(f.Category),
		"confidence":   string(f.Confidence),
		"source_tools": f.SourceTools,
	}
	if d := firstParagraph(f.Description); d != "" {
		ev["description"] = d
	}
	if f.Port > 0 {
		ev["port"] = f.Port
	}
	if f.CVSS > 0 {
		ev["cvss"] = f.CVSS
	}
	if len(f.CVE) > 0 {
		ev["cve"] = f.CVE
	}
	if len(f.CWE) > 0 {
		ev["cwe"] = f.CWE
	}
	for _, e := range f.Evidence {
		if e.Kind == "match" || e.Kind == "headers" {
			continue
		}
		key := e.Kind
		if e.Label != "" {
			key = e.Kind + " " + e.Label
		}
		if _, dup := ev[key]; dup {
			continue
		}
		ev[key] = e.Value
	}
	target := f.Target
	if f.Port > 0 {
		target = fmt.Sprintf("%s:%d", f.Target, f.Port)
	}
	return aiclient.CoreFinding{
		Fingerprint: f.ID,
		Module:      license.Product,
		Check:       strings.Join(f.SourceTools, "+"),
		Title:       f.Title,
		Target:      target,
		Severity:    string(f.Severity),
		Status:      string(f.Status),
		Remediation: f.Remediation,
		Evidence:    ev,
	}
}

func firstParagraph(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "\n\n"); i >= 0 {
		s = s[:i]
	}
	return s
}

// handleExplainDisappearance narrates why a finding present in the previous
// run of a saved assessment is absent from this one. The classification is
// AuditLight's own (see classifyDisappearance); the model only puts it into
// plain language. It respects the same tier gate as the change report.
func (s *Server) handleExplainDisappearance(w http.ResponseWriter, r *http.Request) {
	job, ok := s.job(w, r)
	if !ok {
		return
	}
	if !s.runner.Licence().Caps.Reassessment {
		writeJSON(w, http.StatusPaymentRequired, apiError{
			Error:   "Change tracking is available on the Pro and Team tiers — https://whop.com/nizar-tuanku/auditlight?utm_source=app",
			Upgrade: true,
		})
		return
	}
	id, ok := readExplainRequest(w, r)
	if !ok {
		return
	}
	res, _, err := s.runner.DeltaFor(job)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	var entry *delta.Entry
	for i := range res.Entries {
		if res.Entries[i].Finding != nil && res.Entries[i].Finding.ID == id {
			entry = &res.Entries[i]
			break
		}
	}
	if entry == nil {
		writeJSON(w, http.StatusNotFound, apiError{Error: "No such finding in this comparison."})
		return
	}
	if entry.Change != delta.ChangeResolved {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "This finding is still present in the current run; only a finding that disappeared can be explained here."})
		return
	}
	status, detail := classifyDisappearance(job, entry.Finding)
	if ok, reason := s.aiAllowed(); !ok {
		writeJSON(w, http.StatusOK, explainResponse{Available: false, Reason: reason, Status: string(status), Detail: detail})
		return
	}
	packet, err := disappearancePacket(s.ai.Language, res.BaselineJobID, job.ID, entry.Finding, status, detail)
	if err != nil {
		writeJSON(w, http.StatusOK, explainResponse{Available: false, Reason: "This finding could not be described.", Status: string(status), Detail: detail})
		return
	}
	exp, err := s.ai.Client.Explain(r.Context(), packet)
	if err != nil {
		writeJSON(w, http.StatusOK, explainResponse{Available: false, Reason: "The AI Assist sidecar did not answer. The comparison is unaffected.", Status: string(status), Detail: detail})
		return
	}
	writeJSON(w, http.StatusOK, explainResponse{
		Available:    true,
		Explanation:  exp.ExplanationText,
		WhatToVerify: exp.WhatToVerify,
		Disclaimer:   exp.Disclaimer,
		Status:       string(status),
		Detail:       detail,
	})
}

// disappearancePacket builds the pilot-feature packet. The description is
// bounded the same way NewFindingPacket bounds free text.
func disappearancePacket(lang, baselineID, currentID string, f *finding.Finding, status aiclient.CoverageStatus, detail string) (aiclient.EvidencePacket, error) {
	desc := f.Title
	if d := firstParagraph(f.Description); d != "" {
		desc += " — " + d
	}
	raw, err := json.Marshal(aiclient.AuditLightDisappearance{
		FindingID:   f.ID,
		Description: truncateRunes(desc, 400),
		LastSeenRun: baselineID,
		CurrentRun:  currentID,
		Status:      status,
		Detail:      truncateRunes(detail, 400),
	})
	if err != nil {
		return aiclient.EvidencePacket{}, err
	}
	return aiclient.EvidencePacket{
		Feature:  aiclient.FeatureAuditLightWhyDisappeared,
		Product:  license.Product,
		Finding:  raw,
		Language: aiclient.NormalizeLanguage(lang),
	}, nil
}

// classifyDisappearance maps a delta "resolved" entry onto the closed set
// of coverage statuses, using only what AuditLight itself recorded about
// the current run. The delta package is explicit that "resolved" means
// gone from the results, not fixed, and that the Process Report says
// whether the check even ran; this is that reading, made mechanical:
//
//   - target_skipped: the finding's target was not processed in this run
//     (out of scope, unverified, or refused), with the recorded reason;
//   - check_failed: none of the checks that produced the finding completed
//     successfully in this run (tool absent, skipped, or errored);
//   - no_longer_detected: the checks ran and did not report the condition.
//
// AuditLight never verifies a fix, so it never returns CoverageFixed. A
// reader who wants "fixed" has to establish it themselves — which is the
// point of the "What to verify" list.
func classifyDisappearance(job *store.Job, f *finding.Finding) (aiclient.CoverageStatus, string) {
	for _, t := range job.Targets {
		if t.Processed || !sameHost(t.Target, f.Target) {
			continue
		}
		reason := t.Reason
		if reason == "" {
			reason = "no reason recorded"
		}
		return aiclient.CoverageTargetSkipped, fmt.Sprintf("Target %s was not assessed in this run: %s.", t.Target, reason)
	}

	var failed []string
	completed := false
	for _, tool := range f.SourceTools {
		ranOK, why := adapterOutcome(job.Adapters, tool)
		if ranOK {
			completed = true
			continue
		}
		failed = append(failed, tool+" ("+why+")")
	}
	if !completed {
		if len(failed) == 0 {
			failed = []string{"the check did not run in this assessment"}
		}
		return aiclient.CoverageCheckFailed, "The check that produced this finding did not complete in this run: " + strings.Join(failed, "; ") + "."
	}
	detail := "The check that produced this finding ran and completed in this run and did not report the condition. AuditLight does not verify fixes, so this is not confirmation that the condition is gone."
	if len(failed) > 0 {
		detail += " Note that another check that had also seen it did not complete: " + strings.Join(failed, "; ") + "."
	}
	return aiclient.CoverageNoLongerDetected, detail
}

// adapterOutcome reports whether the named adapter completed at least one
// run in the job, and if not, the recorded reason.
func adapterOutcome(runs []store.AdapterRun, name string) (bool, string) {
	why := "not run"
	seen := false
	for _, a := range runs {
		if a.Name != name {
			continue
		}
		seen = true
		if !a.Skipped && a.OK {
			return true, ""
		}
		if a.Reason != "" {
			why = a.Reason
		} else if a.Skipped {
			why = "skipped"
		} else {
			why = "failed"
		}
	}
	if !seen {
		return false, "not run"
	}
	return false, why
}

// sameHost matches a declared target against a finding's target: exact
// (case-insensitive), or the same host once a scheme, path or port is
// stripped from either side.
func sameHost(declared, found string) bool {
	if strings.EqualFold(strings.TrimSpace(declared), strings.TrimSpace(found)) {
		return true
	}
	a, b := hostOf(declared), hostOf(found)
	return a != "" && strings.EqualFold(a, b)
}

func hostOf(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
