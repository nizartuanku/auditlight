package webui

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/nizartuanku/auditlight/internal/delta"
	"github.com/nizartuanku/auditlight/internal/orchestrator"
	"github.com/nizartuanku/auditlight/internal/report"
	"github.com/nizartuanku/auditlight/internal/store"
)

type definitionRequest struct {
	Name          string   `json:"name"`
	Workspace     string   `json:"workspace"`
	Profile       string   `json:"profile"`
	Operator      string   `json:"operator"`
	Targets       []string `json:"targets"`
	Scope         []string `json:"scope"`
	ScanPath      string   `json:"scan_path"`
	IntervalDays  int      `json:"interval_days"`
	AuthorisedFor int      `json:"authorised_for_days"`
	WebhookURL    string   `json:"webhook_url"`
	NotifyEmail   string   `json:"notify_email"`
	NotifyOn      string   `json:"notify_on"`
	Confirmed     bool     `json:"confirmed"`
}

// definitionView adds derived fields the UI needs but the store should not own.
type definitionView struct {
	*store.Definition
	AuthorisationExpires time.Time `json:"authorisation_expires"`
	AuthorisationValid   bool      `json:"authorisation_valid"`
	DaysLeft             int       `json:"authorisation_days_left"`
}

func viewOf(d *store.Definition, now time.Time) definitionView {
	exp := d.AuthorisationExpires()
	return definitionView{
		Definition:           d,
		AuthorisationExpires: exp,
		AuthorisationValid:   d.AuthorisationValid(now),
		DaysLeft:             int(exp.Sub(now).Hours() / 24),
	}
}

func (s *Server) handleCreateDefinition(w http.ResponseWriter, r *http.Request) {
	var req definitionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "The request body could not be read as JSON."})
		return
	}
	if !req.Confirmed {
		writeJSON(w, http.StatusForbidden, apiError{
			Error: "The authorisation statement was not accepted.",
		})
		return
	}
	d := &store.Definition{
		Name: req.Name, Workspace: req.Workspace, Profile: req.Profile,
		Operator: req.Operator, Targets: req.Targets, Scope: req.Scope,
		ScanPath: req.ScanPath, IntervalDays: req.IntervalDays,
		AuthorisedFor: req.AuthorisedFor, WebhookURL: req.WebhookURL,
		NotifyEmail: req.NotifyEmail, NotifyOn: req.NotifyOn,
	}
	now := time.Now()
	if err := s.runner.SaveDefinition(d, now); err != nil {
		s.writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, viewOf(d, now))
}

func (s *Server) handleListDefinitions(w http.ResponseWriter, r *http.Request) {
	defs, err := s.store.ListDefinitions(r.URL.Query().Get("workspace"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	now := time.Now()
	out := make([]definitionView, 0, len(defs))
	for _, d := range defs {
		out = append(out, viewOf(d, now))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetDefinition(w http.ResponseWriter, r *http.Request) {
	d, err := s.store.GetDefinition(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, apiError{Error: "No such assessment."})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, viewOf(d, time.Now()))
}

func (s *Server) handleDeleteDefinition(w http.ResponseWriter, r *http.Request) {
	err := s.store.DeleteDefinition(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, apiError{Error: "No such assessment."})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRunDefinition(w http.ResponseWriter, r *http.Request) {
	job, err := s.runner.RunDefinition(r.Context(), r.PathValue("id"), orchestrator.TriggerManual, time.Now())
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, apiError{Error: "No such assessment."})
		return
	}
	if err != nil {
		s.writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

// handleReauthorise restarts the authorisation clock. It is a deliberate,
// separate act: renewing permission should never be a side effect of editing
// something else.
func (s *Server) handleReauthorise(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Operator      string `json:"operator"`
		Confirmed     bool   `json:"confirmed"`
		AuthorisedFor int    `json:"authorised_for_days"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "The request body could not be read as JSON."})
		return
	}
	if !req.Confirmed || req.Operator == "" {
		writeJSON(w, http.StatusForbidden, apiError{
			Error: "Re-authorisation needs an operator name and an accepted statement.",
		})
		return
	}
	d, err := s.store.GetDefinition(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, apiError{Error: "No such assessment."})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	now := time.Now()
	d.Operator = req.Operator
	d.AuthorisedAt = now.UTC()
	if req.AuthorisedFor > 0 {
		d.AuthorisedFor = req.AuthorisedFor
	}
	d.LastSkipReason = ""
	if d.IntervalDays > 0 && (d.NextRunAt.IsZero() || d.NextRunAt.Before(now)) {
		d.NextRunAt = now.UTC()
	}
	if err := s.store.UpdateDefinition(d); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, viewOf(d, now))
}

func (s *Server) handleDeltaJSON(w http.ResponseWriter, r *http.Request) {
	job, ok := s.job(w, r)
	if !ok {
		return
	}
	if !s.runner.Licence().Caps.Reassessment {
		writeJSON(w, http.StatusPaymentRequired, apiError{
			Error:   "Change tracking is available on the Pro and Team tiers.",
			Upgrade: true,
		})
		return
	}
	res, _, err := s.runner.DeltaFor(job)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDeltaReport(w http.ResponseWriter, r *http.Request) {
	job, ok := s.job(w, r)
	if !ok {
		return
	}
	caps := s.runner.Licence().Caps
	if !caps.Reassessment {
		writeJSON(w, http.StatusPaymentRequired, apiError{
			Error:   "The change report is available on the Pro and Team tiers.",
			Upgrade: true,
		})
		return
	}
	res, baseline, err := s.runner.DeltaFor(job)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	var def *store.Definition
	if job.DefinitionID != "" {
		def, _ = s.store.GetDefinition(job.DefinitionID)
	}
	b := s.branding
	if !caps.Branding {
		b = report.Branding{}
	}
	if !caps.WhiteLabel {
		b.WhiteLabel = false
	}
	html, err := report.Delta(report.DeltaInput{
		Job: job, Baseline: baseline, Definition: def, Result: res,
		History:  s.history(job),
		Branding: b, Version: s.version(),
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	serveHTML(w, html)
}

// history gathers every completed run of the saved assessment this job belongs
// to, oldest first, so the change report can draw the timeline.
//
// A job with no definition has no history worth drawing — one run is not a
// trend — and the timeline renderer declines to draw fewer than two points.
func (s *Server) history(job *store.Job) []report.RunSnapshot {
	if job == nil || job.DefinitionID == "" {
		return nil
	}
	jobs, err := s.store.ListJobs(job.Workspace)
	if err != nil {
		return nil
	}
	out := make([]report.RunSnapshot, 0, 8)
	for _, j := range jobs {
		if j.DefinitionID != job.DefinitionID || j.State != store.StateCompleted {
			continue
		}
		fs, err := s.store.GetFindings(j.ID)
		if err != nil {
			// A run whose findings cannot be read is left out of the picture
			// rather than drawn as an empty row, which would read as "clean".
			continue
		}
		at := j.Finished
		if at.IsZero() {
			at = j.Started
		}
		out = append(out, report.RunSnapshot{
			JobID: j.ID, At: at, Findings: fs, Targets: j.Targets,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

// writeRefusal maps an orchestrator refusal onto the right status code.
func (s *Server) writeRefusal(w http.ResponseWriter, err error) {
	var refusal *orchestrator.RefusalError
	if errors.As(err, &refusal) {
		code := http.StatusForbidden
		if refusal.Upgrade {
			code = http.StatusPaymentRequired
		}
		writeJSON(w, code, apiError{Error: refusal.Reason, Upgrade: refusal.Upgrade})
		return
	}
	writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
}

var _ = delta.ChangeNew
