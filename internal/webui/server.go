// Package webui serves the dashboard and the REST console.
//
// Everything is served from the binary. The page makes no external request, so
// the dashboard works on an air-gapped host exactly as it does on a laptop.
package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nizartuanku/auditlight/internal/adapters"
	"github.com/nizartuanku/auditlight/internal/authz"
	"github.com/nizartuanku/auditlight/internal/license"
	"github.com/nizartuanku/auditlight/internal/orchestrator"
	"github.com/nizartuanku/auditlight/internal/report"
	"github.com/nizartuanku/auditlight/internal/store"
	"github.com/nizartuanku/auditlight/internal/surface"
	"github.com/nizartuanku/auditlight/internal/version"
)

// Server wires the runner and store to HTTP.
type Server struct {
	runner   *orchestrator.Runner
	store    store.Store
	branding report.Branding
}

// New builds the server.
func New(r *orchestrator.Runner, st store.Store, b report.Branding) *Server {
	return &Server{runner: r, store: st, branding: b}
}

// version reports the running version, for reports.
func (s *Server) version() string { return version.Version }

// Handler returns the routed handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/profiles", s.handleProfiles)
	mux.HandleFunc("POST /api/jobs", s.handleCreateJob)
	mux.HandleFunc("GET /api/jobs", s.handleListJobs)
	mux.HandleFunc("GET /api/jobs/{id}", s.handleGetJob)
	mux.HandleFunc("GET /api/jobs/{id}/findings", s.handleFindings)
	mux.HandleFunc("GET /api/jobs/{id}/surface.json", s.handleSurface)
	mux.HandleFunc("GET /api/jobs/{id}/report/process", s.handleProcessReport)
	mux.HandleFunc("GET /api/jobs/{id}/report/assessment", s.handleAssessmentReport)
	mux.HandleFunc("GET /api/jobs/{id}/export.json", s.handleExport)
	mux.HandleFunc("GET /api/jobs/{id}/report/delta", s.handleDeltaReport)
	mux.HandleFunc("GET /api/jobs/{id}/delta", s.handleDeltaJSON)
	mux.HandleFunc("POST /api/definitions", s.handleCreateDefinition)
	mux.HandleFunc("GET /api/definitions", s.handleListDefinitions)
	mux.HandleFunc("GET /api/definitions/{id}", s.handleGetDefinition)
	mux.HandleFunc("DELETE /api/definitions/{id}", s.handleDeleteDefinition)
	mux.HandleFunc("POST /api/definitions/{id}/run", s.handleRunDefinition)
	mux.HandleFunc("POST /api/definitions/{id}/reauthorise", s.handleReauthorise)
	return securityHeaders(mux)
}

// securityHeaders applies the headers we would flag on someone else's server.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// The UI is entirely inline and must never reach the network.
		h.Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "+
				"img-src data:; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

type apiError struct {
	Error   string `json:"error"`
	Upgrade bool   `json:"upgrade,omitempty"`
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	lic := s.runner.Licence()
	caps := s.runner.Registry().Capabilities()
	native, tools, missing := 0, 0, 0
	for _, c := range caps {
		if c.Kind == adapters.KindNative {
			native++
			continue
		}
		if c.Available {
			tools++
		} else {
			missing++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"product":      version.Product,
		"version":      version.Version,
		"tagline":      version.Tagline,
		"licence":      lic,
		"capabilities": caps,
		"counts": map[string]int{
			"native": native, "tools_present": tools, "tools_missing": missing,
		},
		"affirmation":  authz.Affirmation,
		"reassessment": lic.Caps.Reassessment,
	})
}

func (s *Server) handleProfiles(w http.ResponseWriter, _ *http.Request) {
	caps := s.runner.Licence().Caps
	type row struct {
		orchestrator.Profile
		Allowed bool `json:"allowed"`
	}
	var out []row
	for _, p := range orchestrator.Profiles() {
		out = append(out, row{Profile: p, Allowed: caps.AllowsProfile(p.Name)})
	}
	writeJSON(w, http.StatusOK, out)
}

type createJobRequest struct {
	Profile   string   `json:"profile"`
	Workspace string   `json:"workspace"`
	Operator  string   `json:"operator"`
	Targets   []string `json:"targets"`
	Confirm   []string `json:"confirm"`
	Scope     []string `json:"scope"`
	Confirmed bool     `json:"confirmed"`
	ScanPath  string   `json:"scan_path"`
}

func (s *Server) handleCreateJob(w http.ResponseWriter, r *http.Request) {
	var req createJobRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "The request body could not be read as JSON."})
		return
	}
	job, err := s.runner.Submit(r.Context(), orchestrator.Request{
		Workspace: req.Workspace,
		Profile:   req.Profile,
		ScanPath:  req.ScanPath,
		Authz: authz.Request{
			Operator:  req.Operator,
			Statement: authz.Affirmation,
			Targets:   req.Targets,
			Confirm:   req.Confirm,
			Scope:     req.Scope,
			Confirmed: req.Confirmed,
		},
	})

	if err != nil {
		s.writeRefusal(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.store.ListJobs(r.URL.Query().Get("workspace"))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, jobs)
}

func (s *Server) job(w http.ResponseWriter, r *http.Request) (*store.Job, bool) {
	job, err := s.store.GetJob(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, apiError{Error: "No such job."})
		return nil, false
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return nil, false
	}
	return job, true
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	if job, ok := s.job(w, r); ok {
		writeJSON(w, http.StatusOK, job)
	}
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	job, ok := s.job(w, r)
	if !ok {
		return
	}
	fs, err := s.store.GetFindings(job.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	caps := s.runner.Licence().Caps
	total := len(fs)
	notice := ""
	if !license.Unlimited(caps.MaxFindingsShown) && total > caps.MaxFindingsShown {
		fs = fs[:caps.MaxFindingsShown]
		notice = fmt.Sprintf(
			"%d findings were produced; this licence displays the %d highest-ranked. %d are not shown.",
			total, caps.MaxFindingsShown, total-caps.MaxFindingsShown)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total": total, "shown": len(fs), "notice": notice, "findings": fs,
	})
}

// handleSurface serves the attack-surface graph the explorer draws.
//
// It is available on every tier, free included. The graph is a picture of what
// was observed; the paid value in this product is the reports, not the ability
// to look at your own surface. A free user who can see their surface is more
// likely to want the document that explains it.
//
// The same tier cap that limits the findings list limits the graph, so the
// picture and the list can never disagree about what this licence shows.
func (s *Server) handleSurface(w http.ResponseWriter, r *http.Request) {
	job, ok := s.job(w, r)
	if !ok {
		return
	}
	fs, err := s.store.GetFindings(job.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	caps := s.runner.Licence().Caps
	total := len(fs)
	notice := ""
	if !license.Unlimited(caps.MaxFindingsShown) && total > caps.MaxFindingsShown {
		fs = fs[:caps.MaxFindingsShown]
		notice = fmt.Sprintf(
			"This licence shows %d of %d findings, so the surface drawn here is partial.",
			caps.MaxFindingsShown, total)
	}
	g := surface.Build(job, fs)
	writeJSON(w, http.StatusOK, map[string]any{
		"graph": g, "notice": notice,
	})
}

// reportInput assembles what both reports need.
func (s *Server) reportInput(job *store.Job) (report.Input, error) {
	fs, err := s.store.GetFindings(job.ID)
	if err != nil {
		return report.Input{}, err
	}
	lic := s.runner.Licence()
	caps := lic.Caps
	if !license.Unlimited(caps.MaxFindingsShown) && len(fs) > caps.MaxFindingsShown {
		fs = fs[:caps.MaxFindingsShown]
	}
	var capRows []report.Capability
	for _, c := range s.runner.Registry().Capabilities() {
		capRows = append(capRows, report.Capability{
			Name: c.Name, Kind: string(c.Kind), Describe: c.Describe,
			Available: c.Available, Reason: c.Reason,
		})
	}
	b := s.branding
	if !caps.Branding {
		b = report.Branding{}
	}
	if !caps.WhiteLabel {
		b.WhiteLabel = false
	}
	return report.Input{
		Job: job, Findings: fs, Capabilities: capRows,
		Licence: lic, Branding: b, Version: version.Version,
	}, nil
}

func (s *Server) handleProcessReport(w http.ResponseWriter, r *http.Request) {
	job, ok := s.job(w, r)
	if !ok {
		return
	}
	in, err := s.reportInput(job)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	html, err := report.Process(in)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	serveHTML(w, html)
}

func (s *Server) handleAssessmentReport(w http.ResponseWriter, r *http.Request) {
	job, ok := s.job(w, r)
	if !ok {
		return
	}
	in, err := s.reportInput(job)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	// The Free tier gets a watermarked preview rather than a locked door: the
	// value of the report should be visible before it is paid for.
	if !s.runner.Licence().Caps.AssessmentReport {
		in.Watermark = "PREVIEW"
	}
	html, err := report.Assessment(in)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	serveHTML(w, html)
}

func serveHTML(w http.ResponseWriter, b []byte) {
	// Reports are self-contained documents; the dashboard CSP would break
	// their inline styles, so send a document-appropriate policy instead.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	if !s.runner.Licence().Caps.Export {
		writeJSON(w, http.StatusPaymentRequired, apiError{
			Error:   "Machine-readable export is available on the Pro and Team tiers.",
			Upgrade: true,
		})
		return
	}
	job, ok := s.job(w, r)
	if !ok {
		return
	}
	fs, err := s.store.GetFindings(job.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="auditlight-%s.json"`, job.ID))
	writeJSON(w, http.StatusOK, map[string]any{
		"product": version.Product, "version": version.Version,
		"exported_at": time.Now().UTC(), "job": job, "findings": fs,
	})
}

// Listen starts the server and shuts it down cleanly when ctx is cancelled.
//
// Without the context the process ignored SIGTERM: the scheduler stopped but
// ListenAndServe blocked forever, so `systemctl stop` hung until the service
// manager gave up and sent SIGKILL. A service that has to be killed is a
// service that can lose an in-flight write.
func Listen(ctx context.Context, addr string, h http.Handler) error {
	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		// Give running assessments a moment to finish writing their results.
		shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	}
}
