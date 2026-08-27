package adapters

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nizartuanku/auditlight/internal/finding"
)

// execSpec describes one optional external tool.
type execSpec struct {
	name     string
	binary   string
	describe string
	category finding.Category
	stage    Stage
	// args builds the command line. It receives a scratch directory the tool
	// may write into.
	args func(t Target, scratch string) []string
	// parse turns tool output into findings.
	parse func(t Target, stdout []byte, scratch string, tool string) ([]*finding.Finding, []string, error)
	// safeFlags are recorded in the Process Report as proof of what was enforced.
	safeFlags []string
}

// deniedFlags never reach an external tool, whatever else changes. AuditLight
// has no aggressive mode, and this is where that promise is enforced rather
// than merely stated.
var deniedFlags = []string{
	"--script=exploit", "--script=intrusive", "--script=dos", "--script=brute",
	"-sS", "-sF", "-sX", "-sN", "--min-rate", "-T5",
	"--fuzz", "--dast", "-as", "--attack",
}

// execAdapter runs an external tool if the operator has it installed.
type execAdapter struct{ spec execSpec }

func newExecAdapter(s execSpec) *execAdapter { return &execAdapter{spec: s} }

func (a *execAdapter) Name() string     { return a.spec.name }
func (a *execAdapter) Kind() Kind       { return KindSubprocess }
func (a *execAdapter) Stage() Stage     { return a.spec.stage }
func (a *execAdapter) Describe() string { return a.spec.describe }

func (a *execAdapter) Available() (bool, string) {
	path, err := exec.LookPath(a.spec.binary)
	if err != nil {
		return false, fmt.Sprintf("%s is not installed on this host", a.spec.binary)
	}
	if path == "" {
		return false, fmt.Sprintf("%s could not be located", a.spec.binary)
	}
	return true, ""
}

// SafeFlags exposes the enforced arguments so the report can show them.
func (a *execAdapter) SafeFlags() []string { return a.spec.safeFlags }

// BinaryPath returns the resolved tool path, for the Process Report.
func (a *execAdapter) BinaryPath() string {
	p, err := exec.LookPath(a.spec.binary)
	if err != nil {
		return ""
	}
	return p
}

func (a *execAdapter) Run(ctx context.Context, t Target, p Policy, _ []*finding.Finding) (Result, error) {
	var res Result
	if !p.AllowSubprocess {
		res.Notes = append(res.Notes, fmt.Sprintf("%s was not run: external tools require a paid licence", a.spec.name))
		return res, nil
	}
	ok, why := a.Available()
	if !ok {
		res.Notes = append(res.Notes, why)
		return res, nil
	}
	// A target that looks like a flag would be handed to the tool as one.
	if strings.HasPrefix(t.Raw, "-") {
		return res, fmt.Errorf("%s: refusing target that begins with '-'", a.spec.name)
	}

	scratch, err := os.MkdirTemp("", "auditlight-"+a.spec.name+"-")
	if err != nil {
		return res, fmt.Errorf("%s: scratch directory: %w", a.spec.name, err)
	}
	defer os.RemoveAll(scratch)

	args := a.spec.args(t, scratch)
	for _, arg := range args {
		for _, bad := range deniedFlags {
			if strings.EqualFold(arg, bad) {
				return res, fmt.Errorf("%s: refusing to run with %s; AuditLight has no intrusive mode", a.spec.name, bad)
			}
		}
	}

	cmd := exec.CommandContext(ctx, a.spec.binary, args...) //nolint:gosec // binary and args are fixed by the spec
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	stdout, runErr := cmd.Output()

	fs, notes, parseErr := a.spec.parse(t, stdout, scratch, a.spec.name)
	res.Findings = fs
	res.Notes = append(res.Notes, notes...)

	// A tool that exits non-zero has often still produced usable output, so
	// parse first and only report the failure if nothing came back.
	if runErr != nil && len(fs) == 0 {
		return res, fmt.Errorf("%s: %s", a.spec.name, condense(runErr.Error()))
	}
	if parseErr != nil {
		res.Notes = append(res.Notes, fmt.Sprintf("%s output could not be fully parsed: %s", a.spec.name, condense(parseErr.Error())))
	}
	return res, nil
}

// --- nuclei ---------------------------------------------------------------

func execSpecNuclei() execSpec {
	return execSpec{
		name:      "nuclei",
		binary:    "nuclei",
		describe:  "Template-based detection, with intrusive, DoS and fuzzing templates excluded.",
		category:  finding.CategoryVuln,
		stage:     StageDerived,
		safeFlags: []string{"-etags", "intrusive,dos,fuzz", "-dast=false"},
		args: func(t Target, scratch string) []string {
			target := t.URL
			if target == "" {
				target = t.Host
			}
			return []string{
				"-target", target,
				"-jsonl",
				"-silent",
				"-etags", "intrusive,dos,fuzz",
				"-no-interactsh", // no out-of-band callbacks
				"-disable-update-check",
				"-o", filepath.Join(scratch, "out.jsonl"),
			}
		},
		parse: func(t Target, stdout []byte, scratch, tool string) ([]*finding.Finding, []string, error) {
			data := stdout
			if b, err := os.ReadFile(filepath.Join(scratch, "out.jsonl")); err == nil && len(b) > 0 {
				data = b
			}
			var out []*finding.Finding
			var notes []string
			count := 0
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || !strings.HasPrefix(line, "{") {
					continue
				}
				var ev struct {
					TemplateID string `json:"template-id"`
					Info       struct {
						Name           string   `json:"name"`
						Severity       string   `json:"severity"`
						Description    string   `json:"description"`
						Remediation    string   `json:"remediation"`
						Tags           []string `json:"tags"`
						Classification struct {
							CVEID     []string `json:"cve-id"`
							CWEID     []string `json:"cwe-id"`
							CVSSScore float64  `json:"cvss-score"`
						} `json:"classification"`
					} `json:"info"`
					MatchedAt string `json:"matched-at"`
					Type      string `json:"type"`
				}
				if err := json.Unmarshal([]byte(line), &ev); err != nil {
					continue
				}
				count++
				f := finding.New(t.Raw, 0, finding.CategoryVuln,
					nucleiSeverity(ev.Info.Severity), finding.ConfidenceLikely,
					"nuclei:"+ev.TemplateID,
					firstNonEmpty(ev.Info.Name, ev.TemplateID),
					firstNonEmpty(ev.Info.Description, "Reported by a nuclei detection template."),
					tool)
				f.Remediation = ev.Info.Remediation
				f.CVE = ev.Info.Classification.CVEID
				f.CWE = ev.Info.Classification.CWEID
				f.CVSS = ev.Info.Classification.CVSSScore
				f.AddEvidence("nuclei", "template", ev.TemplateID)
				if ev.MatchedAt != "" {
					f.AddEvidence("nuclei", "matched at", ev.MatchedAt)
				}
				out = append(out, f)
			}
			notes = append(notes, fmt.Sprintf("nuclei reported %d detection(s) with intrusive, DoS and fuzzing templates excluded", count))
			return out, notes, nil
		},
	}
}

func nucleiSeverity(s string) finding.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return finding.SeverityCritical
	case "high":
		return finding.SeverityHigh
	case "medium":
		return finding.SeverityMedium
	case "low":
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}

// --- testssl.sh -----------------------------------------------------------

func execSpecTestSSL() execSpec {
	return execSpec{
		name:      "testssl",
		binary:    "testssl.sh",
		describe:  "Deep TLS analysis, adding cipher and protocol detail beyond the built-in check.",
		category:  finding.CategoryTLS,
		stage:     StageDerived,
		safeFlags: []string{"--quiet", "--jsonfile"},
		args: func(t Target, scratch string) []string {
			target := t.Host
			return []string{
				"--quiet", "--color", "0",
				"--jsonfile", filepath.Join(scratch, "out.json"),
				target,
			}
		},
		parse: func(t Target, stdout []byte, scratch, tool string) ([]*finding.Finding, []string, error) {
			b, err := os.ReadFile(filepath.Join(scratch, "out.json"))
			if err != nil {
				return nil, []string{"testssl produced no JSON output"}, err
			}
			var rows []struct {
				ID       string `json:"id"`
				IP       string `json:"ip"`
				Port     string `json:"port"`
				Severity string `json:"severity"`
				Finding  string `json:"finding"`
				CVE      string `json:"cve"`
			}
			if err := json.Unmarshal(b, &rows); err != nil {
				return nil, []string{"testssl JSON could not be decoded"}, err
			}
			var out []*finding.Finding
			kept := 0
			for _, r := range rows {
				sev := testsslSeverity(r.Severity)
				if sev == "" {
					continue // OK / INFO rows are not findings
				}
				kept++
				f := finding.New(t.Raw, 0, finding.CategoryTLS, sev,
					finding.ConfidenceConfirmed, "testssl:"+r.ID,
					fmt.Sprintf("TLS: %s", r.ID),
					firstNonEmpty(r.Finding, "Reported by testssl.sh."), tool)
				if r.CVE != "" {
					f.CVE = strings.Fields(r.CVE)
				}
				f.AddEvidence("testssl", r.ID, r.Finding)
				out = append(out, f)
			}
			return out, []string{fmt.Sprintf("testssl contributed %d finding(s) from %d checks", kept, len(rows))}, nil
		},
	}
}

func testsslSeverity(s string) finding.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return finding.SeverityCritical
	case "HIGH":
		return finding.SeverityHigh
	case "MEDIUM":
		return finding.SeverityMedium
	case "LOW":
		return finding.SeverityLow
	default:
		return ""
	}
}

// --- lynis ----------------------------------------------------------------

func execSpecLynis() execSpec {
	return execSpec{
		name:      "lynis",
		binary:    "lynis",
		describe:  "Read-only host hardening audit in the CIS tradition.",
		category:  finding.CategoryHardening,
		stage:     StageService,
		safeFlags: []string{"audit", "system", "--quick", "--no-colors"},
		args: func(_ Target, scratch string) []string {
			return []string{
				"audit", "system", "--quick", "--no-colors", "--quiet",
				"--report-file", filepath.Join(scratch, "report.dat"),
				"--logfile", filepath.Join(scratch, "lynis.log"),
			}
		},
		parse: func(t Target, stdout []byte, scratch, tool string) ([]*finding.Finding, []string, error) {
			b, err := os.ReadFile(filepath.Join(scratch, "report.dat"))
			if err != nil {
				return nil, []string{"lynis produced no report file"}, err
			}
			var out []*finding.Finding
			warnings, suggestions := 0, 0
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				var sev finding.Severity
				var kind string
				switch {
				case strings.HasPrefix(line, "warning[]="):
					sev, kind = finding.SeverityMedium, "warning"
					warnings++
					line = strings.TrimPrefix(line, "warning[]=")
				case strings.HasPrefix(line, "suggestion[]="):
					sev, kind = finding.SeverityLow, "suggestion"
					suggestions++
					line = strings.TrimPrefix(line, "suggestion[]=")
				default:
					continue
				}
				parts := strings.Split(line, "|")
				testID := ""
				text := line
				if len(parts) >= 2 {
					testID, text = parts[0], parts[1]
				}
				f := finding.New(t.Raw, 0, finding.CategoryHardening, sev,
					finding.ConfidenceConfirmed, "lynis:"+testID,
					fmt.Sprintf("Host hardening %s: %s", kind, truncate(text, 70)),
					text, tool)
				f.AddEvidence("lynis", testID, text)
				if len(parts) >= 3 && strings.TrimSpace(parts[2]) != "-" {
					f.Remediation = strings.TrimSpace(parts[2])
				}
				out = append(out, f)
			}
			return out, []string{fmt.Sprintf("lynis reported %d warning(s) and %d suggestion(s)", warnings, suggestions)}, nil
		},
	}
}

// --- nmap (bring your own) -------------------------------------------------

func execSpecNmap() execSpec {
	return execSpec{
		name:   "nmap",
		binary: "nmap",
		describe: "Extended service and version detection. Never distributed with AuditLight; " +
			"its licence forbids bundling, so it is used only if you installed it yourself.",
		category:  finding.CategoryNetwork,
		stage:     StageDerived,
		safeFlags: []string{"-sV", "-sT", "--script", "safe", "-T3"},
		args: func(t Target, scratch string) []string {
			return []string{
				"-sV", "-sT", "-T3", "-Pn",
				"--script", "safe",
				"--script-timeout", "30s",
				"-oX", filepath.Join(scratch, "out.xml"),
				t.Host,
			}
		},
		parse: func(t Target, stdout []byte, scratch, tool string) ([]*finding.Finding, []string, error) {
			b, err := os.ReadFile(filepath.Join(scratch, "out.xml"))
			if err != nil {
				return nil, []string{"nmap produced no XML output"}, err
			}
			var doc struct {
				Hosts []struct {
					Ports struct {
						Port []struct {
							PortID   int    `xml:"portid,attr"`
							Protocol string `xml:"protocol,attr"`
							State    struct {
								State string `xml:"state,attr"`
							} `xml:"state"`
							Service struct {
								Name    string `xml:"name,attr"`
								Product string `xml:"product,attr"`
								Version string `xml:"version,attr"`
								Extra   string `xml:"extrainfo,attr"`
							} `xml:"service"`
						} `xml:"port"`
					} `xml:"ports"`
				} `xml:"host"`
			}
			if err := xml.Unmarshal(b, &doc); err != nil {
				return nil, []string{"nmap XML could not be decoded"}, err
			}
			var out []*finding.Finding
			n := 0
			for _, h := range doc.Hosts {
				for _, port := range h.Ports.Port {
					if port.State.State != "open" {
						continue
					}
					desc := strings.TrimSpace(strings.Join([]string{
						port.Service.Product, port.Service.Version, port.Service.Extra,
					}, " "))
					if desc == "" {
						continue
					}
					n++
					f := finding.New(t.Raw, port.PortID, finding.CategoryNetwork,
						finding.SeverityInfo, finding.ConfidenceConfirmed,
						fmt.Sprintf("nmap-service:%d", port.PortID),
						fmt.Sprintf("%s identified on port %d", firstNonEmpty(port.Service.Product, port.Service.Name), port.PortID),
						"nmap identified the service and version listening on this port.", tool)
					f.Status = finding.StatusInformational
					f.AddEvidence("banner", fmt.Sprintf("%s/%d", port.Protocol, port.PortID), desc)
					out = append(out, f)
				}
			}
			return out, []string{fmt.Sprintf("nmap identified %d service(s)", n)}, nil
		},
	}
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	s = sanitise(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
