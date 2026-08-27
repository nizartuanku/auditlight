package adapters

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nizartuanku/auditlight/internal/finding"
)

// Secrets looks for credentials committed into files on a path the operator
// nominates. It reads; it never transmits what it finds, and it never checks a
// candidate credential against the service it belongs to.
type Secrets struct{}

func (*Secrets) Name() string { return "secrets" }
func (*Secrets) Kind() Kind   { return KindNative }
func (*Secrets) Stage() Stage { return StageService }
func (*Secrets) Describe() string {
	return "Scans a nominated filesystem path for exposed credentials and private keys."
}
func (*Secrets) Available() (bool, string) { return true, "" }

type secretRule struct {
	name     string
	re       *regexp.Regexp
	severity finding.Severity
	// entropy, when > 0, requires the captured group to look random enough to
	// be a real key. It is what keeps `api_key = "REPLACE_ME"` out of a report.
	entropy float64
}

var secretRules = []secretRule{
	{name: "Private key block", re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`), severity: finding.SeverityCritical},
	{name: "AWS access key id", re: regexp.MustCompile(`\b((?:AKIA|ASIA)[0-9A-Z]{16})\b`), severity: finding.SeverityCritical},
	{name: "AWS secret access key", re: regexp.MustCompile(`(?i)aws.{0,20}?secret.{0,20}?['"]([A-Za-z0-9/+=]{40})['"]`), severity: finding.SeverityCritical, entropy: 4.0},
	{name: "GitHub token", re: regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,255})\b`), severity: finding.SeverityCritical},
	{name: "Slack token", re: regexp.MustCompile(`\b(xox[baprs]-[A-Za-z0-9-]{10,72})\b`), severity: finding.SeverityHigh},
	{name: "Google API key", re: regexp.MustCompile(`\b(AIza[0-9A-Za-z\-_]{35})\b`), severity: finding.SeverityHigh},
	{name: "Stripe secret key", re: regexp.MustCompile(`\b(sk_live_[0-9a-zA-Z]{24,})\b`), severity: finding.SeverityCritical},
	{name: "Twilio auth token", re: regexp.MustCompile(`(?i)twilio.{0,20}?['"]([0-9a-f]{32})['"]`), severity: finding.SeverityHigh, entropy: 3.2},
	{name: "JSON Web Token", re: regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`), severity: finding.SeverityMedium},
	{name: "Database connection string with password", re: regexp.MustCompile(`(?i)\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:([^\s:@/]{4,})@`), severity: finding.SeverityHigh},
	{name: "Generic hardcoded password", re: regexp.MustCompile(`(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"\s]{8,})['"]`), severity: finding.SeverityMedium, entropy: 3.0},
	{name: "Generic API secret", re: regexp.MustCompile(`(?i)\b(?:api[_-]?key|api[_-]?secret|access[_-]?token|secret[_-]?key)\s*[:=]\s*['"]([^'"\s]{16,})['"]`), severity: finding.SeverityHigh, entropy: 3.5},
}

// skipDirs are directories where a match is almost always a dependency's test
// fixture rather than the operator's own secret.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"build": true, ".next": true, "target": true, "__pycache__": true,
	".venv": true, "venv": true, ".terraform": true, "site-packages": true,
}

// placeholderPattern catches the obvious non-secrets so they never reach a
// report. A finding an auditor has to dismiss costs more than one we withhold.
var placeholderPattern = regexp.MustCompile(`(?i)^(?:x{4,}|\*{4,}|\.{3,}|<[^>]+>|\$\{[^}]+\}|%[a-z_]+%|change[_-]?me|replace[_-]?me|your[_-].*|example.*|sample.*|dummy.*|placeholder.*|test[_-]?(?:key|token|secret|password)?|secret|password|token|redacted|none|null|undefined|todo)$`)

const (
	maxSecretFileSize = 2 << 20 // 2 MiB
	maxSecretFiles    = 5000
)

func (a *Secrets) Run(ctx context.Context, t Target, p Policy, _ []*finding.Finding) (Result, error) {
	var res Result
	root := strings.TrimSpace(p.ScanPath)
	if root == "" {
		res.Notes = append(res.Notes, "no filesystem path was nominated, so the secret scan did not run")
		return res, nil
	}
	info, err := os.Stat(root)
	if err != nil {
		res.Notes = append(res.Notes, fmt.Sprintf("path %q could not be read: %s", root, condense(err.Error())))
		return res, nil
	}
	if !info.IsDir() {
		res.Notes = append(res.Notes, fmt.Sprintf("path %q is not a directory", root))
		return res, nil
	}

	scanned, skipped := 0, 0
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			skipped++
			return nil //nolint:nilerr // an unreadable entry must not abort the scan
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if scanned >= maxSecretFiles {
			return filepath.SkipAll
		}
		fi, err := d.Info()
		if err != nil || fi.Size() == 0 || fi.Size() > maxSecretFileSize || !fi.Mode().IsRegular() {
			skipped++
			return nil
		}
		if isBinaryName(path) {
			skipped++
			return nil
		}
		scanned++
		fs, err := scanFile(t, path, root, a.Name())
		if err != nil {
			skipped++
			return nil //nolint:nilerr // report what we could read
		}
		res.Findings = append(res.Findings, fs...)
		return nil
	})
	if walkErr != nil && ctx.Err() != nil {
		res.Notes = append(res.Notes, "secret scan stopped early: "+ctx.Err().Error())
	}

	res.Notes = append(res.Notes, fmt.Sprintf("scanned %d file(s) under %s; %d skipped as binary, oversized or unreadable", scanned, root, skipped))
	if scanned >= maxSecretFiles {
		res.Notes = append(res.Notes, fmt.Sprintf("file limit of %d reached; the scan did not cover the whole tree", maxSecretFiles))
	}
	return res, nil
}

func scanFile(t Target, path, root, tool string) ([]*finding.Finding, error) {
	f, err := os.Open(path) //nolint:gosec // path comes from the operator's nominated tree
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rel, relErr := filepath.Rel(root, path)
	if relErr != nil {
		rel = path
	}

	var out []*finding.Finding
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 512<<10)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		if len(text) > 4096 {
			// Minified bundles produce noise, not secrets worth reporting.
			continue
		}
		for _, rule := range secretRules {
			m := rule.re.FindStringSubmatch(text)
			if m == nil {
				continue
			}
			captured := ""
			if len(m) > 1 {
				captured = m[1]
			}
			if captured != "" {
				if placeholderPattern.MatchString(captured) {
					continue
				}
				if rule.entropy > 0 && shannon(captured) < rule.entropy {
					continue
				}
			}
			fd := finding.New(t.Raw, 0, finding.CategorySecret, rule.severity,
				finding.ConfidenceLikely,
				fmt.Sprintf("secret:%s:%s:%d", rule.name, rel, line),
				fmt.Sprintf("%s found in %s", rule.name, rel),
				fmt.Sprintf("A value matching %s appears at %s line %d. Credentials in files are read by everyone who can read the file, and they survive in version history long after they are removed from the working tree.", rule.name, rel, line),
				tool)
			fd.Remediation = "Treat the credential as compromised: rotate it, then move it to a secret manager or environment variable. Removing it from the current file is not enough if it was ever committed."
			fd.CWE = []string{"CWE-798"}
			fd.AddEvidence("match", fmt.Sprintf("%s:%d", rel, line), redact(text, captured))
			out = append(out, fd)
		}
	}
	return out, sc.Err()
}

// redact keeps enough of the line to locate the secret without reprinting it in
// full. A report that leaks the credential it is warning about has made things
// worse.
func redact(line, secret string) string {
	line = sanitise(strings.TrimSpace(line))
	if secret == "" {
		if len(line) > 120 {
			return line[:120] + "…"
		}
		return line
	}
	masked := secret
	if len(secret) > 8 {
		masked = secret[:4] + strings.Repeat("•", 8) + secret[len(secret)-2:]
	} else {
		masked = strings.Repeat("•", len(secret))
	}
	out := strings.ReplaceAll(line, secret, masked)
	if len(out) > 160 {
		return out[:160] + "…"
	}
	return out
}

// shannon returns the Shannon entropy of s in bits per character.
func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]float64
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

var binaryExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
	".ico": true, ".pdf": true, ".zip": true, ".gz": true, ".tar": true,
	".bz2": true, ".xz": true, ".7z": true, ".exe": true, ".dll": true,
	".so": true, ".dylib": true, ".class": true, ".jar": true, ".woff": true,
	".woff2": true, ".ttf": true, ".eot": true, ".mp4": true, ".mp3": true,
	".bin": true, ".o": true, ".a": true, ".wasm": true, ".pyc": true,
}

func isBinaryName(path string) bool {
	return binaryExts[strings.ToLower(filepath.Ext(path))]
}
