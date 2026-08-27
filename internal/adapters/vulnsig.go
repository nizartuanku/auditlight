package adapters

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/nizartuanku/auditlight/internal/finding"
)

// VulnSig derives version-based vulnerability findings from evidence other
// adapters already gathered.
//
// This is inference, not proof. A banner says what software claims to be, not
// what it is: back-ported security fixes routinely leave the advertised version
// untouched. Every finding it produces is therefore capped at "likely" and
// carries the reasoning, so a reader can check it rather than take it on trust.
type VulnSig struct{}

func (*VulnSig) Name() string { return "vulnsig" }
func (*VulnSig) Kind() Kind   { return KindNative }
func (*VulnSig) Stage() Stage { return StageDerived }
func (*VulnSig) Describe() string {
	return "Matches observed software versions against an embedded signature set."
}
func (*VulnSig) Available() (bool, string) { return true, "" }

// signature describes a version range that is known to be end-of-life or to
// carry a well-documented weakness.
type signature struct {
	product  string // lower-case product token as it appears in banners
	below    string // versions strictly below this are matched
	atLeast  string // ...and at or above this, when set
	severity finding.Severity
	summary  string
	cve      []string
	fix      string
}

// signatures is deliberately small and conservative. Every entry is a
// long-standing, uncontroversial fact rather than a snapshot of a feed that
// would be stale the week after release. Depth beyond this is what the optional
// nuclei adapter is for, and the honest limits say so.
var signatures = []signature{
	{
		product: "openssh", below: "7.4", severity: finding.SeverityMedium,
		summary: "OpenSSH releases before 7.4 are long past support and carry a series of documented weaknesses, including the CVE-2016-10009 agent-forwarding issue.",
		cve:     []string{"CVE-2016-10009", "CVE-2016-10012"},
		fix:     "Upgrade OpenSSH to a currently supported release.",
	},
	{
		product: "openssh", below: "9.3", atLeast: "8.5", severity: finding.SeverityHigh,
		summary: "OpenSSH between 8.5 and 9.3 is affected by CVE-2023-38408, a remote code execution issue in the ssh-agent PKCS#11 provider.",
		cve:     []string{"CVE-2023-38408"},
		fix:     "Upgrade to OpenSSH 9.3p2 or later.",
	},
	{
		product: "apache", below: "2.4.52", severity: finding.SeverityHigh,
		summary: "Apache httpd before 2.4.52 predates the fixes for the 2021 path traversal and RCE issues (CVE-2021-41773 and CVE-2021-42013), which were exploited in the wild.",
		cve:     []string{"CVE-2021-41773", "CVE-2021-42013"},
		fix:     "Upgrade Apache httpd to 2.4.52 or later.",
	},
	{
		product: "nginx", below: "1.20.1", severity: finding.SeverityMedium,
		summary: "nginx before 1.20.1 predates the fix for the DNS resolver off-by-one issue CVE-2021-23017.",
		cve:     []string{"CVE-2021-23017"},
		fix:     "Upgrade nginx to 1.20.1 or later.",
	},
	{
		product: "php", below: "7.4", severity: finding.SeverityHigh,
		summary: "PHP before 7.4 no longer receives security support. Unsupported interpreters accumulate unpatched issues indefinitely.",
		fix:     "Move to a PHP release that is still receiving security updates.",
	},
	{
		product: "php", below: "8.1.28", atLeast: "8.0", severity: finding.SeverityCritical,
		summary: "PHP 8.0 and early 8.1 releases predate the fix for CVE-2024-4577, an argument-injection issue in CGI mode that leads to remote code execution and was exploited within days of disclosure.",
		cve:     []string{"CVE-2024-4577"},
		fix:     "Upgrade PHP to 8.1.29, 8.2.20, 8.3.8 or later.",
	},
	{
		product: "exim", below: "4.94.2", severity: finding.SeverityCritical,
		summary: "Exim before 4.94.2 is affected by the 21Nails cluster of vulnerabilities, several of which allow remote code execution.",
		fix:     "Upgrade Exim to 4.94.2 or later.",
	},
	{
		product: "proftpd", below: "1.3.6", severity: finding.SeverityHigh,
		summary: "ProFTPD before 1.3.6 carries the mod_copy arbitrary file copy issue CVE-2015-3306.",
		cve:     []string{"CVE-2015-3306"},
		fix:     "Upgrade ProFTPD to 1.3.6 or later and disable mod_copy if it is not required.",
	},
	{
		product: "vsftpd", below: "3.0.3", severity: finding.SeverityMedium,
		summary: "vsftpd before 3.0.3 is outdated; the 2.3.4 line in particular shipped with a backdoor in a compromised tarball.",
		fix:     "Upgrade vsftpd to 3.0.3 or later from a verified source.",
	},
	{
		product: "mysql", below: "5.7", severity: finding.SeverityMedium,
		summary: "MySQL before 5.7 is out of support and no longer receives security fixes.",
		fix:     "Upgrade to a supported MySQL or MariaDB release.",
	},
	{
		product: "postgresql", below: "12", severity: finding.SeverityMedium,
		summary: "PostgreSQL releases before 12 have reached end of life and receive no further security fixes.",
		fix:     "Upgrade to a supported PostgreSQL major version.",
	},
	{
		product: "iis", below: "8.0", severity: finding.SeverityMedium,
		summary: "IIS below 8.0 implies a Windows Server release that has reached end of support.",
		fix:     "Move the workload to a supported Windows Server and IIS version.",
	},
}

// productAliases maps what banners actually say to the tokens signatures use.
var productAliases = map[string]string{
	"apache":        "apache",
	"httpd":         "apache",
	"nginx":         "nginx",
	"openssh":       "openssh",
	"ssh":           "openssh",
	"php":           "php",
	"php-fpm":       "php",
	"exim":          "exim",
	"proftpd":       "proftpd",
	"vsftpd":        "vsftpd",
	"mysql":         "mysql",
	"mariadb":       "mysql",
	"postgresql":    "postgresql",
	"postgres":      "postgresql",
	"iis":           "iis",
	"microsoft-iis": "iis",
}

var versionInText = regexp.MustCompile(`(?i)([A-Za-z][A-Za-z0-9_\-]{1,24})[/ _-]v?(\d+(?:\.\d+){0,3})`)

func (a *VulnSig) Run(_ context.Context, t Target, _ Policy, prior []*finding.Finding) (Result, error) {
	var res Result
	type observed struct {
		product string
		version string
		port    int
		source  string
		raw     string
	}
	var seen []observed
	dedupe := map[string]bool{}

	for _, pf := range prior {
		if pf.Target != t.Raw {
			continue
		}
		for _, e := range pf.Evidence {
			switch e.Kind {
			case "banner", "header", "fingerprint", "http":
			default:
				continue
			}
			for _, m := range versionInText.FindAllStringSubmatch(e.Value, -1) {
				token := strings.ToLower(m[1])
				product, ok := productAliases[token]
				if !ok {
					continue
				}
				key := fmt.Sprintf("%s|%s|%d", product, m[2], pf.Port)
				if dedupe[key] {
					continue
				}
				dedupe[key] = true
				seen = append(seen, observed{
					product: product, version: m[2], port: pf.Port,
					source: pf.SourceTools[0], raw: e.Value,
				})
			}
		}
	}

	if len(seen) == 0 {
		res.Notes = append(res.Notes, "no software version was observable, so signature matching produced nothing")
		return res, nil
	}

	for _, o := range seen {
		matched := false
		for _, sig := range signatures {
			if sig.product != o.product {
				continue
			}
			if compareVersions(o.version, sig.below) >= 0 {
				continue
			}
			if sig.atLeast != "" && compareVersions(o.version, sig.atLeast) < 0 {
				continue
			}
			matched = true
			f := finding.New(t.Raw, o.port, finding.CategoryVuln, sig.severity,
				// Capped at "likely": a version string is evidence, not proof.
				finding.ConfidenceLikely,
				fmt.Sprintf("vulnsig:%s:%s:%s", o.product, o.version, sig.below),
				fmt.Sprintf("%s %s is affected by known issues", displayProduct(o.product), o.version),
				sig.summary+"\n\nThis match is based on the version the service advertises. Distributions frequently back-port fixes without changing that string, so confirm the build before treating it as exploitable.",
				a.Name())
			f.Remediation = sig.fix
			f.CVE = sig.cve
			f.AddEvidence("inference", "observed version",
				fmt.Sprintf("%s %s (from %s)", displayProduct(o.product), o.version, o.source))
			f.AddEvidence("inference", "matched rule",
				fmt.Sprintf("versions below %s%s", sig.below, atLeastSuffix(sig.atLeast)))
			res.Findings = append(res.Findings, f)
		}
		if !matched {
			f := finding.New(t.Raw, o.port, finding.CategoryVuln, finding.SeverityInfo,
				finding.ConfidenceConfirmed,
				fmt.Sprintf("version-observed:%s:%s:%d", o.product, o.version, o.port),
				fmt.Sprintf("%s %s observed", displayProduct(o.product), o.version),
				"The version was recorded but matched no signature in the embedded set. The embedded set is intentionally small; it is not a vulnerability feed, and absence here is not evidence that the version is unaffected.",
				a.Name())
			f.Status = finding.StatusInformational
			f.AddEvidence("inference", "observed version", fmt.Sprintf("%s %s", displayProduct(o.product), o.version))
			res.Findings = append(res.Findings, f)
		}
	}
	return res, nil
}

func atLeastSuffix(atLeast string) string {
	if atLeast == "" {
		return ""
	}
	return " and at or above " + atLeast
}

func displayProduct(p string) string {
	switch p {
	case "openssh":
		return "OpenSSH"
	case "apache":
		return "Apache httpd"
	case "nginx":
		return "nginx"
	case "php":
		return "PHP"
	case "mysql":
		return "MySQL/MariaDB"
	case "postgresql":
		return "PostgreSQL"
	case "iis":
		return "Microsoft IIS"
	case "exim":
		return "Exim"
	case "proftpd":
		return "ProFTPD"
	case "vsftpd":
		return "vsftpd"
	default:
		return p
	}
}

// compareVersions compares dotted numeric versions. Missing components count as
// zero, so "8" and "8.0.0" are equal. It returns -1, 0 or 1.
func compareVersions(a, b string) int {
	as := splitVersion(a)
	bs := splitVersion(b)
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	return 0
}

func splitVersion(v string) []int {
	parts := strings.Split(strings.TrimSpace(v), ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		// Trim non-numeric suffixes such as the "p1" in "9.3p1".
		end := 0
		for end < len(p) && p[end] >= '0' && p[end] <= '9' {
			end++
		}
		if end == 0 {
			out = append(out, 0)
			continue
		}
		n, err := strconv.Atoi(p[:end])
		if err != nil {
			n = 0
		}
		out = append(out, n)
	}
	return out
}
