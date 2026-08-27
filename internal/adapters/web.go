package adapters

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nizartuanku/auditlight/internal/finding"
)

// HTTPProbe inspects HTTP services: liveness, status, title, server software
// and observable technology. It reads a bounded body and follows a bounded
// number of redirects, so a hostile or misconfigured endpoint cannot stall or
// exhaust the scanner.
type HTTPProbe struct{}

func (*HTTPProbe) Name() string { return "httpprobe" }
func (*HTTPProbe) Kind() Kind   { return KindNative }
func (*HTTPProbe) Stage() Stage { return StageService }
func (*HTTPProbe) Describe() string {
	return "Probes HTTP services for status, title, server software and technology fingerprints."
}
func (*HTTPProbe) Available() (bool, string) { return true, "" }

const (
	maxBodyBytes  = 256 << 10 // 256 KiB is ample to read a <title> and fingerprints
	maxRedirects  = 5
	evidenceHdrs  = "headers"
	sigHTTPPrefix = "http-service:"
)

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func (a *HTTPProbe) Run(ctx context.Context, t Target, p Policy, prior []*finding.Finding) (Result, error) {
	var res Result

	for _, ep := range httpEndpoints(t, prior) {
		select {
		case <-ctx.Done():
			res.Notes = append(res.Notes, "http probing stopped early: "+ctx.Err().Error())
			return res, nil
		default:
		}
		f, note := a.probe(ctx, t, ep, p)
		if note != "" {
			res.Notes = append(res.Notes, note)
		}
		if f != nil {
			res.Findings = append(res.Findings, f...)
		}
	}
	if len(res.Findings) == 0 && len(res.Notes) == 0 {
		res.Notes = append(res.Notes, "no HTTP service was reachable on this target")
	}
	return res, nil
}

type endpoint struct {
	url  string
	port int
	tls  bool
}

// httpEndpoints decides what to probe: an explicit URL if the operator gave
// one, otherwise every open port that conventionally speaks HTTP.
func httpEndpoints(t Target, prior []*finding.Finding) []endpoint {
	if t.URL != "" {
		port := 80
		isTLS := strings.HasPrefix(strings.ToLower(t.URL), "https://")
		if isTLS {
			port = 443
		}
		return []endpoint{{url: t.URL, port: port, tls: isTLS}}
	}
	var eps []endpoint
	for _, port := range openPortsFrom(prior, t.Raw) {
		isTLS, ok := isHTTPPort(port)
		if !ok {
			continue
		}
		scheme := "http"
		if isTLS {
			scheme = "https"
		}
		eps = append(eps, endpoint{
			url:  fmt.Sprintf("%s://%s:%d/", scheme, t.Host, port),
			port: port, tls: isTLS,
		})
	}
	if len(eps) == 0 && len(openPortsFrom(prior, t.Raw)) == 0 {
		// Nothing known yet: try the two conventional ports directly.
		eps = []endpoint{
			{url: "https://" + t.Host + "/", port: 443, tls: true},
			{url: "http://" + t.Host + "/", port: 80, tls: false},
		}
	}
	sort.Slice(eps, func(i, j int) bool { return eps[i].port < eps[j].port })
	return eps
}

func newHTTPClient(p Policy) *http.Client {
	return &http.Client{
		Timeout: p.Timeout,
		Transport: &http.Transport{
			// Certificate problems are reported by the tlsaudit adapter. If the
			// probe refused to connect to a host with a bad certificate it
			// would report nothing at all about it, which is less useful and
			// less honest than connecting and saying what is wrong.
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // audited above
			TLSHandshakeTimeout:   p.DialTimeout,
			ResponseHeaderTimeout: p.Timeout,
			DisableKeepAlives:     true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func (a *HTTPProbe) probe(ctx context.Context, t Target, ep endpoint, p Policy) ([]*finding.Finding, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.url, nil)
	if err != nil {
		return nil, fmt.Sprintf("%s: malformed URL", ep.url)
	}
	req.Header.Set("User-Agent", "AuditLight/0.1 (+authorised security assessment)")
	req.Header.Set("Accept", "*/*")

	client := newHTTPClient(p)
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Sprintf("%s: %v", ep.url, condense(err.Error()))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	elapsed := time.Since(start)

	title := ""
	if m := titlePattern.FindSubmatch(body); m != nil {
		title = strings.TrimSpace(sanitise(string(m[1])))
		if len(title) > 120 {
			title = title[:120] + "…"
		}
	}

	f := finding.New(t.Raw, ep.port, finding.CategoryWeb, finding.SeverityInfo,
		finding.ConfidenceConfirmed,
		fmt.Sprintf("%s%d", sigHTTPPrefix, ep.port),
		fmt.Sprintf("HTTP service responding on port %d", ep.port),
		fmt.Sprintf("An HTTP service answered on %s with status %d in %s. This records the web surface that exists; the checks that follow inspect how it is configured.",
			ep.url, resp.StatusCode, elapsed.Round(time.Millisecond)),
		a.Name())
	f.Status = finding.StatusInformational
	f.AddEvidence("http", "url", ep.url)
	f.AddEvidence("http", "status", fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode)))
	if title != "" {
		f.AddEvidence("http", "title", title)
	}
	f.AddEvidence(evidenceHdrs, "response headers", formatHeaders(resp.Header))

	out := []*finding.Finding{f}

	// Server software disclosure.
	for _, h := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"} {
		v := resp.Header.Get(h)
		if v == "" {
			continue
		}
		sev := finding.SeverityInfo
		status := finding.StatusInformational
		if versionPattern.MatchString(v) {
			sev = finding.SeverityLow
			status = finding.StatusOpen
		}
		d := finding.New(t.Raw, ep.port, finding.CategoryWeb, sev,
			finding.ConfidenceConfirmed,
			fmt.Sprintf("header-disclosure:%d:%s", ep.port, strings.ToLower(h)),
			fmt.Sprintf("%s header discloses software details", h),
			fmt.Sprintf("The %s response header reveals %q. Published version numbers let an attacker match the host to known vulnerabilities from a distance, before touching it.", h, v),
			a.Name())
		d.Remediation = fmt.Sprintf("Remove or generalise the %s header at the web server or reverse proxy.", h)
		d.AddEvidence("header", h, v)
		d.Status = status
		out = append(out, d)
	}

	// Observable technology, from headers and body markers.
	if techs := fingerprint(resp.Header, body); len(techs) > 0 {
		d := finding.New(t.Raw, ep.port, finding.CategoryWeb, finding.SeverityInfo,
			finding.ConfidenceLikely,
			fmt.Sprintf("tech:%d", ep.port),
			"Technology stack observable from the response",
			"The response exposes markers identifying the technologies in use. This is inventory information: it is useful for your own asset register, and equally useful to anyone else.",
			a.Name())
		d.Status = finding.StatusInformational
		d.AddEvidence("fingerprint", "technologies", strings.Join(techs, ", "))
		out = append(out, d)
	}

	// Directory listing is a real disclosure, not just noise.
	if resp.StatusCode == http.StatusOK && looksLikeDirectoryListing(body) {
		d := finding.New(t.Raw, ep.port, finding.CategoryWeb, finding.SeverityMedium,
			finding.ConfidenceLikely,
			fmt.Sprintf("dirlist:%d", ep.port),
			"Directory listing appears to be enabled",
			"The response looks like an automatically generated index of files rather than a page. Directory listings disclose file names, backup copies and paths that were never meant to be advertised.",
			a.Name())
		d.Remediation = "Disable automatic directory indexing (for example `autoindex off` in nginx or `Options -Indexes` in Apache) and place an index file in the directory."
		d.AddEvidence("http", "url", ep.url)
		out = append(out, d)
	}

	return out, ""
}

func formatHeaders(h http.Header) string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		for _, v := range h[k] {
			fmt.Fprintf(&b, "%s: %s\n", k, sanitise(v))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

var techMarkers = []struct {
	name   string
	header string
	value  string
	body   string
}{
	{name: "WordPress", body: "/wp-content/"},
	{name: "Drupal", header: "X-Drupal-Cache"},
	{name: "Joomla", body: "/media/jui/"},
	{name: "Laravel", header: "Set-Cookie", value: "laravel_session"},
	{name: "Django", header: "Set-Cookie", value: "csrftoken"},
	{name: "Express", header: "X-Powered-By", value: "Express"},
	{name: "PHP", header: "X-Powered-By", value: "PHP"},
	{name: "ASP.NET", header: "X-AspNet-Version"},
	{name: "nginx", header: "Server", value: "nginx"},
	{name: "Apache httpd", header: "Server", value: "Apache"},
	{name: "Microsoft IIS", header: "Server", value: "IIS"},
	{name: "Caddy", header: "Server", value: "Caddy"},
	{name: "Cloudflare", header: "Server", value: "cloudflare"},
	{name: "React", body: "__REACT_DEVTOOLS_GLOBAL_HOOK__"},
	{name: "Next.js", header: "X-Powered-By", value: "Next.js"},
	{name: "Vue.js", body: "data-v-app"},
	{name: "Grafana", body: "grafana-app"},
	{name: "Jenkins", header: "X-Jenkins"},
	{name: "Kibana", header: "kbn-name"},
}

func fingerprint(h http.Header, body []byte) []string {
	var out []string
	seen := map[string]bool{}
	lowerBody := strings.ToLower(string(body))
	for _, m := range techMarkers {
		hit := false
		switch {
		case m.header != "" && m.value != "":
			hit = strings.Contains(strings.ToLower(strings.Join(h.Values(m.header), " ")), strings.ToLower(m.value))
		case m.header != "":
			hit = h.Get(m.header) != ""
		case m.body != "":
			hit = strings.Contains(lowerBody, strings.ToLower(m.body))
		}
		if hit && !seen[m.name] {
			seen[m.name] = true
			out = append(out, m.name)
		}
	}
	sort.Strings(out)
	return out
}

func looksLikeDirectoryListing(body []byte) bool {
	s := strings.ToLower(string(body))
	return strings.Contains(s, "<title>index of /") ||
		(strings.Contains(s, "directory listing for") && strings.Contains(s, "<ul>"))
}

func condense(s string) string {
	s = sanitise(s)
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}

// Headers evaluates security header posture. It is a derived adapter: it reads
// the headers httpprobe already captured rather than issuing fresh requests.
type Headers struct{}

func (*Headers) Name() string { return "headers" }
func (*Headers) Kind() Kind   { return KindNative }
func (*Headers) Stage() Stage { return StageDerived }
func (*Headers) Describe() string {
	return "Evaluates security headers and cookie flags from responses already captured."
}
func (*Headers) Available() (bool, string) { return true, "" }

type headerCheck struct {
	header   string
	severity finding.Severity
	title    string
	why      string
	fix      string
}

var headerChecks = []headerCheck{
	{
		header: "Strict-Transport-Security", severity: finding.SeverityMedium,
		title: "HSTS is not set",
		why:   "Without Strict-Transport-Security a browser will still try plain HTTP first, which leaves room for an attacker on the path to keep the connection unencrypted.",
		fix:   "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` over HTTPS, after confirming every subdomain can serve TLS.",
	},
	{
		header: "Content-Security-Policy", severity: finding.SeverityMedium,
		title: "Content Security Policy is not set",
		why:   "Without a CSP the browser will execute any script the page references. A CSP is the main structural defence against cross-site scripting.",
		fix:   "Introduce a Content-Security-Policy, starting in report-only mode to find breakage before enforcing it.",
	},
	{
		header: "X-Content-Type-Options", severity: finding.SeverityLow,
		title: "X-Content-Type-Options is not set",
		why:   "Without `nosniff` a browser may second-guess the declared content type and execute a file the server meant to serve as data.",
		fix:   "Send `X-Content-Type-Options: nosniff`.",
	},
	{
		header: "X-Frame-Options", severity: finding.SeverityLow,
		title: "Framing is not restricted",
		why:   "Neither X-Frame-Options nor a CSP frame-ancestors directive is present, so the page can be embedded in another site and used for clickjacking.",
		fix:   "Send `X-Frame-Options: DENY`, or better, a `frame-ancestors` directive in the Content-Security-Policy.",
	},
	{
		header: "Referrer-Policy", severity: finding.SeverityLow,
		title: "Referrer-Policy is not set",
		why:   "Without a referrer policy the full URL, including anything sensitive in the path or query, is sent to third-party sites the page links to.",
		fix:   "Send `Referrer-Policy: strict-origin-when-cross-origin`.",
	},
}

func (a *Headers) Run(_ context.Context, t Target, _ Policy, prior []*finding.Finding) (Result, error) {
	var res Result
	found := false

	for _, pf := range prior {
		if pf.Target != t.Raw || !strings.HasPrefix(pf.Signature(), sigHTTPPrefix) {
			continue
		}
		raw := evidenceValue(pf, evidenceHdrs)
		if raw == "" {
			continue
		}
		found = true
		hdrs := parseHeaderBlock(raw)
		port := pf.Port
		secure := port == 443 || port == 8443

		for _, c := range headerChecks {
			if _, ok := hdrs[strings.ToLower(c.header)]; ok {
				continue
			}
			// Framing may be covered by a CSP directive instead.
			if c.header == "X-Frame-Options" {
				if csp, ok := hdrs["content-security-policy"]; ok && strings.Contains(strings.ToLower(csp), "frame-ancestors") {
					continue
				}
			}
			// HSTS only means anything over HTTPS.
			if c.header == "Strict-Transport-Security" && !secure {
				continue
			}
			f := finding.New(t.Raw, port, finding.CategoryWeb, c.severity,
				finding.ConfidenceConfirmed,
				fmt.Sprintf("missing-header:%d:%s", port, strings.ToLower(c.header)),
				c.title, c.why, a.Name())
			f.Remediation = c.fix
			f.CWE = []string{"CWE-693"}
			f.AddEvidence("header", "absent", c.header+" was not present in the response")
			res.Findings = append(res.Findings, f)
		}

		// Cookie flags.
		for _, sc := range hdrs.values("set-cookie") {
			lower := strings.ToLower(sc)
			name := sc
			if i := strings.Index(sc, "="); i > 0 {
				name = sc[:i]
			}
			var missing []string
			if !strings.Contains(lower, "httponly") {
				missing = append(missing, "HttpOnly")
			}
			if secure && !strings.Contains(lower, "secure") {
				missing = append(missing, "Secure")
			}
			if !strings.Contains(lower, "samesite") {
				missing = append(missing, "SameSite")
			}
			if len(missing) == 0 {
				continue
			}
			f := finding.New(t.Raw, port, finding.CategoryWeb, finding.SeverityLow,
				finding.ConfidenceConfirmed,
				fmt.Sprintf("cookie-flags:%d:%s", port, strings.ToLower(name)),
				fmt.Sprintf("Cookie %q is missing %s", name, strings.Join(missing, " and ")),
				fmt.Sprintf("The cookie %q is set without %s. Missing flags widen how a cookie can be read or sent: HttpOnly keeps it away from scripts, Secure keeps it off plain HTTP, and SameSite limits cross-site submission.", name, strings.Join(missing, ", ")),
				a.Name())
			f.Remediation = "Set the missing attributes when issuing the cookie."
			f.CWE = []string{"CWE-1004"}
			f.AddEvidence("header", "Set-Cookie", sc)
			res.Findings = append(res.Findings, f)
		}
	}

	if !found {
		res.Notes = append(res.Notes, "no captured HTTP response was available to evaluate headers against")
	}
	return res, nil
}

type headerMap map[string]string

func (h headerMap) values(k string) []string {
	v, ok := h[k]
	if !ok || v == "" {
		return nil
	}
	return strings.Split(v, "\x00")
}

func parseHeaderBlock(raw string) headerMap {
	m := headerMap{}
	for _, line := range strings.Split(raw, "\n") {
		i := strings.Index(line, ":")
		if i <= 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(line[:i]))
		v := strings.TrimSpace(line[i+1:])
		if cur, ok := m[k]; ok {
			m[k] = cur + "\x00" + v
		} else {
			m[k] = v
		}
	}
	return m
}

func evidenceValue(f *finding.Finding, kind string) string {
	for _, e := range f.Evidence {
		if e.Kind == kind {
			return e.Value
		}
	}
	return ""
}
