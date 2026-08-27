package adapters

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nizartuanku/auditlight/internal/finding"
)

func TestNewTargetParsing(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantURL  bool
	}{
		{"example.com", "example.com", false},
		{"https://app.example.com/x?y=1", "app.example.com", true},
		{"http://example.com:8080/", "example.com", true},
		{"EXAMPLE.com.", "example.com", false},
		{"192.0.2.1:443", "192.0.2.1", false},
		{"[2001:db8::1]", "2001:db8::1", false},
	}
	for _, tc := range cases {
		got := NewTarget(tc.in)
		if got.Host != tc.wantHost {
			t.Errorf("NewTarget(%q).Host = %q, want %q", tc.in, got.Host, tc.wantHost)
		}
		if (got.URL != "") != tc.wantURL {
			t.Errorf("NewTarget(%q).URL = %q, wantURL=%v", tc.in, got.URL, tc.wantURL)
		}
	}
}

func TestVersionComparison(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2", "1.2.0", 0},
		{"8", "8.0.0", 0},
		{"1.2.3", "1.2.4", -1},
		{"2.0", "1.9.9", 1},
		{"9.3p1", "9.3", 0},
		{"7.4", "9.3", -1},
		{"1.20.1", "1.20.0", 1},
	}
	for _, tc := range cases {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestSanitiseStripsControlCharacters(t *testing.T) {
	in := "SSH-2.0-OpenSSH_7.2\x00\x1b[31mred\x07\nnext"
	got := sanitise(in)
	if strings.ContainsAny(got, "\x00\x07\x1b") {
		t.Fatalf("control characters survived: %q", got)
	}
	if !strings.Contains(got, "OpenSSH_7.2") {
		t.Fatalf("useful content lost: %q", got)
	}
}

func TestShannonEntropySeparatesKeysFromPlaceholders(t *testing.T) {
	if h := shannon("aaaaaaaaaaaaaaaa"); h > 1 {
		t.Fatalf("repeated characters should have near-zero entropy, got %v", h)
	}
	if h := shannon("wJalrXUtnFEMI7K9bPxRfiCYEXAMPLEKEY123456"); h < 3.5 {
		t.Fatalf("a random-looking key should have high entropy, got %v", h)
	}
}

func TestRedactMasksTheSecret(t *testing.T) {
	// Assembled rather than written out. The value is invented — nothing was
	// ever issued against it — but a literal that looks like a live key trips
	// hosted secret scanning on every push, for the maintainer and for anyone
	// who forks this. Splitting it costs nothing and spares everyone the
	// habit of clicking through a security warning.
	secret := "sk_" + "live_" + "abcdefghijklmnop12345678"
	line := `api_key = "` + secret + `"`
	got := redact(line, secret)
	if strings.Contains(got, secret) {
		t.Fatalf("the full secret must never appear in a report: %q", got)
	}
	if !strings.Contains(got, "api_key") {
		t.Fatalf("context should survive redaction: %q", got)
	}
}

func TestPlaceholderPatternRejectsObviousNonSecrets(t *testing.T) {
	for _, s := range []string{"CHANGEME", "your-api-key", "xxxxxxxx", "<token>", "${SECRET}", "placeholder", "REDACTED"} {
		if !placeholderPattern.MatchString(s) {
			t.Errorf("%q should be treated as a placeholder", s)
		}
	}
	for _, s := range []string{"wJalrXUtnFEMI7K9bPxRfiCY", "ghp_" + "1234567890abcdefghij"} {
		if placeholderPattern.MatchString(s) {
			t.Errorf("%q should not be treated as a placeholder", s)
		}
	}
}

func TestSecretsAdapterFindsAndRedacts(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\nPASSWORD=\"CHANGEME\"\n")
	write("id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----\n")
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0o750); err != nil {
		t.Fatal(err)
	}
	write("node_modules/leak.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	p := DefaultPolicy()
	p.ScanPath = dir
	res, err := (&Secrets{}).Run(context.Background(), NewTarget("localhost"), p, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res.Findings) < 2 {
		t.Fatalf("expected the AWS key and the private key, got %d finding(s)", len(res.Findings))
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Target, "node_modules") {
			t.Fatal("dependency directories must be skipped")
		}
		for _, e := range f.Evidence {
			if strings.Contains(e.Value, "AKIAIOSFODNN7EXAMPLE") {
				t.Fatalf("the raw secret leaked into evidence: %q", e.Value)
			}
		}
	}
	// The placeholder password must not have produced a finding.
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "password") && strings.Contains(f.Title, "config.env") {
			t.Fatal("a CHANGEME placeholder should not be reported as a secret")
		}
	}
	if len(res.Notes) == 0 {
		t.Fatal("the scan should report what it covered")
	}
}

func TestSecretsAdapterSaysSoWhenNoPathGiven(t *testing.T) {
	res, err := (&Secrets{}).Run(context.Background(), NewTarget("example.com"), DefaultPolicy(), nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatal("no path means no findings")
	}
	if len(res.Notes) == 0 || !strings.Contains(res.Notes[0], "did not run") {
		t.Fatalf("the adapter must say it did not run: %v", res.Notes)
	}
}

func TestHTTPProbeAndHeadersAgainstLocalServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Powered-By", "PHP/7.2.1")
		w.Header().Set("Set-Cookie", "session=abc; Path=/")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html><head><title>Test Service</title></head><body>hi</body></html>"))
	}))
	defer srv.Close()

	target := NewTarget(srv.URL)
	p := DefaultPolicy()

	probe := &HTTPProbe{}
	res, err := probe.Run(context.Background(), target, p, nil)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("probing a live server should produce findings")
	}

	var sawService, sawServerHeader bool
	for _, f := range res.Findings {
		if strings.HasPrefix(f.Signature(), sigHTTPPrefix) {
			sawService = true
			if evidenceValue(f, evidenceHdrs) == "" {
				t.Fatal("the service finding must capture the response headers")
			}
		}
		if strings.Contains(f.Title, "Server header") {
			sawServerHeader = true
		}
	}
	if !sawService {
		t.Fatal("no HTTP service finding was produced")
	}
	if !sawServerHeader {
		t.Fatal("the version-bearing Server header should be reported")
	}

	// The derived headers adapter reads what the probe captured.
	hres, err := (&Headers{}).Run(context.Background(), target, p, res.Findings)
	if err != nil {
		t.Fatalf("headers: %v", err)
	}
	var missingCSP, cookieFlags bool
	for _, f := range hres.Findings {
		if strings.Contains(f.Title, "Content Security Policy") {
			missingCSP = true
		}
		if strings.Contains(f.Title, "missing") && strings.Contains(f.Title, "session") {
			cookieFlags = true
		}
	}
	if !missingCSP {
		t.Fatal("a missing CSP should be reported")
	}
	if !cookieFlags {
		t.Fatal("a cookie without HttpOnly or SameSite should be reported")
	}

	// vulnsig derives from the same evidence.
	vres, err := (&VulnSig{}).Run(context.Background(), target, p, res.Findings)
	if err != nil {
		t.Fatalf("vulnsig: %v", err)
	}
	var flaggedPHP bool
	for _, f := range vres.Findings {
		if strings.Contains(f.Title, "PHP") && f.Severity != finding.SeverityInfo {
			flaggedPHP = true
			if f.Confidence == finding.ConfidenceConfirmed {
				t.Fatal("a version-derived finding must never be reported as confirmed")
			}
			if !strings.Contains(f.Description, "back-port") {
				t.Fatal("the finding must explain the back-porting caveat")
			}
		}
	}
	if !flaggedPHP {
		t.Fatal("PHP 7.2.1 should match an end-of-life signature")
	}
}

func TestPortScanFindsAListeningPort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	target := NewTarget(srv.URL)
	port := portOf(t, srv.URL)

	p := DefaultPolicy()
	p.Ports = []int{port, port + 1}

	res, err := (&PortScan{}).Run(context.Background(), target, p, nil)
	if err != nil {
		t.Fatalf("portscan: %v", err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Port == port {
			found = true
			if f.Confidence != finding.ConfidenceConfirmed {
				t.Fatal("a completed handshake is direct observation")
			}
		}
	}
	if !found {
		t.Fatalf("the listening port %d was not found", port)
	}
}

func TestTLSAuditReadsASelfSignedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	port := portOf(t, srv.URL)
	target := NewTarget("127.0.0.1")
	p := DefaultPolicy()

	// Feed the audit an open-port finding so it knows where to look.
	prior := []*finding.Finding{
		finding.New(target.Raw, port, finding.CategoryNetwork, finding.SeverityInfo,
			finding.ConfidenceConfirmed, "open-port:"+itoa(port), "open", "d", "portscan"),
	}
	// The conventional-port heuristic only recognises 443/8443, so drive the
	// per-port audit directly.
	fs, note := (&TLSAudit{}).auditPort(context.Background(), target, port, p)
	_ = prior
	if note != "" && len(fs) == 0 {
		t.Skipf("TLS handshake unavailable in this environment: %s", note)
	}
	var sawConnection bool
	for _, f := range fs {
		if strings.Contains(f.Title, "TLS connection details") {
			sawConnection = true
		}
	}
	if !sawConnection {
		t.Fatal("the audit should always record what was negotiated")
	}
}

func TestExecAdapterRefusesWithoutPaidTier(t *testing.T) {
	a := newExecAdapter(execSpecNuclei())
	p := DefaultPolicy()
	p.AllowSubprocess = false
	res, err := a.Run(context.Background(), NewTarget("example.com"), p, nil)
	if err != nil {
		t.Fatalf("an unavailable tool is not an error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatal("no findings should be produced")
	}
	if len(res.Notes) == 0 || !strings.Contains(res.Notes[0], "paid licence") {
		t.Fatalf("the reason must be recorded: %v", res.Notes)
	}
}

func TestExecAdapterRefusesFlagLikeTarget(t *testing.T) {
	a := newExecAdapter(execSpecNmap())
	p := DefaultPolicy()
	p.AllowSubprocess = true
	if ok, _ := a.Available(); !ok {
		t.Skip("nmap is not installed here")
	}
	_, err := a.Run(context.Background(), NewTarget("--script=exploit"), p, nil)
	if err == nil {
		t.Fatal("a target that looks like a flag must be refused")
	}
}

func TestRegistryCapabilitiesCoverEveryAdapter(t *testing.T) {
	r := NewRegistry()
	caps := r.Capabilities()
	if len(caps) != len(r.All()) {
		t.Fatalf("capabilities = %d, adapters = %d", len(caps), len(r.All()))
	}
	native := 0
	for _, c := range caps {
		if c.Describe == "" {
			t.Fatalf("adapter %q has no description", c.Name)
		}
		if c.Kind == KindNative {
			native++
			if !c.Available {
				t.Fatalf("native adapter %q must always be available", c.Name)
			}
		}
		if !c.Available && c.Reason == "" {
			t.Fatalf("adapter %q is unavailable with no reason given", c.Name)
		}
	}
	if native < 8 {
		t.Fatalf("native adapters = %d; the binary should stand alone", native)
	}
}

func TestDeniedFlagsAreNeverInASpec(t *testing.T) {
	specs := []execSpec{execSpecNuclei(), execSpecTestSSL(), execSpecLynis(), execSpecNmap()}
	for _, s := range specs {
		args := s.args(NewTarget("example.com"), t.TempDir())
		for _, a := range args {
			for _, bad := range deniedFlags {
				if strings.EqualFold(a, bad) {
					t.Fatalf("spec %q would pass the forbidden flag %q", s.name, bad)
				}
			}
		}
	}
}

func TestNucleiSpecAlwaysExcludesIntrusiveTemplates(t *testing.T) {
	args := execSpecNuclei().args(NewTarget("https://example.com"), t.TempDir())
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-etags intrusive,dos,fuzz") {
		t.Fatalf("intrusive templates must always be excluded: %s", joined)
	}
	if !strings.Contains(joined, "-no-interactsh") {
		t.Fatalf("out-of-band callbacks must be disabled: %s", joined)
	}
}

func TestFormatAndParseHeadersRoundTrip(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "a=1")
	h.Add("Set-Cookie", "b=2")
	h.Set("Server", "nginx")
	block := formatHeaders(h)
	m := parseHeaderBlock(block)
	if m["server"] != "nginx" {
		t.Fatalf("server = %q", m["server"])
	}
	if got := m.values("set-cookie"); len(got) != 2 {
		t.Fatalf("set-cookie values = %v, want two", got)
	}
}

func TestIsHTTPPort(t *testing.T) {
	if isTLS, ok := isHTTPPort(443); !ok || !isTLS {
		t.Fatal("443 is HTTPS")
	}
	if isTLS, ok := isHTTPPort(80); !ok || isTLS {
		t.Fatal("80 is plain HTTP")
	}
	if _, ok := isHTTPPort(22); ok {
		t.Fatal("22 is not an HTTP port")
	}
}

func TestExposureRiskFlagsDatastores(t *testing.T) {
	if sev, _ := exposureRisk(6379); sev != finding.SeverityHigh {
		t.Fatalf("redis severity = %q", sev)
	}
	if sev, _ := exposureRisk(2375); sev != finding.SeverityCritical {
		t.Fatalf("unauthenticated docker api severity = %q", sev)
	}
	if sev, _ := exposureRisk(443); sev != "" {
		t.Fatalf("https should carry no inherent exposure risk, got %q", sev)
	}
}

// helpers

func portOf(t *testing.T, rawURL string) int {
	t.Helper()
	i := strings.LastIndex(rawURL, ":")
	if i < 0 {
		t.Fatalf("no port in %q", rawURL)
	}
	p := 0
	for _, c := range rawURL[i+1:] {
		if c < '0' || c > '9' {
			break
		}
		p = p*10 + int(c-'0')
	}
	if p == 0 {
		t.Fatalf("could not parse port from %q", rawURL)
	}
	return p
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

var _ = tls.VersionTLS12
