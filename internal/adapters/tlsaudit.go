package adapters

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/nizartuanku/auditlight/internal/finding"
)

// TLSAudit inspects TLS configuration and certificates.
//
// Everything here is negotiation only: the adapter offers a protocol version or
// a cipher and observes whether the server agrees. No traffic is decrypted and
// no weakness is exercised beyond establishing that the server would accept it.
type TLSAudit struct{}

func (*TLSAudit) Name() string { return "tlsaudit" }
func (*TLSAudit) Kind() Kind   { return KindNative }
func (*TLSAudit) Stage() Stage { return StageService }
func (*TLSAudit) Describe() string {
	return "Checks TLS protocol versions, cipher strength and certificate validity."
}
func (*TLSAudit) Available() (bool, string) { return true, "" }

// expiryWarning is when a certificate becomes a finding rather than a fact.
const expiryWarning = 30 * 24 * time.Hour

func (a *TLSAudit) Run(ctx context.Context, t Target, p Policy, prior []*finding.Finding) (Result, error) {
	var res Result
	for _, port := range tlsPorts(t, prior) {
		select {
		case <-ctx.Done():
			res.Notes = append(res.Notes, "TLS audit stopped early: "+ctx.Err().Error())
			return res, nil
		default:
		}
		fs, note := a.auditPort(ctx, t, port, p)
		if note != "" {
			res.Notes = append(res.Notes, note)
		}
		res.Findings = append(res.Findings, fs...)
	}
	if len(res.Findings) == 0 && len(res.Notes) == 0 {
		res.Notes = append(res.Notes, "no TLS service was reachable on this target")
	}
	return res, nil
}

func tlsPorts(t Target, prior []*finding.Finding) []int {
	var ports []int
	seen := map[int]bool{}
	for _, port := range openPortsFrom(prior, t.Raw) {
		if isTLS, ok := isHTTPPort(port); ok && isTLS {
			if !seen[port] {
				seen[port] = true
				ports = append(ports, port)
			}
		}
	}
	// Other conventional TLS ports.
	for _, port := range openPortsFrom(prior, t.Raw) {
		switch port {
		case 465, 636, 993, 995:
			if !seen[port] {
				seen[port] = true
				ports = append(ports, port)
			}
		}
	}
	if len(ports) == 0 {
		if t.URL != "" && !strings.HasPrefix(strings.ToLower(t.URL), "https://") {
			return nil
		}
		ports = []int{443}
	}
	return ports
}

// handshake attempts a TLS handshake with the given constraints and returns the
// negotiated state.
func handshake(ctx context.Context, p Policy, host string, port int, cfg *tls.Config) (tls.ConnectionState, error) {
	var zero tls.ConnectionState
	raw, err := dial(ctx, p, host, port)
	if err != nil {
		return zero, err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(p.Timeout))
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return zero, err
	}
	st := conn.ConnectionState()
	conn.Close()
	return st, nil
}

func (a *TLSAudit) auditPort(ctx context.Context, t Target, port int, p Policy) ([]*finding.Finding, string) {
	serverName := t.Host
	if net.ParseIP(serverName) != nil {
		// SNI is not valid for a bare IP; leave it empty and rely on the
		// default certificate.
		serverName = ""
	}

	base := func(minV, maxV uint16, ciphers []uint16) *tls.Config {
		return &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, //nolint:gosec // validity is assessed explicitly below
			MinVersion:         minV,
			MaxVersion:         maxV,
			CipherSuites:       ciphers,
		}
	}

	// Baseline handshake to obtain the certificate chain.
	st, err := handshake(ctx, p, t.Host, port, base(tls.VersionTLS10, tls.VersionTLS13, nil))
	if err != nil {
		return nil, fmt.Sprintf("%s:%d: TLS handshake failed: %s", t.Host, port, condense(err.Error()))
	}

	var out []*finding.Finding
	out = append(out, a.protocolFindings(ctx, t, port, p, base)...)
	out = append(out, a.cipherFindings(ctx, t, port, p, base)...)
	out = append(out, a.certificateFindings(t, port, st, serverName)...)
	return out, ""
}

type versionProbe struct {
	version  uint16
	label    string
	severity finding.Severity
	why      string
	fix      string
}

func (a *TLSAudit) protocolFindings(ctx context.Context, t Target, port int, p Policy, base func(uint16, uint16, []uint16) *tls.Config) []*finding.Finding {
	probes := []versionProbe{
		{tls.VersionTLS10, "TLS 1.0", finding.SeverityMedium,
			"The server still accepts TLS 1.0. It was deprecated in 2021 (RFC 8996); its cipher constructions are no longer considered sound and major browsers refuse it.",
			"Disable TLS 1.0 and 1.1, and require TLS 1.2 as a minimum."},
		{tls.VersionTLS11, "TLS 1.1", finding.SeverityMedium,
			"The server still accepts TLS 1.1, deprecated alongside TLS 1.0 in RFC 8996.",
			"Disable TLS 1.1 and require TLS 1.2 as a minimum."},
	}

	var out []*finding.Finding
	supported := map[string]bool{}

	for _, pr := range probes {
		if _, err := handshake(ctx, p, t.Host, port, base(pr.version, pr.version, nil)); err == nil {
			supported[pr.label] = true
			f := finding.New(t.Raw, port, finding.CategoryTLS, pr.severity,
				finding.ConfidenceConfirmed,
				fmt.Sprintf("tls-version:%d:%s", port, pr.label),
				fmt.Sprintf("%s is still accepted", pr.label),
				pr.why, a.Name())
			f.Remediation = pr.fix
			f.AddEvidence("tls", "negotiated", fmt.Sprintf("handshake completed with %s on %s:%d", pr.label, t.Host, port))
			out = append(out, f)
		}
	}

	// Note modern support as context, not as a defect.
	for _, v := range []struct {
		ver   uint16
		label string
	}{{tls.VersionTLS12, "TLS 1.2"}, {tls.VersionTLS13, "TLS 1.3"}} {
		if _, err := handshake(ctx, p, t.Host, port, base(v.ver, v.ver, nil)); err == nil {
			supported[v.label] = true
		}
	}
	if !supported["TLS 1.3"] && supported["TLS 1.2"] {
		f := finding.New(t.Raw, port, finding.CategoryTLS, finding.SeverityLow,
			finding.ConfidenceConfirmed,
			fmt.Sprintf("tls-no13:%d", port),
			"TLS 1.3 is not offered",
			"The server negotiates TLS 1.2 but not TLS 1.3. TLS 1.3 removes the legacy constructions that most TLS attacks rely on and completes the handshake in fewer round trips.",
			a.Name())
		f.Remediation = "Enable TLS 1.3 alongside TLS 1.2."
		out = append(out, f)
	}

	var labels []string
	for l := range supported {
		labels = append(labels, l)
	}
	if len(labels) > 0 {
		f := finding.New(t.Raw, port, finding.CategoryTLS, finding.SeverityInfo,
			finding.ConfidenceConfirmed,
			fmt.Sprintf("tls-versions:%d", port),
			"TLS protocol versions accepted",
			"Record of which protocol versions completed a handshake.", a.Name())
		f.Status = finding.StatusInformational
		f.AddEvidence("tls", "accepted versions", strings.Join(sortedStrings(labels), ", "))
		out = append(out, f)
	}
	return out
}

func (a *TLSAudit) cipherFindings(ctx context.Context, t Target, port int, p Policy, base func(uint16, uint16, []uint16) *tls.Config) []*finding.Finding {
	var weak []string
	// tls.InsecureCipherSuites is Go's own list of suites it implements but
	// considers unsafe. Offering exactly one at a time tells us whether the
	// server would accept it.
	for _, cs := range tls.InsecureCipherSuites() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		cfg := base(tls.VersionTLS10, tls.VersionTLS12, []uint16{cs.ID})
		if _, err := handshake(ctx, p, t.Host, port, cfg); err == nil {
			weak = append(weak, cs.Name)
		}
	}
	if len(weak) == 0 {
		return nil
	}
	f := finding.New(t.Raw, port, finding.CategoryTLS, finding.SeverityMedium,
		finding.ConfidenceConfirmed,
		fmt.Sprintf("tls-weak-cipher:%d", port),
		fmt.Sprintf("%d cipher suite(s) considered insecure are accepted", len(weak)),
		"The server completed a handshake using cipher suites that are no longer considered safe. These include constructions vulnerable to known padding and stream-cipher attacks.",
		a.Name())
	f.Remediation = "Restrict the cipher list to AEAD suites (AES-GCM or ChaCha20-Poly1305) with forward secrecy, and remove RC4, 3DES and CBC-mode suites."
	f.AddEvidence("tls", "accepted weak suites", strings.Join(sortedStrings(weak), ", "))
	f.CWE = []string{"CWE-327"}
	return []*finding.Finding{f}
}

func (a *TLSAudit) certificateFindings(t Target, port int, st tls.ConnectionState, serverName string) []*finding.Finding {
	if len(st.PeerCertificates) == 0 {
		return nil
	}
	leaf := st.PeerCertificates[0]
	now := time.Now()
	var out []*finding.Finding

	newf := func(sev finding.Severity, sig, title, desc, fix string) *finding.Finding {
		f := finding.New(t.Raw, port, finding.CategoryTLS, sev, finding.ConfidenceConfirmed,
			fmt.Sprintf("%s:%d", sig, port), title, desc, "tlsaudit")
		f.Remediation = fix
		f.AddEvidence("certificate", "subject", leaf.Subject.String())
		f.AddEvidence("certificate", "issuer", leaf.Issuer.String())
		f.AddEvidence("certificate", "validity", fmt.Sprintf("%s → %s",
			leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339)))
		out = append(out, f)
		return f
	}

	switch {
	case now.After(leaf.NotAfter):
		newf(finding.SeverityHigh, "cert-expired", "Certificate has expired",
			fmt.Sprintf("The certificate expired on %s. Clients will refuse the connection or warn loudly, and users learn to click through warnings.",
				leaf.NotAfter.UTC().Format("2 January 2006")),
			"Renew the certificate and automate renewal so the next expiry is not a surprise.")
	case now.Before(leaf.NotBefore):
		newf(finding.SeverityHigh, "cert-not-yet-valid", "Certificate is not yet valid",
			fmt.Sprintf("The certificate becomes valid on %s. Until then clients will reject it.",
				leaf.NotBefore.UTC().Format("2 January 2006")),
			"Check the certificate issuance and the system clock on the server.")
	case leaf.NotAfter.Sub(now) < expiryWarning:
		days := int(leaf.NotAfter.Sub(now).Hours() / 24)
		newf(finding.SeverityMedium, "cert-expiring", fmt.Sprintf("Certificate expires in %d day(s)", days),
			fmt.Sprintf("The certificate expires on %s. Renewal that depends on someone remembering is the usual cause of an outage here.",
				leaf.NotAfter.UTC().Format("2 January 2006")),
			"Renew now and automate renewal with monitoring on the expiry date.")
	}

	// Self-signed: subject equals issuer and it is not a recognised CA chain.
	if leaf.Subject.String() == leaf.Issuer.String() {
		newf(finding.SeverityMedium, "cert-self-signed", "Certificate is self-signed",
			"The certificate is its own issuer. Clients cannot establish trust without manual pinning, so warnings become routine and a genuine interception attempt looks the same as a normal day.",
			"Issue the certificate from a trusted CA. For internal services, use an internal CA distributed to clients.")
	}

	// Hostname match.
	if serverName != "" {
		if err := leaf.VerifyHostname(serverName); err != nil {
			f := newf(finding.SeverityMedium, "cert-hostname", "Certificate does not cover this hostname",
				fmt.Sprintf("The certificate presented on %s is not valid for that name. Clients will warn, and the mismatch usually means a default virtual host is answering.", serverName),
				"Issue or install a certificate whose subject alternative names include this hostname.")
			f.AddEvidence("certificate", "names", strings.Join(leaf.DNSNames, ", "))
		}
	}

	// Chain trust, evaluated against the system roots.
	if serverName != "" {
		opts := x509.VerifyOptions{DNSName: serverName, Intermediates: x509.NewCertPool()}
		for _, c := range st.PeerCertificates[1:] {
			opts.Intermediates.AddCert(c)
		}
		if _, err := leaf.Verify(opts); err != nil && leaf.Subject.String() != leaf.Issuer.String() {
			f := newf(finding.SeverityMedium, "cert-chain", "Certificate chain does not verify",
				"The presented chain could not be verified against the system trust store. A missing intermediate is the usual cause, and it breaks clients that do not fetch it themselves.",
				"Serve the full chain, including intermediates, from the web server.")
			f.AddEvidence("certificate", "verification error", condense(err.Error()))
		}
	}

	// Signature algorithm.
	switch leaf.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1, x509.MD5WithRSA:
		f := newf(finding.SeverityHigh, "cert-weak-sig", "Certificate uses a weak signature algorithm",
			fmt.Sprintf("The certificate is signed with %s. Practical collision attacks against SHA-1 and MD5 mean such a signature no longer proves what it should.", leaf.SignatureAlgorithm),
			"Reissue the certificate with a SHA-256 or stronger signature.")
		f.CWE = []string{"CWE-327"}
	}

	// Key strength.
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if bits := pub.N.BitLen(); bits < 2048 {
			f := newf(finding.SeverityHigh, "cert-weak-key", fmt.Sprintf("RSA key is only %d bits", bits),
				fmt.Sprintf("The certificate carries a %d-bit RSA key. Anything below 2048 bits is outside current guidance.", bits),
				"Reissue with at least a 2048-bit RSA key, or an ECDSA P-256 key.")
			f.CWE = []string{"CWE-326"}
		}
	case *ecdsa.PublicKey:
		if pub.Curve.Params().BitSize < 256 {
			newf(finding.SeverityHigh, "cert-weak-key", "ECDSA curve is below 256 bits",
				"The certificate uses an elliptic curve smaller than P-256, which is below current guidance.",
				"Reissue with P-256 or stronger.")
		}
	case ed25519.PublicKey:
		// Ed25519 is fine.
	}

	// Long validity periods concentrate risk on a single key.
	if leaf.NotAfter.Sub(leaf.NotBefore) > 400*24*time.Hour {
		f := newf(finding.SeverityLow, "cert-long-validity", "Certificate validity period is unusually long",
			fmt.Sprintf("The certificate is valid for %d days. Public CAs are limited to around 398 days; a longer window means a compromised key stays useful for longer.",
				int(leaf.NotAfter.Sub(leaf.NotBefore).Hours()/24)),
			"Shorten the validity period and automate renewal.")
		f.Status = finding.StatusOpen
	}

	// Record what was negotiated, as context.
	ctxf := finding.New(t.Raw, port, finding.CategoryTLS, finding.SeverityInfo,
		finding.ConfidenceConfirmed,
		fmt.Sprintf("tls-connection:%d", port),
		"TLS connection details",
		"Record of the protocol version, cipher suite and certificate observed.", "tlsaudit")
	ctxf.Status = finding.StatusInformational
	ctxf.AddEvidence("tls", "version", tlsVersionName(st.Version))
	ctxf.AddEvidence("tls", "cipher", tls.CipherSuiteName(st.CipherSuite))
	ctxf.AddEvidence("certificate", "subject", leaf.Subject.String())
	ctxf.AddEvidence("certificate", "expires", leaf.NotAfter.UTC().Format("2 January 2006"))
	if len(leaf.DNSNames) > 0 {
		ctxf.AddEvidence("certificate", "names", strings.Join(leaf.DNSNames, ", "))
	}
	out = append(out, ctxf)

	return out
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "0x" + strconv.FormatUint(uint64(v), 16)
	}
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
