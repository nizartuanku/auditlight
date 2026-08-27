package adapters

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nizartuanku/auditlight/internal/finding"
)

// PortScan finds reachable TCP services with a plain connect scan.
//
// A connect scan completes the handshake and closes. It sends no payload and
// leaves an ordinary entry in the target's logs, which is the behaviour an
// audit should have: visible, attributable, and harmless.
type PortScan struct{}

func (*PortScan) Name() string { return "portscan" }
func (*PortScan) Kind() Kind   { return KindNative }
func (*PortScan) Stage() Stage { return StageNetwork }
func (*PortScan) Describe() string {
	return "TCP connect scan across a curated port set to find reachable services."
}
func (*PortScan) Available() (bool, string) { return true, "" }

func (a *PortScan) Run(ctx context.Context, t Target, p Policy, _ []*finding.Finding) (Result, error) {
	var res Result
	if t.Host == "" {
		return res, fmt.Errorf("portscan: empty host")
	}

	lim := newLimiter(p)
	defer lim.close()

	type openPort struct {
		port int
		rtt  time.Duration
	}
	var (
		mu    sync.Mutex
		open  []openPort
		notes []string
	)

	sem := make(chan struct{}, max(1, p.Concurrency))
	var wg sync.WaitGroup
	for _, port := range p.Ports {
		select {
		case <-ctx.Done():
			notes = append(notes, "scan stopped early: "+ctx.Err().Error())
			wg.Wait()
			res.Notes = notes
			return res, nil
		default:
		}
		if p.RateLimit > 0 {
			if err := lim.wait(ctx); err != nil {
				break
			}
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			start := time.Now()
			conn, err := dial(ctx, p, t.Host, port)
			if err != nil {
				return
			}
			rtt := time.Since(start)
			conn.Close()
			mu.Lock()
			open = append(open, openPort{port: port, rtt: rtt})
			mu.Unlock()
		}(port)
	}
	wg.Wait()

	for _, op := range open {
		svc := serviceName(op.port)
		sev := finding.SeverityInfo
		desc := fmt.Sprintf("%s is reachable on TCP port %d. Every reachable service widens the attack surface and should be deliberate rather than incidental.", svc, op.port)
		remedy := "Confirm this service is meant to be reachable from where the scan ran. If it is not, restrict it at the firewall or bind it to an internal interface."

		// Services that should almost never face an untrusted network.
		if s, why := exposureRisk(op.port); s != "" {
			sev = s
			desc = why
			remedy = fmt.Sprintf("Restrict %s to trusted networks, or place it behind a VPN or bastion. Datastores and management interfaces should not be reachable from an untrusted network.", svc)
		}

		f := finding.New(t.Raw, op.port, finding.CategoryNetwork, sev,
			finding.ConfidenceConfirmed,
			fmt.Sprintf("open-port:%d", op.port),
			fmt.Sprintf("%s reachable on port %d", svc, op.port),
			desc, a.Name())
		f.Remediation = remedy
		f.AddEvidence("connection", "handshake", fmt.Sprintf("TCP connect to %s:%d succeeded in %s", t.Host, op.port, op.rtt.Round(time.Millisecond)))
		if sev == finding.SeverityInfo {
			f.Status = finding.StatusInformational
		}
		res.Findings = append(res.Findings, f)
	}

	if len(open) == 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("no reachable TCP service found among %d probed ports", len(p.Ports)))
	}
	res.Notes = append(res.Notes, notes...)
	return res, nil
}

// exposureRisk flags services that are dangerous to expose broadly. The
// severity reflects exposure, not a proven vulnerability, and the wording says
// so.
func exposureRisk(port int) (finding.Severity, string) {
	switch port {
	case 6379:
		return finding.SeverityHigh, "Redis is reachable on port 6379. Redis has no authentication by default, so a reachable instance is frequently readable and writable by anyone who can connect."
	case 11211:
		return finding.SeverityHigh, "Memcached is reachable on port 11211. It has no authentication and has been widely abused for reflection amplification."
	case 27017:
		return finding.SeverityHigh, "MongoDB is reachable on port 27017. Exposed instances are a recurring source of data disclosure."
	case 9200:
		return finding.SeverityHigh, "Elasticsearch is reachable on port 9200. Its HTTP API exposes index contents unless access control is configured."
	case 2375:
		return finding.SeverityCritical, "The Docker API is reachable on port 2375 without TLS. Anyone who can reach it can generally start containers on the host."
	case 2376:
		return finding.SeverityHigh, "The Docker API is reachable on port 2376. Even with TLS enabled, this endpoint grants far-reaching control and should not face an untrusted network."
	case 3306, 5432, 1433, 1521:
		return finding.SeverityMedium, fmt.Sprintf("A database service (%s) is reachable on port %d. Databases are rarely meant to be reachable beyond the application tier.", serviceName(port), port)
	case 23:
		return finding.SeverityHigh, "Telnet is reachable on port 23. Telnet carries credentials in clear text and has no modern justification on a network you do not fully control."
	case 445, 139:
		return finding.SeverityHigh, fmt.Sprintf("SMB is reachable on port %d. File sharing exposed beyond a trusted segment is a well-worn entry point.", port)
	case 3389:
		return finding.SeverityMedium, "RDP is reachable on port 3389. Directly exposed RDP attracts sustained credential attacks."
	case 5900:
		return finding.SeverityMedium, "VNC is reachable on port 5900. VNC authentication is weak and often absent."
	case 161:
		return finding.SeverityMedium, "SNMP is reachable on port 161. Default community strings frequently disclose device configuration."
	case 2049:
		return finding.SeverityMedium, "NFS is reachable on port 2049. Exported shares are often readable more widely than intended."
	}
	return "", ""
}

// Banner identifies services from what they announce on connect.
//
// The read is bounded by io.LimitReader. An unbounded read here is a real
// hazard: an endpoint that streams without pause can exhaust the scanning
// host's memory, turning an audit into an outage on the auditor's own machine.
type Banner struct{}

func (*Banner) Name() string { return "banner" }
func (*Banner) Kind() Kind   { return KindNative }
func (*Banner) Stage() Stage { return StageService }
func (*Banner) Describe() string {
	return "Reads service banners to identify software and version, with a hard read limit."
}
func (*Banner) Available() (bool, string) { return true, "" }

const maxBannerBytes = 512

var versionPattern = regexp.MustCompile(`(?i)([A-Za-z][A-Za-z0-9_\-\.]{1,30})[/ ]v?(\d+\.\d+(?:\.\d+)?)`)

func (a *Banner) Run(ctx context.Context, t Target, p Policy, prior []*finding.Finding) (Result, error) {
	var res Result
	ports := openPortsFrom(prior, t.Raw)
	if len(ports) == 0 {
		res.Notes = append(res.Notes, "no open port was known when banner grabbing ran")
		return res, nil
	}

	for _, port := range ports {
		select {
		case <-ctx.Done():
			res.Notes = append(res.Notes, "banner grabbing stopped early: "+ctx.Err().Error())
			return res, nil
		default:
		}
		// HTTP is handled by the httpprobe adapter, which reads it properly.
		if _, isHTTP := isHTTPPort(port); isHTTP {
			continue
		}
		conn, err := dial(ctx, p, t.Host, port)
		if err != nil {
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(p.DialTimeout))
		buf := make([]byte, maxBannerBytes)
		n, _ := io.ReadFull(io.LimitReader(conn, maxBannerBytes), buf)
		conn.Close()
		if n == 0 {
			continue
		}
		raw := strings.TrimSpace(sanitise(string(buf[:n])))
		if raw == "" {
			continue
		}

		f := finding.New(t.Raw, port, finding.CategoryNetwork, finding.SeverityInfo,
			finding.ConfidenceConfirmed,
			fmt.Sprintf("banner:%d", port),
			fmt.Sprintf("%s on port %d identifies itself", serviceName(port), port),
			"The service announces software details on connection. Version banners let anyone scanning the internet match the host against known vulnerabilities without touching it further.",
			a.Name())
		f.Remediation = "Suppress or generalise the version banner where the software allows it. This is defence in depth, not a fix in itself — keep patching."
		f.AddEvidence("banner", fmt.Sprintf("%s:%d", t.Host, port), raw)
		f.Status = finding.StatusInformational

		if m := versionPattern.FindStringSubmatch(raw); m != nil {
			f.Title = fmt.Sprintf("%s %s disclosed on port %d", m[1], m[2], port)
			f.Severity = finding.SeverityLow
			f.Status = finding.StatusOpen
		}
		res.Findings = append(res.Findings, f)
	}
	return res, nil
}

// openPortsFrom extracts the ports an earlier stage found open for this target.
func openPortsFrom(prior []*finding.Finding, target string) []int {
	var ports []int
	seen := map[int]bool{}
	for _, f := range prior {
		if f.Target != target || f.Port == 0 {
			continue
		}
		if !strings.HasPrefix(f.Signature(), "open-port:") {
			continue
		}
		if !seen[f.Port] {
			seen[f.Port] = true
			ports = append(ports, f.Port)
		}
	}
	return ports
}

// sanitise strips control characters so a hostile banner cannot corrupt a
// terminal or inject markup into a report.
func sanitise(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t' || r == '\r':
			b.WriteRune(' ')
		case r < 0x20 || r == 0x7f:
			// drop
		default:
			b.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
