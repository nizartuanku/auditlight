// Package adapters holds the checks AuditLight runs.
//
// Two kinds exist. Native adapters are implemented on the Go standard library
// and are always available, which is what lets the binary complete an
// assessment with nothing else installed. Subprocess adapters shell out to an
// external tool if the operator has one, adding depth without ever becoming a
// requirement.
//
// Every adapter is detection-only. None sends a payload meant to change state,
// none attempts authentication, and none carries an intrusive mode that could
// be switched on.
package adapters

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/nizartuanku/auditlight/internal/finding"
)

// Kind distinguishes built-in checks from external tools.
type Kind string

const (
	KindNative     Kind = "native"
	KindSubprocess Kind = "subprocess"
)

// Stage orders execution. Later stages can read the findings produced by
// earlier ones, which is how derived adapters work without re-probing.
type Stage int

const (
	StageDiscovery Stage = iota // find assets
	StageNetwork                // ports and banners
	StageService                // per-service inspection
	StageDerived                // conclusions drawn from earlier findings
)

// Target is one thing to assess.
type Target struct {
	Raw  string // exactly what the operator typed
	Host string // normalised hostname or IP
	URL  string // http(s) URL when the operator supplied a scheme
}

// NewTarget parses an operator-supplied target.
func NewTarget(raw string) Target {
	t := Target{Raw: strings.TrimSpace(raw)}
	s := strings.ToLower(t.Raw)
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		t.URL = t.Raw
	}
	h := s
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if strings.HasPrefix(h, "[") {
		if j := strings.Index(h, "]"); j > 0 {
			h = h[1:j]
		}
	} else if i := strings.LastIndex(h, ":"); i >= 0 && strings.Count(h, ":") == 1 {
		h = h[:i]
	}
	t.Host = strings.TrimSuffix(h, ".")
	return t
}

// Policy is the safety envelope every adapter runs inside. The orchestrator
// owns it; adapters may read it but never widen it.
type Policy struct {
	Timeout         time.Duration // per-operation
	Concurrency     int           // parallel operations within one adapter
	RateLimit       int           // operations per second, 0 = unmetered
	Ports           []int         // ports the network stage may touch
	AllowSubprocess bool          // paid tiers only
	MaxSubdomains   int           // cap on enumeration breadth
	DialTimeout     time.Duration

	// ScanPath is the filesystem tree the secret scan reads. It is empty
	// unless the operator nominates one, and adapters that need it say so
	// rather than silently doing nothing.
	ScanPath string
}

// DefaultPolicy is deliberately conservative. AuditLight has no aggressive mode.
func DefaultPolicy() Policy {
	return Policy{
		Timeout:       6 * time.Second,
		DialTimeout:   2500 * time.Millisecond,
		Concurrency:   24,
		RateLimit:     0,
		Ports:         DefaultPorts(),
		MaxSubdomains: 60,
	}
}

// DefaultPorts is a curated list of ports worth checking on a perimeter. It is
// short on purpose: a full 65535-port sweep is noisy, slow, and rarely changes
// the conclusion of an audit.
func DefaultPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443,
		445, 465, 587, 636, 993, 995, 1433, 1521, 2049, 2375, 2376, 3000,
		3306, 3389, 5432, 5601, 5900, 5985, 6379, 8000, 8080, 8081, 8443,
		8888, 9000, 9090, 9200, 11211, 27017,
	}
}

// Result is what an adapter returns.
type Result struct {
	Findings []*finding.Finding
	// Notes explain partial outcomes: a port that timed out, a record that
	// could not be read. They surface in the Process Report so that gaps in
	// coverage are visible rather than implied.
	Notes []string
}

// Adapter is one check.
type Adapter interface {
	Name() string
	Kind() Kind
	Stage() Stage
	// Describe is one sentence shown in the capability matrix.
	Describe() string
	// Available reports whether the adapter can run here, and why not if it
	// cannot. Native adapters are always available.
	Available() (bool, string)
	// Run performs the check. prior holds findings from earlier stages.
	Run(ctx context.Context, t Target, p Policy, prior []*finding.Finding) (Result, error)
}

// Registry holds the adapters this binary knows about.
type Registry struct {
	adapters []Adapter
}

// NewRegistry builds the registry with every adapter compiled in.
func NewRegistry() *Registry {
	return &Registry{adapters: []Adapter{
		&Subdomain{}, &PortScan{}, &Banner{}, &HTTPProbe{},
		&TLSAudit{}, &DNSEmail{}, &Secrets{}, &Headers{}, &VulnSig{},
		newExecAdapter(execSpecNuclei()),
		newExecAdapter(execSpecTestSSL()),
		newExecAdapter(execSpecLynis()),
		newExecAdapter(execSpecNmap()),
	}}
}

// All returns every registered adapter.
func (r *Registry) All() []Adapter { return r.adapters }

// ByName looks an adapter up.
func (r *Registry) ByName(name string) (Adapter, bool) {
	for _, a := range r.adapters {
		if a.Name() == name {
			return a, true
		}
	}
	return nil, false
}

// Capability is one row of the capability matrix shown in the UI and report.
type Capability struct {
	Name      string `json:"name"`
	Kind      Kind   `json:"kind"`
	Describe  string `json:"describe"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// Capabilities reports what this installation can actually do. Being explicit
// about what is missing is the point: a report that quietly skipped half its
// checks would read as a clean bill of health.
func (r *Registry) Capabilities() []Capability {
	out := make([]Capability, 0, len(r.adapters))
	for _, a := range r.adapters {
		ok, reason := a.Available()
		out = append(out, Capability{
			Name: a.Name(), Kind: a.Kind(), Describe: a.Describe(),
			Available: ok, Reason: reason,
		})
	}
	return out
}

// --- shared helpers -------------------------------------------------------

// dial opens a TCP connection inside the policy's dial timeout.
func dial(ctx context.Context, p Policy, host string, port int) (net.Conn, error) {
	d := net.Dialer{Timeout: p.DialTimeout}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
}

// limiter paces work to the policy's rate limit. A zero rate means unmetered.
type limiter struct {
	tick <-chan time.Time
	stop func()
}

func newLimiter(p Policy) *limiter {
	if p.RateLimit <= 0 {
		return &limiter{}
	}
	t := time.NewTicker(time.Second / time.Duration(p.RateLimit))
	return &limiter{tick: t.C, stop: t.Stop}
}

func (l *limiter) wait(ctx context.Context) error {
	if l.tick == nil {
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.tick:
		return nil
	}
}

func (l *limiter) close() {
	if l.stop != nil {
		l.stop()
	}
}

// serviceName maps a port to its conventional service, for readable findings.
func serviceName(port int) string {
	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "Telnet"
	case 25, 465, 587:
		return "SMTP"
	case 53:
		return "DNS"
	case 80, 8000, 8080, 8081, 8888, 3000:
		return "HTTP"
	case 110:
		return "POP3"
	case 143, 993:
		return "IMAP"
	case 161:
		return "SNMP"
	case 389, 636:
		return "LDAP"
	case 443, 8443:
		return "HTTPS"
	case 445, 139:
		return "SMB"
	case 1433:
		return "MSSQL"
	case 1521:
		return "Oracle"
	case 2375, 2376:
		return "Docker API"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 5432:
		return "PostgreSQL"
	case 5601:
		return "Kibana"
	case 5900:
		return "VNC"
	case 6379:
		return "Redis"
	case 9200:
		return "Elasticsearch"
	case 11211:
		return "Memcached"
	case 27017:
		return "MongoDB"
	default:
		return fmt.Sprintf("port %d", port)
	}
}

// isHTTPPort reports whether a port conventionally speaks HTTP(S).
func isHTTPPort(port int) (tls bool, ok bool) {
	switch port {
	case 80, 3000, 8000, 8080, 8081, 8888, 9000, 9090, 5601:
		return false, true
	case 443, 8443:
		return true, true
	}
	return false, false
}
