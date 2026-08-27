// Package license implements offline Ed25519 licence validation and the tier
// caps that follow from it.
//
// Design rule: the guard never panics and never fails closed in a way that
// breaks the binary. A missing, malformed, expired, or forged key degrades to
// Free and records an accurate notice explaining why. The free build ships with
// an empty issuer key and simply runs as Free.
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// KeyPrefix is the wire prefix of every Hexward licence key. It is baked into
// binaries as protocol, not branding, and is intentionally unchanged across the
// line so existing keys stay valid.
const KeyPrefix = "SNTL1-"

// Product is the module id this binary validates keys for.
const Product = "auditlight"

// IssuerPublicKey is set at build time via
//
//	-ldflags "-X github.com/nizartuanku/auditlight/internal/license.IssuerPublicKey=<base64>"
//
// The open-source build leaves it empty and therefore always runs as Free.
var IssuerPublicKey = ""

// Tier is the entitlement level.
type Tier string

const (
	TierFree Tier = "free"
	TierPro  Tier = "pro"
	TierTeam Tier = "team"
)

// Valid reports whether t is a known tier.
func (t Tier) Valid() bool { return t == TierFree || t == TierPro || t == TierTeam }

// Title returns a display name.
func (t Tier) Title() string {
	switch t {
	case TierPro:
		return "Pro"
	case TierTeam:
		return "Team"
	default:
		return "Free"
	}
}

// Claims is the signed payload of a licence key.
type Claims struct {
	Product  string `json:"p"`
	Tier     Tier   `json:"t"`
	Licensee string `json:"l,omitempty"`
	IssuedAt int64  `json:"i"`
	Expires  int64  `json:"e,omitempty"` // unix seconds; 0 means perpetual
}

// Caps are the concrete limits a tier grants.
type Caps struct {
	Tier Tier `json:"tier"`

	Profiles         []string `json:"profiles"`
	MaxTargets       int      `json:"max_targets"` // 0 = unlimited
	MaxActiveJobs    int      `json:"max_active_jobs"`
	MaxFindingsShown int      `json:"max_findings_shown"` // 0 = unlimited
	MaxWorkspaces    int      `json:"max_workspaces"`
	// MaxDefinitions caps saved assessments; 0 = unlimited.
	MaxDefinitions int `json:"max_definitions"`

	AssessmentReport bool `json:"assessment_report"` // false = watermarked preview only
	Export           bool `json:"export"`
	SubprocessTools  bool `json:"subprocess_tools"`
	Correlation      bool `json:"correlation"`
	Branding         bool `json:"branding"`
	WhiteLabel       bool `json:"white_label"`
	// Reassessment unlocks saved assessments, scheduling, the change report
	// and notifications — the difference between a scanner and an audit trail.
	Reassessment bool `json:"reassessment"`

	ComplianceFrameworks []string `json:"compliance_frameworks"`
}

// Unlimited reports whether n means "no limit".
func Unlimited(n int) bool { return n == 0 }

// CapsFor returns the caps granted by a tier.
func CapsFor(t Tier) Caps {
	switch t {
	case TierTeam:
		return Caps{
			Tier:                 TierTeam,
			Profiles:             []string{"perimeter", "web", "tls-email", "hardening", "full"},
			MaxTargets:           0,
			MaxActiveJobs:        0,
			MaxFindingsShown:     0,
			MaxWorkspaces:        0,
			MaxDefinitions:       0,
			AssessmentReport:     true,
			Export:               true,
			SubprocessTools:      true,
			Correlation:          true,
			Branding:             true,
			WhiteLabel:           true,
			Reassessment:         true,
			ComplianceFrameworks: []string{"ISO 27001:2022", "CIS v8", "NIST CSF 2.0", "UU PDP"},
		}
	case TierPro:
		return Caps{
			Tier:                 TierPro,
			Profiles:             []string{"perimeter", "web", "tls-email", "hardening", "full"},
			MaxTargets:           0,
			MaxActiveJobs:        25,
			MaxFindingsShown:     0,
			MaxWorkspaces:        10,
			MaxDefinitions:       10,
			AssessmentReport:     true,
			Export:               true,
			SubprocessTools:      true,
			Correlation:          true,
			Branding:             true,
			WhiteLabel:           false,
			Reassessment:         true,
			ComplianceFrameworks: []string{"ISO 27001:2022", "CIS v8"},
		}
	default:
		return Caps{
			Tier:                 TierFree,
			Profiles:             []string{"perimeter", "web"},
			MaxTargets:           3,
			MaxActiveJobs:        1,
			MaxFindingsShown:     50,
			MaxWorkspaces:        1,
			MaxDefinitions:       0,
			AssessmentReport:     false,
			Export:               false,
			SubprocessTools:      false,
			Correlation:          false,
			Branding:             false,
			WhiteLabel:           false,
			Reassessment:         false,
			ComplianceFrameworks: nil,
		}
	}
}

// AllowsProfile reports whether the caps permit the named profile.
func (c Caps) AllowsProfile(name string) bool {
	for _, p := range c.Profiles {
		if p == name {
			return true
		}
	}
	return false
}

// State is the resolved licence status of the running binary.
type State struct {
	Tier     Tier   `json:"tier"`
	Caps     Caps   `json:"caps"`
	Licensee string `json:"licensee,omitempty"`
	Expires  string `json:"expires,omitempty"`

	// Notice explains the outcome in plain language. It is always populated and
	// is what the UI shows on the licence line, so it must be accurate: it says
	// "no key" when there is no key and "invalid signature" when a key is forged.
	Notice string `json:"notice"`
	// Valid is true only when a real signed key was accepted.
	Valid bool `json:"valid"`
}

// Encode builds a licence key string from claims and a private key.
func Encode(claims Claims, priv ed25519.PrivateKey) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("license: marshal claims: %w", err)
	}
	sig := ed25519.Sign(priv, payload)
	enc := base64.RawURLEncoding
	return KeyPrefix + enc.EncodeToString(payload) + "." + enc.EncodeToString(sig), nil
}

// parse splits and verifies a key, returning its claims.
func parse(key string, pub ed25519.PublicKey) (Claims, error) {
	var c Claims
	key = strings.TrimSpace(key)
	if !strings.HasPrefix(key, KeyPrefix) {
		return c, fmt.Errorf("unrecognised key format")
	}
	body := strings.TrimPrefix(key, KeyPrefix)
	parts := strings.Split(body, ".")
	if len(parts) != 2 {
		return c, fmt.Errorf("malformed key")
	}
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(parts[0])
	if err != nil {
		return c, fmt.Errorf("malformed key payload")
	}
	sig, err := enc.DecodeString(parts[1])
	if err != nil {
		return c, fmt.Errorf("malformed key signature")
	}
	if len(sig) != ed25519.SignatureSize {
		return c, fmt.Errorf("invalid signature length")
	}
	if !ed25519.Verify(pub, payload, sig) {
		return c, fmt.Errorf("invalid signature")
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, fmt.Errorf("malformed claims")
	}
	return c, nil
}

// freeState builds the degraded state with an accurate reason.
func freeState(notice string) State {
	return State{
		Tier:   TierFree,
		Caps:   CapsFor(TierFree),
		Notice: notice,
		Valid:  false,
	}
}

// Resolve validates key against the compiled-in issuer key and returns the
// resulting state. It never returns an error: every failure path degrades to
// Free with an explanatory notice.
func Resolve(key string) State {
	return resolveWith(key, IssuerPublicKey, time.Now())
}

// resolveWith is Resolve with the issuer key and clock injected, so tests can
// exercise every path offline.
func resolveWith(key, issuerB64 string, now time.Time) State {
	if strings.TrimSpace(issuerB64) == "" {
		// Open-source build: no issuer key compiled in.
		return freeState("Free edition — no issuer key in this build.")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(issuerB64))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		// A broken build constant must not crash the binary.
		return freeState("Running as Free — the issuer key in this build is unreadable.")
	}
	pub := ed25519.PublicKey(raw)

	if strings.TrimSpace(key) == "" {
		return freeState("Free edition — no licence key configured.")
	}

	claims, err := parse(key, pub)
	if err != nil {
		return freeState("Running as Free — licence key rejected: " + err.Error() + ".")
	}
	if claims.Product != Product {
		return freeState(fmt.Sprintf("Running as Free — this key is for %q, not %q.", claims.Product, Product))
	}
	if !claims.Tier.Valid() || claims.Tier == TierFree {
		return freeState("Running as Free — the key carries no paid tier.")
	}
	if claims.Expires != 0 && now.After(time.Unix(claims.Expires, 0)) {
		return freeState(fmt.Sprintf("Running as Free — licence expired on %s.",
			time.Unix(claims.Expires, 0).UTC().Format("2 January 2006")))
	}

	st := State{
		Tier:     claims.Tier,
		Caps:     CapsFor(claims.Tier),
		Licensee: claims.Licensee,
		Valid:    true,
	}
	if claims.Expires != 0 {
		st.Expires = time.Unix(claims.Expires, 0).UTC().Format("2 January 2006")
		st.Notice = fmt.Sprintf("%s licence — valid until %s.", claims.Tier.Title(), st.Expires)
	} else {
		st.Notice = fmt.Sprintf("%s licence — active.", claims.Tier.Title())
	}
	if claims.Licensee != "" {
		st.Notice = claims.Licensee + " · " + st.Notice
	}
	return st
}
