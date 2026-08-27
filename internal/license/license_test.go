package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func issuer(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pub), priv
}

func TestValidKeyGrantsTier(t *testing.T) {
	pub, priv := issuer(t)
	key, err := Encode(Claims{
		Product: Product, Tier: TierPro, Licensee: "Acme Ltd", IssuedAt: time.Now().Unix(),
	}, priv)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.HasPrefix(key, KeyPrefix) {
		t.Fatalf("key should start with %q, got %q", KeyPrefix, key[:10])
	}

	st := resolveWith(key, pub, time.Now())
	if !st.Valid || st.Tier != TierPro {
		t.Fatalf("state = %+v, want a valid pro licence", st)
	}
	if !st.Caps.AssessmentReport || !st.Caps.SubprocessTools {
		t.Fatal("pro caps should include the assessment report and external tools")
	}
	if !strings.Contains(st.Notice, "Acme Ltd") {
		t.Fatalf("notice should name the licensee: %q", st.Notice)
	}
}

// The guard must degrade rather than fail. Each of these paths has to end at
// Free with an accurate explanation, and none may panic.
func TestEveryFailurePathDegradesToFree(t *testing.T) {
	pub, priv := issuer(t)
	otherPub, otherPriv := issuer(t)
	_ = otherPub

	valid, _ := Encode(Claims{Product: Product, Tier: TierPro, IssuedAt: time.Now().Unix()}, priv)
	forged, _ := Encode(Claims{Product: Product, Tier: TierTeam, IssuedAt: time.Now().Unix()}, otherPriv)
	wrongProduct, _ := Encode(Claims{Product: "certlight", Tier: TierPro, IssuedAt: time.Now().Unix()}, priv)
	expired, _ := Encode(Claims{
		Product: Product, Tier: TierPro, IssuedAt: time.Now().AddDate(-2, 0, 0).Unix(),
		Expires: time.Now().AddDate(-1, 0, 0).Unix(),
	}, priv)
	freeTier, _ := Encode(Claims{Product: Product, Tier: TierFree, IssuedAt: time.Now().Unix()}, priv)

	cases := []struct {
		name       string
		key        string
		issuer     string
		wantNotice string
	}{
		{"no issuer key compiled in", valid, "", "no issuer key"},
		{"unreadable issuer key", valid, "!!!not base64!!!", "unreadable"},
		{"no key supplied", "", pub, "no licence key"},
		{"whitespace key", "   ", pub, "no licence key"},
		{"not our format", "ABC123", pub, "unrecognised key format"},
		{"malformed body", KeyPrefix + "onlyonepart", pub, "malformed key"},
		{"bad base64 payload", KeyPrefix + "!!!.!!!", pub, "malformed key payload"},
		{"forged signature", forged, pub, "invalid signature"},
		{"wrong product", wrongProduct, pub, "not"},
		{"expired", expired, pub, "expired"},
		{"free tier claim", freeTier, pub, "no paid tier"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := resolveWith(tc.key, tc.issuer, time.Now())
			if st.Valid {
				t.Fatalf("state should not be valid: %+v", st)
			}
			if st.Tier != TierFree {
				t.Fatalf("tier = %q, want free", st.Tier)
			}
			if st.Notice == "" {
				t.Fatal("a degraded state must always explain itself")
			}
			if !strings.Contains(strings.ToLower(st.Notice), strings.ToLower(tc.wantNotice)) {
				t.Fatalf("notice %q should mention %q", st.Notice, tc.wantNotice)
			}
			// Free caps must be intact, not zero values.
			if len(st.Caps.Profiles) == 0 {
				t.Fatal("degraded state must still carry usable free caps")
			}
		})
	}
}

func TestExpiryBoundary(t *testing.T) {
	pub, priv := issuer(t)
	exp := time.Now().Add(time.Hour)
	key, _ := Encode(Claims{
		Product: Product, Tier: TierTeam, IssuedAt: time.Now().Unix(), Expires: exp.Unix(),
	}, priv)

	if st := resolveWith(key, pub, exp.Add(-time.Minute)); !st.Valid {
		t.Fatalf("licence should still be valid before expiry: %q", st.Notice)
	}
	if st := resolveWith(key, pub, exp.Add(time.Minute)); st.Valid {
		t.Fatal("licence should be invalid after expiry")
	}
}

func TestCapsLadder(t *testing.T) {
	free, pro, team := CapsFor(TierFree), CapsFor(TierPro), CapsFor(TierTeam)

	if free.AllowsProfile("full") {
		t.Fatal("free must not unlock the full profile")
	}
	if !pro.AllowsProfile("full") || !team.AllowsProfile("full") {
		t.Fatal("paid tiers must unlock the full profile")
	}
	if free.MaxFindingsShown == 0 {
		t.Fatal("free must cap findings shown")
	}
	if pro.MaxFindingsShown != 0 || team.MaxFindingsShown != 0 {
		t.Fatal("paid tiers must not cap findings shown")
	}
	if free.AssessmentReport {
		t.Fatal("free must not include the full assessment report")
	}
	if pro.WhiteLabel {
		t.Fatal("white label belongs to team only")
	}
	if !team.WhiteLabel {
		t.Fatal("team must include white label")
	}
	if len(free.ComplianceFrameworks) != 0 {
		t.Fatal("free must not include compliance mapping")
	}
	if len(team.ComplianceFrameworks) <= len(pro.ComplianceFrameworks) {
		t.Fatal("team must map more frameworks than pro")
	}
}

func TestUnlimitedHelper(t *testing.T) {
	if !Unlimited(0) || Unlimited(5) {
		t.Fatal("zero means unlimited; a positive number does not")
	}
}
