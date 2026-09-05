package licence_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/entitlement"
	"netops/backend/internal/licence"
	"netops/backend/internal/licence/signer"
)

// licence_test.go — the mechanism's proof.
//
// External test package (licence_test) on purpose: every assertion below goes
// through the EXPORTED surface, which is the surface the api, the signer and a
// customer's offline verification all use. A test that reaches into unexported
// state proves the implementation, not the promise.

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

// testKey generates a throwaway signing identity. Every test gets its own, so
// nothing here depends on — or can be broken by rotating — the embedded LAB key.
func testKey(t *testing.T) signer.KeyPair {
	t.Helper()
	kp, err := signer.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return kp
}

// verifierFor builds a verifier trusting exactly the given keys.
func verifierFor(keys ...licence.PublicKey) licence.Verifier { return licence.NewVerifier(keys...) }

func pub(kp signer.KeyPair, role string) licence.PublicKey {
	return licence.NewPublicKey(kp.Public, role, "test key")
}

var (
	issued  = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expires = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
)

// teamDoc is a representative Team licence: 250 devices, 100 prefixes, and the
// one feature the owner locked to Team.
func teamDoc() licence.Document {
	base, _ := entitlement.TierCeilings(entitlement.TierTeam)
	return licence.Document{
		LicenceID: "acme-20260101",
		Customer:  "Acme Networks",
		Tier:      entitlement.TierTeam,
		IssuedAt:  issued,
		ExpiresAt: expires,
		Ceilings:  base,
		Features:  []entitlement.Feature{entitlement.FeatureSecurityFindings},
		Support:   licence.Support{Level: "business hours", Contact: "support@example.test"},
		GraceDays: 30,
	}
}

func signDoc(t *testing.T, d licence.Document, kp signer.KeyPair) []byte {
	t.Helper()
	signed, err := signer.Sign(d, kp.Private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// ─────────────────────────────────────────────────────────────────────────────
// Signature: valid / invalid / tampered
// ─────────────────────────────────────────────────────────────────────────────

func TestVerifyValidSignature(t *testing.T) {
	kp := testKey(t)
	raw := signDoc(t, teamDoc(), kp)

	st, err := verifierFor(pub(kp, licence.RoleCurrent)).Verify(raw, issued.AddDate(0, 1, 0))
	if err != nil {
		t.Fatalf("a correctly signed licence must verify: %v", err)
	}
	if st.Source != licence.SourceFile {
		t.Fatalf("source = %q, want %q", st.Source, licence.SourceFile)
	}
	if st.Tier != entitlement.TierTeam {
		t.Fatalf("tier = %q, want team", st.Tier)
	}
	if st.Customer != "Acme Networks" || st.LicenceID != "acme-20260101" {
		t.Fatalf("identity not carried through: %+v", st)
	}
	if !st.Has(entitlement.FeatureSecurityFindings) {
		t.Fatal("Team licence must grant security findings")
	}
	if st.InGrace || st.Degraded {
		t.Fatalf("a live licence is neither in grace nor degraded: %+v", st)
	}
	if st.Ceilings.Devices != 250 || st.Ceilings.WatchedPrefixes != 100 {
		t.Fatalf("ceilings not carried through: %+v", st.Ceilings)
	}
}

func TestVerifyRejectsUnsigned(t *testing.T) {
	kp := testKey(t)
	d := teamDoc()
	d.KeyID = kp.ID // names a key, but carries no signature
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifierFor(pub(kp, licence.RoleCurrent)).Verify(raw, issued); err == nil {
		t.Fatal("an unsigned document must not verify")
	}
}

// TestVerifyRejectsTampered is the property the whole mechanism rests on:
// editing ANY signed field invalidates the file. It walks the fields an
// attacker would actually want — the ceilings, the tier, the features, the
// expiry — rather than asserting the happy case once.
func TestVerifyRejectsTampered(t *testing.T) {
	kp := testKey(t)
	v := verifierFor(pub(kp, licence.RoleCurrent))
	raw := signDoc(t, teamDoc(), kp)

	tamper := map[string]func(m map[string]any){
		"raise the device ceiling": func(m map[string]any) {
			m["ceilings"].(map[string]any)["devices"] = 100000
		},
		"raise the prefix ceiling": func(m map[string]any) {
			m["ceilings"].(map[string]any)["watched_prefixes"] = 100000
		},
		"promote the tier": func(m map[string]any) { m["tier"] = string(entitlement.TierEnterprise) },
		"add a feature": func(m map[string]any) {
			m["features"] = []any{string(entitlement.FeatureSecurityFindings), string(entitlement.FeatureSAML)}
		},
		"extend the expiry":   func(m map[string]any) { m["expires_at"] = "2099-01-01T00:00:00Z" },
		"extend the grace":    func(m map[string]any) { m["grace_days"] = 100000 },
		"rename the customer": func(m map[string]any) { m["customer"] = "Someone Else" },
	}
	for name, mutate := range tamper {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			mutate(m)
			bad, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			st, err := v.Verify(bad, issued)
			if err == nil {
				t.Fatalf("tampering (%s) must be refused, got state %+v", name, st)
			}
			// And the fail-closed direction: a refused document yields Community,
			// never the tampered values.
			if st.Tier != entitlement.TierCommunity || st.Ceilings.Devices != 25 {
				t.Fatalf("a refused licence must fall back to Community, got %+v", st)
			}
		})
	}
}

// TestVerifyIgnoresCosmeticReserialisation is the other half of the same
// property: canonicalisation must let an operator pretty-print, reorder keys or
// re-encode timestamps without breaking a valid licence. If this fails, real
// customers will report "your licence file stopped working" after opening it in
// an editor.
func TestVerifyIgnoresCosmeticReserialisation(t *testing.T) {
	kp := testKey(t)
	v := verifierFor(pub(kp, licence.RoleCurrent))
	raw := signDoc(t, teamDoc(), kp)

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	// Re-marshalling a Go map emits keys in sorted order and re-indents — a
	// different byte sequence for the same document.
	pretty, err := json.MarshalIndent(m, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	pretty = append(pretty, '\n', '\n')
	if _, err := v.Verify(pretty, issued); err != nil {
		t.Fatalf("a pretty-printed copy of a valid licence must still verify: %v", err)
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	kp := testKey(t)
	v := verifierFor(pub(kp, licence.RoleCurrent))
	for name, body := range map[string]string{
		"empty":                  "",
		"not json":               "this is not a licence",
		"json but not a licence": `{"hello":"world"}`,
		"unknown field":          `{"licence_id":"x","surprise":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Verify([]byte(body), issued); err == nil {
				t.Fatal("garbage must not verify")
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Expiry and grace
// ─────────────────────────────────────────────────────────────────────────────

// TestExpiryAndGrace walks the mechanism's three states. NOTE the commercial
// policy is an owner decision still open (see the package doc): what is asserted
// here is the MECHANISM — that grace is the issuer's number, that degradation
// falls back to Community, and that nothing is lost on the way.
func TestExpiryAndGrace(t *testing.T) {
	kp := testKey(t)
	v := verifierFor(pub(kp, licence.RoleCurrent))
	raw := signDoc(t, teamDoc(), kp) // 30 issuer-set grace days

	t.Run("live", func(t *testing.T) {
		st, err := v.Verify(raw, expires.Add(-24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if st.InGrace || st.Degraded || st.Tier != entitlement.TierTeam {
			t.Fatalf("a day before expiry the licence is simply live: %+v", st)
		}
	})

	t.Run("in grace", func(t *testing.T) {
		st, err := v.Verify(raw, expires.AddDate(0, 0, 10))
		if err != nil {
			t.Fatalf("an expired licence is still AUTHENTIC and must verify: %v", err)
		}
		if !st.InGrace {
			t.Fatalf("10 days past expiry with 30 grace days is in grace: %+v", st)
		}
		if st.Degraded {
			t.Fatal("in grace is not degraded")
		}
		if st.Tier != entitlement.TierTeam || !st.Has(entitlement.FeatureSecurityFindings) {
			t.Fatal("grace keeps the licensed tier and its features — that is what grace IS")
		}
		if st.Reason == "" {
			t.Fatal("grace must carry an honest reason for the banner and the alert")
		}
	})

	t.Run("after grace", func(t *testing.T) {
		st, err := v.Verify(raw, expires.AddDate(0, 0, 45))
		if err != nil {
			t.Fatal(err)
		}
		if !st.Degraded {
			t.Fatalf("45 days past expiry with 30 grace days is degraded: %+v", st)
		}
		if st.Tier != entitlement.TierCommunity {
			t.Fatalf("degraded runs at Community ceilings, got %q", st.Tier)
		}
		if st.Ceilings.Devices != 25 || st.Ceilings.WatchedPrefixes != 5 {
			t.Fatalf("degraded ceilings must be the Community ones: %+v", st.Ceilings)
		}
		if len(st.Features) != 0 {
			t.Fatalf("degraded grants no commercial feature, got %v", st.Features)
		}
		// The honesty requirement: the customer's real tier is REMEMBERED so the
		// page can say "your Team licence expired" rather than pretending they
		// were always Community.
		if st.LicensedTier != entitlement.TierTeam {
			t.Fatalf("the licensed tier must be remembered, got %q", st.LicensedTier)
		}
		if st.Customer == "" || st.LicenceID == "" || st.Reason == "" {
			t.Fatalf("degradation must stay attributable and explained: %+v", st)
		}
	})
}

// TestNoBuiltInGraceDefault pins the owner's instruction: grace_days is
// ISSUER-SET and the product invents no default. A licence with no grace period
// degrades at expiry, not thirty days later.
func TestNoBuiltInGraceDefault(t *testing.T) {
	kp := testKey(t)
	d := teamDoc()
	d.GraceDays = 0
	raw := signDoc(t, d, kp)

	st, err := verifierFor(pub(kp, licence.RoleCurrent)).Verify(raw, expires.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if st.InGrace {
		t.Fatal("a licence with grace_days=0 has NO grace — the product must not invent one")
	}
	if !st.Degraded {
		t.Fatalf("with no grace, expiry degrades immediately: %+v", st)
	}
}

func TestDaysToExpiry(t *testing.T) {
	kp := testKey(t)
	raw := signDoc(t, teamDoc(), kp)
	st, err := verifierFor(pub(kp, licence.RoleCurrent)).Verify(raw, expires.AddDate(0, 0, -10))
	if err != nil {
		t.Fatal(err)
	}
	d, ok := st.DaysToExpiry(expires.AddDate(0, 0, -10))
	if !ok || d != 10 {
		t.Fatalf("days to expiry = %d (ok=%v), want 10", d, ok)
	}
	// Past expiry it goes negative and stays honest, and a partial day rounds
	// away from zero so "12 hours late" never reads as "on time".
	d, _ = st.DaysToExpiry(expires.Add(12 * time.Hour))
	if d != -1 {
		t.Fatalf("12 hours past expiry = %d days, want -1", d)
	}
	// Community has nothing to expire and says so rather than reporting 0.
	if _, ok := licence.Community().DaysToExpiry(time.Now()); ok {
		t.Fatal("Community must report no expiry, not a zero one")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Key rotation
// ─────────────────────────────────────────────────────────────────────────────

// TestKeyRotation is the design's rotation promise (§3: "the binary carries the
// current + previous key"): a licence issued under the retired key keeps
// working, one signed by a key we never trusted does not, and the two failures
// are DISTINGUISHABLE so a rotation mistake is diagnosable.
func TestKeyRotation(t *testing.T) {
	oldKey := testKey(t)
	newKey := testKey(t)
	strangerKey := testKey(t)

	// The shipped build after a rotation: new key current, old key previous.
	v := verifierFor(
		pub(newKey, licence.RoleCurrent),
		pub(oldKey, licence.RolePrevious),
	)

	t.Run("current key accepted", func(t *testing.T) {
		if _, err := v.Verify(signDoc(t, teamDoc(), newKey), issued); err != nil {
			t.Fatalf("the current key must verify: %v", err)
		}
	})

	t.Run("previous key accepted", func(t *testing.T) {
		// This is the whole point of rotation: licences already in the field keep
		// working while new ones are issued under the new key.
		if _, err := v.Verify(signDoc(t, teamDoc(), oldKey), issued); err != nil {
			t.Fatalf("the previous key must still verify — otherwise rotation strands every issued licence: %v", err)
		}
	})

	t.Run("unknown key refused", func(t *testing.T) {
		st, err := v.Verify(signDoc(t, teamDoc(), strangerKey), issued)
		if err == nil {
			t.Fatal("a licence signed by an untrusted key must be refused")
		}
		if !strings.Contains(err.Error(), "unknown signing key") {
			t.Fatalf("an untrusted key must be its OWN diagnosis, not a bare bad-signature: %v", err)
		}
		if st.Tier != entitlement.TierCommunity {
			t.Fatalf("refusal falls back to Community, got %q", st.Tier)
		}
	})

	t.Run("key swap is detected", func(t *testing.T) {
		// Sign with the stranger, then relabel the file as the current key. The
		// key_id lookup succeeds; the signature does not. This must read as a bad
		// SIGNATURE, not an unknown key.
		signed, err := signer.Sign(teamDoc(), strangerKey.Private)
		if err != nil {
			t.Fatal(err)
		}
		signed.KeyID = newKey.ID
		raw, err := json.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		_, err = v.Verify(raw, issued)
		if err == nil {
			t.Fatal("a signature from the wrong key must be refused")
		}
		if !strings.Contains(err.Error(), "signature does not verify") {
			t.Fatalf("want a signature diagnosis, got: %v", err)
		}
	})

	t.Run("no key_id is refused", func(t *testing.T) {
		// "Try every key until one works" would make rotation untraceable. A
		// document must name the key it was signed with.
		signed, err := signer.Sign(teamDoc(), newKey.Private)
		if err != nil {
			t.Fatal(err)
		}
		signed.KeyID = ""
		raw, err := json.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(raw, issued); err == nil {
			t.Fatal("a document that names no key must be refused")
		}
	})
}

// TestEmbeddedKeysAreUsable proves the shipped build can actually verify
// something — an embedded key that does not parse would make every valid
// licence look like a customer problem.
func TestEmbeddedKeysAreUsable(t *testing.T) {
	keys := licence.EmbeddedKeys()
	if len(keys) == 0 {
		t.Fatal("a build with no embedded key refuses every licence")
	}
	if len(keys) > 2 {
		t.Fatalf("at most two keys (current + previous) — %d is an accumulation, not a rotation", len(keys))
	}
	cur, ok := licence.CurrentKey()
	if !ok {
		t.Fatal("exactly one key must be marked current")
	}
	if len(cur.Key) != ed25519.PublicKeySize {
		t.Fatalf("current key is %d bytes", len(cur.Key))
	}
	if cur.Base64 == "" || cur.ID == "" || cur.Note == "" {
		t.Fatalf("a key must carry its id, base64 and ceremony note: %+v", cur)
	}
	// The key id must actually be derived from the key — otherwise the field is
	// decoration and a rotation mistake would be invisible.
	if licence.KeyID(cur.Key) != cur.ID {
		t.Fatal("key id must be the key's own fingerprint")
	}
	if _, err := base64.StdEncoding.DecodeString(cur.Base64); err != nil {
		t.Fatalf("the published base64 must decode — customers paste it: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Closed vocabulary
// ─────────────────────────────────────────────────────────────────────────────

// TestClosedVocabulary: a licence naming a tier or feature we do not know is
// REFUSED, not silently narrowed. A typo in an issued licence must be a loud
// failure at issue time, not a capability the customer paid for and did not get.
func TestClosedVocabulary(t *testing.T) {
	kp := testKey(t)
	v := verifierFor(pub(kp, licence.RoleCurrent))

	t.Run("unknown feature is refused at issue time", func(t *testing.T) {
		d := teamDoc()
		d.Features = []entitlement.Feature{"reports"} // a tiering-plan PROPOSAL, not a locked feature
		if _, err := signer.Sign(d, kp.Private); err == nil {
			t.Fatal("the signer must refuse to issue a licence naming a feature outside the closed vocabulary")
		}
	})

	t.Run("unknown tier is refused at issue time", func(t *testing.T) {
		d := teamDoc()
		d.Tier = "platinum"
		if _, err := signer.Sign(d, kp.Private); err == nil {
			t.Fatal("the signer must refuse an unknown tier")
		}
	})

	t.Run("unknown feature smuggled past the signer is refused at install time", func(t *testing.T) {
		// Defence in depth: even correctly signed (by a trusted key), a document
		// outside the vocabulary does not take effect.
		d := teamDoc()
		raw := signDoc(t, d, kp)
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		m["features"] = []any{"root_access"}
		bad, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(bad, issued); err == nil {
			t.Fatal("a document with an unknown feature must not take effect")
		}
	})

	t.Run("the vocabulary is exactly the owner's locked set", func(t *testing.T) {
		want := map[entitlement.Feature]entitlement.Tier{
			entitlement.FeatureSecurityFindings: entitlement.TierTeam,
			entitlement.FeatureSecurityDialects: entitlement.TierEnterprise,
			entitlement.FeatureSIEMExport:       entitlement.TierEnterprise,
			entitlement.FeatureMSPManagement:    entitlement.TierEnterprise,
			entitlement.FeatureSAML:             entitlement.TierEnterprise,
			entitlement.FeatureSCIM:             entitlement.TierEnterprise,
			entitlement.FeatureLDAP:             entitlement.TierEnterprise,
		}
		got := entitlement.Features()
		if len(got) != len(want) {
			t.Fatalf("the LOCKED commercial set has %d features, found %d (%v) — adding one gates a capability for every customer and takes an owner decision, not a diff",
				len(want), len(got), got)
		}
		for _, f := range got {
			tier, ok := want[f]
			if !ok {
				t.Fatalf("%q is not in the owner's locked set", f)
			}
			if entitlement.FeatureTier(f) != tier {
				t.Fatalf("%q is included in %q, want %q", f, entitlement.FeatureTier(f), tier)
			}
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Community defaults
// ─────────────────────────────────────────────────────────────────────────────

// TestCommunityDefaults pins the free tier's numbers. The two ENFORCED ones are
// owner decisions; changing either changes what every free deployment can do.
func TestCommunityDefaults(t *testing.T) {
	st := licence.Community()
	if st.Source != licence.SourceCommunity || st.Tier != entitlement.TierCommunity {
		t.Fatalf("no file means Community: %+v", st)
	}
	if st.LoadError != "" {
		t.Fatal("no licence installed is NOT an error state")
	}
	if len(st.Features) != 0 {
		t.Fatalf("Community grants no commercial feature, got %v", st.Features)
	}
	if st.InGrace || st.Degraded {
		t.Fatal("Community is the normal free tier, not a degraded one")
	}
	for name, want := range map[string]int{
		entitlement.CeilingDevices:              25, // owner-decided, ENFORCED
		entitlement.CeilingWatchedPrefixes:      5,  // owner-decided, ENFORCED
		entitlement.CeilingTenants:              1,
		entitlement.CeilingOrgs:                 1,
		entitlement.CeilingRetentionDays:        7,
		entitlement.CeilingSkills:               0,
		entitlement.CeilingProviderTokensPerDay: 0,
	} {
		got, ok := st.Ceilings.Get(name)
		if !ok {
			t.Fatalf("%s is not in the closed ceiling vocabulary", name)
		}
		if got != want {
			t.Fatalf("Community %s = %d, want %d", name, got, want)
		}
	}
	// And the Summary an operator reads at boot must name the two that bite.
	s := st.Summary()
	if !strings.Contains(s, "Community") || !strings.Contains(s, "25 devices") || !strings.Contains(s, "5 watched prefixes") {
		t.Fatalf("the Community summary must state the enforced ceilings: %q", s)
	}
}

// TestOnlyDecidedCeilingsAreEnforced pins the owner's "everything else in the
// tiering plan is a PROPOSAL" instruction. Enforcing an undecided limit would
// be inventing commercial policy.
func TestOnlyDecidedCeilingsAreEnforced(t *testing.T) {
	enforced := []string{}
	for _, n := range entitlement.CeilingNames() {
		if entitlement.Enforced(n) {
			enforced = append(enforced, n)
		}
	}
	want := []string{entitlement.CeilingDevices, entitlement.CeilingWatchedPrefixes}
	if len(enforced) != len(want) {
		t.Fatalf("enforced ceilings = %v, want exactly %v — retention, tenants, orgs, skills and provider tokens are tiering-plan proposals the owner has not decided",
			enforced, want)
	}
	for i, n := range want {
		if enforced[i] != n {
			t.Fatalf("enforced[%d] = %q, want %q", i, enforced[i], n)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Honest degradation: the over-ceiling list
// ─────────────────────────────────────────────────────────────────────────────

// TestDegradedListsOverCeilingItems is the design's honesty rule made
// executable: when usage exceeds a ceiling, the excess is LISTED with a number
// and a lifting tier — not hidden, not silently dropped, and nothing deleted.
func TestDegradedListsOverCeilingItems(t *testing.T) {
	kp := testKey(t)
	raw := signDoc(t, teamDoc(), kp)
	st, err := verifierFor(pub(kp, licence.RoleCurrent)).Verify(raw, expires.AddDate(0, 0, 45))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Degraded {
		t.Fatal("precondition: this state is degraded")
	}

	// 40 devices and 12 prefixes against degraded Community ceilings of 25 / 5.
	over := st.Overages(licence.Usage{
		entitlement.CeilingDevices:         40,
		entitlement.CeilingWatchedPrefixes: 12,
	})
	if len(over) != 2 {
		t.Fatalf("both over-ceiling items must be listed, got %d: %+v", len(over), over)
	}
	byName := map[string]licence.Overage{}
	for _, o := range over {
		byName[o.Ceiling] = o
	}
	dev := byName[entitlement.CeilingDevices]
	if dev.Current != 40 || dev.Limit != 25 || dev.Over != 15 {
		t.Fatalf("device overage must be exact (40 of 25, 15 over), got %+v", dev)
	}
	if dev.LiftedBy != entitlement.TierTeam {
		t.Fatalf("40 devices is lifted by Team (250), got %q", dev.LiftedBy)
	}
	// The message is what the operator reads. It must say the excess is STILL
	// THERE — the design's "nothing is deleted, nothing is hidden".
	if !strings.Contains(dev.Message, "nothing has been deleted") {
		t.Fatalf("the overage message must state that nothing was deleted: %q", dev.Message)
	}

	t.Run("under the ceiling lists nothing", func(t *testing.T) {
		if o := st.Overages(licence.Usage{entitlement.CeilingDevices: 25}); len(o) != 0 {
			t.Fatalf("exactly at the ceiling is not over it: %+v", o)
		}
	})

	t.Run("an unmeasured ceiling is omitted, not reported as zero", func(t *testing.T) {
		// Community allows 0 skills. If an unmeasured ceiling defaulted to 0 it
		// would look "fine"; if it defaulted to anything else it would look
		// broken. It must simply not appear.
		for _, o := range st.Overages(licence.Usage{}) {
			t.Fatalf("nothing measured means nothing reported, got %+v", o)
		}
	})

	t.Run("un-enforced ceilings never produce an overage", func(t *testing.T) {
		// Retention is carried but not gated. Reporting an overage on a limit
		// nothing enforces would be theatre.
		o := st.Overages(licence.Usage{entitlement.CeilingRetentionDays: 365})
		if len(o) != 0 {
			t.Fatalf("un-enforced ceilings must not produce overages: %+v", o)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Store
// ─────────────────────────────────────────────────────────────────────────────

func TestFileStore(t *testing.T) {
	kp := testKey(t)
	v := verifierFor(pub(kp, licence.RoleCurrent))
	path := filepath.Join(t.TempDir(), "api", "licence.json")
	now := issued.AddDate(0, 1, 0)
	st := licence.NewFileStore(path, licence.FileStoreOptions{
		Verifier: v,
		Now:      func() time.Time { return now },
		Poll:     0,
	})

	t.Run("no file is Community and not an error", func(t *testing.T) {
		got := st.State()
		if got.Source != licence.SourceCommunity {
			t.Fatalf("missing file must be Community, got %+v", got)
		}
		if got.LoadError != "" {
			t.Fatalf("a missing licence is a supported state, not a failure: %q", got.LoadError)
		}
		if _, err := st.Raw(); err == nil {
			t.Fatal("Raw must report that nothing is installed")
		}
	})

	t.Run("install writes and takes effect", func(t *testing.T) {
		got, err := st.Install(signDoc(t, teamDoc(), kp), now)
		if err != nil {
			t.Fatalf("install: %v", err)
		}
		if got.Tier != entitlement.TierTeam {
			t.Fatalf("tier = %q", got.Tier)
		}
		if st.State().Tier != entitlement.TierTeam {
			t.Fatal("the installed licence must be the state in force")
		}
		// The directory did not exist: the atomic write must have created it.
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("the document must be on disk at the documented path: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("licence file mode = %#o, want 0600", perm)
		}
		raw, err := st.Raw()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := licence.Parse(raw); err != nil {
			t.Fatalf("the stored bytes must be the document we can hand back: %v", err)
		}
	})

	t.Run("a refused document never displaces a working licence", func(t *testing.T) {
		// This is the property that makes the upload button safe to press.
		before, err := st.Raw()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Install([]byte(`{"licence_id":"nope"}`), now); err == nil {
			t.Fatal("a malformed document must be refused")
		}
		after, err := st.Raw()
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Fatal("a refused upload must not touch the stored licence")
		}
		if st.State().Tier != entitlement.TierTeam {
			t.Fatal("a refused upload must not change the tier in force")
		}
	})

	t.Run("no leftover temp files", func(t *testing.T) {
		// The atomic-write contract: a failed or completed write leaves no
		// litter that LoadPrefix-style scans would trip over.
		ents, err := os.ReadDir(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".tmp") {
				t.Fatalf("temp file left behind: %s", e.Name())
			}
		}
	})

	t.Run("reload picks up a hand-dropped file", func(t *testing.T) {
		// The design's other install path: "drop the file at data/api/licence.json".
		ent := teamDoc()
		ent.Tier = entitlement.TierEnterprise
		ent.LicenceID = "dropped-by-hand"
		ent.Ceilings.Devices = entitlement.Unlimited
		ent.Features = []entitlement.Feature{entitlement.FeatureSAML, entitlement.FeatureSIEMExport}
		if err := os.WriteFile(path, signDoc(t, ent, kp), 0o600); err != nil {
			t.Fatal(err)
		}
		got := st.Reload()
		if got.LicenceID != "dropped-by-hand" || got.Tier != entitlement.TierEnterprise {
			t.Fatalf("a hand-dropped licence must be picked up: %+v", got)
		}
		if got.Ceilings.Devices != entitlement.Unlimited {
			t.Fatalf("unlimited must survive the round trip, got %d", got.Ceilings.Devices)
		}
	})

	t.Run("a corrupt installed file is Community plus a loud reason", func(t *testing.T) {
		// Fail closed, but never fail SILENT and never fail the product: an
		// unreadable licence must not be able to stop the api.
		if err := os.WriteFile(path, []byte("corrupted"), 0o600); err != nil {
			t.Fatal(err)
		}
		got := st.Reload()
		if got.Tier != entitlement.TierCommunity {
			t.Fatalf("a corrupt licence falls back to Community, got %q", got.Tier)
		}
		if got.LoadError == "" {
			t.Fatal("a corrupt licence must say what is wrong — losing a tier silently is the worst outcome")
		}
		if !strings.Contains(got.Summary(), "REFUSED") {
			t.Fatalf("the boot summary must surface the refusal: %q", got.Summary())
		}
	})

	t.Run("remove returns to Community", func(t *testing.T) {
		got, err := st.Remove()
		if err != nil {
			t.Fatalf("remove: %v", err)
		}
		if got.Source != licence.SourceCommunity || got.LoadError != "" {
			t.Fatalf("after removal the state is plain Community: %+v", got)
		}
		if _, err := st.Remove(); err != nil {
			t.Fatalf("removing an absent licence is not an error: %v", err)
		}
	})
}

// TestStoreReevaluatesAcrossExpiry proves a running api notices its licence
// expiring without anyone touching the file — the failure mode would be a
// deployment that stays "licensed" until the next restart.
func TestStoreReevaluatesAcrossExpiry(t *testing.T) {
	kp := testKey(t)
	path := filepath.Join(t.TempDir(), "licence.json")
	if err := os.WriteFile(path, signDoc(t, teamDoc(), kp), 0o600); err != nil {
		t.Fatal(err)
	}
	clock := issued
	st := licence.NewFileStore(path, licence.FileStoreOptions{
		Verifier: verifierFor(pub(kp, licence.RoleCurrent)),
		Now:      func() time.Time { return clock },
		Poll:     time.Nanosecond, // every read re-checks
	})
	if got := st.State(); got.InGrace || got.Degraded {
		t.Fatalf("precondition: live, got %+v", got)
	}
	clock = expires.AddDate(0, 0, 10)
	if got := st.State(); !got.InGrace {
		t.Fatalf("crossing expiry must be noticed without a restart: %+v", got)
	}
	clock = expires.AddDate(0, 0, 45)
	if got := st.State(); !got.Degraded {
		t.Fatalf("crossing the end of grace must be noticed without a restart: %+v", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Signer
// ─────────────────────────────────────────────────────────────────────────────

func TestSignerKeyCustody(t *testing.T) {
	dir := t.TempDir()
	kp := testKey(t)
	path := filepath.Join(dir, "signing.ed25519")

	if err := signer.WritePrivateKey(path, kp); err != nil {
		t.Fatalf("write key: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("private key mode = %#o, want 0600", perm)
	}

	t.Run("never clobbers an existing key", func(t *testing.T) {
		// Overwriting a signing key would strand every licence issued under it,
		// with no error and no way back.
		if err := signer.WritePrivateKey(path, testKey(t)); err == nil {
			t.Fatal("writing over an existing signing key must be refused")
		}
	})

	t.Run("round-trips", func(t *testing.T) {
		priv, err := signer.LoadPrivateKey(path)
		if err != nil {
			t.Fatal(err)
		}
		if !priv.Equal(kp.Private) {
			t.Fatal("the loaded key must be the key we wrote")
		}
	})

	t.Run("refuses a group- or world-readable key", func(t *testing.T) {
		loose := filepath.Join(dir, "loose.ed25519")
		if err := os.WriteFile(loose, []byte(kp.PrivateBase64()), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := signer.LoadPrivateKey(loose)
		if err == nil {
			t.Fatal("a world-readable signing key must not be used")
		}
		if !strings.Contains(err.Error(), "0600") {
			t.Fatalf("the refusal must say what to fix: %v", err)
		}
	})
}

// TestSignerRefusesInvalidLicence: an invalid licence must be impossible to
// ISSUE, so our mistake never leaves the signing machine.
func TestSignerRefusesInvalidLicence(t *testing.T) {
	kp := testKey(t)
	for name, mutate := range map[string]func(*licence.Document){
		"no customer":         func(d *licence.Document) { d.Customer = "" },
		"no licence id":       func(d *licence.Document) { d.LicenceID = "" },
		"expiry before issue": func(d *licence.Document) { d.ExpiresAt = d.IssuedAt.Add(-time.Hour) },
		"negative grace":      func(d *licence.Document) { d.GraceDays = -1 },
		"nonsense ceiling":    func(d *licence.Document) { d.Ceilings.Devices = -7 },
	} {
		t.Run(name, func(t *testing.T) {
			d := teamDoc()
			mutate(&d)
			if _, err := signer.Sign(d, kp.Private); err == nil {
				t.Fatal("the signer must refuse to issue this")
			}
		})
	}
}

// TestNilServiceIsCommunity guards a classic Go trap that the whole fail-closed
// property rests on.
//
// The server holds `entitlements *licence.Service` and passes it where an
// `entitlement.Service` INTERFACE is expected. A nil *Service inside a non-nil
// interface value does NOT compare equal to nil, so entitlement's `if svc ==
// nil` guard does not fire and the methods are called on a nil receiver. If any
// of them panicked, an unwired build would crash on the first device create; if
// any of them returned a zero Ceilings, an unwired build would refuse
// EVERYTHING (a zero devices ceiling is a real zero, not unlimited).
//
// Both outcomes are unacceptable, so every method is nil-receiver-safe and
// answers Community. This test is the thing that keeps it that way.
func TestNilServiceIsCommunity(t *testing.T) {
	var svc *licence.Service // typed nil
	// Through a slice so the premise is checked at RUN time: a direct
	// `var iface entitlement.Service = svc; iface == nil` is a comparison the
	// compiler folds and staticcheck (correctly) calls out as never true — which
	// is exactly the fact being asserted, but asserted where a reader can see it
	// rather than only in a linter's head.
	boxed := []entitlement.Service{svc}
	iface := boxed[0]
	if iface == nil {
		t.Fatal("precondition: a typed nil inside an interface is NOT nil — if that ever changed, entitlement's own nil guard would start firing and the guards below would be moot")
	}

	if got := svc.State(); got.Source != licence.SourceCommunity {
		t.Fatalf("State on a nil service must be Community, got %+v", got)
	}
	if got := svc.Tier(); got != entitlement.TierCommunity {
		t.Fatalf("Tier = %q, want community", got)
	}
	for _, f := range entitlement.Features() {
		if svc.Entitled(f) {
			t.Fatalf("a nil service must grant nothing, granted %q", f)
		}
	}
	limit, lifted := svc.Ceiling(entitlement.CeilingDevices)
	if limit != 25 {
		t.Fatalf("device ceiling on a nil service = %d, want the Community 25 — a zero here would refuse EVERY device", limit)
	}
	if lifted != entitlement.TierTeam {
		t.Fatalf("lifted_by = %q, want team", lifted)
	}
	// And the gates behave: 25 admitted, 26 refused, nothing granted.
	if err := entitlement.CheckCeiling(iface, entitlement.CeilingDevices, 10); err != nil {
		t.Fatalf("an unwired build must still admit devices below the ceiling: %v", err)
	}
	if err := entitlement.CheckCeiling(iface, entitlement.CeilingDevices, 25); err == nil {
		t.Fatal("an unwired build must still enforce the Community ceiling — failing OPEN would make forgetting the wiring an unlimited licence")
	}
	if err := entitlement.Require(iface, entitlement.FeatureSAML); err == nil {
		t.Fatal("an unwired build must refuse every commercial feature")
	}
	// Metrics too: a nil service must render nothing rather than panic in the
	// scrape handler.
	var b strings.Builder
	svc.WriteMetrics(&b, time.Now())
	if b.Len() != 0 {
		t.Fatalf("a nil service writes no metrics, got %q", b.String())
	}
}
