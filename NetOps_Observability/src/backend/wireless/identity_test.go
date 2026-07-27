package wireless

import (
	"strings"
	"testing"
)

// Identity is deterministic: the same inputs always produce the same id, and
// the id never depends on a display name — an AP rename must not fork history.
func TestAPIDDeterministicAndRenameStable(t *testing.T) {
	a := APID("t1", "cisco", "FCW1234L0AB", "aa:bb:cc:dd:ee:00")
	b := APID("t1", "cisco", "FCW1234L0AB", "aa:bb:cc:dd:ee:00")
	if a != b {
		t.Fatalf("APID not deterministic: %q vs %q", a, b)
	}
	// Same serial, different MAC (radio card swap) → same identity: serial wins.
	c := APID("t1", "cisco", "FCW1234L0AB", "11:22:33:44:55:66")
	if a != c {
		t.Fatalf("serial-based identity must not depend on MAC: %q vs %q", a, c)
	}
	// No serial → MAC-based, and MAC formats converge.
	m1 := APID("t1", "cisco", "", "AA-BB-CC-DD-EE-00")
	m2 := APID("t1", "cisco", "", "aabb.ccdd.ee00")
	if m1 != m2 {
		t.Fatalf("MAC canonicalization failed: %q vs %q", m1, m2)
	}
	if a == m1 {
		t.Fatal("serial identity and MAC identity must differ")
	}
}

// Tenant is always part of the identity: the same physical AP serial in two
// tenants is two entities that never join (§3a).
func TestIdentityTenantScoped(t *testing.T) {
	if APID("t1", "cisco", "S1", "") == APID("t2", "cisco", "S1", "") {
		t.Fatal("APID must be tenant-scoped")
	}
	if SSIDID("t1", "corp") == SSIDID("t2", "corp") {
		t.Fatal("SSIDID must be tenant-scoped")
	}
	if SessionID("t1", "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", 1000) ==
		SessionID("t2", "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", 1000) {
		t.Fatal("SessionID must be tenant-scoped")
	}
}

// WLAN identity is controller-scoped; SSID identity deliberately is NOT
// (report §9): "corp" on two controllers is one SSID and two WLANs.
func TestWLANControllerScopedSSIDNot(t *testing.T) {
	w1 := WLANID("t1", "wlc-a", "corp-profile")
	w2 := WLANID("t1", "wlc-b", "corp-profile")
	if w1 == w2 {
		t.Fatal("WLANID must be controller-scoped")
	}
	// Bound to variables so the comparison is not two identical expressions
	// (staticcheck SA4000) — the point is that two SEPARATE calls with the same
	// inputs agree, which is what determinism means.
	s1, s2 := SSIDID("t1", "corp"), SSIDID("t1", "corp")
	if s1 != s2 {
		t.Fatal("SSIDID must be stable")
	}
}

// Randomized-MAC detection: locally-administered bit set → randomized;
// malformed input fails CLOSED (true) so the identity ladder under-claims.
func TestIsRandomizedMAC(t *testing.T) {
	cases := []struct {
		mac  string
		want bool
	}{
		{"02:00:5e:00:53:01", true},  // U/L set — randomized
		{"da:a1:19:00:00:01", true},  // U/L set (0xda & 0x02)
		{"00:00:5e:00:53:01", false}, // globally unique
		{"a8:66:7f:04:00:01", false}, // globally unique
		{"garbage", true},            // malformed → fail closed
		{"", true},                   // empty → fail closed
	}
	for _, c := range cases {
		if got := IsRandomizedMAC(c.mac); got != c.want {
			t.Errorf("IsRandomizedMAC(%q) = %v, want %v", c.mac, got, c.want)
		}
	}
}

// devicePart mirrors engine.py device_part() (split on the FIRST ':') — the
// grounding contract the entity_id forms must satisfy.
func devicePart(entityID string) string {
	if i := strings.IndexByte(entityID, ':'); i >= 0 {
		return entityID[:i]
	}
	return entityID
}

// The entity_id forms must ground each sub-entity to ITS OWN device token —
// never to a shared estate-wide prefix. The engine splits on the FIRST ':',
// so the prefix joins with '-': "ap:<id>:radio0" would ground every AP in the
// tenant to the literal token "ap" (the #99 weld bug); "ap-<id>:radio0"
// grounds to "ap-<id>". This test is the regression guard for that exact bug.
func TestEntityIDFormsGroundPerDevice(t *testing.T) {
	ap := APID("t1", "cisco", "S1", "")
	if strings.Contains(ap, ":") {
		t.Fatalf("hash ids must never contain ':' (got %q)", ap)
	}
	if got := devicePart(RadioEntityID(ap, 1)); got != "ap-"+ap {
		t.Fatalf("radio grounds to %q, want %q — estate-wide weld hazard", got, "ap-"+ap)
	}
	if got := devicePart(BSSIDEntityID(ap, "AA-BB-CC-DD-EE-0F")); got != "ap-"+ap {
		t.Fatalf("bssid grounds to %q, want %q", got, "ap-"+ap)
	}
	if got := devicePart(MemberEntityID("c1", "m1")); got != "wlc-c1" {
		t.Fatalf("member grounds to %q, want wlc-c1", got)
	}
	if got := devicePart(SessionEntityID("cl1", "s1")); got != "wcl-cl1" {
		t.Fatalf("session grounds to %q, want wcl-cl1", got)
	}
	// Two different APs' radios must ground to two different device tokens.
	ap2 := APID("t1", "cisco", "S2", "")
	if devicePart(RadioEntityID(ap, 0)) == devicePart(RadioEntityID(ap2, 0)) {
		t.Fatal("different APs ground to the same device token — the #99 weld bug")
	}
	if got := APEntityID(ap); got != "ap-"+ap {
		t.Fatalf("APEntityID = %q", got)
	}
	if got := ControllerEntityID("c1"); got != "wlc-c1" {
		t.Fatalf("ControllerEntityID = %q", got)
	}
}

// RadioID identity axis is the slot, never the band (dual-5GHz APs).
func TestRadioIDSlotBased(t *testing.T) {
	if RadioID("ap1", 0) == RadioID("ap1", 1) {
		t.Fatal("distinct slots must be distinct radios")
	}
	if RadioID("ap1", 0) != "ap1|0" {
		t.Fatalf("RadioID shape changed: %q", RadioID("ap1", 0))
	}
}
