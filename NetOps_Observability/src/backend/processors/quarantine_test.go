package processors

// quarantine_test.go — F-11 seal-or-quarantine (tracker #151 step 3, owner
// decision 2026-08-12). The generated router config must carry a quarantine
// stage for the device-attribution lanes whenever sealing is configured:
// an event whose identity the device→tenant registry does not know (a
// registry MISS — distinct from a registry hit that maps a KNOWN platform
// device to the empty tenant) must never be stored as plaintext in the
// shared untagged bucket. It is replaced wholesale by a metadata envelope
// whose payload is sealed under the dedicated `quarantine` key scope.
//
// Fail-closed shape (INV-F11-06): the stage is its OWN remap with
// drop_on_abort/drop_on_error and NO reroute — a runtime seal failure DROPS
// the event (counted by Vector's error metrics, alerted on) instead of
// letting plaintext continue to a sink or to the plaintext deadletter index.

import (
	"strings"
	"testing"
)

// quarantineLanes mirrors the design: syslog/snmptrap/flows are the lanes
// whose tenant comes from the device registry. applogs (platform-only by
// construction) and cloudlogs (authenticated producer stamp) never quarantine.
var wantQuarantineLanes = []string{"syslog", "snmptrap", "flows"}

func TestGeneratedConfigCarriesQuarantineStage(t *testing.T) {
	withSealEngine(t, newStubSealEngine())
	cfg := mustGenerate(t, nil)

	for _, lane := range wantQuarantineLanes {
		qName := lane + "_quarantine"
		if !strings.Contains(cfg, "  "+qName+":") {
			t.Fatalf("lane %s: generated config has no %s transform — a registry-miss "+
				"event stays plaintext in the shared untagged bucket (F-11)", lane, qName)
		}
		block := sectionOf(t, cfg, "  "+qName+":")

		// The stage consumes the lane input and the rules chain consumes IT.
		if !strings.Contains(block, "inputs: ["+laneInputs[lane]+"]") {
			t.Errorf("lane %s: quarantine stage must consume %s", lane, laneInputs[lane])
		}
		applyBlock := sectionOf(t, cfg, "  "+applyName(lane)+":")
		if !strings.Contains(applyBlock, "inputs: ["+qName+"]") {
			t.Errorf("lane %s: %s must consume the quarantine stage (got:\n%s)",
				lane, applyName(lane), applyBlock)
		}

		// Fail-closed remap semantics: abort/error ⇒ DROP, never reroute (the
		// deadletter index is durable plaintext — INV-F11-06).
		for _, needle := range []string{"drop_on_abort: true", "drop_on_error: true"} {
			if !strings.Contains(block, needle) {
				t.Errorf("lane %s: quarantine stage missing %q", lane, needle)
			}
		}
		if strings.Contains(block, "reroute_dropped: true") {
			t.Errorf("lane %s: quarantine stage must NOT reroute dropped events — "+
				"the deadletter index is plaintext", lane)
		}

		// The guard: registry MISS and still-untenanted. A registry hit with an
		// empty tenant is a KNOWN PLATFORM device and must pass untouched.
		if !strings.Contains(block, `.tenant_registry) ?? "") == "miss"`) {
			t.Errorf("lane %s: quarantine guard must key on the registry-miss stamp "+
				"(tenant_id == \"\" alone would swallow known platform devices)", lane)
		}

		// The envelope: metadata only outside the ciphertext.
		for _, needle := range []string{
			`"reason": "TENANT_UNATTRIBUTABLE"`,
			`"cx_quarantine": true`,
			"uuid_v4()",   // event_id for idempotent re-injection
			"sha2(",       // identity kept as a hash, never plaintext
			"encode_json", // the whole original event becomes the payload
		} {
			if !strings.Contains(block, needle) {
				t.Errorf("lane %s: quarantine envelope missing %s", lane, needle)
			}
		}

		// The payload is sealed under the dedicated scope, via the SAME engine
		// snippet tenants use (stub emits a recognizable marker), and a belt
		// guard aborts (⇒ drop) if the payload somehow is not a token.
		if !strings.Contains(block, "cx_quarantine_payload") {
			t.Errorf("lane %s: quarantine stage never touches the payload field", lane)
		}
		// E651 regression (live router, 2026-08-12): the payload must land via
		// set!() — a map-literal assignment types the field as a known string
		// and the engine snippet's `?? ""` becomes a compile error that makes
		// the router refuse the entire config.
		if !strings.Contains(block, `set!(value: ., path: ["cx_quarantine_payload"]`) {
			t.Errorf("lane %s: payload must be assigned via set!() type-erasure — "+
				"a typed assignment breaks the shared seal snippet (E651)", lane)
		}
		if strings.Contains(block, `"cx_quarantine_payload": _cx_q_payload`) {
			t.Errorf("lane %s: payload back in the map literal — E651 returns", lane)
		}
		if !strings.Contains(block, `starts_with(to_string(.cx_quarantine_payload) ?? "", "<enc:v1:")`) ||
			!strings.Contains(block, "abort") {
			t.Errorf("lane %s: missing the not-sealed-then-abort belt — a seal "+
				"engine regression would emit plaintext payloads (INV-F11-06)", lane)
		}
	}

	// Out-of-scope lanes stay untouched.
	for _, lane := range []string{"applogs", "cloudlogs"} {
		if strings.Contains(cfg, "  "+lane+"_quarantine:") {
			t.Errorf("lane %s must NOT quarantine (platform-only / authenticated "+
				"producer stamp — Case 1)", lane)
		}
		applyBlock := sectionOf(t, cfg, "  "+applyName(lane)+":")
		if !strings.Contains(applyBlock, "inputs: ["+laneInputs[lane]+"]") {
			t.Errorf("lane %s: chain input changed unexpectedly", lane)
		}
	}
}

func TestQuarantineStageAbsentWithoutSealing(t *testing.T) {
	withSealEngine(t, nil)
	cfg := mustGenerate(t, nil)
	if strings.Contains(cfg, "_quarantine:") {
		t.Fatal("without a seal engine the quarantine stage must not exist — " +
			"a SECRET[] reference with no custody makes the router refuse to " +
			"boot on every plaintext deployment")
	}
	for _, lane := range laneOrder {
		applyBlock := sectionOf(t, cfg, "  "+applyName(lane)+":")
		if !strings.Contains(applyBlock, "inputs: ["+laneInputs[lane]+"]") {
			t.Errorf("lane %s: baseline chain input must be unchanged", lane)
		}
	}
}

func TestQuarantineEngineRefusalFailsGeneration(t *testing.T) {
	// Review fix 2026-08-14 (supersedes the omit-the-stage contract this test
	// used to pin): with sealing configured, an engine that refuses the
	// quarantine scope (custody hiccup at generation time — e.g. a lazy
	// first-mint store failure) must FAIL the whole generation. The old
	// behavior omitted the stage silently: no error, no SECRET[] refs (so no
	// exit-78 boot backstop), and every registry-MISS event flowed plaintext
	// into the shared -untagged- indices until the next regen. The caller
	// (writeProcessorsConfig) keeps the last-good config on error — pinned by
	// TestProcessorsRegenKeepsLastGoodConfigOnQuarantineSealFailure.
	e := newStubSealEngine()
	e.failFor[QuarantineScope] = true
	withSealEngine(t, e)
	cfg, err := GenerateRouterConfig(nil)
	if err == nil {
		t.Fatal("engine refused the quarantine scope but generation succeeded — " +
			"the config would silently store unattributable events in plaintext (INV-F11-06)")
	}
	if !strings.Contains(err.Error(), QuarantineScope) {
		t.Fatalf("the error must name the quarantine scope so the operator can act on it, got: %v", err)
	}
	if cfg != "" {
		t.Fatalf("a failed generation must not hand back a partial config:\n%s", cfg)
	}
}

// sectionOf returns the YAML block starting at the given top-of-block marker
// up to the next transform at the same indent, so assertions bind to ONE
// transform rather than the whole file.
func sectionOf(t *testing.T, cfg, marker string) string {
	t.Helper()
	i := strings.Index(cfg, marker)
	if i < 0 {
		t.Fatalf("generated config has no %q", strings.TrimSpace(marker))
	}
	rest := cfg[i+len(marker):]
	end := len(rest)
	for off := 0; ; {
		j := strings.Index(rest[off:], "\n  ")
		if j < 0 {
			break
		}
		line := rest[off+j+1:]
		if !strings.HasPrefix(line, "   ") && strings.Contains(line[:strings.IndexByte(line, '\n')+1], ":") {
			end = off + j
			break
		}
		off += j + 3
	}
	return rest[:end]
}
