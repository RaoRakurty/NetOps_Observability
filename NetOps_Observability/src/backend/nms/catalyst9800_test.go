package nms

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/wireless"
)

// Fixtures are doc_claimed (fixtures/catalyst9800/README.md): they encode the
// transformer's contract against the published Cisco-IOS-XE-wireless-* YANG
// models, not against a live controller. These tests prove the CANONICAL side
// — identity discipline, inventory shape, the client-count rule — which holds
// regardless of leaf-spelling corrections a live WLC may force later.

func c9800Fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("fixtures", "catalyst9800", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestC9800CAPWAPTransform(t *testing.T) {
	b, err := Catalyst9800Transformer{}.Transform("t1", "int-9800", c9800Fixture(t, "capwap_data.json"))
	if err != nil {
		t.Fatal(err)
	}
	if b.Wireless == nil || len(b.Wireless.APs) != 2 {
		t.Fatalf("want 2 APs, got %+v", b.Wireless)
	}
	if len(b.Wireless.Controllers) != 1 {
		t.Fatalf("want the logical controller row, got %d", len(b.Wireless.Controllers))
	}
	// Identity is MAC-based and deterministic — the same MAC via the radio
	// stream must land on the same ap_id (cross-stream convergence).
	wantID := wireless.APID("t1", "cisco", "", "a8:66:7f:04:00:01")
	ap := b.Wireless.APs[0]
	if ap.APID != wantID {
		t.Fatalf("ap_id %q, want MAC-based %q", ap.APID, wantID)
	}
	if ap.Serial != "FCW1234L0AB" || ap.Model != "C9130AXI-B" {
		t.Fatalf("serial/model not carried: %+v", ap)
	}
	if ap.ControllerRef != c9800ControllerID("t1", "int-9800") {
		t.Fatalf("AP must bind to the LOGICAL controller: %+v", ap)
	}
	// Join state: registered → up, disjoined → down.
	if len(b.States) != 2 {
		t.Fatalf("want 2 ap_join states, got %d", len(b.States))
	}
	if b.States[0].StateKind != "ap_join" || b.States[0].CurrentState != "up" {
		t.Fatalf("registered AP state: %+v", b.States[0])
	}
	if b.States[1].CurrentState != "down" {
		t.Fatalf("disjoined AP state: %+v", b.States[1])
	}
	// The state entity key is the canonical entity id (device_part contract).
	if !strings.HasPrefix(b.States[0].EntityKey, "ap-") {
		t.Fatalf("state entity key must be the canonical ap- entity id: %q", b.States[0].EntityKey)
	}
}

func TestC9800RadioTransform(t *testing.T) {
	b, err := Catalyst9800Transformer{}.Transform("t1", "int-9800", c9800Fixture(t, "radio_oper.json"))
	if err != nil {
		t.Fatal(err)
	}
	if b.Wireless == nil || len(b.Wireless.Radios) != 2 {
		t.Fatalf("want 2 radios, got %+v", b.Wireless)
	}
	apID := wireless.APID("t1", "cisco", "", "a8:66:7f:04:00:01")
	r0, r1 := b.Wireless.Radios[0], b.Wireless.Radios[1]
	if r0.APID != apID || r1.APID != apID {
		t.Fatalf("radios must converge on the capwap stream's ap_id")
	}
	if r0.Slot != 0 || r0.Band != "2.4GHz" || r0.OperState != "up" {
		t.Fatalf("slot0: %+v", r0)
	}
	if r1.Slot != 1 || r1.Band != "5GHz" || r1.OperState != "down" {
		t.Fatalf("slot1: %+v", r1)
	}
}

func TestC9800WLANTransform(t *testing.T) {
	b, err := Catalyst9800Transformer{}.Transform("t1", "int-9800", c9800Fixture(t, "wlan_cfg.json"))
	if err != nil {
		t.Fatal(err)
	}
	if b.Wireless == nil || len(b.Wireless.WLANs) != 2 {
		t.Fatalf("want 2 WLANs, got %+v", b.Wireless)
	}
	w := b.Wireless.WLANs[0]
	if w.ProfileName != "corp-profile" || w.SSIDName != "corp" || !w.Enabled {
		t.Fatalf("wlan: %+v", w)
	}
	// WLAN id is controller-scoped; SSID id is not (report §9).
	if w.WLANID != wireless.WLANID("t1", c9800ControllerID("t1", "int-9800"), "corp-profile") {
		t.Fatal("WLAN identity must be controller-scoped")
	}
	if w.SSIDRef != wireless.SSIDID("t1", "corp") {
		t.Fatal("SSID identity must be estate-scoped (tenant|name)")
	}
	// Unmapped security fields stay "unknown" — never guessed.
	if w.SecurityMode != "unknown" || w.AuthMethod != "unknown" {
		t.Fatalf("unmapped security must be 'unknown', got %+v", w)
	}
}

// The Phase-2 client rule (report §20): COUNTS, never clients. No per-client
// output of any kind — a client MAC must not appear in any metric line.
func TestC9800ClientTransformCountsOnly(t *testing.T) {
	b, err := Catalyst9800Transformer{}.Transform("t1", "int-9800", c9800Fixture(t, "client_oper.json"))
	if err != nil {
		t.Fatal(err)
	}
	if b.Wireless != nil && !b.Wireless.Empty() {
		t.Fatal("client stream must not emit inventory in Phase 2")
	}
	if len(b.Events) != 0 || len(b.States) != 0 {
		t.Fatal("client stream must not emit events/states in Phase 2")
	}
	var total, perAP float64
	for _, m := range b.Metrics {
		for _, v := range m.Tags {
			if strings.Contains(v, ":") && len(v) == 17 {
				t.Fatalf("a client MAC leaked into metric tags: %v", m.Tags)
			}
		}
		switch m.Name {
		case "controller_metric_wireless_client_count":
			total = m.Value
		case "controller_metric_wireless_ap_client_count":
			perAP += m.Value
		}
	}
	// 3 rows, 2 in run state (the associating client is not counted).
	if total != 2 {
		t.Fatalf("client_count = %v, want 2 (only run-state clients)", total)
	}
	if perAP != 2 {
		t.Fatalf("sum per-AP = %v, want 2", perAP)
	}
}

func TestC9800RRMTransform(t *testing.T) {
	b, err := Catalyst9800Transformer{}.Transform("t1", "int-9800", c9800Fixture(t, "rrm_measurement.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Metrics) != 1 {
		t.Fatalf("want 1 channel-util metric, got %d", len(b.Metrics))
	}
	m := b.Metrics[0]
	if m.Name != "controller_metric_wireless_channel_util_pct" || m.Value != 61.5 {
		t.Fatalf("metric: %+v", m)
	}
	if m.Tags["slot"] != "1" || !strings.HasPrefix(m.Tags["device"], "ap-") {
		t.Fatalf("tags must carry canonical device + slot: %v", m.Tags)
	}
}

// Capability honesty (report §13): a capability the connector has not proven
// is declared at its true fidelity, and absent capabilities read as
// FidelityNone — never as supported.
func TestC9800CapabilityHonesty(t *testing.T) {
	spec := Specs()["catalyst_9800"]
	if len(spec.Capabilities) == 0 {
		t.Fatal("catalyst_9800 must declare capabilities")
	}
	for _, d := range spec.Capabilities {
		if d.Fidelity == FidelityLabValidated || d.Fidelity == FidelityLiveValidated {
			t.Errorf("%s claims %s with no lab/live system to have earned it (B7)", d.Capability, d.Fidelity)
		}
		if d.Fidelity == FidelityDocClaimed && d.Notes == "" {
			t.Errorf("%s: doc_claimed requires the citation in Notes", d.Capability)
		}
	}
	// MLO/roams/onboarding are declared none — the honest holes.
	for _, c := range []Capability{CapMLOLinks, CapRoamEvents, CapOnboardingFailures} {
		d, ok := spec.CapabilityOf(c)
		if !ok || d.Fidelity != FidelityNone {
			t.Errorf("%s must be declared FidelityNone until mapped", c)
		}
	}
	// Absent = fail closed.
	if _, ok := spec.CapabilityOf(Capability("wireless.never_declared")); ok {
		t.Fatal("undeclared capability must not resolve")
	}
}
