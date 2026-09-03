package alertwebhook

// tenant_isolation_test.go — CLAUDE.md §3a rule 5 for the vmalert delivery path.
//
// This endpoint is platform-GLOBAL plumbing: everything it dispatches lands on
// channels that are not principal-scoped and cannot be (the shared PagerDuty
// routing key, platform-scoped SNS, and the operator's host-monitoring phone
// topic). There is therefore no such thing as "the right tenant" for an alert
// here — the only correct handling of tenant-identifying data on this path is
// to refuse it. These tests pin that refusal, in both of its forms:
//
//	1. an alert that NAMES a tenant   (tenant/org/customer/account spellings);
//	2. an alert that names a tenant's DEVICE (device/interface/peer/hostname).
//
// (2) is the one that bites in practice. 126 of the 130 rules in
// src/config/rules.yaml are per-device customer telemetry whose annotations
// interpolate {{ $labels.device }}; none of them stamps a tenant label. Before
// this guard, the layer normalization stamped layer="platform" on every one of
// them, which defeated notify.PlatformScopeFilter (the #103 guard that exists
// precisely to keep customer alerts off the global key) and put customer router
// hostnames on the platform operator's phone.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"netops/backend/notify"
)

// ── (1) an alert that names a tenant ────────────────────────────────────────

// TestEveryTenantSpellingIsRefused pins the whole refusal vocabulary, not just
// the three spellings our own rules happen to use — the threat model is a rule
// bug, and a rule bug is as likely to write org_id as org.
func TestEveryTenantSpellingIsRefused(t *testing.T) {
	for _, label := range tenantLabels {
		t.Run(label, func(t *testing.T) {
			r := newRig(t, time.Minute)
			body := fmt.Sprintf(
				`[{"status":"firing","labels":{"alertname":"Leaky","severity":"critical","layer":"stack",%q:"acme"}}]`,
				label)
			if w := r.post(t, body, bearer); w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			if fired, resolved := r.disp.counts(); fired != 0 || resolved != 0 {
				t.Fatalf("%q reached the GLOBAL channels (%d fired / %d resolved) — cross-tenant leak",
					label, fired, resolved)
			}
		})
	}
}

// TestTenantLabelRefusalIsCaseInsensitive — a refusal a capital letter defeats
// is not a refusal.
func TestTenantLabelRefusalIsCaseInsensitive(t *testing.T) {
	for _, label := range []string{"Tenant", "TENANT_ID", "Org", "Customer_ID"} {
		t.Run(label, func(t *testing.T) {
			r := newRig(t, time.Minute)
			body := fmt.Sprintf(
				`[{"status":"firing","labels":{"alertname":"Leaky","severity":"critical","layer":"stack",%q:"acme"}}]`,
				label)
			if w := r.post(t, body, bearer); w.Code != http.StatusOK {
				t.Fatalf("status = %d", w.Code)
			}
			if fired, _ := r.disp.counts(); fired != 0 {
				t.Fatalf("%q slipped past the refusal on capitalisation alone", label)
			}
		})
	}
}

// TestTenantIdentityInAnAnnotationIsRefused — annotations are a DELIVERY
// channel here (summaryOf/descriptionOf copy their values verbatim onto the
// operator's phone), so they are scanned like labels, not treated as metadata.
func TestTenantIdentityInAnAnnotationIsRefused(t *testing.T) {
	r := newRig(t, time.Minute)
	body := `[{"status":"firing","labels":{"alertname":"Leaky","severity":"critical","layer":"stack"},` +
		`"annotations":{"summary":"something is wrong","tenant":"acme"}}]`
	if w := r.post(t, body, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if fired, _ := r.disp.counts(); fired != 0 {
		t.Fatal("a tenant identity carried in an ANNOTATION reached the global channels")
	}
}

// ── (2) an alert that names a tenant's device ───────────────────────────────

// TestCustomerDeviceAlertsNeverReachTheGlobalChannels is the regression test
// for the leak this file was written for. Each case is a real rule from
// src/config/rules.yaml, with the labels vmalert actually stamps.
func TestCustomerDeviceAlertsNeverReachTheGlobalChannels(t *testing.T) {
	cases := []struct {
		name   string
		labels string
		summ   string
	}{
		{"DeviceUnreachable",
			`"alertname":"DeviceUnreachable","severity":"critical","device":"acme-core-01","collector":"snmpv2c"`,
			"acme-core-01 unreachable from snmpv2c"},
		{"InterfaceDown",
			`"alertname":"InterfaceDown","severity":"warning","device":"acme-edge-2","interface":"GigabitEthernet0/1"`,
			"acme-edge-2 GigabitEthernet0/1 is down"},
		{"BGPSessionDown",
			`"alertname":"BGPSessionDown","severity":"critical","device":"acme-border","peer":"203.0.113.7"`,
			"acme-border BGP peer 203.0.113.7 is down"},
		{"HighCPU",
			`"alertname":"HighCPU","severity":"warning","hostname":"acme-agg-9"`,
			"acme-agg-9 CPU is high"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, time.Minute)
			body := fmt.Sprintf(`[{"status":"firing","labels":{%s},"annotations":{"summary":%q}}]`,
				tc.labels, tc.summ)
			w := r.post(t, body, bearer)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (a drop is not a client error)", w.Code)
			}
			if fired, resolved := r.disp.counts(); fired != 0 || resolved != 0 {
				t.Fatalf("a CUSTOMER-network alert reached the platform-global channels "+
					"(%d fired / %d resolved) — the customer's device name is on every operator's phone",
					fired, resolved)
			}
			if !strings.Contains(metricsText(r.mx), "netops_alert_webhook_dropped_customer_total 1") {
				t.Error("the drop was not counted — a silent drop is not observable (§10)")
			}
			var decoded map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &decoded); err != nil {
				t.Fatalf("response body: %v", err)
			}
			if decoded["dropped_customer"] != float64(1) {
				t.Errorf("response dropped_customer = %v, want 1", decoded["dropped_customer"])
			}
		})
	}
}

// TestTheDiscriminatorIsTheLayerStampNotTheLabelName is the regression test for
// the false positive found while building this guard: `device` appears on BOTH
// a customer router alert and a host-filesystem alert. Only the second is
// authored as self-health, and only the second may be delivered. Same label,
// same value shape, opposite verdicts — decided by the server-side stamp.
func TestTheDiscriminatorIsTheLayerStampNotTheLabelName(t *testing.T) {
	const customer = `[{"status":"firing","labels":{"alertname":"DeviceUnreachable","severity":"critical",` +
		`"device":"spine1","collector":"snmpv2c","alertgroup":"noc-availability"},` +
		`"annotations":{"summary":"spine1 unreachable from snmpv2c"}}]`
	const host = `[{"status":"firing","labels":{"alertname":"HostDiskLow","severity":"critical","layer":"host",` +
		`"device":"/dev/mapper/ubuntu--vg-ubuntu--lv","mountpoint":"/","fstype":"ext4"},` +
		`"annotations":{"summary":"only 4% free on /"}}]`

	rc := newRig(t, time.Minute)
	if w := rc.post(t, customer, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if fired, _ := rc.disp.counts(); fired != 0 {
		t.Fatal("an unauthored device alert was delivered — a customer router name reached the global channels")
	}

	rh := newRig(t, time.Minute)
	if w := rh.post(t, host, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if fired, _ := rh.disp.counts(); fired != 1 {
		t.Fatalf("fired = %d, want 1 — a host-filesystem alert stamped layer:host is platform health "+
			"and must not be collateral damage of the customer refusal", fired)
	}
}

// TestCustomerAlertResolveIsRefusedToo — the resolve leg carries the same
// identity and gets the same answer.
func TestCustomerAlertResolveIsRefusedToo(t *testing.T) {
	r := newRig(t, time.Minute)
	body := `[{"status":"resolved","labels":{"alertname":"DeviceUnreachable","device":"acme-core-01"},` +
		`"annotations":{"summary":"acme-core-01 recovered"}}]`
	if w := r.post(t, body, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if _, resolved := r.disp.counts(); resolved != 0 {
		t.Fatal("a customer-network RESOLVE reached the platform-global channels")
	}
}

// TestCustomerDeviceAlertNeverReachesTheHostPhoneRoute — the product dispatcher
// and the host-monitoring phone route are two independent destinations. Both
// must be closed, so both are asserted.
func TestCustomerDeviceAlertNeverReachesTheHostPhoneRoute(t *testing.T) {
	r := newHostRig(t, time.Minute, newFakePusher())
	body := `[{"status":"firing","labels":{"alertname":"DeviceUnreachable","severity":"critical",` +
		`"device":"acme-core-01","collector":"snmpv2c"},` +
		`"annotations":{"summary":"acme-core-01 unreachable from snmpv2c"}}]`
	if w := r.post(t, body, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if n := r.push.count(); n != 0 {
		t.Fatalf("%d push(es) to the operator's phone carried a customer device name", n)
	}
}

// ── the layer normalization must stay a closed allowlist ────────────────────

// TestLayerNormalizationOnlyCoversOurOwnSelfHealthLayers is the structural half
// of the fix. Normalizing an unrecognised layer onto notify.PlatformLayers is
// how the #103 guard was defeated: a value we do not recognise is not a value
// we may vouch for.
func TestLayerNormalizationOnlyCoversOurOwnSelfHealthLayers(t *testing.T) {
	// Every layer vmalert's own rule files stamp normalizes to a platform layer
	// that notify.PlatformScopeFilter accepts — this is what keeps the
	// correlation/bus/ingest/storage self-health alerts paging.
	for layer := range vmalertSelfHealthLayers {
		r := newRig(t, time.Minute)
		body := fmt.Sprintf(
			`[{"status":"firing","labels":{"alertname":"CorrelationConsumerDead","severity":"critical","layer":%q}}]`,
			layer)
		if w := r.post(t, body, bearer); w.Code != http.StatusOK {
			t.Fatalf("layer %q: status = %d", layer, w.Code)
		}
		fired, _ := r.disp.counts()
		if fired != 1 {
			t.Fatalf("layer %q: fired = %d, want 1 — platform self-health must still be delivered", layer, fired)
		}
		got := r.disp.fired[0].Labels["layer"]
		if !notify.PlatformLayers[got] {
			t.Fatalf("layer %q normalized to %q, which notify.PlatformScopeFilter rejects", layer, got)
		}
	}

	// An unrecognised layer is left ALONE, so the default-closed filter keeps
	// rejecting it downstream.
	r := newRig(t, time.Minute)
	body := `[{"status":"firing","labels":{"alertname":"SomethingNew","severity":"critical","layer":"invented"}}]`
	if w := r.post(t, body, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if n, _ := r.disp.counts(); n != 1 {
		t.Fatalf("fired = %d, want 1 (the receiver forwards; the SCOPE filter is what rejects)", n)
	}
	if got := r.disp.fired[0].Labels["layer"]; got != "invented" {
		t.Fatalf("an unrecognised layer was rewritten to %q — that is the laundering this guard forbids", got)
	}
	if notify.PlatformLayers["invented"] {
		t.Fatal("test premise broken: 'invented' must not be a platform layer")
	}
}

// TestPlatformSelfHealthIsUnaffectedByTheRefusals guards the other direction:
// the refusals must not have broken the alerts this path exists to deliver.
// These are the real self-health rules, with the labels they actually carry.
func TestPlatformSelfHealthIsUnaffectedByTheRefusals(t *testing.T) {
	// Every label set below was taken from the live stack's vmalert
	// /api/v1/alerts, not invented — including the two that carry a `device`
	// label whose value is a HOST FILESYSTEM, not a customer router. Those are
	// the false positives a name-only refusal would have created, and they are
	// pinned here so the discriminator cannot be simplified back to one.
	cases := []string{
		`"alertname":"ContainerDown","severity":"critical","layer":"stack","container":"api"`,
		`"alertname":"CollectorDown","severity":"critical","collector":"snmpv2c","alertgroup":"noc-self-health"`,
		`"alertname":"NoSamplesIngested","severity":"warning","collector":"snmpv2c"`,
		`"alertname":"CorrDeadLettersRising","severity":"warning","layer":"correlation"`,
		`"alertname":"OpenSearchDocumentsRejected","severity":"warning","layer":"storage"`,
		`"alertname":"ClickHouseMemoryPressure","severity":"critical","layer":"clickhouse"`,
		`"alertname":"VectorComponentErrors","severity":"warning","layer":"ingest","component_id":"os_applogs","instance":"vector-router:9598"`,
		// device="/dev/mapper/…" is a host filesystem. layer:host is the rule
		// author's server-side assertion that this is platform health, so it
		// delivers — the device VALUE is data and is never what decides.
		`"alertname":"DiskHeadroomLow","severity":"warning","layer":"host","device":"/dev/mapper/ubuntu--vg-ubuntu--lv","mountpoint":"/","fstype":"ext4"`,
		`"alertname":"HostDiskLow","severity":"critical","layer":"host","device":"/dev/mapper/ubuntu--vg-ubuntu--lv","mountpoint":"/","fstype":"ext4"`,
	}
	for _, labels := range cases {
		r := newRig(t, time.Minute)
		body := fmt.Sprintf(`[{"status":"firing","labels":{%s},"annotations":{"summary":"platform self-health"}}]`, labels)
		if w := r.post(t, body, bearer); w.Code != http.StatusOK {
			t.Fatalf("status = %d", w.Code)
		}
		if fired, _ := r.disp.counts(); fired != 1 {
			t.Fatalf("platform self-health alert was dropped (%s) — the refusals over-reached", labels)
		}
		if got := r.disp.fired[0].Labels["layer"]; !notify.PlatformLayers[got] {
			t.Fatalf("platform self-health alert carries layer %q, which the scope filter rejects (%s)", got, labels)
		}
	}
}

// TestTheTwoRefusalVocabulariesDoNotOverlap keeps the two lists honest: a label
// in both would make one counter unreachable and the metrics misleading.
func TestTheTwoRefusalVocabulariesDoNotOverlap(t *testing.T) {
	seen := map[string]bool{}
	for _, l := range tenantLabels {
		if l != strings.ToLower(l) {
			t.Errorf("tenantLabels entry %q is not lower-case — foldKeys compares against lower-case keys", l)
		}
		seen[l] = true
	}
	for _, l := range customerIdentityLabels {
		if l != strings.ToLower(l) {
			t.Errorf("customerIdentityLabels entry %q is not lower-case", l)
		}
		if seen[l] {
			t.Errorf("%q is in BOTH refusal lists — one counter becomes unreachable", l)
		}
	}
}
