package nms

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("fixtures", rel))
	if err != nil {
		t.Fatalf("fixture %s: %v", rel, err)
	}
	return b
}

func TestMerakiTransformer(t *testing.T) {
	b, err := MerakiTransformer{}.Transform("t-a", "int-mer", loadFixture(t, "meraki/webhook_alert.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Events) != 1 {
		t.Fatalf("want 1 event, got %d", len(b.Events))
	}
	e := b.Events[0]
	if e.TenantID != "t-a" || e.SourceSystem != "meraki" {
		t.Fatalf("tenant/source wrong: %+v", e)
	}
	if e.EventID != "1234567890" || e.DeviceID != "Q234-ABCD-5678" || e.SiteID != "N_24329156" {
		t.Fatalf("field mapping wrong: %+v", e)
	}
	if e.NormalizedEventType != "controller_device_unreachable" { // "WAN 1 connectivity lost"
		t.Fatalf("norm type: %s", e.NormalizedEventType)
	}
	if e.Severity != "crit" {
		t.Fatalf("severity: %s", e.Severity)
	}
	if e.EventTime.IsZero() || e.DedupeKey == "" {
		t.Fatalf("time/dedupe missing: %+v", e)
	}
}

func TestVManageTransformerEmitsEventAndState(t *testing.T) {
	b, err := VManageTransformer{}.Transform("t-b", "int-vm", loadFixture(t, "vmanage/tunnel_down.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The canonical two-class case: one alarm → an event AND a state.
	if len(b.Events) != 1 || len(b.States) != 1 {
		t.Fatalf("want 1 event + 1 state, got %d/%d", len(b.Events), len(b.States))
	}
	e := b.Events[0]
	if e.NormalizedEventType != "controller_bfd_down" || e.Severity != "crit" {
		t.Fatalf("event norm/sev wrong: %+v", e)
	}
	if e.DeviceID != "10.1.1.1" || e.SiteID != "100" {
		t.Fatalf("device/site wrong: %+v", e)
	}
	s := b.States[0]
	if s.StateKind != "bfd" || s.CurrentState != "down" || s.TenantID != "t-b" {
		t.Fatalf("state wrong: %+v", s)
	}
}

func TestCatalystTransformer(t *testing.T) {
	b, err := CatalystTransformer{}.Transform("t-c", "int-cc", loadFixture(t, "catalyst/assurance_issue.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Events) != 1 {
		t.Fatalf("events: %d", len(b.Events))
	}
	e := b.Events[0]
	if e.SourceSystem != "catalyst_center" || e.Severity != "crit" /*P1*/ || e.InterfaceName != "GigabitEthernet1/0/1" {
		t.Fatalf("catalyst mapping: %+v", e)
	}
	if e.SiteName == "" || e.DeviceName != "SW-Access-3" {
		t.Fatalf("site/device: %+v", e)
	}
	// Active interface issue → a state row.
	if len(b.States) != 1 || b.States[0].StateKind != "intf_oper" {
		t.Fatalf("expected intf_oper state: %+v", b.States)
	}
}

func TestNDFCTransformer(t *testing.T) {
	b, err := NDFCTransformer{}.Transform("t-d", "int-nd", loadFixture(t, "ndfc/fabric_alarm.json"))
	if err != nil {
		t.Fatal(err)
	}
	e := b.Events[0]
	if e.SourceSystem != "ndfc" || e.CorrelationHints["fabric"] != "DC1-VXLAN-Fabric" || e.CorrelationHints["vrf"] != "PROD" {
		t.Fatalf("ndfc fabric context: %+v", e)
	}
	if e.InterfaceName != "Ethernet1/5" {
		t.Fatalf("interface: %s", e.InterfaceName)
	}
	if len(b.States) != 1 || b.States[0].StateKind != "intf_oper" {
		t.Fatalf("expected intf_oper state: %+v", b.States)
	}
}

func TestVersaDirectorTransformer(t *testing.T) {
	b, err := VersaDirectorTransformer{}.Transform("t-e", "int-vd", loadFixture(t, "versa_director/tunnel_alarm.json"))
	if err != nil {
		t.Fatal(err)
	}
	e := b.Events[0]
	if e.SourceSystem != "versa_director" || e.NormalizedEventType != "controller_tunnel_state" || e.TunnelID != "vpn-branch12-hub1" {
		t.Fatalf("versa director mapping: %+v", e)
	}
	if e.CorrelationHints["transport"] != "INET-1" || e.CorrelationHints["sla_violation"] != "true" {
		t.Fatalf("versa hints: %+v", e.CorrelationHints)
	}
	if len(b.States) != 1 || b.States[0].StateKind != "tunnel" {
		t.Fatalf("expected tunnel state: %+v", b.States)
	}
}

func TestVersaConcertoTransformer(t *testing.T) {
	b, err := VersaConcertoTransformer{}.Transform("t-f", "int-vc", loadFixture(t, "versa_concerto/security_event.json"))
	if err != nil {
		t.Fatal(err)
	}
	e := b.Events[0]
	if e.SourceSystem != "versa_concerto" || e.NormalizedEventType != "controller_policy_change" || e.Application != "TorGuard" {
		t.Fatalf("concerto mapping: %+v", e)
	}
	// Policy change → discriminating evidence role.
	if e.EvidenceRole != RoleDiscriminating {
		t.Fatalf("policy change must be discriminating, got %s", e.EvidenceRole)
	}
}

func TestPrimeTransformerXML(t *testing.T) {
	b, err := PrimeTransformer{}.Transform("t-g", "int-pr", loadFixture(t, "prime/device_alarm.xml"))
	if err != nil {
		t.Fatal(err)
	}
	e := b.Events[0]
	if e.SourceSystem != "prime" || e.NormalizedEventType != "controller_device_unreachable" || e.Severity != "crit" {
		t.Fatalf("prime XML mapping: %+v", e)
	}
	if e.DeviceID != "10.20.30.40" || e.DeviceName != "Router-WAN-7" {
		t.Fatalf("prime device: %+v", e)
	}
	if len(b.States) != 1 || b.States[0].StateKind != "reachability" {
		t.Fatalf("expected reachability state: %+v", b.States)
	}
}

func TestPrimeTransformerJSON(t *testing.T) {
	// Same connector must parse the JSON encoding too (§7).
	js := `{"queryResponse":{"entity":[{"alarmDTO":{"objectId":"77","severity":"Critical","eventType":"DEVICE_UNREACHABLE","source":"R1","deviceName":"R1","deviceIpAddress":"1.2.3.4","timeStamp":1751540360000,"message":"down"}}]}}`
	b, err := PrimeTransformer{}.Transform("t-g", "int-pr", []byte(js))
	if err != nil || len(b.Events) != 1 {
		t.Fatalf("prime JSON parse: %v %d", err, len(b.Events))
	}
	if b.Events[0].DeviceID != "1.2.3.4" {
		t.Fatalf("prime JSON device: %+v", b.Events[0])
	}
}

func TestGenericTransformerObjectAndArray(t *testing.T) {
	// Single object.
	b, err := GenericTransformer{}.Transform("t-h", "int-g", loadFixture(t, "generic/event.json"))
	if err != nil || len(b.Events) != 1 {
		t.Fatalf("generic object: %v %d", err, len(b.Events))
	}
	if b.Events[0].DeviceID != "edge-3" {
		t.Fatalf("generic mapping: %+v", b.Events[0])
	}
	// Array of two.
	arr := `[{"event_id":"1","message":"a"},{"event_id":"2","message":"b"}]`
	b2, _ := GenericTransformer{}.Transform("t-h", "int-g", []byte(arr))
	if len(b2.Events) != 2 {
		t.Fatalf("generic array: %d", len(b2.Events))
	}
}

// TestTransformerTenantStamping — every transformer must stamp the tenant it was
// called with (never trust a tenant in the payload). Multi-tenant isolation.
func TestTransformerTenantStamping(t *testing.T) {
	cases := []struct {
		name string
		fn   func(string, string, []byte) (Batch, error)
		fix  string
	}{
		{"meraki", MerakiTransformer{}.Transform, "meraki/webhook_alert.json"},
		{"vmanage", VManageTransformer{}.Transform, "vmanage/tunnel_down.json"},
		{"catalyst", CatalystTransformer{}.Transform, "catalyst/assurance_issue.json"},
		{"ndfc", NDFCTransformer{}.Transform, "ndfc/fabric_alarm.json"},
		{"versa_director", VersaDirectorTransformer{}.Transform, "versa_director/tunnel_alarm.json"},
		{"versa_concerto", VersaConcertoTransformer{}.Transform, "versa_concerto/security_event.json"},
		{"prime", PrimeTransformer{}.Transform, "prime/device_alarm.xml"},
		{"generic", GenericTransformer{}.Transform, "generic/event.json"},
	}
	for _, c := range cases {
		b, err := c.fn("tenant-XYZ", "int-1", loadFixture(t, c.fix))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		for _, e := range b.Events {
			if e.TenantID != "tenant-XYZ" {
				t.Errorf("%s: event not stamped with caller tenant: %q", c.name, e.TenantID)
			}
			if e.DedupeKey == "" {
				t.Errorf("%s: event missing dedupe key", c.name)
			}
		}
		for _, s := range b.States {
			if s.TenantID != "tenant-XYZ" {
				t.Errorf("%s: state not stamped with caller tenant: %q", c.name, s.TenantID)
			}
		}
	}
}

func TestMerakiWebhookVerify(t *testing.T) {
	body := loadFixture(t, "meraki/webhook_alert.json")
	secret := []byte("REDACTED") // matches sharedSecret in the fixture
	r := httptest.NewRequest("POST", "/webhook", nil)
	if err := (MerakiWebhook{}).Verify(r, body, secret); err != nil {
		t.Fatalf("valid shared secret must pass: %v", err)
	}
	if err := (MerakiWebhook{}).Verify(r, body, []byte("wrong")); err == nil {
		t.Fatal("wrong secret must fail")
	}
	// Tampered body with a matching shared secret still passes secret check but
	// a bad-JSON body fails.
	if err := (MerakiWebhook{}).Verify(r, []byte("not json"), secret); err == nil {
		t.Fatal("non-JSON body must fail")
	}
}

func TestGenericWebhookHMAC(t *testing.T) {
	body := []byte(`{"event_id":"1"}`)
	secret := []byte("s3cr3t")
	// Compute the expected signature the same way Verify does.
	r := httptest.NewRequest("POST", "/webhook", nil)
	// No header → fail.
	if err := (GenericWebhook{}).Verify(r, body, secret); err == nil {
		t.Fatal("missing signature must fail")
	}
	// Correct HMAC → pass.
	sig := hmacHex(secret, body)
	r.Header.Set("X-Correlix-Signature", sig)
	if err := (GenericWebhook{}).Verify(r, body, secret); err != nil {
		t.Fatalf("valid HMAC must pass: %v", err)
	}
	// Tampered body → fail.
	if err := (GenericWebhook{}).Verify(r, []byte(`{"event_id":"2"}`), secret); err == nil {
		t.Fatal("tampered body must fail")
	}
	_ = strings.TrimSpace
}

// hmacHex computes hex(HMAC-SHA256(secret, body)) for webhook tests.
func hmacHex(secret, body []byte) string {
	mac := hmacNewSHA256(secret)
	mac.Write(body)
	return hexEncode(mac.Sum(nil))
}

func TestVManageStatsTransformerMetrics(t *testing.T) {
	b, err := VManageStatsTransformer{}.Transform("t-b", "int-vm", loadFixture(t, "vmanage/approute_stats.json"))
	if err != nil {
		t.Fatal(err)
	}
	// 2 tunnels × 4 metrics each = 8 controller_metric samples; no events/states.
	if len(b.Metrics) != 8 || len(b.Events) != 0 || len(b.States) != 0 {
		t.Fatalf("want 8 metrics only, got m=%d e=%d s=%d", len(b.Metrics), len(b.Events), len(b.States))
	}
	// Check the mandatory join tags + a value.
	var sawLatency bool
	for _, m := range b.Metrics {
		if m.Tags["tenant_id"] != "t-b" || m.Tags["device"] != "vEdge-Branch-1" || m.Tags["site"] != "100" {
			t.Fatalf("metric tags wrong: %+v", m.Tags)
		}
		if m.Name == "controller_metric_tunnel_latency_ms" && m.Value == 12.4 {
			sawLatency = true
		}
	}
	if !sawLatency {
		t.Fatal("expected the 12.4ms latency sample")
	}
}

func TestVManageOMPStateKind(t *testing.T) {
	// An OMP alarm must map to the omp state kind (not generic).
	raw := `{"data":[{"uuid":"o1","type":"omp-state-change","component":"OMP","severity":"Major","entry_time":1751540400000,"system_ip":"10.1.1.1","host_name":"vEdge-1","site_id":"100","active":true}]}`
	b, err := VManageTransformer{}.Transform("t-b", "int-vm", []byte(raw))
	if err != nil || len(b.States) != 1 {
		t.Fatalf("omp: %v states=%d", err, len(b.States))
	}
	if b.States[0].StateKind != "omp" {
		t.Fatalf("omp state kind = %s", b.States[0].StateKind)
	}
}
