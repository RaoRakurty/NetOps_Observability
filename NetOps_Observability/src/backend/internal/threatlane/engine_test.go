package threatlane

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"netops/backend/internal/secbus"
	"netops/backend/internal/secfindings"
)

func fixedClock() func() time.Time {
	t := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

func newEngine(logs MemLogSource, flows MemFlowSource) *Engine {
	return NewEngine(DefaultCatalog(), logs, flows, WithClock(fixedClock()), WithScanID("scan-1"))
}

func findingByRule(fs []secfindings.Finding, ruleID string) (secfindings.Finding, bool) {
	for _, f := range fs {
		if f.RawRuleID == ruleID {
			return f, true
		}
	}
	return secfindings.Finding{}, false
}

// ── behavioral: beaconing ────────────────────────────────────────────────────

func TestBeaconing_PeriodicTripsIrregularDoesnt(t *testing.T) {
	base := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)
	// Clockwork: 8 flows exactly 60s apart, small payloads → beaconing.
	var periodic MemFlowSource
	for i := 0; i < 8; i++ {
		periodic = append(periodic, FlowRecord{
			TenantID: "acme", DeviceID: "edge-1", Hostname: "edge-1",
			SrcAddr: "10.0.0.5", DstAddr: "203.0.113.9", DstPort: 443, Proto: 6,
			Bytes: 512, Packets: 4, Start: base.Add(time.Duration(i) * 60 * time.Second),
		})
	}
	fs, err := newEngine(nil, periodic).Detect(context.Background())
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	f, ok := findingByRule(fs, "flow-beaconing")
	if !ok {
		t.Fatal("periodic series did not trip beaconing")
	}
	if f.StatusID != secfindings.StatusWarning {
		t.Errorf("beaconing verdict = %v, want Warning", f.StatusID)
	}
	if f.EvidenceClass != secfindings.EvidenceSignal {
		t.Errorf("evidence class = %q, want signal", f.EvidenceClass)
	}
	if f.TenantID != "acme" {
		t.Errorf("tenant = %q, want acme (stamped from record)", f.TenantID)
	}

	// Irregular intervals → no beaconing.
	offsets := []int{0, 5, 200, 3, 400, 9, 600, 2}
	var irregular MemFlowSource
	for i, off := range offsets {
		irregular = append(irregular, FlowRecord{
			TenantID: "acme", DeviceID: "edge-1", SrcAddr: "10.0.0.6", DstAddr: "203.0.113.10",
			DstPort: 443, Proto: 6, Bytes: 512, Start: base.Add(time.Duration(off+i*700) * time.Second),
		})
	}
	fs2, err := newEngine(nil, irregular).Detect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findingByRule(fs2, "flow-beaconing"); ok {
		t.Error("irregular series must not trip beaconing")
	}
}

// ── behavioral: exfil ────────────────────────────────────────────────────────

func TestExfil_VolumetricEgressToExternal(t *testing.T) {
	big := MemFlowSource{{
		TenantID: "acme", DeviceID: "edge-1", SrcAddr: "10.0.0.5", DstAddr: "198.51.100.7",
		DstPort: 443, Proto: 6, Bytes: 600 * 1024 * 1024, Packets: 400000, Start: time.Unix(1000, 0).UTC(),
	}}
	fs, err := newEngine(nil, big).Detect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findingByRule(fs, "flow-exfil-egress"); !ok {
		t.Fatal("large egress to external peer must trip exfil")
	} else if f.Severity != secfindings.SeverityHigh {
		t.Errorf("exfil severity = %q, want high", f.Severity)
	}

	// Same volume but destination is INTERNAL → not exfil.
	internal := MemFlowSource{{
		TenantID: "acme", DeviceID: "edge-1", SrcAddr: "10.0.0.5", DstAddr: "10.9.9.9",
		DstPort: 445, Proto: 6, Bytes: 600 * 1024 * 1024, Start: time.Unix(1000, 0).UTC(),
	}}
	fs2, err := newEngine(nil, internal).Detect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findingByRule(fs2, "flow-exfil-egress"); ok {
		t.Error("internal→internal volume must not trip exfil")
	}
}

// ── behavioral: scan fan-out ─────────────────────────────────────────────────

func TestScanFanout_ManyHostsTrips(t *testing.T) {
	var scan MemFlowSource
	for i := 1; i <= 120; i++ {
		scan = append(scan, FlowRecord{
			TenantID: "acme", DeviceID: "edge-1", SrcAddr: "10.0.0.9",
			DstAddr: "10.1.0." + itoa(i), DstPort: 22, Proto: 6, Bytes: 60, Start: time.Unix(int64(i), 0).UTC(),
		})
	}
	fs, err := newEngine(nil, scan).Detect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findingByRule(fs, "flow-scan-fanout")
	if !ok {
		t.Fatal("120-host fan-out must trip scan")
	}
	if f.ControlID != "T1046" {
		t.Errorf("scan technique = %q, want T1046", f.ControlID)
	}

	// A handful of hosts must not trip.
	small := MemFlowSource{
		{TenantID: "acme", DeviceID: "edge-1", SrcAddr: "10.0.0.9", DstAddr: "10.1.0.1", DstPort: 22, Start: time.Unix(1, 0).UTC()},
		{TenantID: "acme", DeviceID: "edge-1", SrcAddr: "10.0.0.9", DstAddr: "10.1.0.2", DstPort: 22, Start: time.Unix(2, 0).UTC()},
	}
	fs2, _ := newEngine(nil, small).Detect(context.Background())
	if _, ok := findingByRule(fs2, "flow-scan-fanout"); ok {
		t.Error("2-host fan-out must not trip scan")
	}
}

// ── fail-closed ──────────────────────────────────────────────────────────────

func TestFailClosed_SourceErrorPropagates(t *testing.T) {
	boom := errors.New("store down")

	// Log source failure → whole run fails, no findings (never a false clear).
	e1 := NewEngine(DefaultCatalog(), FailingLogSource(boom), MemFlowSource(nil), WithClock(fixedClock()))
	if fs, err := e1.Detect(context.Background()); err == nil || fs != nil {
		t.Fatalf("log-source failure must fail closed, got fs=%v err=%v", fs, err)
	}
	// Flow source failure → same.
	e2 := NewEngine(DefaultCatalog(), MemLogSource(nil), FailingFlowSource(boom), WithClock(fixedClock()))
	if fs, err := e2.Detect(context.Background()); err == nil || fs != nil {
		t.Fatalf("flow-source failure must fail closed, got fs=%v err=%v", fs, err)
	}
}

func TestEmptySources_NoFindingsNoError(t *testing.T) {
	fs, err := newEngine(nil, nil).Detect(context.Background())
	if err != nil {
		t.Fatalf("empty sources should not error: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("empty sources should yield no findings, got %d", len(fs))
	}
}

// ── determinism ──────────────────────────────────────────────────────────────

func TestDeterministicOrdering(t *testing.T) {
	logs := MemLogSource{
		{TenantID: "acme", DeviceID: "d2", Mnemonic: "X", Message: "clear logging"},
		{TenantID: "acme", DeviceID: "d1", Mnemonic: "Y", Message: "no logging host 1.1.1.1"},
	}
	var flows MemFlowSource
	for i := 0; i < 8; i++ {
		flows = append(flows, FlowRecord{TenantID: "acme", DeviceID: "d3", SrcAddr: "10.0.0.1", DstAddr: "203.0.113.1", Bytes: 100, Start: time.Unix(int64(i*60), 0).UTC()})
	}
	first, err := newEngine(logs, flows).Detect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := newEngine(logs, flows).Detect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("non-deterministic output on run %d", i)
		}
	}
}

// ── §3a: tenant stamped from the record, isolated per record ─────────────────

func TestTenantStampedPerRecord(t *testing.T) {
	logs := MemLogSource{
		{TenantID: "tenant-a", DeviceID: "d1", Mnemonic: "M", Message: "clear logging"},
		{TenantID: "tenant-b", DeviceID: "d2", Mnemonic: "M", Message: "clear logging"},
	}
	fs, err := newEngine(logs, nil).Detect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range fs {
		got[f.Resource.DeviceID] = f.TenantID
	}
	if got["d1"] != "tenant-a" || got["d2"] != "tenant-b" {
		t.Fatalf("tenant not stamped per record: %v", got)
	}
}

// ── integration: findings flow through secbus as security_signal ─────────────

func TestFindingsMapThroughSecbus(t *testing.T) {
	logs := MemLogSource{{TenantID: "acme", DeviceID: "edge-1", Hostname: "edge-1", Mnemonic: "M", Message: "no logging host 10.1.1.1"}}
	fs, err := newEngine(logs, nil).Detect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("expected at least one finding")
	}
	ev, err := secbus.FromFinding(fs[0])
	if err != nil {
		t.Fatalf("secbus.FromFinding: %v", err)
	}
	if ev.Kind != secbus.KindSignal {
		t.Errorf("bus kind = %q, want %q", ev.Kind, secbus.KindSignal)
	}
	if ev.TenantID != "acme" {
		t.Errorf("bus tenant = %q, want acme", ev.TenantID)
	}
	if ev.EntityID != "edge-1" {
		t.Errorf("bus entity = %q, want edge-1", ev.EntityID)
	}
	if ev.Attrs["control_id"] != "T1562.001" {
		t.Errorf("bus attrs.control_id = %v, want T1562.001", ev.Attrs["control_id"])
	}
	// Deterministic native id: same finding → same id.
	ev2, _ := secbus.FromFinding(fs[0])
	if ev.NativeID != ev2.NativeID || ev.NativeID == "" {
		t.Errorf("native id not stable/non-empty: %q vs %q", ev.NativeID, ev2.NativeID)
	}
}

// itoa is a tiny stdlib-free int→string for test dst addresses.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [4]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
