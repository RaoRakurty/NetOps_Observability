// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"bufio"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Tracker 387, trap semantics: golden fixtures from REAL lab traps
// (testdata/traps_lab_20261110.jsonl, read from OpenSearch on 2026-11-10 with no
// community value: the receiver never stored one) and standards-exact synthetic
// ones. Every assertion tests a VALUE.

// labNames is the inventory's display name per device id, as the receiver's
// attribution stamps it (deviceName). The BGP records were stored by a receiver
// older than PR 13's attribution, so the test attributes them to the lab's
// inventory id for cEDGE-81, the device that sent them.
var labNames = map[string]string{"vedge-51-0a0b4db5": "vEdge-51", "cedge-81-11060ae2": "cEDGE-81", "vedge-20-1e95f00f": "vEdge-20"}

const cedge81 = "cedge-81-11060ae2"

type labTrap struct {
	Capture     string `json:"_capture"`
	Timestamp   string `json:"timestamp"`
	Host        string `json:"host"`
	Device      string `json:"device"`
	SNMPVersion string `json:"snmp_version"`
	TrapOID     string `json:"trap_oid"`
	Varbinds    []struct {
		OID   string `json:"oid"`
		Value string `json:"value"`
	} `json:"varbinds"`
}

func loadLabTraps(t *testing.T) []labTrap {
	t.Helper()
	f, err := os.Open("testdata/traps_lab_20261110.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []labTrap
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var lt labTrap
		if err := json.Unmarshal(sc.Bytes(), &lt); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(sc.Text()), "community") || strings.Contains(sc.Text(), "snmp_comm") {
			t.Fatal("a lab fixture must never carry a community")
		}
		out = append(out, lt)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func labByCapture(t *testing.T, capture string) []labTrap {
	t.Helper()
	var out []labTrap
	for _, lt := range loadLabTraps(t) {
		if lt.Capture == capture {
			out = append(out, lt)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no lab record %q", capture)
	}
	return out
}

// buildEvent decodes a record's varbinds the way the receiver does after the
// PDU is read (finalizeTrap, attribution, interfaceFor).
func buildEvent(lt labTrap, device string) *TrapEvent {
	ev := &TrapEvent{Signal: "snmptrap", Timestamp: lt.Timestamp, Host: lt.Host, Device: device,
		Version: lt.SNMPVersion, TrapOID: lt.TrapOID}
	for _, vb := range lt.Varbinds {
		ev.Varbinds = append(ev.Varbinds, decodeVarbind(vb.OID, vb.Value))
	}
	ev.TrapName, ev.Severity = trapMeta(lt.TrapOID)
	ev.DeviceName = labNames[device]
	interfaceFor(ev, nil)
	return ev
}

func receiveTime(t *testing.T, ts string) time.Time {
	t.Helper()
	rt, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func eq[T comparable](t *testing.T, what string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

func metric(t *testing.T, ev *TrapEvent, name string) TrapMetric {
	t.Helper()
	m, ok := ev.Metrics[name]
	if !ok {
		t.Fatalf("metric %s absent; have %+v (invalid %v)", name, ev.Metrics, ev.MetricsInvalid)
	}
	return m
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// ── CPU: the owner's golden trap ─────────────────────────────────────────────

func TestTrapGolden_CPUCriticalFromTheLab(t *testing.T) {
	lt := labByCapture(t, "cpu_golden_critical")[0]
	ev := buildEvent(lt, lt.Device)
	deriveEnvelopeWith(ev, newTrapTransitions(0), receiveTime(t, lt.Timestamp))

	eq(t, "title", ev.Title, "CPU utilization reached 100% on vEdge-51 — system CPU 95.85%")
	eq(t, "title_basis", ev.TitleBasis, titleTemplated)
	eq(t, "native_severity", ev.NativeSeverity, "critical(1)")
	eq(t, "severity (normalized, independent)", ev.Severity, "crit")
	tot := metric(t, ev, "cpu_total_percent")
	eq(t, "cpu_total", tot.Value, 100.0)
	eq(t, "cpu_total basis", tot.Basis, "derived")
	eq(t, "cpu_total formula", tot.Formula, "100 - idle")
	sys := metric(t, ev, "cpu_system_percent")
	eq(t, "cpu_system", sys.Value, 95.85)
	eq(t, "cpu_system basis", sys.Basis, "observed")
	eq(t, "cpu_user", metric(t, ev, "cpu_user_percent").Value, 4.15)
	eq(t, "cpu_idle", metric(t, ev, "cpu_idle_percent").Value, 0.0)
	eq(t, "unit", sys.Unit, "percent")
	if len(ev.MetricsInvalid) != 0 {
		t.Errorf("metrics_invalid %v", ev.MetricsInvalid)
	}
	if ev.ThresholdReportedPercent == nil || *ev.ThresholdReportedPercent != 90 {
		t.Fatalf("threshold %v", ev.ThresholdReportedPercent)
	}
	eq(t, "threshold_basis", ev.ThresholdBasis, "reported_by_device")
	eq(t, "device_event_time", ev.DeviceEventTime, "2026-11-10T04:07:27.5Z")
	eq(t, "received_time", ev.ReceivedTime, "2026-11-10T04:07:51.913Z")
	if ev.ObservedDelayS == nil || *ev.ObservedDelayS != 24.413 {
		t.Errorf("observed_delay_s %v", ev.ObservedDelayS)
	}
	eq(t, "delay_basis", ev.DelayBasis, "device_clock_vs_receive")
	if ev.DeviceUptimeS == nil || *ev.DeviceUptimeS <= 0 || ev.DeviceUptimeHuman == "" {
		t.Errorf("uptime %v %q", ev.DeviceUptimeS, ev.DeviceUptimeHuman)
	}
	eq(t, "correlation_key", ev.CorrelationKey, "cpu:vedge-51-0a0b4db5:device")
	eq(t, "event_id", ev.EventID, ev.MessageKey)
	eq(t, "lifecycle_state", ev.LifecycleState, lifecycleRaise)
	eq(t, "lifecycle_basis (nothing remembered yet)", ev.LifecycleBasis, lifecycleUnknown)
	eq(t, "recovery_verified", ev.RecoveryVerified, false)
	eq(t, "auth_model", ev.AuthModel, "community")
	eq(t, "platform (VIPTELA-TRAPS is SD-WAN only)", ev.Platform, "SD-WAN")
	eq(t, "authenticated stays false for v2c", ev.Authenticated, false)
	eq(t, "op_state", ev.OpState, "alarm")
	if ev.Guidance == nil || ev.Guidance.Basis != "pack_guidance" || !strings.HasPrefix(ev.Guidance.Impact[0], "Sustained high CPU") {
		t.Fatalf("guidance %+v", ev.Guidance)
	}
	if ev.BGP != nil {
		t.Errorf("a CPU trap carries no bgp object: %+v", ev.BGP)
	}
	en := ev.Enrichment
	for _, f := range []string{"metrics.cpu_system_percent", "native_severity", "threshold_reported_percent", "device_event_time"} {
		if !contains(en.FieldsObserved, f) {
			t.Errorf("observed lacks %s: %v", f, en.FieldsObserved)
		}
	}
	for _, f := range []string{"metrics.cpu_total_percent", "title", "observed_delay_s", "correlation_key", "lifecycle_state"} {
		if !contains(en.FieldsDerived, f) {
			t.Errorf("derived lacks %s: %v", f, en.FieldsDerived)
		}
	}
	if !reflect.DeepEqual(en.FieldsGuidance, []string{"guidance.impact", "guidance.next_checks"}) || len(en.Unknown) != 0 {
		t.Errorf("guidance %v unknown %v", en.FieldsGuidance, en.Unknown)
	}
	// The varbinds: full instance OIDs, SMI type names, raw values, decoded.
	byName := map[string]TrapVarbind{}
	for _, vb := range ev.Varbinds {
		byName[vb.Name] = vb
	}
	eq(t, "severity varbind decoded", byName["netconfNotificationSeverity"].Decoded, "critical")
	eq(t, "severity varbind raw", byName["netconfNotificationSeverity"].Raw, "1")
	eq(t, "eventTime decoded", byName["eventTime"].Decoded, "2026-11-10T04:07:27.5Z")
	eq(t, "eventTime type", byName["eventTime"].Type, "DateAndTime")
	eq(t, "warning type", byName["viptelaSystemWarning"].Type, "OCTET STRING")
	eq(t, "warning oid", byName["viptelaSystemWarning"].OID, "1.3.6.1.4.1.41916.100.1.54.0")
	eq(t, "sysUpTime type", byName["sysUpTime"].Type, "TimeTicks")
}

func TestTrapGolden_CPUJSONContract(t *testing.T) {
	lt := labByCapture(t, "cpu_golden_critical")[0]
	ev := buildEvent(lt, lt.Device)
	ev.CommunityPresent = true
	deriveEnvelopeWith(ev, newTrapTransitions(0), receiveTime(t, lt.Timestamp))
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"title", "native_severity", "metrics", "threshold_reported_percent", "threshold_basis",
		"device_event_time", "received_time", "observed_delay_s", "delay_basis", "device_uptime_s", "device_uptime_human",
		"correlation_key", "event_id", "lifecycle_state", "lifecycle_basis", "auth_model", "guidance", "enrichment",
		"varbinds", "mib_module", "trap_oid", "snmp_version", "snmp_community_present", "authenticated"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("contract field %q missing", k)
		}
	}
	if doc["snmp_community_present"] != true {
		t.Errorf("snmp_community_present must be the boolean true: %v", doc["snmp_community_present"])
	}
	for _, k := range []string{"bgp", "recovery_verified", "metrics_invalid", "snmp_community"} {
		if _, ok := doc[k]; ok {
			t.Errorf("%q must be absent on this trap: %v", k, doc[k])
		}
	}
	m := doc["metrics"].(map[string]any)["cpu_total_percent"].(map[string]any)
	if m["value"] != 100.0 || m["basis"] != "derived" || m["formula"] != "100 - idle" {
		t.Errorf("cpu_total_percent wire shape %v", m)
	}
	en := doc["enrichment"].(map[string]any)
	if u, ok := en["unknown"].([]any); !ok || len(u) != 0 {
		t.Errorf("enrichment.unknown must be an empty array, got %v", en["unknown"])
	}
}

// raise -> downgrade -> escalate -> verified recovery, all real (vEdge-51,
// 01:00:38-01:00:42). A lower severity is never a recovery.
func TestTrapGolden_CPULifecycleFromTheLab(t *testing.T) {
	tg := newTrapTransitions(0)
	type want struct {
		state, basis string
		recovered    bool
		title        string
	}
	steps := []struct {
		capture string
		want    want
	}{
		{"cpu_seq_clear", want{lifecycleClear, lifecycleUnknown, true, "CPU utilization back to normal on vEdge-51 (34.54% in use)"}},
		{"cpu_seq_raise_major", want{lifecycleRaise, lifecycleFromMemory, false, ""}},
		{"cpu_seq_downgrade_minor", want{lifecycleDowngrade, lifecycleFromMemory, false, ""}},
		{"cpu_seq_escalate_major", want{lifecycleEscalate, lifecycleFromMemory, false, ""}},
		{"cpu_seq_clear_recovery", want{lifecycleClear, lifecycleFromMemory, true, ""}},
	}
	for _, s := range steps {
		lt := labByCapture(t, s.capture)[0]
		ev := buildEvent(lt, lt.Device)
		deriveEnvelopeWith(ev, tg, receiveTime(t, lt.Timestamp))
		eq(t, s.capture+" lifecycle_state", ev.LifecycleState, s.want.state)
		eq(t, s.capture+" lifecycle_basis", ev.LifecycleBasis, s.want.basis)
		eq(t, s.capture+" recovery_verified", ev.RecoveryVerified, s.want.recovered)
		if s.want.title != "" {
			eq(t, s.capture+" title", ev.Title, s.want.title)
		}
		if s.capture == "cpu_seq_downgrade_minor" {
			eq(t, "a downgrade is still an alarm", ev.OpState, "alarm")
			if ev.ThresholdReportedPercent == nil || *ev.ThresholdReportedPercent != 60 {
				t.Errorf("downgrade threshold %v", ev.ThresholdReportedPercent)
			}
		}
	}
}

func TestTrapLifecycle_RepeatAndLateReport(t *testing.T) {
	tg := newTrapTransitions(0)
	mk := func(sev, devTime string) *TrapEvent {
		ev := &TrapEvent{Device: "d1", Family: "cpu", EventState: trapStateRaise, Severity: sev, DeviceEventTime: devTime}
		ev.CorrelationKey = correlationKey(ev)
		tg.observeLifecycle(ev)
		return ev
	}
	eq(t, "first", mk("err", "2026-11-10T04:00:10Z").LifecycleState, lifecycleRaise)
	eq(t, "same severity", mk("err", "2026-11-10T04:00:20Z").LifecycleState, lifecycleRepeat)
	late := mk("crit", "2026-11-10T04:00:05Z")
	eq(t, "late basis", late.LifecycleBasis, lifecycleLate)
	// The late report did not rewind memory: the next one compares against err.
	eq(t, "after late", mk("warning", "2026-11-10T04:00:30Z").LifecycleState, lifecycleDowngrade)
	// Unattributed: never remembered, always basis unknown.
	ev := &TrapEvent{Family: "cpu", EventState: trapStateRaise, Severity: "err"}
	tg.observeLifecycle(ev)
	eq(t, "unkeyed basis", ev.LifecycleBasis, lifecycleUnknown)
	// A point event states no lifecycle.
	pt := &TrapEvent{Device: "d1", Family: "cpu", EventState: trapStatePoint}
	pt.CorrelationKey = correlationKey(pt)
	tg.observeLifecycle(pt)
	eq(t, "point", pt.LifecycleState, "")
}

func TestTrapGolden_CPUMalformedValuesAreRefusedNotShown(t *testing.T) {
	lt := labByCapture(t, "cpu_golden_critical")[0]
	for i := range lt.Varbinds {
		switch {
		case strings.HasSuffix(lt.Varbinds[i].OID, ".190.0"):
			lt.Varbinds[i].Value = "abc" // user: not a number
		case strings.HasSuffix(lt.Varbinds[i].OID, ".191.0"):
			lt.Varbinds[i].Value = "150" // system: out of range
		case strings.HasSuffix(lt.Varbinds[i].OID, ".192.0"):
			lt.Varbinds[i].Value = "-1" // idle: out of range, so no total either
		}
	}
	ev := buildEvent(lt, lt.Device)
	deriveEnvelopeWith(ev, nil, receiveTime(t, lt.Timestamp))
	if len(ev.Metrics) != 0 {
		t.Errorf("no metric may survive: %+v", ev.Metrics)
	}
	if !reflect.DeepEqual(ev.MetricsInvalid, []string{"cpu_idle_percent", "cpu_system_percent", "cpu_user_percent"}) {
		t.Errorf("metrics_invalid %v", ev.MetricsInvalid)
	}
	if len(ev.Values) != 0 {
		t.Errorf("the legacy values must not keep a refused number: %v", ev.Values)
	}
	eq(t, "title without numbers", ev.Title, "CPU on vEdge-51 is above 90%, as the device reports")
	if !contains(ev.Enrichment.Unknown, "metrics.cpu_idle_percent") {
		t.Errorf("unknown %v", ev.Enrichment.Unknown)
	}
}

func TestTrapGolden_CPUMissingInventory(t *testing.T) {
	lt := labByCapture(t, "cpu_golden_critical")[0]
	ev := buildEvent(lt, "")
	deriveEnvelopeWith(ev, newTrapTransitions(0), receiveTime(t, lt.Timestamp))
	eq(t, "title names the source", ev.Title, "CPU utilization reached 100% on 192.168.222.101 — system CPU 95.85%")
	eq(t, "no key without a device", ev.CorrelationKey, "")
	eq(t, "lifecycle basis", ev.LifecycleBasis, lifecycleUnknown)
	if !contains(ev.Enrichment.Unknown, "device") {
		t.Errorf("unknown %v", ev.Enrichment.Unknown)
	}
}

// ── BGP: the real never-established flap ──────────────────────────────────────

func TestTrapGolden_BGPNeverEstablishedFromTheLab(t *testing.T) {
	tg := newTrapTransitions(0)
	for _, lt := range labByCapture(t, "bgp_forward_before") {
		ev := buildEvent(lt, cedge81)
		deriveEnvelopeWith(ev, tg, receiveTime(t, lt.Timestamp))
		eq(t, "forward title", ev.Title, "BGP neighbour 192.168.200.34 on cEDGE-81 went from Idle to Active (never established)")
		eq(t, "forward class", ev.BGP.TransitionClass, bgpNeverEstablished)
		eq(t, "CISCO-BGP4-MIB is shared by IOS, IOS-XE and NX-OS: no platform", ev.Platform, "")
	}
	group := labByCapture(t, "bgp_transition")
	var ids = map[string]int{}
	var seqs []int
	for i, lt := range group {
		ev := buildEvent(lt, cedge81)
		deriveEnvelopeWith(ev, tg, receiveTime(t, lt.Timestamp))
		b := ev.BGP
		if b == nil {
			t.Fatalf("%s: no bgp object", lt.TrapOID)
		}
		eq(t, lt.TrapOID+" peer", b.PeerAddress, "192.168.200.34")
		eq(t, lt.TrapOID+" afi", b.PeerAFI, "ipv4")
		if b.State == "idle" {
			ids[ev.TransitionID]++
			seqs = append(seqs, ev.TransitionSeq)
			eq(t, lt.TrapOID+" prev", b.PrevState, "active")
			eq(t, lt.TrapOID+" class", b.TransitionClass, bgpNeverEstablished)
			eq(t, lt.TrapOID+" op_state", ev.OpState, "degraded")
			eq(t, lt.TrapOID+" impact", ev.Impact, "degraded")
			eq(t, lt.TrapOID+" event_severity", ev.EventSeverity, "warning")
			eq(t, lt.TrapOID+" title", ev.Title, "BGP neighbour 192.168.200.34 on cEDGE-81 went from Active to Idle (never established)")
			if !strings.HasPrefix(ev.Guidance.Impact[0], "This session did not reach Established") {
				t.Errorf("%s guidance %v", lt.TrapOID, ev.Guidance.Impact)
			}
			eq(t, lt.TrapOID+" key", ev.CorrelationKey, "bgp:cedge-81-11060ae2:-/ipv4/192.168.200.34")
			eq(t, lt.TrapOID+" representative", ev.TransitionRepresentative, ev.TransitionSeq == 1)
		}
		switch i {
		case 0: // cbgpPeer2BackwardTransNotification: bare index, no prior state of its own
			eq(t, "vendor-form peer", b.PeerBasis, peerFromVendorForm)
			eq(t, "prior from the peer's history", b.PrevStateBasis, bgpPrevFromPeerHistory)
		case 1: // bgpBackwardTransition: RFC index, no prior state of its own
			eq(t, "rfc peer", b.PeerBasis, peerFromIndex)
			eq(t, "prior still from history", b.PrevStateBasis, bgpPrevFromPeerHistory)
		case 2: // cbgpPeer2BackwardTransition carries cbgpPeer2PrevState
			eq(t, "prior from the trap", b.PrevStateBasis, bgpPrevFromTrap)
		}
	}
	if len(ids) != 1 {
		t.Fatalf("one transition, got ids %v", ids)
	}
	if !reflect.DeepEqual(seqs, []int{1, 2, 3, 4, 5, 6}) {
		t.Errorf("seqs %v", seqs)
	}
}

func TestTrapGolden_BGPWithoutHistoryNeverClaimsALoss(t *testing.T) {
	// A fresh receiver: the first report names no prior state and nothing is
	// remembered, so the class is unknown, never session_lost.
	lt := labByCapture(t, "bgp_transition")[0]
	ev := buildEvent(lt, cedge81)
	deriveEnvelopeWith(ev, newTrapTransitions(0), receiveTime(t, lt.Timestamp))
	eq(t, "class", ev.BGP.TransitionClass, bgpTransitionUnknown)
	eq(t, "prev", ev.BGP.PrevState, "")
	eq(t, "op_state", ev.OpState, "unknown")
	eq(t, "title", ev.Title, "BGP neighbour 192.168.200.34 on cEDGE-81 moved to Idle")
	if strings.Contains(strings.ToLower(ev.Title), "lost") || ev.Impact == "service_affecting" {
		t.Errorf("an unevidenced transition must not read as a loss: %q %q", ev.Title, ev.Impact)
	}
	eq(t, "generic guidance", ev.Guidance.Impact[0][:22], "A BGP session changed ")
}

// ── BGP: synthetic, standards-exact ───────────────────────────────────────────

const (
	cbgpPeer2Col = "1.3.6.1.4.1.9.9.187.1.2.5.1."
	bgpPeerCol   = "1.3.6.1.2.1.15.3.1."
	cbgpPeerCol  = "1.3.6.1.4.1.9.9.187.1.2.1.1."
)

func synth(oid, device string, ts time.Time, vbs ...[2]string) *TrapEvent {
	lt := labTrap{Timestamp: ts.UTC().Format(time.RFC3339Nano), Host: "192.0.2.1", SNMPVersion: "v2c", TrapOID: oid}
	for _, v := range vbs {
		lt.Varbinds = append(lt.Varbinds, struct {
			OID   string `json:"oid"`
			Value string `json:"value"`
		}{v[0], v[1]})
	}
	return buildEvent(lt, device)
}

func TestTrapSynthetic_SessionLostSixReportsOneTransition(t *testing.T) {
	tg := newTrapTransitions(0)
	t0 := time.Date(2026, 11, 10, 6, 0, 0, 0, time.UTC)
	peer := "10.20.30.40"
	up := [2]string{"1.3.6.1.2.1.1.3.0", "5000000"}
	reports := []*TrapEvent{
		synth("1.3.6.1.4.1.9.9.187.0.6", cedge81, t0, up, [2]string{cbgpPeer2Col + "17." + peer, "0x0400"}, [2]string{cbgpPeer2Col + "3." + peer, "1"}),
		synth("1.3.6.1.2.1.15.7.2", cedge81, t0.Add(400*time.Millisecond), up, [2]string{bgpPeerCol + "14." + peer, "0x0400"}, [2]string{bgpPeerCol + "2." + peer, "1"}),
		synth("1.3.6.1.4.1.9.9.187.0.8", cedge81, t0.Add(500*time.Millisecond), up, [2]string{cbgpPeer2Col + "3." + peer, "1"}, [2]string{cbgpPeer2Col + "29." + peer, "6"}),
		synth("1.3.6.1.4.1.9.9.187.0.2", cedge81, t0.Add(510*time.Millisecond), up, [2]string{bgpPeerCol + "2." + peer, "1"}, [2]string{cbgpPeerCol + "8." + peer, "6"}),
		synth("1.3.6.1.4.1.9.9.187.0.7", cedge81, t0.Add(600*time.Millisecond), up, [2]string{cbgpPeer2Col + "3." + peer, "1"}, [2]string{cbgpPeer2Col + "29." + peer, "6"}),
		synth("1.3.6.1.4.1.9.9.187.0.1", cedge81, t0.Add(900*time.Millisecond), up, [2]string{bgpPeerCol + "2." + peer, "1"}, [2]string{cbgpPeerCol + "8." + peer, "6"}),
	}
	// What the peer reached before: established (a bgpEstablished a minute ago).
	est := synth("1.3.6.1.2.1.15.7.1", cedge81, t0.Add(-time.Minute), up, [2]string{bgpPeerCol + "2." + peer, "6"})
	deriveEnvelopeWith(est, tg, t0.Add(-time.Minute))
	eq(t, "established", est.BGP.TransitionClass, bgpSessionUp)
	ids := map[string]bool{}
	for i, ev := range reports {
		deriveEnvelopeWith(ev, tg, t0.Add(time.Duration(i)*100*time.Millisecond))
		ids[ev.TransitionID] = true
		eq(t, ev.TrapOID+" class", ev.BGP.TransitionClass, bgpSessionLost)
		eq(t, ev.TrapOID+" op_state", ev.OpState, "down")
		eq(t, ev.TrapOID+" impact", ev.Impact, "service_affecting")
		eq(t, ev.TrapOID+" event_severity", ev.EventSeverity, "err")
		eq(t, ev.TrapOID+" occurrence_count", ev.OccurrenceCount, i+1)
	}
	if len(ids) != 1 {
		t.Fatalf("six reports, one transition: %v", ids)
	}
	eq(t, "title", reports[0].Title, "BGP neighbour 10.20.30.40 on cEDGE-81 went from Established to Idle (session lost) — last error: Hold Timer Expired")
	if c := reports[0].BGP.LastErrorCode; c == nil || *c != 4 {
		t.Errorf("last error code %v", c)
	}
	eq(t, "lifecycle of the first", reports[0].LifecycleState, lifecycleRaise)
	eq(t, "lifecycle of a repeat", reports[3].LifecycleState, lifecycleRepeat)
}

func TestTrapSynthetic_Peer2IndexForms(t *testing.T) {
	t0 := time.Date(2026, 11, 10, 6, 0, 0, 0, time.UTC)
	v6 := "32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1"
	cases := []struct {
		index, peer, afi, basis string
	}{
		{"2.16." + v6, "2001:db8::1", "ipv6", peerFromIndex},                 // RFC 4001 type.len.octets
		{"1.4.10.0.0.1", "10.0.0.1", "ipv4", peerFromIndex},                  // RFC 4001 IPv4
		{v6, "2001:db8::1", "ipv6", peerFromVendorForm},                      // IOS-XE bare IPv6
		{"4.20." + v6 + ".0.0.0.3", "2001:db8::1%3", "ipv6z", peerFromIndex}, // ipv6z with zone 3
		{"1.4.10.0.1", "", "", peerUnparsed},                                 // truncated: never guessed
		{"1.4.10.0.0.256", "", "", peerUnparsed},                             // not an octet
		{"7.4.10.0.0.1", "", "", peerUnparsed},                               // no such InetAddressType
	}
	for _, c := range cases {
		ev := synth("1.3.6.1.4.1.9.9.187.0.8", cedge81, t0, [2]string{cbgpPeer2Col + "3." + c.index, "1"}, [2]string{cbgpPeer2Col + "29." + c.index, "6"})
		deriveEnvelopeWith(ev, nil, t0)
		eq(t, c.index+" peer", ev.BGP.PeerAddress, c.peer)
		eq(t, c.index+" afi", ev.BGP.PeerAFI, c.afi)
		eq(t, c.index+" basis", ev.BGP.PeerBasis, c.basis)
		if c.basis == peerUnparsed {
			eq(t, c.index+" no key", ev.CorrelationKey, "")
			eq(t, c.index+" title", ev.Title, "A BGP neighbour on cEDGE-81 moved to Idle (session lost)")
		}
	}
}

func TestTrapSynthetic_MultiVendorBGP(t *testing.T) {
	t0 := time.Date(2026, 11, 10, 6, 0, 0, 0, time.UTC)
	v6 := "32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.2"
	ara := "1.3.6.1.4.1.30065.4.1.1."
	jnx := "1.3.6.1.4.1.2636.5.1.1.2."
	nok := "1.3.6.1.4.1.6527.3.1.2.14.4.7.1."
	cases := []struct {
		name, oid                      string
		vbs                            [][2]string
		peer, afi, vrf, state, lastErr string
	}{
		{"arista", "1.3.6.1.4.1.30065.4.1.0.2", [][2]string{
			{ara + "2.1.13.1.2.16." + v6, "1"}, {ara + "3.1.1.1.2.16." + v6, "6"}, {ara + "3.1.2.1.2.16." + v6, "2"}},
			"2001:db8::2", "ipv6", "1", "idle", "Cease / Administrative Shutdown"},
		{"juniper", "1.3.6.1.4.1.2636.5.1.1.1.0.2", [][2]string{
			{jnx + "1.1.1.2.0.1.4.10.0.0.1.1.4.10.0.0.2", "1"}, {jnx + "2.1.1.1.0.1.4.10.0.0.1.1.4.10.0.0.2", "0x0400"}},
			"10.0.0.2", "ipv4", "0", "idle", "Hold Timer Expired"},
		{"nokia", "1.3.6.1.4.1.6527.3.1.3.14.0.8", [][2]string{{nok + "59.1.2.16." + v6, "1"}},
			"2001:db8::2", "ipv6", "1", "idle", ""},
	}
	for _, c := range cases {
		ev := synth(c.oid, "dev-"+c.name, t0, c.vbs...)
		deriveEnvelopeWith(ev, nil, t0)
		if ev.BGP == nil {
			t.Fatalf("%s: no bgp object (varbinds %+v)", c.name, ev.Varbinds)
		}
		eq(t, c.name+" peer", ev.BGP.PeerAddress, c.peer)
		eq(t, c.name+" afi", ev.BGP.PeerAFI, c.afi)
		eq(t, c.name+" vrf", ev.BGP.VRF, c.vrf)
		eq(t, c.name+" state", ev.BGP.State, c.state)
		eq(t, c.name+" basis", ev.BGP.PeerBasis, peerFromIndex)
		eq(t, c.name+" last error", ev.BGP.LastError, c.lastErr)
		eq(t, c.name+" title basis", ev.TitleBasis, titleTemplated)
	}
}

// ── Interfaces ────────────────────────────────────────────────────────────────

func TestTrapSynthetic_InterfaceTitleAndIntent(t *testing.T) {
	t0 := time.Date(2026, 11, 10, 6, 0, 0, 0, time.UTC)
	mk := func(admin string) *TrapEvent {
		ev := synth("1.3.6.1.6.3.1.1.5.3", "vedge-20-1e95f00f", t0,
			[2]string{"1.3.6.1.2.1.2.2.1.1.3", "3"}, [2]string{"1.3.6.1.2.1.2.2.1.7.3", admin},
			[2]string{"1.3.6.1.2.1.2.2.1.8.3", "2"}, [2]string{"1.3.6.1.2.1.31.1.1.1.1.3", "ge0/3"})
		deriveEnvelopeWith(ev, nil, t0)
		return ev
	}
	fault := mk("1")
	eq(t, "title", fault.Title, "Interface ge0/3 on vEdge-20 went down (admin up)")
	eq(t, "op_state", fault.OpState, "down")
	eq(t, "impact", fault.Impact, "service_affecting")
	eq(t, "key", fault.CorrelationKey, "link_state:vedge-20-1e95f00f:if/ge0/3")
	shut := mk("2")
	eq(t, "title shut", shut.Title, "Interface ge0/3 on vEdge-20 went down (admin down)")
	eq(t, "an operator's shutdown is no service fault", shut.Impact, "none")
	eq(t, "shut severity", shut.EventSeverity, "notice")
}

// ── Fallback ──────────────────────────────────────────────────────────────────

func TestTrapTitle_UnlistedNotificationKeepsTheSummary(t *testing.T) {
	t0 := time.Date(2026, 11, 10, 6, 0, 0, 0, time.UTC)
	ev := synth("1.3.6.1.4.1.9.9.187.0.3", cedge81, t0) // cbgpPrefixThresholdExceeded: no wording
	deriveEnvelopeWith(ev, nil, t0)
	eq(t, "basis", ev.TitleBasis, titleFallback)
	eq(t, "title", ev.Title, "Cisco cbgpPrefixThresholdExceeded")
}
