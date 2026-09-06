// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bmp

// metrics_test.go — the exposition surface.
//
// Two properties: the scrape is BYTE-STABLE (sorted labels, so a diff between
// two scrapes is a real change), and every method is nil-safe so a metric-less
// deployment needs no branch at the call site.

import (
	"strings"
	"testing"
)

func TestMetricsExpositionIsCompleteAndStable(t *testing.T) {
	m := NewMetrics()
	m.Session(OutcomeAccepted)
	m.Session(OutcomeUnknownSource)
	m.Session(OutcomeUnknownSource)
	m.Session(OutcomeAtCapacity)
	m.Session(OutcomeBadAddress)
	m.SessionOpened()
	m.SessionOpened()
	m.SessionClosed()
	m.Message(MsgRouteMonitoring)
	m.Message(MsgRouteMonitoring)
	m.Message(MsgPeerUp)
	m.Message(MsgType(99))
	m.ParseError(StageHeader)
	m.ParseError(StageMessage)
	m.ParseError(StageOversize)
	m.ParseError(StageRead)
	m.Unsupported(KindAddressFamily, 3)
	m.Unsupported(KindPathAttribute, 1)
	m.Unsupported(KindMessageType, 1)
	m.UpdatesStored(10)
	m.UpdatesDropped(4)

	var b strings.Builder
	m.Write(&b)
	out := b.String()

	for _, want := range []string{
		`netops_bmp_sessions_total{outcome="accepted"} 1`,
		`netops_bmp_sessions_total{outcome="unknown_source"} 2`,
		`netops_bmp_sessions_total{outcome="at_capacity"} 1`,
		`netops_bmp_sessions_total{outcome="bad_address"} 1`,
		"netops_bmp_sessions_active 1",
		`netops_bmp_messages_total{type="route_monitoring"} 2`,
		`netops_bmp_messages_total{type="peer_up"} 1`,
		`netops_bmp_messages_total{type="unknown"} 1`,
		`netops_bmp_parse_errors_total{stage="header"} 1`,
		`netops_bmp_parse_errors_total{stage="oversize"} 1`,
		`netops_bmp_unsupported_total{kind="address_family"} 3`,
		"netops_bmp_updates_stored_total 10",
		"netops_bmp_updates_dropped_total 4",
		"# TYPE netops_bmp_sessions_active gauge",
		"# TYPE netops_bmp_updates_dropped_total counter",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scrape is missing %q:\n%s", want, out)
		}
	}

	// Byte stability: a second scrape of unchanged counters is identical.
	var b2 strings.Builder
	m.Write(&b2)
	if b2.String() != out {
		t.Fatal("two scrapes of the same counters differ — the label order is not sorted")
	}
	// Labels within a family are sorted.
	idx := func(s string) int { return strings.Index(out, s) }
	if idx(`outcome="accepted"`) > idx(`outcome="at_capacity"`) {
		t.Fatal("outcome labels are not sorted")
	}
}

func TestActiveGaugeNeverGoesNegative(t *testing.T) {
	m := NewMetrics()
	m.SessionClosed()
	m.SessionClosed()
	if got := m.Snapshot().Active; got != 0 {
		t.Fatalf("active = %d — a gauge that reads negative is a bug reported as data", got)
	}
}

func TestZeroCountersEmitTheHelpButNoSeries(t *testing.T) {
	var b strings.Builder
	NewMetrics().Write(&b)
	out := b.String()
	if !strings.Contains(out, "# HELP netops_bmp_messages_total") {
		t.Fatal("the HELP line must be present even with no observations")
	}
	if strings.Contains(out, `netops_bmp_messages_total{`) {
		t.Fatal("a family with no observations must emit no series")
	}
	if !strings.Contains(out, "netops_bmp_sessions_active 0") {
		t.Fatal("the gauge must always report a value")
	}
}

func TestEveryMetricsMethodIsNilSafe(t *testing.T) {
	var m *Metrics
	m.Session(OutcomeAccepted)
	m.SessionOpened()
	m.SessionClosed()
	m.Message(MsgPeerUp)
	m.ParseError(StageRead)
	m.Unsupported(KindMessageType, 1)
	m.UpdatesStored(1)
	m.UpdatesDropped(1)
	var b strings.Builder
	m.Write(&b)
	if b.Len() != 0 {
		t.Fatalf("a nil Metrics wrote %q", b.String())
	}
	snap := m.Snapshot()
	if snap.Sessions == nil || snap.Messages == nil || snap.ParseErrors == nil || snap.Unsupported == nil {
		t.Fatal("a nil Metrics must still return a usable, empty Snapshot")
	}
}

func TestNonPositiveIncrementsAreIgnored(t *testing.T) {
	m := NewMetrics()
	m.Unsupported(KindMessageType, 0)
	m.Unsupported(KindMessageType, -5)
	m.UpdatesStored(0)
	m.UpdatesDropped(-1)
	snap := m.Snapshot()
	if len(snap.Unsupported) != 0 || snap.UpdatesStored != 0 || snap.UpdatesDropped != 0 {
		t.Fatalf("a non-positive increment moved a counter: %+v", snap)
	}
}

func TestSnapshotIsACopyNotAView(t *testing.T) {
	m := NewMetrics()
	m.Message(MsgPeerUp)
	snap := m.Snapshot()
	m.Message(MsgPeerUp)
	if snap.Messages["peer_up"] != 1 {
		t.Fatal("the snapshot aliased the live counters")
	}
	snap.Messages["peer_up"] = 999
	if m.Snapshot().Messages["peer_up"] != 2 {
		t.Fatal("mutating a snapshot changed the live counters")
	}
}

func TestPeerDownReasonTextCoversTheRegistry(t *testing.T) {
	want := map[uint8]string{
		1: "local_notification",
		2: "local_fsm",
		3: "remote_notification",
		4: "remote_no_notification",
		5: "peer_deconfigured",
		6: "local_system_closed",
		9: "unknown",
	}
	for code, text := range want {
		if got := (PeerDown{Reason: code}).ReasonText(); got != text {
			t.Errorf("reason %d = %q, want %q", code, got, text)
		}
	}
}

func TestTerminationReasonTextCoversTheRegistry(t *testing.T) {
	for code, want := range map[uint16]string{
		0: "administratively closed",
		1: "unspecified reason",
		2: "out of resources",
		3: "redundant connection",
		4: "permanently administratively closed",
	} {
		if got := terminationReason(&Termination{ReasonCode: code, HasReason: true}); !strings.Contains(got, want) {
			t.Errorf("termination reason %d = %q, want it to name %q", code, got, want)
		}
	}
	if got := terminationReason(&Termination{ReasonCode: 77, HasReason: true}); !strings.Contains(got, "77") {
		t.Errorf("an unassigned reason must still be reported: %q", got)
	}
	if got := terminationReason(nil); got == "" {
		t.Error("a nil termination must still yield a reason")
	}
	if got := terminationReason(&Termination{}); !strings.Contains(got, "terminated") {
		t.Errorf("a reasonless termination = %q", got)
	}
}
