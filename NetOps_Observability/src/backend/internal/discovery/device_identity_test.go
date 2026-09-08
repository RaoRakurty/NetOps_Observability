// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery

// device_identity_test.go — the HARDWARE IDENTITY half of the enrichment tick:
// what lands on the inventory row when a probe reads a chassis serial, what is
// persisted, and — the part that matters most — what is left ALONE.

import (
	"context"
	"testing"
	"time"

	"netops/backend/internal/deviceident"
	"netops/backend/internal/osprobe"
	"netops/backend/models"
)

// identitySource is a rung that answers both questions from a script.
type identitySource struct {
	method   osprobe.Method
	version  map[string]string
	identity map[string]deviceident.Identity
	calls    []string
}

func (s *identitySource) Method() osprobe.Method { return s.method }

func (s *identitySource) Probe(_ context.Context, t osprobe.Target) (string, error) {
	s.calls = append(s.calls, t.DeviceID)
	return s.version[t.DeviceID], nil
}

func (s *identitySource) ProbeWithIdentity(_ context.Context, t osprobe.Target) (string, deviceident.Identity, error) {
	s.calls = append(s.calls, t.DeviceID)
	return s.version[t.DeviceID], s.identity[t.DeviceID], nil
}

func srlIdentity() deviceident.Identity {
	return deviceident.Identity{
		Serial: "Sim Serial No.", Model: "7220 IXR-D3L",
		SerialCommand: "show version", ModelCommand: "show version", ProfileID: "nokia/srlinux",
	}
}

// TestEnrichmentLearnsTheSerialAndItsProvenance — the headline: a row that knew
// nothing about the chassis it names acquires a serial, a model, a source and a
// timestamp, and (being an operator-owned row) all of it is persisted.
func TestEnrichmentLearnsTheSerialAndItsProvenance(t *testing.T) {
	st := newProbeStore(spineRow())
	a := NewDiscoveryAggregator()
	a.SetStore(st)
	a.SetOSVersionLadder(ladderOf(t, &identitySource{
		method:   osprobe.MethodSSH,
		version:  map[string]string{"spine1": srlProbed},
		identity: map[string]deviceident.Identity{"spine1": srlIdentity()},
	}))

	a.enrichOSVersions(context.Background())

	got, ok := a.Get("spine1")
	if !ok {
		t.Fatal("the device left the inventory")
	}
	if got.SerialNumber != "Sim Serial No." {
		t.Errorf("serial_number = %q, want what the device printed", got.SerialNumber)
	}
	if got.SerialSource != string(osprobe.MethodSSH) {
		t.Errorf("serial_source = %q, want ssh", got.SerialSource)
	}
	if got.SerialAt.IsZero() {
		t.Error("serial_at is zero — a reading nobody can tell is stale")
	}
	if got.Model != "7220 IXR-D3L" {
		t.Errorf("model = %q, want the chassis type the device printed", got.Model)
	}
	if got.OSVersion != srlProbed {
		t.Errorf("os_version = %q — the version half must still land", got.OSVersion)
	}
	persisted := st.get("spine1")
	if persisted.SerialNumber != "Sim Serial No." || persisted.SerialSource != "ssh" {
		t.Errorf("persisted row = (%q via %q), want the learned serial and its provenance",
			persisted.SerialNumber, persisted.SerialSource)
	}
	if st.putCall != 1 {
		t.Errorf("wrote the store %d times, want ONE write for both halves of the reading", st.putCall)
	}
}

// TestEnrichmentNeverInventsASerial — the invariant, through the tick. A rung
// that read nothing leaves the row exactly as it was.
func TestEnrichmentNeverInventsASerial(t *testing.T) {
	st := newProbeStore(spineRow())
	a := NewDiscoveryAggregator()
	a.SetStore(st)
	a.SetOSVersionLadder(ladderOf(t, &identitySource{
		method:  osprobe.MethodSSH,
		version: map[string]string{"spine1": srlProbed},
		// no identity: the device answered, and nothing in the answer was a serial
	}))

	a.enrichOSVersions(context.Background())

	got, _ := a.Get("spine1")
	if got.SerialNumber != "" || got.SerialSource != "" || !got.SerialAt.IsZero() {
		t.Fatalf("invented an identity: serial=%q source=%q at=%v",
			got.SerialNumber, got.SerialSource, got.SerialAt)
	}
	if got.Model != "" {
		t.Errorf("model = %q, want it left unset", got.Model)
	}
}

// TestEnrichmentNeverErasesASerialWithATransientEmptyRead — overwrite rule 1: a
// probe that could not read a serial must not blank one that was read before.
func TestEnrichmentNeverErasesASerialWithATransientEmptyRead(t *testing.T) {
	row := spineRow()
	row.SerialNumber, row.SerialSource = "SN-EARLIER", string(osprobe.MethodSSH)
	a := NewDiscoveryAggregator()
	a.SetStore(newProbeStore(row))
	a.SetOSVersionLadder(ladderOf(t, &identitySource{method: osprobe.MethodSSH}))

	a.enrichOSVersions(context.Background())

	if got, _ := a.Get("spine1"); got.SerialNumber != "SN-EARLIER" {
		t.Fatalf("serial_number = %q, want the earlier reading kept", got.SerialNumber)
	}
}

// TestEnrichmentNeverDisplacesAnOperatorsSerial — overwrite rule 3. An operator
// (or an importer) stated the serial; nothing a probe reads may overwrite it,
// and the device is not even asked.
func TestEnrichmentNeverDisplacesAnOperatorsSerial(t *testing.T) {
	row := spineRow()
	row.SerialNumber, row.SerialSource = "SN-FROM-ASSET-REGISTER", string(osprobe.MethodManual)
	row.OSVersion, row.OSVersionSource = srlProbed, string(osprobe.MethodSSH)
	a := NewDiscoveryAggregator()
	a.SetStore(newProbeStore(row))
	src := &identitySource{
		method:   osprobe.MethodSSH,
		version:  map[string]string{"spine1": srlProbed},
		identity: map[string]deviceident.Identity{"spine1": srlIdentity()},
	}
	a.SetOSVersionLadder(ladderOf(t, src))

	a.enrichOSVersions(context.Background())

	got, _ := a.Get("spine1")
	if got.SerialNumber != "SN-FROM-ASSET-REGISTER" || got.SerialSource != string(osprobe.MethodManual) {
		t.Fatalf("row = (%q via %q), want the operator's value untouched", got.SerialNumber, got.SerialSource)
	}
	if got.Model != "" {
		t.Errorf("model = %q — a probe whose serial was refused must not write the model beside it", got.Model)
	}
}

// TestEnrichmentRefreshesTheSerialItOwns — overwrite rule 2, and the chassis-swap
// path: when the rung that owns the row reads a NEW serial, the model moves with
// it. A row carrying one chassis's serial and another's model describes no device
// that exists.
func TestEnrichmentRefreshesTheSerialItOwns(t *testing.T) {
	row := spineRow()
	row.SerialNumber, row.SerialSource = "SN-OLD", string(osprobe.MethodSSH)
	row.Model = "7220 IXR-D2L"
	a := NewDiscoveryAggregator()
	a.SetStore(newProbeStore(row))
	a.SetOSVersionLadder(ladderOf(t, &identitySource{
		method: osprobe.MethodSSH,
		identity: map[string]deviceident.Identity{"spine1": {
			Serial: "SN-NEW", Model: "7220 IXR-D3L", SerialCommand: "show version",
		}},
	}))

	a.enrichOSVersions(context.Background())

	got, _ := a.Get("spine1")
	if got.SerialNumber != "SN-NEW" {
		t.Errorf("serial_number = %q, want the refreshed reading", got.SerialNumber)
	}
	if got.Model != "7220 IXR-D3L" {
		t.Errorf("model = %q, want it to move with the serial the same rung owns", got.Model)
	}
}

// TestEnrichmentFillsAnEmptyModelButDoesNotDisplaceAnInventorysOne — the MODEL
// rule. A blank column is nobody's answer, so a probe fills it; a model an
// inventory supplied is a second CLAIM, and silently picking a winner would
// destroy the evidence that the two disagree.
func TestEnrichmentFillsAnEmptyModelButDoesNotDisplaceAnInventorysOne(t *testing.T) {
	t.Run("fills an empty model", func(t *testing.T) {
		a := NewDiscoveryAggregator()
		a.SetStore(newProbeStore(spineRow()))
		a.SetOSVersionLadder(ladderOf(t, &identitySource{
			method:   osprobe.MethodSSH,
			identity: map[string]deviceident.Identity{"spine1": srlIdentity()},
		}))
		a.enrichOSVersions(context.Background())
		if got, _ := a.Get("spine1"); got.Model != "7220 IXR-D3L" {
			t.Fatalf("model = %q, want the probe's reading in an empty column", got.Model)
		}
	})
	t.Run("does not displace an inventory's model", func(t *testing.T) {
		row := spineRow()
		row.Model = "7220-IXR-D3L (from NetBox)"
		a := NewDiscoveryAggregator()
		a.SetStore(newProbeStore(row))
		a.SetOSVersionLadder(ladderOf(t, &identitySource{
			method:   osprobe.MethodSSH,
			identity: map[string]deviceident.Identity{"spine1": srlIdentity()},
		}))
		a.enrichOSVersions(context.Background())
		got, _ := a.Get("spine1")
		if got.Model != "7220-IXR-D3L (from NetBox)" {
			t.Errorf("model = %q, want the inventory's claim preserved", got.Model)
		}
		if got.SerialNumber != "Sim Serial No." {
			t.Errorf("serial_number = %q — the serial must still land", got.SerialNumber)
		}
	})
}

// TestEnrichmentProbesARowThatHasAVersionButNoSerial — the coverage case: the
// version ladder shipped first, so most rows already carry a version. Those rows
// must still be asked for a serial, or the feature would only ever reach devices
// that were discovered after it.
func TestEnrichmentProbesARowThatHasAVersionButNoSerial(t *testing.T) {
	row := spineRow()
	row.OSVersion, row.OSVersionSource = srlProbed, string(osprobe.MethodSSH)
	a := NewDiscoveryAggregator()
	a.SetStore(newProbeStore(row))
	src := &identitySource{
		method:   osprobe.MethodSSH,
		version:  map[string]string{"spine1": srlProbed},
		identity: map[string]deviceident.Identity{"spine1": srlIdentity()},
	}
	a.SetOSVersionLadder(ladderOf(t, src))

	a.enrichOSVersions(context.Background())

	if got, _ := a.Get("spine1"); got.SerialNumber != "Sim Serial No." {
		t.Fatalf("serial_number = %q, want the probe to have run for the half that was missing", got.SerialNumber)
	}
}

// TestEnrichmentDoesNotReProbeInsideTheCoolDown — a platform that answers with a
// version and will never answer with a serial must not be re-dialled every half
// hour forever. Something was learned, so the SLOW refresh applies to both
// halves.
func TestEnrichmentDoesNotReProbeInsideTheCoolDown(t *testing.T) {
	a := NewDiscoveryAggregator()
	a.SetStore(newProbeStore(spineRow()))
	src := &identitySource{method: osprobe.MethodSSH, version: map[string]string{"spine1": srlProbed}}
	a.SetOSVersionLadder(ladderOf(t, src))

	a.enrichOSVersions(context.Background())
	a.enrichOSVersions(context.Background())

	if len(src.calls) != 1 {
		t.Fatalf("dialled %v — a row that learned a version must wait out the refresh interval", src.calls)
	}
}

// ── the write path ──────────────────────────────────────────────────────────

// TestUpsertRefusesAClaimedSerialProvenance — a caller MAY state a serial (that
// is how a device nothing can log into gets one) but may not claim a probe read
// it: a body carrying `"serial_source": "ssh"` would fake an audit trail AND
// change which rung is allowed to refresh the row.
func TestUpsertRefusesAClaimedSerialProvenance(t *testing.T) {
	a := NewDiscoveryAggregator()
	a.SetStore(newProbeStore())
	d := spineRow()
	d.SerialNumber, d.SerialSource = "SN-CLAIMED", string(osprobe.MethodSSH)
	d.SerialAt = time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := a.Upsert(d); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, _ := a.Get("spine1")
	if got.SerialNumber != "SN-CLAIMED" {
		t.Errorf("serial_number = %q, want the caller's value kept", got.SerialNumber)
	}
	if got.SerialSource != string(osprobe.MethodManual) {
		t.Errorf("serial_source = %q, want it forced to manual", got.SerialSource)
	}
	if got.SerialAt.Year() == 1999 {
		t.Error("the caller's timestamp was trusted")
	}

	// Round-tripping the object must not relabel a value as hand-written or
	// re-stamp it: an unchanged serial keeps the provenance the row already had.
	round := got
	round.SerialSource, round.SerialAt = "", time.Time{}
	if err := a.Upsert(round); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	after, _ := a.Get("spine1")
	if after.SerialSource != got.SerialSource || !after.SerialAt.Equal(got.SerialAt) {
		t.Errorf("round trip changed provenance: (%q, %v) -> (%q, %v)",
			got.SerialSource, got.SerialAt, after.SerialSource, after.SerialAt)
	}

	// And an empty serial carries no provenance at all.
	blank := spineRow()
	blank.ID = "spine2"
	blank.SerialSource = string(osprobe.MethodSSH)
	if err := a.Upsert(blank); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if s2, _ := a.Get("spine2"); s2.SerialSource != "" {
		t.Errorf("serial_source = %q on a row with no serial", s2.SerialSource)
	}
}

// TestMergeCarriesTheSerialWithItsProvenance — a merge that took one and left
// the other would produce a row claiming a serial was read off a device by a
// source that never read it.
func TestMergeCarriesTheSerialWithItsProvenance(t *testing.T) {
	at := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	base := models.Device{ID: "d1", Name: "core-01", Source: "netbox"}
	other := models.Device{
		ID: "d1", Name: "core-01", Source: "snmp",
		SerialNumber: "SN-READ", SerialSource: string(osprobe.MethodSSH), SerialAt: at,
	}
	got := mergeDevices(base, other)
	if got.SerialNumber != "SN-READ" || got.SerialSource != string(osprobe.MethodSSH) || !got.SerialAt.Equal(at) {
		t.Fatalf("merged = (%q via %q at %v), want all three to travel together",
			got.SerialNumber, got.SerialSource, got.SerialAt)
	}

	// A base that already carries a serial keeps its own, provenance included.
	base.SerialNumber, base.SerialSource = "SN-BASE", string(osprobe.MethodManual)
	got = mergeDevices(base, other)
	if got.SerialNumber != "SN-BASE" || got.SerialSource != string(osprobe.MethodManual) {
		t.Fatalf("merged = (%q via %q), want the base's own", got.SerialNumber, got.SerialSource)
	}
}
