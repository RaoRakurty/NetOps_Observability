package discovery

// legacy_scan_id_test.go — M1: the ScanDeviceID address-hash change shipped
// with no migration. Every consumer keyed by scan id predates it — the F-69
// delete tombstones (IsSuppressed) and per-device state — so re-keying the
// whole fleet on upgrade would resurrect every operator-deleted device and
// orphan its state. The fix keeps a uniquely-named device on its legacy
// (address-less) id and only applies the hash when a name collision actually
// exists. These tests lock both halves.

import (
	"context"
	"os"
	"testing"

	"netops/backend/models"
)

// memKV is an in-memory KV for the DevStore (absent key = fresh install).
type memKV map[string][]byte

func (m memKV) Load(key string) ([]byte, error) {
	b, ok := m[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}
func (m memKV) Save(key string, data []byte) error { m[key] = data; return nil }

func newLegacyIDSource() *SNMPSource {
	cfg := func() ScanSettings {
		return ScanSettings{Enabled: true, Ranges: []string{"10.9.0.0/29"}, Community: "public"}
	}
	s := NewSNMPSource(cfg, nil)
	s.SetProbeForTest(func(_ context.Context, addr, _ string) (string, string, string, bool) {
		switch addr {
		case "10.9.0.1":
			return "core1", "arista", "descr", true // unique name → legacy id
		case "10.9.0.2", "10.9.0.3":
			return "switch", "cisco", "descr", true // colliding factory default
		}
		return "", "", "", false
	})
	return s
}

func TestM1LegacyScanIDPreservedAndCollisionsStillDisambiguated(t *testing.T) {
	s := newLegacyIDSource()
	devs, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	byID := map[string]models.Device{}
	for _, d := range devs {
		byID[d.ID] = d
	}
	// The uniquely-named device keeps its pre-change, address-less id — the id
	// its tombstone and per-device state are keyed by.
	if _, ok := byID["core1"]; !ok {
		t.Fatalf("uniquely-named device re-keyed away from legacy id: ids=%v", keysOf(byID))
	}
	// The colliding pair still gets distinct, address-hashed ids (the collision
	// fix this change exists for must survive the migration shim).
	h2 := ScanDeviceID("switch", "10.9.0.2")
	h3 := ScanDeviceID("switch", "10.9.0.3")
	if h2 == h3 {
		t.Fatal("hash form did not disambiguate")
	}
	if _, ok := byID[h2]; !ok {
		t.Fatalf("colliding device 10.9.0.2 not under its hashed id: ids=%v", keysOf(byID))
	}
	if _, ok := byID[h3]; !ok {
		t.Fatalf("colliding device 10.9.0.3 not under its hashed id: ids=%v", keysOf(byID))
	}
	if _, ok := byID["switch"]; ok {
		t.Fatal("colliding name must not also appear under the bare legacy id")
	}
}

// TestM1SuppressedLegacyIDStaysSuppressed: an operator deleted a device before
// the id change (tombstone keyed by the LEGACY id). A rescan returning the same
// name+address must stay suppressed — resurrecting it would undo the delete.
func TestM1SuppressedLegacyIDStaysSuppressed(t *testing.T) {
	st := NewDevStore("devices.json", memKV{}, nil)
	if err := st.Remove("core1"); err != nil { // records the F-69 tombstone
		t.Fatalf("remove: %v", err)
	}
	a := NewDiscoveryAggregator()
	a.SetStore(st)

	s := newLegacyIDSource()
	a.PollOnceForTest(context.Background(), s)

	for _, d := range a.RawDevices() {
		if d.ID == "core1" || d.Name == "core1" {
			t.Fatalf("operator-deleted device resurrected after rescan as %+v", d)
		}
	}
	// The un-deleted devices still arrive.
	if got := len(a.RawDevices()); got != 2 {
		t.Fatalf("want the 2 surviving devices, got %d: %+v", got, a.RawDevices())
	}
}

func keysOf(m map[string]models.Device) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
