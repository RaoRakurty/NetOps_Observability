package discovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/models"
)

// devstore_records_test.go — the GA scale P0: per-device persistence.
//
// The defect these pin: saveLocked marshalled the ENTIRE fleet on EVERY
// Put/Remove, so bulk onboarding was O(N²) (measured 155 devices/s at small N
// collapsing to 14/s by 3.3k devices; GA needs 10k+ linear). With a
// prefix-capable backend each Put is exactly ONE bounded record write.
//
// These are deterministic accounting tests (Save calls + bytes), NEVER timing
// tests.

// recKV is an in-memory PrefixKV that counts operations and can inject
// failures per key. Mutex-guarded because the store's background hit flusher
// (ultra 9, devstore_compact.go) writes from its own goroutine; tests that can
// run concurrently with it read through get/counts, never k.m directly.
type recKV struct {
	mu         sync.Mutex
	m          map[string][]byte
	saves      int
	savedBytes int
	deletes    int
	failSave   map[string]error
	failDelete map[string]error
	prefixErr  error
}

func newRecKV() *recKV {
	return &recKV{m: map[string][]byte{}, failSave: map[string]error{}, failDelete: map[string]error{}}
}

func (k *recKV) Load(key string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	b, ok := k.m[key]
	if !ok {
		// The Backend contract: absent key = os.ErrNotExist-wrapped.
		return nil, fmt.Errorf("key %s: %w", key, os.ErrNotExist)
	}
	return b, nil
}

func (k *recKV) Save(key string, data []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.failSave[key]; err != nil {
		return err
	}
	k.saves++
	k.savedBytes += len(data)
	cp := make([]byte, len(data))
	copy(cp, data)
	k.m[key] = cp
	return nil
}

func (k *recKV) LoadPrefix(prefix string) (map[string][]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.prefixErr != nil {
		return nil, k.prefixErr
	}
	out := map[string][]byte{}
	for key, b := range k.m {
		if strings.HasPrefix(key, prefix) {
			out[key] = b
		}
	}
	return out, nil
}

func (k *recKV) Delete(key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.failDelete[key]; err != nil {
		return err
	}
	k.deletes++
	delete(k.m, key)
	return nil
}

// get is the locked read for tests that inspect the backend while the store's
// background hit flusher may be live.
func (k *recKV) get(key string) ([]byte, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	b, ok := k.m[key]
	return b, ok
}

// counts reads the operation counters under the lock.
func (k *recKV) counts() (saves, deletes int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.saves, k.deletes
}

// TestPerDevicePutWritesO1Records is the linearity proof: the N-th Put writes
// the SAME number of records (one) and a bounded number of bytes as the first —
// no full-fleet rewrite anywhere in the hot path.
func TestPerDevicePutWritesO1Records(t *testing.T) {
	kv := newRecKV()
	st := NewDevStore("devices.json", kv, nil)
	if err := st.Unreadable(); err != nil {
		t.Fatalf("fresh store must load clean: %v", err)
	}

	const n = 1000
	const perRecordByteCap = 2048 // one device record is small and CONSTANT-size-ish; the old blob at N=1000 was ~150KB
	var firstBytes int
	for i := 0; i < n; i++ {
		beforeSaves, beforeBytes := kv.saves, kv.savedBytes
		d := models.Device{
			ID:       fmt.Sprintf("edge-router-%04d", i),
			Name:     fmt.Sprintf("edge-router-%04d", i),
			Address:  fmt.Sprintf("10.42.%d.%d", i/250, i%250),
			TenantID: "t_scale",
			Source:   "manual",
		}
		if err := st.Put(d); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
		saves, bytes := kv.saves-beforeSaves, kv.savedBytes-beforeBytes
		if saves != 1 {
			t.Fatalf("Put #%d issued %d record writes, want exactly 1 — the O(N²) fleet rewrite is back", i, saves)
		}
		if bytes > perRecordByteCap {
			t.Fatalf("Put #%d wrote %d bytes (cap %d) — write size must not grow with the fleet", i, bytes, perRecordByteCap)
		}
		if i == 0 {
			firstBytes = bytes
		}
		if i == n-1 && bytes > 2*firstBytes {
			t.Fatalf("last Put wrote %d bytes vs first Put's %d — write size grew with N", bytes, firstBytes)
		}
	}

	// Remove: exactly one tombstone Save (+ one record Delete).
	beforeSaves, beforeDeletes := kv.saves, kv.deletes
	if err := st.Remove("edge-router-0001"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if s := kv.saves - beforeSaves; s != 1 {
		t.Fatalf("Remove issued %d Saves, want exactly 1 (the tombstone)", s)
	}
	if d := kv.deletes - beforeDeletes; d != 1 {
		t.Fatalf("Remove issued %d Deletes, want exactly 1 (the record)", d)
	}

	// And the state actually round-trips: a fresh boot sees N-1 devices + 1 tombstone.
	st2 := NewDevStore("devices.json", kv, nil)
	if err := st2.Unreadable(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := len(st2.Devices()); got != n-1 {
		t.Fatalf("after restart: %d devices, want %d", got, n-1)
	}
	if !st2.IsSuppressed("edge-router-0001") {
		t.Fatal("tombstone did not survive the restart")
	}
}

// TestLegacyBlobMigratesToPerRecordStore: first boot over a pre-fix store
// splits the single blob into per-record keys, keeps every device AND every
// tombstone, writes the completion marker, and leaves the legacy blob
// untouched (the documented downgrade snapshot).
func TestLegacyBlobMigratesToPerRecordStore(t *testing.T) {
	kv := newRecKV()
	legacy := devPersistFile{
		Manual: map[string]models.Device{
			"core-sw01": {ID: "core-sw01", Name: "core-sw01", Address: "10.0.0.1", TenantID: "t_a", Source: "manual"},
			"core-sw02": {ID: "core-sw02", Name: "core-sw02", Address: "10.0.0.2", TenantID: "t_b", Source: "manual"},
		},
		// Recent on purpose: this test pins MIGRATION FIDELITY, not retention.
		// Since tracker 175 a never-hit tombstone older than the retention
		// horizon is compacted at the next (adopt-path) boot — that behaviour has
		// its own tests in devstore_compact_test.go.
		Suppressed: map[string]time.Time{
			"deleted-fw": time.Now().UTC().Add(-time.Hour),
		},
	}
	blob, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	kv.m["devices.json"] = blob

	st := NewDevStore("devices.json", kv, nil)
	if err := st.Unreadable(); err != nil {
		t.Fatalf("migration boot: %v", err)
	}
	if got := len(st.Devices()); got != 2 {
		t.Fatalf("migrated devices = %d, want 2", got)
	}
	if !st.IsSuppressed("deleted-fw") {
		t.Fatal("tombstone lost in migration (F-69 class)")
	}
	// Per-record keys exist; marker exists; legacy blob byte-identical.
	for _, id := range []string{"core-sw01", "core-sw02"} {
		if _, ok := kv.m[st.manualKey(id)]; !ok {
			t.Fatalf("no per-record key for %q after migration", id)
		}
	}
	if _, ok := kv.m[st.suppressedKey("deleted-fw")]; !ok {
		t.Fatal("no per-record tombstone after migration")
	}
	if _, ok := kv.m[st.markerKey()]; !ok {
		t.Fatal("migration completion marker missing")
	}
	if string(kv.m["devices.json"]) != string(blob) {
		t.Fatal("migration modified the legacy blob — the downgrade snapshot must stay frozen")
	}

	// Second boot: marker present ⇒ per-record store is authoritative and the
	// migration does not re-run (no extra writes).
	saves := kv.saves
	st2 := NewDevStore("devices.json", kv, nil)
	if err := st2.Unreadable(); err != nil {
		t.Fatalf("post-migration boot: %v", err)
	}
	if kv.saves != saves {
		t.Fatalf("a migrated store re-ran the migration (%d extra writes)", kv.saves-saves)
	}
	if len(st2.Devices()) != 2 || !st2.IsSuppressed("deleted-fw") {
		t.Fatal("post-migration load lost state")
	}
}

// TestMigrationCrashRerunsIdempotently: a crash before the completion marker
// (simulated by failing the marker write) leaves a half-split store that
// REFUSES writes; the next boot re-runs the split from the intact legacy blob,
// converges (including sweeping stray records), and no tombstone is lost.
func TestMigrationCrashRerunsIdempotently(t *testing.T) {
	kv := newRecKV()
	legacy := devPersistFile{
		Manual: map[string]models.Device{"r1": {ID: "r1", Name: "r1", Source: "manual"}},
		// Recent for the same reason as above (tracker 175 retention).
		Suppressed: map[string]time.Time{"gone1": time.Now().UTC().Add(-time.Hour)},
	}
	blob, _ := json.Marshal(legacy)
	kv.m["devices.json"] = blob

	// Boot 1 crashes at the marker write.
	probe := NewDevStore("devices.json", newRecKV(), nil) // key-derivation helper only
	kv.failSave[probe.markerKey()] = errors.New("disk full")
	st := NewDevStore("devices.json", kv, nil)
	if st.Unreadable() == nil {
		t.Fatal("a migration that could not complete must refuse the store (writes would be swept by the re-run)")
	}
	if err := st.Put(models.Device{ID: "x", Name: "x"}); err == nil {
		t.Fatal("write accepted while the migration marker never landed")
	}

	// A stray record from an even earlier crashed migration sits under the prefix.
	kv.m[probe.recPrefix()+"manual/deadbeef-stray"] = []byte(`{"id":"stray"}`)

	// Boot 2: marker write works now. The re-run must converge exactly.
	delete(kv.failSave, probe.markerKey())
	st2 := NewDevStore("devices.json", kv, nil)
	if err := st2.Unreadable(); err != nil {
		t.Fatalf("re-run boot: %v", err)
	}
	if len(st2.Devices()) != 1 || !st2.IsSuppressed("gone1") {
		t.Fatalf("re-run lost state: devices=%d suppressed=%v", len(st2.Devices()), st2.IsSuppressed("gone1"))
	}
	if _, ok := kv.m[probe.recPrefix()+"manual/deadbeef-stray"]; ok {
		t.Fatal("stray record from a crashed migration survived the re-run sweep")
	}
	if _, ok := kv.m[probe.markerKey()]; !ok {
		t.Fatal("marker missing after successful re-run")
	}

	// Boot 3 is a plain load — idempotence proven by zero extra writes.
	saves := kv.saves
	if st3 := NewDevStore("devices.json", kv, nil); st3.Unreadable() != nil {
		t.Fatal("boot 3 failed")
	}
	if kv.saves != saves {
		t.Fatal("migration ran again after completion")
	}
}

// TestPrefixLoadFailureRefusesWrites is the F-62/F-69 boot contract in
// per-record mode: an unreadable store means "we do not know what is stored",
// so every write is refused and NOTHING is issued to the backend.
func TestPrefixLoadFailureRefusesWrites(t *testing.T) {
	kv := newRecKV()
	kv.prefixErr = errors.New("backend down")
	st := NewDevStore("devices.json", kv, nil)
	if st.Unreadable() == nil {
		t.Fatal("boot read failure must be reported, not treated as an empty store")
	}
	if err := st.Put(models.Device{ID: "d1", Name: "d1"}); err == nil {
		t.Fatal("Put accepted against an unread store")
	}
	if err := st.Remove("d1"); err == nil {
		t.Fatal("Remove accepted against an unread store")
	}
	if kv.saves != 0 || kv.deletes != 0 {
		t.Fatalf("writes were issued against an unread store (saves=%d deletes=%d)", kv.saves, kv.deletes)
	}
}

// TestPutFailureLeavesMemoryConsistent: persistence-before-mutation — a failed
// backend write must leave RAM claiming nothing the store does not have.
func TestPutFailureLeavesMemoryConsistent(t *testing.T) {
	kv := newRecKV()
	st := NewDevStore("devices.json", kv, nil)
	kv.failSave[st.manualKey("d1")] = errors.New("no space")
	if err := st.Put(models.Device{ID: "d1", Name: "d1"}); err == nil {
		t.Fatal("Put reported success while the record write failed")
	}
	if len(st.Devices()) != 0 {
		t.Fatal("failed Put left the device in RAM — it would vanish at the next restart")
	}
}

// TestPutTombstoneClearFailureKeepsSuppression: recreating a deleted device
// requires BOTH the record write and the tombstone delete. If the tombstone
// delete fails, the Put fails, the suppression stands in RAM, and a reload
// resolves the on-disk record+tombstone pair the same way (tombstone wins) —
// RAM and disk agree.
func TestPutTombstoneClearFailureKeepsSuppression(t *testing.T) {
	kv := newRecKV()
	st := NewDevStore("devices.json", kv, nil)
	const id = "fw-edge-1"
	if err := st.Remove(id); err != nil {
		t.Fatal(err)
	}
	kv.failDelete[st.suppressedKey(id)] = errors.New("backend refused")
	if err := st.Put(models.Device{ID: id, Name: id}); err == nil {
		t.Fatal("Put reported success while the tombstone survived — the new device would be invisible")
	}
	if !st.IsSuppressed(id) || len(st.Devices()) != 0 {
		t.Fatal("failed Put mutated RAM")
	}
	// Reload: disk has record + tombstone; tombstone must win and the stale
	// record must be swept.
	delete(kv.failDelete, st.suppressedKey(id))
	st2 := NewDevStore("devices.json", kv, nil)
	if err := st2.Unreadable(); err != nil {
		t.Fatal(err)
	}
	if !st2.IsSuppressed(id) {
		t.Fatal("tombstone lost across reload — the deleted device would resurrect")
	}
	if len(st2.Devices()) != 0 {
		t.Fatal("tombstone-shadowed record surfaced as a live device")
	}
	if _, ok := kv.m[st.manualKey(id)]; ok {
		t.Fatal("shadowed record was not swept at load")
	}
}

// TestRemoveTombstoneWriteFailureRollsBack: the tombstone IS the delete; if it
// cannot be persisted the Remove fails and the device stays.
func TestRemoveTombstoneWriteFailureRollsBack(t *testing.T) {
	kv := newRecKV()
	st := NewDevStore("devices.json", kv, nil)
	const id = "sw-agg-9"
	if err := st.Put(models.Device{ID: id, Name: id}); err != nil {
		t.Fatal(err)
	}
	kv.failSave[st.suppressedKey(id)] = errors.New("io error")
	if err := st.Remove(id); err == nil {
		t.Fatal("Remove reported success while the tombstone never landed (F-69: the 204 would be a lie)")
	}
	if st.IsSuppressed(id) {
		t.Fatal("failed Remove left a suppression in RAM")
	}
	if len(st.Devices()) != 1 {
		t.Fatal("failed Remove dropped the device from RAM")
	}
}

// TestUnsafeDeviceIDsGetSafeRecordNames: ids are operator/scan-derived and may
// contain path separators, dots, LIKE metacharacters or unicode. The record
// NAME must be safe in both key spaces (hex only past the prefix) while the id
// round-trips exactly through the record body.
func TestUnsafeDeviceIDsGetSafeRecordNames(t *testing.T) {
	kv := newRecKV()
	st := NewDevStore("devices.json", kv, nil)
	hostile := []string{
		"../../etc/passwd",
		"a/b/c",
		"100%_load",
		"röuter-ü1",
		"", // the F-8 pre-fix empty id must still be storable (SetStore repairs it above this layer)
	}
	for _, id := range hostile {
		if err := st.Put(models.Device{ID: id, Name: "n", Source: "manual"}); err != nil {
			t.Fatalf("put %q: %v", id, err)
		}
	}
	for key := range kv.m {
		if key == "devices.json" || key == st.markerKey() {
			continue
		}
		rest := strings.TrimPrefix(strings.TrimPrefix(key, st.manualPrefix()), st.suppressedPrefix())
		if strings.ContainsAny(rest, "/\\%_.") {
			t.Fatalf("record name %q leaks unsafe id characters into the key space", key)
		}
	}
	st2 := NewDevStore("devices.json", kv, nil)
	got := map[string]bool{}
	for _, d := range st2.Devices() {
		got[d.ID] = true
	}
	for _, id := range hostile {
		if !got[id] {
			t.Fatalf("id %q did not round-trip through its hashed record", id)
		}
	}
}

// TestAdoptRefusesMisnamedRecord: a record whose name does not match its
// content is corruption (or a colliding copy) — the load must refuse the store
// rather than let two records claim one id.
func TestAdoptRefusesMisnamedRecord(t *testing.T) {
	kv := newRecKV()
	st := NewDevStore("devices.json", kv, nil) // fresh → writes marker
	if err := st.Put(models.Device{ID: "good", Name: "good"}); err != nil {
		t.Fatal(err)
	}
	// A copied record under the wrong name claims a different id.
	kv.m[st.manualPrefix()+strings.Repeat("ab", 32)] = kv.m[st.manualKey("good")]
	st2 := NewDevStore("devices.json", kv, nil)
	if st2.Unreadable() == nil {
		t.Fatal("a store with a name/content mismatch loaded clean — duplicate-id records went undetected")
	}
	if err := st2.Put(models.Device{ID: "x", Name: "x"}); err == nil {
		t.Fatal("write accepted against a refused store")
	}
}

// TestNonPrefixBackendKeepsWholeBlobBehavior: a KV without the prefix
// capability (test fakes, hypothetical blob-only backends) must keep the exact
// legacy semantics — full-blob write on Put, tombstone in the blob, reload.
func TestNonPrefixBackendKeepsWholeBlobBehavior(t *testing.T) {
	kv := memKV{} // the plain fake from legacy_scan_id_test.go — no prefix capability
	st := NewDevStore("devices.json", kv, nil)
	if err := st.Put(models.Device{ID: "d1", Name: "d1", Source: "manual"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Remove("d2"); err != nil {
		t.Fatal(err)
	}
	blob, ok := kv["devices.json"]
	if !ok {
		t.Fatal("legacy mode did not write the whole-blob key")
	}
	var f devPersistFile
	if err := json.Unmarshal(blob, &f); err != nil {
		t.Fatalf("legacy blob shape changed: %v", err)
	}
	if _, ok := f.Manual["d1"]; !ok {
		t.Fatal("device missing from the legacy blob")
	}
	if _, ok := f.Suppressed["d2"]; !ok {
		t.Fatal("tombstone missing from the legacy blob")
	}
	st2 := NewDevStore("devices.json", kv, nil)
	if len(st2.Devices()) != 1 || !st2.IsSuppressed("d2") {
		t.Fatal("legacy blob did not reload")
	}
}
