package backend

// onboarding_cost_test.go — G1 GA-gate: the API-LEVEL onboarding cost budget.
//
// The scale-test P0 this pins (docs/scale/SCALE_TEST_FINDINGS.md, "Device
// inventory / onboarding"): POST /api/devices degraded 155/s → 63/s → 25/s over
// the first 2k devices because every create re-marshalled and re-wrote the
// ENTIRE fleet (O(N²) bulk onboarding). The store-level accounting proof lives
// in internal/discovery/devstore_records_test.go; these tests extend the same
// deterministic accounting guarantee to the FULL request path — real router,
// real auth middleware, real handler, real DevStore wiring — so a regression
// ANYWHERE on the create path (handler, aggregator, store, kv adapter) fails
// the suite, not just a regression inside the store.
//
// Deterministic accounting only (backend calls + bytes). NEVER timing.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"netops/backend/models"
)

// countingKV is an in-memory platformdb.PrefixBackend that counts every
// backend operation and every byte written, with a device-store-scoped view
// (keys under devicesPath()+".d/") so the device-write budget is asserted
// independently of the other stores that share the process-global backend
// (audit trail, sessions, ...).
type countingKV struct {
	mu        sync.Mutex
	m         map[string][]byte
	devPrefix string

	loads, saves, prefixLoads, deletes int
	devSaves                           int
	devSavedBytes                      int
}

func newCountingKV(devPrefix string) *countingKV {
	return &countingKV{m: map[string][]byte{}, devPrefix: devPrefix}
}

type kvSnapshot struct {
	totalCalls    int
	devSaves      int
	devSavedBytes int
}

func (k *countingKV) snapshot() kvSnapshot {
	k.mu.Lock()
	defer k.mu.Unlock()
	return kvSnapshot{
		totalCalls:    k.loads + k.saves + k.prefixLoads + k.deletes,
		devSaves:      k.devSaves,
		devSavedBytes: k.devSavedBytes,
	}
}

func (a kvSnapshot) minus(b kvSnapshot) kvSnapshot {
	return kvSnapshot{
		totalCalls:    a.totalCalls - b.totalCalls,
		devSaves:      a.devSaves - b.devSaves,
		devSavedBytes: a.devSavedBytes - b.devSavedBytes,
	}
}

func (k *countingKV) Load(key string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.loads++
	b, ok := k.m[key]
	if !ok {
		// Backend contract: absent key = os.ErrNotExist-wrapped.
		return nil, fmt.Errorf("key %s: %w", key, os.ErrNotExist)
	}
	return b, nil
}

func (k *countingKV) Save(key string, data []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.saves++
	if strings.HasPrefix(key, k.devPrefix) {
		k.devSaves++
		k.devSavedBytes += len(data)
	}
	k.m[key] = append([]byte(nil), data...)
	return nil
}

func (k *countingKV) LoadPrefix(prefix string) (map[string][]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.prefixLoads++
	out := map[string][]byte{}
	for key, b := range k.m {
		if strings.HasPrefix(key, prefix) {
			out[key] = append([]byte(nil), b...)
		}
	}
	return out, nil
}

func (k *countingKV) Delete(key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.deletes++
	delete(k.m, key)
	return nil
}

// TestDeviceCreateHTTPCostIsO1Records drives ~600 creates through the real
// POST /api/devices handler and asserts the N-th create writes the SAME number
// of device records (exactly one) and a bounded number of bytes as the first —
// the API-level linearity proof. It also bounds TOTAL backend calls per create
// (all stores), so an O(N) call amplification introduced anywhere else on the
// create path (e.g. a per-create fleet re-read) is caught even if the device
// store itself stays O(1).
func TestDeviceCreateHTTPCostIsO1Records(t *testing.T) {
	kv := newCountingKV(devicesPath() + ".d/")
	withBackend(t, kv)

	srv, s := newTestServerState(t)
	// Wire the persistent device store exactly as newServer does at runtime
	// (the shared fixture leaves the aggregator store-less).
	s.discovery.SetStore(newDeviceStore(devicesPath()))

	admin := login(t, srv, "admin", "Passw0rd!2345")

	const n = 600
	// One device record is small and constant-size-ish. The pre-fix whole-fleet
	// blob at N=600 was ~90KB per create; a healthy per-record write is well
	// under 2KB.
	const perRecordByteCap = 2048

	var baseline kvSnapshot // steady-state per-create cost, measured at i==10
	var last kvSnapshot
	for i := 0; i < n; i++ {
		before := kv.snapshot()
		body := map[string]string{
			"id":        fmt.Sprintf("scale-edge-%04d", i),
			"name":      fmt.Sprintf("scale-edge-%04d", i),
			"address":   fmt.Sprintf("10.42.%d.%d", i/250, i%250),
			"tenant_id": "t_scale",
			"source":    "manual",
		}
		st, resp := do(t, srv, "POST", "/api/devices", admin.Token, body)
		if st != 201 {
			t.Fatalf("create #%d: status %d: %s", i, st, resp)
		}
		d := kv.snapshot().minus(before)

		// The device-store budget: exactly ONE record write, bounded bytes.
		if d.devSaves != 1 {
			t.Fatalf("create #%d issued %d device-record writes, want exactly 1 — "+
				"the O(N²) whole-fleet rewrite (scale P0) is back on the API path", i, d.devSaves)
		}
		if d.devSavedBytes > perRecordByteCap {
			t.Fatalf("create #%d wrote %d device-store bytes (cap %d) — the write "+
				"size must not grow with the fleet", i, d.devSavedBytes, perRecordByteCap)
		}
		if i == 10 {
			baseline = d
		}
		last = d
	}

	// Last create vs the steady-state baseline: bytes and total backend calls
	// must be a small constant, independent of N. (Total calls include the
	// bounded audit-ring write each mutating request makes — a constant per
	// request; the slack tolerates constants, never O(N).)
	if last.devSavedBytes > 2*baseline.devSavedBytes {
		t.Fatalf("create #%d wrote %d device-store bytes vs baseline %d — write size grew with N",
			n-1, last.devSavedBytes, baseline.devSavedBytes)
	}
	if baseline.totalCalls == 0 {
		t.Fatal("accounting broke: baseline create issued zero backend calls")
	}
	if last.totalCalls > 2*baseline.totalCalls+4 {
		t.Fatalf("create #%d issued %d total backend calls vs baseline %d — the create "+
			"path gained per-fleet backend work", n-1, last.totalCalls, baseline.totalCalls)
	}

	// The creates were real: a fresh store over the same backend sees all N.
	st2 := newDeviceStore(devicesPath())
	if err := st2.Unreadable(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := len(st2.Devices()); got != n {
		t.Fatalf("persisted %d devices, want %d — 201s were returned for writes that never landed", got, n)
	}
}

// TestDeviceListHTTPBackendBudget is the read-side budget contract:
//
//	GET /api/devices is served ENTIRELY from the in-memory aggregator cache
//	(plus the in-memory wireless store) — its backend I/O budget is ZERO
//	calls, independent of fleet size.
//
// The DevStore is read once at SetStore/boot; a list request must never fan
// out to the kv layer. If someone "fixes" the list to re-read persistence per
// request, N devices × M dashboard pollers becomes an O(N·M) backend load and
// this test fails.
func TestDeviceListHTTPBackendBudget(t *testing.T) {
	kv := newCountingKV(devicesPath() + ".d/")
	withBackend(t, kv)

	srv, s := newTestServerState(t)
	s.discovery.SetStore(newDeviceStore(devicesPath()))
	admin := login(t, srv, "admin", "Passw0rd!2345")

	const n = 500
	for i := 0; i < n; i++ {
		st, resp := do(t, srv, "POST", "/api/devices", admin.Token, map[string]string{
			"id":      fmt.Sprintf("list-dev-%04d", i),
			"name":    fmt.Sprintf("list-dev-%04d", i),
			"address": fmt.Sprintf("10.9.%d.%d", i/250, i%250),
		})
		if st != 201 {
			t.Fatalf("seed create #%d: status %d: %s", i, st, resp)
		}
	}

	before := kv.snapshot()
	st, body := do(t, srv, "GET", "/api/devices", admin.Token, nil)
	if st != 200 {
		t.Fatalf("list: status %d: %s", st, body)
	}
	var rows []models.Device
	if err := json.Unmarshal(body, &rows); err != nil {
		t.Fatalf("list body: %v", err)
	}
	if len(rows) != n {
		t.Fatalf("list returned %d devices, want %d (deviceDefaultPage=5000 covers the fleet)", len(rows), n)
	}
	if d := kv.snapshot().minus(before); d.totalCalls != 0 {
		t.Fatalf("GET /api/devices issued %d backend calls, budget is 0 — the list "+
			"must be served from the in-memory aggregator cache, never from per-request "+
			"persistence reads", d.totalCalls)
	}
}
