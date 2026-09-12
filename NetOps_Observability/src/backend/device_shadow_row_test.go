// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// device_shadow_row_test.go — TRACKER 181: a create that dedupe absorbs must
// not persist a row of its own.
//
// The recorded defect: handleDevices POST called discovery.Upsert BEFORE
// ResolveIdentity, so the requested id was written even when the identity
// merged into an existing device. The loser stayed persisted as a SHADOW —
// invisible to GET /api/devices (the read path shows the merged survivor),
// still addressable by DELETE, and it SURFACED the moment the absorber was
// deleted. Two overlapping scale runs (2026-08-29) left 1,000 such rows that no
// prefix-scoped cleanup could list.
//
// The contract these tests pin:
//
//	201 Created  — the requested identity was genuinely new AND was persisted
//	200 OK       — the identity already existed; NOTHING was written and the
//	               body/headers name the device that actually owns it
//	always      — the RAW row set (what DELETE can address) equals the
//	               PROJECTED device set (what GET shows), per tenant
//
// §3a: identity resolution is tenant-partitioned. The same hostname and the
// same management address in another tenant is a DIFFERENT device and must
// create independently.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"netops/backend/internal/discovery"
	"netops/backend/models"
)

// postDeviceAs is postDevice with an explicit principal (postDevice is
// super-admin only; the isolation cases need tenant-scoped operators).
func postDeviceAs(t *testing.T, s *server, claims jwtClaims, body map[string]any) (int, models.Device, http.Header) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rr := httptest.NewRecorder()
	s.handleDevices(rr, req("POST", "/api/devices", string(b), claims))
	var got models.Device
	if rr.Code < 300 {
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode response (code %d): %v — body %s", rr.Code, err, rr.Body.String())
		}
	}
	return rr.Code, got, rr.Result().Header
}

// rawDeviceIDs is the set of PERSISTED rows — the pre-dedupe cache, which is
// what DELETE /api/devices/{id} addresses. A shadow row shows up here and
// nowhere else, which is exactly why the defect went unnoticed.
func rawDeviceIDs(s *server) map[string]bool {
	out := map[string]bool{}
	for _, d := range s.discovery.RawDevices() {
		out[d.ID] = true
	}
	return out
}

func listDeviceIDs(t *testing.T, s *server, claims jwtClaims) map[string]bool {
	t.Helper()
	rr := httptest.NewRecorder()
	s.handleDevices(rr, req("GET", "/api/devices", "", claims))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/devices: %d %s", rr.Code, rr.Body.String())
	}
	var devs []models.Device
	if err := json.Unmarshal(rr.Body.Bytes(), &devs); err != nil {
		t.Fatalf("decode device list: %v — body %s", err, rr.Body.String())
	}
	out := map[string]bool{}
	for _, d := range devs {
		out[d.ID] = true
	}
	return out
}

func deleteDeviceAs(t *testing.T, s *server, claims jwtClaims, id string) int {
	t.Helper()
	rr := httptest.NewRecorder()
	s.handleDeviceByID(rr, req("DELETE", "/api/devices/"+id, "", claims))
	return rr.Code
}

// (a) THE FIX. A create absorbed by dedupe writes NO row. Reverting the
// ordering (Upsert before the identity resolution) leaves two raw rows and
// fails here — this is the mutant guard.
func TestAbsorbedCreateWritesNoShadowRow(t *testing.T) {
	_, s := newTestServerState(t)
	const addr = "198.51.100.120"
	// "aaa-stale" sorts before "zzz-replacement", so the stale record survives
	// the merge — the shape of the recorded incident.
	if code, _, _ := postDevice(t, s, map[string]any{
		"name": "aaa-stale", "address": addr, "type": "router",
	}); code != http.StatusCreated {
		t.Fatalf("seeding the stale device: want 201, got %d", code)
	}
	survivor := discovery.ScanDeviceID("aaa-stale", addr)
	requested := discovery.ScanDeviceID("zzz-replacement", addr)

	code, got, hdr := postDevice(t, s, map[string]any{
		"name": "zzz-replacement", "address": addr, "type": "router",
	})
	if code != http.StatusOK {
		t.Fatalf("absorbed create: want 200, got %d", code)
	}
	if got.ID != survivor {
		t.Fatalf("absorbed create must return the canonical device %s, got %s", survivor, got.ID)
	}
	if hdr.Get("X-Device-Canonical-Id") != survivor || hdr.Get("X-Device-Requested-Id") != requested {
		t.Fatalf("headers must name both identities: canonical=%q requested=%q",
			hdr.Get("X-Device-Canonical-Id"), hdr.Get("X-Device-Requested-Id"))
	}

	raw := rawDeviceIDs(s)
	if raw[requested] {
		t.Fatalf("SHADOW ROW: %s was absorbed by %s but is still persisted (tracker 181)", requested, survivor)
	}
	if len(raw) != 1 {
		t.Fatalf("one identity must persist exactly one row, got %d: %v", len(raw), raw)
	}
	// GET and DELETE must agree about what exists.
	if ids := listDeviceIDs(t, s, superA()); len(ids) != 1 || !ids[survivor] {
		t.Fatalf("GET must show exactly the surviving device, got %v", ids)
	}
}

// (b) No behaviour change for a genuinely new identity: still 201, still
// persisted, still retrievable.
func TestGenuinelyNewCreateStillReturns201AndPersists(t *testing.T) {
	_, s := newTestServerState(t)
	code, got, hdr := postDevice(t, s, map[string]any{
		"name": "leaf-new", "address": "198.51.100.121", "type": "router",
	})
	if code != http.StatusCreated {
		t.Fatalf("fresh identity: want 201, got %d", code)
	}
	if got.ID != discovery.ScanDeviceID("leaf-new", "198.51.100.121") {
		t.Fatalf("201 must return the requested identity, got %s", got.ID)
	}
	if hdr.Get("X-Device-Canonical-Id") != got.ID {
		t.Fatalf("canonical header %q != body id %q", hdr.Get("X-Device-Canonical-Id"), got.ID)
	}
	if hdr.Get("X-Device-Requested-Id") != "" {
		t.Fatalf("a create that was NOT absorbed must not advertise a diverging requested id, got %q",
			hdr.Get("X-Device-Requested-Id"))
	}
	if raw := rawDeviceIDs(s); !raw[got.ID] || len(raw) != 1 {
		t.Fatalf("201 must persist exactly its own row, got %v", raw)
	}
	if _, ok := deviceByID(s, got.ID); !ok {
		t.Fatalf("201 was returned but %s is not retrievable", got.ID)
	}
	// A second, unrelated identity is unaffected by the first.
	if code, _, _ := postDevice(t, s, map[string]any{
		"name": "leaf-new-2", "address": "198.51.100.122", "type": "router",
	}); code != http.StatusCreated {
		t.Fatalf("second fresh identity: want 201, got %d", code)
	}
	if raw := rawDeviceIDs(s); len(raw) != 2 {
		t.Fatalf("two distinct identities must persist two rows, got %v", raw)
	}
}

// (c) §3a. The SAME identity signature (name + management address) in another
// tenant is a different device: it must NOT merge, must create independently,
// and neither tenant may see the other's row.
func TestSameIdentityInAnotherTenantCreatesIndependently(t *testing.T) {
	_, s := newTestServerState(t)
	const (
		name = "core-sw01"
		addr = "10.10.0.1"
	)
	codeA, devA, _ := postDeviceAs(t, s, acme(), map[string]any{
		"name": name, "address": addr, "type": "router",
	})
	if codeA != http.StatusCreated {
		t.Fatalf("acme create: want 201, got %d", codeA)
	}
	codeB, devB, hdrB := postDeviceAs(t, s, globex(), map[string]any{
		"name": name, "address": addr, "type": "router",
	})
	if codeB != http.StatusCreated {
		t.Fatalf("CROSS-TENANT MERGE: globex's own device was absorbed by acme's (got %d, canonical %q)",
			codeB, hdrB.Get("X-Device-Canonical-Id"))
	}
	// Ids are derived from (name, address) — both tenant-independent — so the
	// two tenants derived the SAME key and the second create REPLACED the
	// first tenant's row: a cross-tenant write. Independent devices need
	// independent keys.
	if devA.ID == devB.ID {
		t.Fatalf("CROSS-TENANT KEY COLLISION: both tenants own row %q — one of them was overwritten", devA.ID)
	}
	if raw := rawDeviceIDs(s); len(raw) != 2 || !raw[devA.ID] || !raw[devB.ID] {
		t.Fatalf("both tenants must keep their own persisted row, got %v", raw)
	}
	if devA.TenantID != "acme" || devB.TenantID != "globex" {
		t.Fatalf("TenantID must be stamped from the principal: %q / %q", devA.TenantID, devB.TenantID)
	}
	// Two independent rows survive the projection, one per tenant.
	perTenant := map[string]int{}
	for _, d := range s.discovery.Devices() {
		perTenant[d.TenantID]++
	}
	if perTenant["acme"] != 1 || perTenant["globex"] != 1 {
		t.Fatalf("each tenant must keep its own device, got %v", perTenant)
	}
	// And neither tenant can see the other's.
	for _, tc := range []struct {
		claims jwtClaims
		tenant string
	}{{acme(), "acme"}, {globex(), "globex"}} {
		rr := httptest.NewRecorder()
		s.handleDevices(rr, req("GET", "/api/devices", "", tc.claims))
		var devs []models.Device
		if err := json.Unmarshal(rr.Body.Bytes(), &devs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(devs) != 1 {
			t.Fatalf("%s must see exactly its own device, got %d: %+v", tc.tenant, len(devs), devs)
		}
		if devs[0].TenantID != tc.tenant {
			t.Fatalf("TENANT LEAK: %s saw a device owned by %q", tc.tenant, devs[0].TenantID)
		}
	}
}

// (d) THE RECORDED 181 REPRODUCTION: the absorbed row was invisible to GET
// while the absorber existed and SURFACED when the absorber was deleted. After
// the fix, deleting the absorber leaves nothing behind.
func TestAbsorbedCreateDoesNotSurfaceWhenTheAbsorberIsDeleted(t *testing.T) {
	_, s := newTestServerState(t)
	const addr = "198.51.100.123"
	if code, _, _ := postDevice(t, s, map[string]any{
		"name": "aaa-run1", "address": addr, "type": "router",
	}); code != http.StatusCreated {
		t.Fatalf("run-1 create: want 201, got %d", code)
	}
	survivor := discovery.ScanDeviceID("aaa-run1", addr)
	// The second scale run re-provisions the same address under a new name.
	code, _, _ := postDevice(t, s, map[string]any{
		"name": "zzz-run2", "address": addr, "type": "router",
	})
	if code != http.StatusOK {
		t.Fatalf("run-2 create was absorbed, so it must answer 200, got %d", code)
	}
	// Cleanup deletes what GET listed — the absorber.
	if st := deleteDeviceAs(t, s, superA(), survivor); st != http.StatusNoContent {
		t.Fatalf("delete absorber: want 204, got %d", st)
	}
	if ids := listDeviceIDs(t, s, superA()); len(ids) != 0 {
		t.Fatalf("SHADOW SURFACED after the absorber was deleted: %v (tracker 181)", ids)
	}
	if raw := rawDeviceIDs(s); len(raw) != 0 {
		t.Fatalf("a cleanup that removed every listed device must leave no rows, got %v", raw)
	}
}

// GET and DELETE must agree: the absorbed id is not addressable, because it was
// never written. A tenant-scoped principal gets 404 (the id does not exist for
// it), which is also the §3a answer for an id it may not reach.
func TestAbsorbedCreateIDIsNotAddressable(t *testing.T) {
	_, s := newTestServerState(t)
	const addr = "10.10.0.9"
	if code, _, _ := postDeviceAs(t, s, acme(), map[string]any{
		"name": "aaa-keeper", "address": addr, "type": "router",
	}); code != http.StatusCreated {
		t.Fatalf("seed: want 201, got %d", code)
	}
	code, _, hdr := postDeviceAs(t, s, acme(), map[string]any{
		"name": "zzz-absorbed", "address": addr, "type": "router",
	})
	if code != http.StatusOK {
		t.Fatalf("absorbed create: want 200, got %d", code)
	}
	requested := hdr.Get("X-Device-Requested-Id")
	if requested == "" {
		t.Fatal("absorbed create must name the identity that was not created")
	}
	if st := deleteDeviceAs(t, s, acme(), requested); st != http.StatusNotFound {
		t.Fatalf("the absorbed id must not be addressable by DELETE: want 404, got %d", st)
	}
	if _, ok := s.discovery.Get(requested); ok {
		t.Fatalf("row %s exists in the store but never existed for GET — that is the shadow", requested)
	}
}

// Resolve-then-persist is one atomic step: eight concurrent creates that all
// claim ONE management address must produce exactly one row and exactly one
// 201. A check-then-act split (resolve outside the lock) would let several
// callers decide they were new and race shadow rows into the cache.
func TestConcurrentCreatesOfOneIdentityWriteOneRow(t *testing.T) {
	_, s := newTestServerState(t)
	var wg sync.WaitGroup
	codes := make([]int, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Distinct hostnames, one address: every one of these is a create
			// of its OWN identity, and all but one must lose the merge.
			b, err := json.Marshal(map[string]any{
				"name": fmt.Sprintf("race-181-%d", i), "address": "198.51.100.124", "type": "router",
			})
			if err != nil {
				return
			}
			rr := httptest.NewRecorder()
			s.handleDevices(rr, req("POST", "/api/devices", string(b), superA()))
			codes[i] = rr.Code
		}(i)
	}
	wg.Wait()
	created := 0
	for i, c := range codes {
		switch c {
		case http.StatusCreated:
			created++
		case http.StatusOK:
		default:
			t.Fatalf("goroutine %d: unexpected status %d", i, c)
		}
	}
	if created != 1 {
		t.Fatalf("exactly one concurrent create may own the identity, got %d", created)
	}
	if raw := rawDeviceIDs(s); len(raw) != 1 {
		t.Fatalf("one identity must persist exactly one row, got %d: %v", len(raw), raw)
	}
}
