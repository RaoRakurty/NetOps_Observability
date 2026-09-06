// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"netops/backend/internal/discovery"
	"netops/backend/models"
)

// TRACKER 161 — the device-onboarding identity contract.
//
//	201 Created  = the REQUESTED identity exists and is retrievable
//	200 OK       = the request resolved to an existing canonical device;
//	               nothing was created under the requested identity, and the
//	               body is the identity that actually survived
//
// The defect this pins: the handler answered 201 and echoed the caller's own
// object back even when cross-source dedupe had absorbed it. The caller was
// told its device existed under the name it chose. It did not, and because the
// tenant-enrichment export writes the SURVIVOR's name, every event bearing the
// absorbed name was unattributable forever.
//
// Measured live 2026-08-19 (ladder 08192206q18i): a previous run's cleanup
// crashed and left 73 devices behind; the replacements were re-provisioned onto
// the same management addresses, lost the merge deterministically, and produced
// 927/1000 device coverage while the API reported 1000 successful creates.

func postDevice(t *testing.T, s *server, body map[string]any) (int, models.Device, http.Header) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rr := httptest.NewRecorder()
	s.handleDevices(rr, req("POST", "/api/devices", string(b), superA()))
	var got models.Device
	if rr.Code < 300 {
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode response (code %d): %v — body %s", rr.Code, err, rr.Body.String())
		}
	}
	return rr.Code, got, rr.Result().Header
}

func deviceByID(s *server, id string) (models.Device, bool) {
	for _, d := range s.discovery.Devices() {
		if d.ID == id {
			return d, true
		}
	}
	return models.Device{}, false
}

// A device created on a free address keeps its own identity: 201, retrievable.
func TestCreateWithFreshIdentityReturns201AndIsRetrievable(t *testing.T) {
	_, s := newTestServerState(t)
	code, got, hdr := postDevice(t, s, map[string]any{
		"name": "leaf-a", "address": "198.51.100.10", "type": "router",
	})
	if code != http.StatusCreated {
		t.Fatalf("want 201 for a fresh identity, got %d", code)
	}
	if _, ok := deviceByID(s, got.ID); !ok {
		t.Fatalf("201 was returned but %s is not retrievable — that is the false success", got.ID)
	}
	if hdr.Get("X-Device-Canonical-Id") != got.ID {
		t.Fatalf("canonical id header %q != body id %q", hdr.Get("X-Device-Canonical-Id"), got.ID)
	}
}

// THE OPERATIONAL SCENARIO: replace a switch, give the replacement a new
// hostname on the same management IP. This is device re-provisioning, not a
// synthetic corner case — it is what produced the 927/1000 gap.
//
// NOTE ON ORDERING, which the first version of this test got wrong: the merge
// winner is decided by sort.Strings over the cache ids, so whether the stale or
// the replacement device survives depends on their NAMES. The live incident had
// mlx-0818… (stale) sorting before mlx-0819… (new), so the stale record won.
// This test reproduces that ordering deliberately; the symmetric case is
// covered below. The CONTRACT is the same either way — whoever loses must not
// be told 201.
func TestReprovisionedDeviceOnSameAddressIsNotAFalseSuccess(t *testing.T) {
	_, s := newTestServerState(t)
	// "aaa-stale" sorts before "zzz-replacement", so the stale record wins —
	// the shape of the 2026-08-19 incident.
	if code, _, _ := postDevice(t, s, map[string]any{
		"name": "aaa-stale", "address": "198.51.100.20", "type": "router",
	}); code != http.StatusCreated {
		t.Fatalf("seeding the stale device: want 201, got %d", code)
	}
	code, got, hdr := postDevice(t, s, map[string]any{
		"name": "zzz-replacement", "address": "198.51.100.20", "type": "router",
	})
	if code == http.StatusCreated {
		t.Fatalf("201 for a device absorbed by dedupe is the tracker-161 defect: " +
			"the caller is told 'zzz-replacement' exists when it does not")
	}
	if code != http.StatusOK {
		t.Fatalf("want 200 for an absorbed create, got %d", code)
	}
	if got.ID == "" {
		t.Fatal("an absorbed create must still return the canonical device")
	}
	if _, ok := deviceByID(s, got.ID); !ok {
		t.Fatalf("returned canonical id %s is not retrievable", got.ID)
	}
	if hdr.Get("X-Device-Canonical-Id") != got.ID {
		t.Fatalf("canonical header %q != body %q", hdr.Get("X-Device-Canonical-Id"), got.ID)
	}
	if hdr.Get("X-Device-Requested-Id") == "" {
		t.Fatal("an absorbed create must name the identity that was NOT created")
	}
	if hdr.Get("X-Device-Requested-Id") == got.ID {
		t.Fatal("requested and canonical must differ when the request was absorbed")
	}
}

// Same hostname, different address: distinct identities must both survive.
func TestSameNameDifferentAddressDoesNotCollapseSilently(t *testing.T) {
	_, s := newTestServerState(t)
	c1, d1, _ := postDevice(t, s, map[string]any{
		"name": "core-1", "address": "198.51.100.30", "type": "router",
	})
	c2, d2, _ := postDevice(t, s, map[string]any{
		"name": "core-1", "address": "198.51.100.31", "type": "router",
	})
	// Whatever the merge decides, the caller must never be told 201 for an
	// identity that is not retrievable.
	for i, tc := range []struct {
		code int
		dev  models.Device
	}{{c1, d1}, {c2, d2}} {
		if tc.code == http.StatusCreated {
			if _, ok := deviceByID(s, tc.dev.ID); !ok {
				t.Fatalf("case %d: 201 for %s but it is not retrievable", i, tc.dev.ID)
			}
		}
	}
}

// Re-onboarding the SAME device must be idempotent and honest.
func TestReOnboardingTheSameDeviceIsHonest(t *testing.T) {
	_, s := newTestServerState(t)
	body := map[string]any{"name": "leaf-b", "address": "198.51.100.40", "type": "router"}
	c1, d1, _ := postDevice(t, s, body)
	if c1 != http.StatusCreated {
		t.Fatalf("first create: want 201, got %d", c1)
	}
	c2, d2, _ := postDevice(t, s, body)
	if d2.ID != d1.ID {
		t.Fatalf("re-onboard changed the canonical id: %s -> %s", d1.ID, d2.ID)
	}
	if c2 == http.StatusCreated {
		if _, ok := deviceByID(s, d2.ID); !ok {
			t.Fatalf("201 on re-onboard but %s not retrievable", d2.ID)
		}
	}
}

// Every 201 in a bulk onboard must be retrievable — the property the ladder's
// devices_created count was silently assuming.
func TestBulkOnboardEvery201IsRetrievable(t *testing.T) {
	_, s := newTestServerState(t)
	created := map[string]bool{}
	for i := 0; i < 60; i++ {
		code, got, _ := postDevice(t, s, map[string]any{
			"name":    fmt.Sprintf("mlx-bulk-%05d", i),
			"address": fmt.Sprintf("198.51.%d.%d", i/250, i%250+1),
			"type":    "router",
		})
		if code == http.StatusCreated {
			created[got.ID] = true
		}
	}
	for id := range created {
		if _, ok := deviceByID(s, id); !ok {
			t.Fatalf("device %s got 201 but is not retrievable", id)
		}
	}
	if len(created) != 60 {
		t.Fatalf("60 distinct addresses should all create; got %d", len(created))
	}
}

// Stale residue then re-onboard: exactly the failed-cleanup shape.
func TestStaleResidueThenReonboardIsReported(t *testing.T) {
	_, s := newTestServerState(t)
	const addr = "198.51.100.50"
	postDevice(t, s, map[string]any{"name": "mlx-oldrun-00927", "address": addr, "type": "router"})
	code, got, hdr := postDevice(t, s,
		map[string]any{"name": "mlx-newrun-00927", "address": addr, "type": "router"})
	if code == http.StatusCreated && !strings.Contains(got.ID, "newrun") {
		t.Fatalf("201 returned but canonical id %s is not the requested identity", got.ID)
	}
	if code == http.StatusOK && hdr.Get("X-Device-Requested-Id") == "" {
		t.Fatal("absorbed create must name the requested identity")
	}
	if _, ok := deviceByID(s, got.ID); !ok {
		t.Fatalf("returned id %s is not retrievable", got.ID)
	}
}

// Concurrent onboarding of the same identity must not produce a 201 whose
// device cannot be found.
func TestConcurrentDuplicateOnboardingNeverLies(t *testing.T) {
	_, s := newTestServerState(t)
	var wg sync.WaitGroup
	codes := make([]int, 8)
	devs := make([]models.Device, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			b, _ := json.Marshal(map[string]any{
				"name": "race-1", "address": "198.51.100.60", "type": "router",
			})
			rr := httptest.NewRecorder()
			s.handleDevices(rr, req("POST", "/api/devices", string(b), superA()))
			codes[i] = rr.Code
			_ = json.Unmarshal(rr.Body.Bytes(), &devs[i])
		}(i)
	}
	wg.Wait()
	for i, c := range codes {
		if c == http.StatusCreated {
			if _, ok := deviceByID(s, devs[i].ID); !ok {
				t.Fatalf("goroutine %d got 201 for unretrievable %s", i, devs[i].ID)
			}
		}
	}
}

// ResolveIdentity must agree with what /api/devices actually shows — the whole
// reason it is derived from the same dedupe rather than reimplementing it.
func TestResolveIdentityAgreesWithTheReadPath(t *testing.T) {
	agg := discovery.NewDiscoveryAggregator()
	if err := agg.Upsert(models.Device{ID: "b-two", Name: "b-two", Address: "203.0.113.9"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := agg.Upsert(models.Device{ID: "a-one", Name: "a-one", Address: "203.0.113.9"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	devices := agg.Devices()
	if len(devices) != 1 {
		t.Fatalf("two records on one address must merge to 1, got %d", len(devices))
	}
	survivor := devices[0].ID
	for _, id := range []string{"a-one", "b-two"} {
		canonical, kept, found := agg.ResolveIdentity(id)
		if !found {
			t.Fatalf("ResolveIdentity(%s) not found", id)
		}
		if canonical.ID != survivor {
			t.Fatalf("ResolveIdentity(%s) says %s, read path says %s", id, canonical.ID, survivor)
		}
		if kept != (id == survivor) {
			t.Fatalf("ResolveIdentity(%s) kept=%v but survivor is %s", id, kept, survivor)
		}
	}
}

// The mirror image: when the REPLACEMENT sorts first it wins, and the stale
// record is the one absorbed. The contract must hold in both directions, so
// neither outcome is baked into the test suite as "the" answer.
func TestWhicheverRecordLosesTheMergeIsNotToldItWasCreated(t *testing.T) {
	for _, tc := range []struct{ first, second string }{
		{"aaa-stale", "zzz-replacement"},
		{"zzz-stale", "aaa-replacement"},
	} {
		t.Run(tc.first+"_then_"+tc.second, func(t *testing.T) {
			_, s := newTestServerState(t)
			const addr = "198.51.100.70"
			if c, _, _ := postDevice(t, s,
				map[string]any{"name": tc.first, "address": addr, "type": "router"}); c != http.StatusCreated {
				t.Fatalf("seed: want 201, got %d", c)
			}
			code, got, hdr := postDevice(t, s,
				map[string]any{"name": tc.second, "address": addr, "type": "router"})
			if _, ok := deviceByID(s, got.ID); !ok {
				t.Fatalf("returned id %s is not retrievable", got.ID)
			}
			switch code {
			case http.StatusCreated:
				// The second create won: its identity must be the canonical one.
				if !strings.Contains(got.ID, strings.Split(tc.second, "-")[0]) {
					t.Fatalf("201 but canonical id %s is not the requested identity %s",
						got.ID, tc.second)
				}
			case http.StatusOK:
				if hdr.Get("X-Device-Requested-Id") == "" {
					t.Fatal("absorbed create must name the identity that was not created")
				}
				if hdr.Get("X-Device-Requested-Id") == got.ID {
					t.Fatal("requested and canonical must differ on an absorbed create")
				}
			default:
				t.Fatalf("unexpected status %d", code)
			}
			// Exactly one device on that address, whichever won.
			n := 0
			for _, d := range s.discovery.Devices() {
				if d.Address == addr {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("two records share an address but %d survived", n)
			}
		})
	}
}
