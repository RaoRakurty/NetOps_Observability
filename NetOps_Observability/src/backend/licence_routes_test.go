// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/audit"
	"netops/backend/internal/discovery"
	"netops/backend/internal/entitlement"
	"netops/backend/internal/licence"
	"netops/backend/internal/licence/signer"
	"netops/backend/internal/rbac"
	"netops/backend/models"
)

// licence_routes_test.go — the ENFORCEMENT proof.
//
// internal/licence proves the mechanism (signature, expiry, rotation, closed
// vocabulary) and internal/entitlement proves the semantics. Neither can prove
// the three things that only exist here, in the wiring:
//
//  1. the CHOKEPOINTS are actually wired — a gate nobody calls is decoration,
//     and every one of these tests drives the real handler, not a helper;
//  2. the GATES on /api/system/licence are the right ones per verb and run
//     before anything else happens — requirePlatformAdmin on the writes,
//     requireAdmin plus a TENANT-SCOPED projection on the read;
//  3. the mux registration exists, so the route is reachable at all.
//
// Every test builds its own signing key: nothing here depends on, or can be
// broken by rotating, the key embedded in the shipped build.

// ─────────────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────────────

// licTestKey is a throwaway signing identity plus the verifier that trusts it.
type licTestKey struct {
	kp signer.KeyPair
	v  licence.Verifier
}

func newLicTestKey(t *testing.T) licTestKey {
	t.Helper()
	kp, err := signer.GenerateKey()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	return licTestKey{kp: kp, v: licence.NewVerifier(licence.NewPublicKey(kp.Public, licence.RoleCurrent, "test key"))}
}

// issue signs a licence at the given tier with the given features and ceiling
// overrides, and returns the document bytes.
func (k licTestKey) issue(t *testing.T, tier entitlement.Tier, features []entitlement.Feature, override func(*entitlement.Ceilings)) []byte {
	t.Helper()
	c, ok := entitlement.TierCeilings(tier)
	if !ok {
		t.Fatalf("no reference ceilings for tier %q", tier)
	}
	if override != nil {
		override(&c)
	}
	doc := licence.Document{
		LicenceID: "test-" + string(tier),
		Customer:  "Test Customer",
		Tier:      tier,
		IssuedAt:  time.Now().UTC().Add(-24 * time.Hour),
		ExpiresAt: time.Now().UTC().AddDate(1, 0, 0),
		Ceilings:  c,
		Features:  features,
		GraceDays: 30,
	}
	signed, err := signer.Sign(doc, k.kp.Private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// licStore builds a FileStore trusting only k. With raw == nil no licence is
// installed, which is the Community case.
func (k licTestKey) store(t *testing.T, raw []byte) licence.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "licence.json")
	if raw != nil {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return licence.NewFileStore(path, licence.FileStoreOptions{
		Verifier: k.v,
		Now:      time.Now,
		Poll:     time.Nanosecond, // every read re-checks: no cache to reason about
	})
}

// licService is the entitlement service under a given licence (nil = Community).
func (k licTestKey) service(t *testing.T, raw []byte) *licence.Service {
	t.Helper()
	return licence.NewService(k.store(t, raw))
}

// licClaims is a platform-owner principal (cross-tenant, super-admin).
func licClaims() jwtClaims {
	return jwtClaims{Sub: "owner@example.test", Role: rbac.RoleSuperAdmin, Tenant: TenantGlobal}
}

// licTenantAdminClaims is a TENANT admin: it holds full administration:admin
// but is NOT the platform owner. Every platform-global gate must refuse it.
func licTenantAdminClaims() jwtClaims {
	return jwtClaims{Sub: "admin@acme.test", Role: rbac.RoleSuperAdmin, Tenant: "acme"}
}

func licReq(method, path, body string, c jwtClaims) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	return r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
}

// licAssertRefusal asserts the response is the structured 402 naming the
// expected ceiling or feature and a lifting tier.
func licAssertRefusal(t *testing.T, w *httptest.ResponseRecorder, wantKind, wantName string, wantLift entitlement.Tier) {
	t.Helper()
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402 (licence refusal); body = %s", w.Code, w.Body.String())
	}
	var body struct {
		Error    string           `json:"error"`
		Ceiling  string           `json:"ceiling"`
		Feature  string           `json:"feature"`
		Current  int              `json:"current"`
		Limit    int              `json:"limit"`
		Tier     entitlement.Tier `json:"tier"`
		LiftedBy entitlement.Tier `json:"lifted_by"`
		Message  string           `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("the 402 body must be the JSON the upgrade card renders: %v (%s)", err, w.Body.String())
	}
	if body.Error != wantKind {
		t.Fatalf("error = %q, want %q", body.Error, wantKind)
	}
	got := body.Ceiling
	if wantKind == entitlement.KindFeature {
		got = body.Feature
	}
	if got != wantName {
		t.Fatalf("refusal names %q, want %q", got, wantName)
	}
	if body.LiftedBy != wantLift {
		t.Fatalf("lifted_by = %q, want %q — a refusal that does not say what lifts it is a dead end", body.LiftedBy, wantLift)
	}
	if strings.TrimSpace(body.Message) == "" {
		t.Fatal("the refusal must carry an operator-facing message")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CHOKEPOINT 1 — device admission (manual create)
// ─────────────────────────────────────────────────────────────────────────────

// licDeviceServer builds the minimum server able to serve POST /api/devices,
// seeded with `seed` MONITORED devices.
//
// The seed is written BEFORE the ceiling is injected, deliberately: the fixture
// is "a deployment that already monitors this many", not "a deployment that
// just asked permission for this many", and the gate under test is the NEXT
// transition. Seeded devices carry an address and the manual source, which is
// what makes them monitored (internal/devmon).
func licDeviceServer(t *testing.T, ent *licence.Service, seed int) *server {
	t.Helper()
	roles, err := newRoleStore(filepath.Join(t.TempDir(), "roles.json"))
	if err != nil {
		t.Fatal(err)
	}
	d := discovery.NewDiscoveryAggregator()
	for i := 0; i < seed; i++ {
		dev := models.Device{
			ID: "seed-" + strconv.Itoa(i), Name: "seed-" + strconv.Itoa(i),
			Address: "10.90." + strconv.Itoa(i/250) + "." + strconv.Itoa(i%250),
			Source:  "manual",
		}
		if err := d.Upsert(dev); err != nil {
			t.Fatalf("seed device %d: %v", i, err)
		}
	}
	if got := len(d.Devices()); got != seed {
		t.Fatalf("harness seeded %d devices, wanted %d", got, seed)
	}
	if got := d.MonitoredCount(); got != seed {
		t.Fatalf("harness seeded %d MONITORED devices, wanted %d — the fixture must "+
			"represent a deployment that is actually collecting from them", got, seed)
	}
	d.SetMonitorGate(func(current int) error {
		return entitlement.CheckCeiling(ent, entitlement.CeilingDevices, current)
	})
	return &server{roles: roles, discovery: d, entitlements: ent}
}

// TestLicenceDeviceCeiling is the headline enforcement: under Community the
// 26th MONITORED device is refused and under a Team licence it is admitted.
// Same handler, same request, one file's difference.
func TestLicenceDeviceCeiling(t *testing.T) {
	k := newLicTestKey(t)
	const body = `{"name":"new-switch","address":"10.10.10.10"}`

	t.Run("community admits the 25th", func(t *testing.T) {
		s := licDeviceServer(t, k.service(t, nil), 24)
		w := httptest.NewRecorder()
		s.handleDevices(w, licReq(http.MethodPost, "/api/devices", body, licClaims()))
		if w.Code == http.StatusPaymentRequired {
			t.Fatalf("the 25th monitored device is inside the Community ceiling and must be admitted: %s", w.Body.String())
		}
		if got := s.discovery.MonitoredCount(); got != 25 {
			t.Fatalf("monitored = %d, want 25", got)
		}
	})

	t.Run("community refuses the 26th", func(t *testing.T) {
		s := licDeviceServer(t, k.service(t, nil), 25)
		w := httptest.NewRecorder()
		s.handleDevices(w, licReq(http.MethodPost, "/api/devices", body, licClaims()))
		licAssertRefusal(t, w, entitlement.KindCeiling, entitlement.CeilingDevices, entitlement.TierTeam)
		// And nothing was written: a refused create must not half-happen.
		if len(s.discovery.Devices()) != 25 {
			t.Fatalf("a refused create must not add a device, fleet is now %d", len(s.discovery.Devices()))
		}
	})

	t.Run("the refusal names the unit it counts", func(t *testing.T) {
		// The machine token must say monitored_devices, so no client can render
		// a limit on collection as a limit on inventory rows.
		s := licDeviceServer(t, k.service(t, nil), 25)
		w := httptest.NewRecorder()
		s.handleDevices(w, licReq(http.MethodPost, "/api/devices", body, licClaims()))
		var got struct {
			Unit    string `json:"unit"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Unit != entitlement.UnitMonitoredDevices {
			t.Fatalf("unit = %q, want %q", got.Unit, entitlement.UnitMonitoredDevices)
		}
		if !strings.Contains(got.Message, "monitored devices") {
			t.Fatalf("the sentence must say what is limited: %q", got.Message)
		}
	})

	t.Run("a Team licence lifts it", func(t *testing.T) {
		// The SAME request, the SAME handler, one signed file's difference.
		s := licDeviceServer(t, k.service(t, k.issue(t, entitlement.TierTeam, nil, nil)), 25)
		w := httptest.NewRecorder()
		s.handleDevices(w, licReq(http.MethodPost, "/api/devices", body, licClaims()))
		if w.Code == http.StatusPaymentRequired {
			t.Fatalf("a Team licence covers 250 devices — the 26th must be admitted: %s", w.Body.String())
		}
		if len(s.discovery.Devices()) != 26 {
			t.Fatalf("the device must actually be admitted, fleet is %d", len(s.discovery.Devices()))
		}
	})

	t.Run("re-posting an existing device at the ceiling is not refused", func(t *testing.T) {
		// Re-onboarding writes no new row. Refusing it would make a fleet at
		// exactly the ceiling impossible to re-provision.
		s := licDeviceServer(t, k.service(t, nil), 25)
		existing := s.discovery.Devices()[0]
		w := httptest.NewRecorder()
		s.handleDevices(w, licReq(http.MethodPost, "/api/devices",
			`{"id":"`+existing.ID+`","name":"`+existing.Name+`","address":"`+existing.Address+`"}`, licClaims()))
		if w.Code == http.StatusPaymentRequired {
			t.Fatalf("re-posting a device that already exists adds nothing and must not be refused: %s", w.Body.String())
		}
	})

	t.Run("adding a second telemetry method at the ceiling is not refused", func(t *testing.T) {
		// The unit is the DEVICE. A device already counted may gain a gNMI
		// subscription and an SNMP credential without consuming anything more,
		// and the count must not move.
		s := licDeviceServer(t, k.service(t, nil), 25)
		existing := s.discovery.Devices()[0]
		w := httptest.NewRecorder()
		s.handleDevices(w, licReq(http.MethodPost, "/api/devices",
			`{"id":"`+existing.ID+`","name":"`+existing.Name+`","address":"`+existing.Address+`",`+
				`"credential_ref":"lab-v2c","labels":{"gnmi":"true"}}`, licClaims()))
		if w.Code == http.StatusPaymentRequired {
			t.Fatalf("a device that is already monitored may add telemetry: %s", w.Body.String())
		}
		if got := s.discovery.MonitoredCount(); got != 25 {
			t.Fatalf("monitored = %d, want 25 — several methods on one device are still one device", got)
		}
	})
}

// TestLicenceDiscoveryIsNeverCharged is the C4 decision end to end: discovery
// finds a network far larger than the ceiling, every device lands in the
// inventory, and NONE of it consumes the allowance.
func TestLicenceDiscoveryIsNeverCharged(t *testing.T) {
	k := newLicTestKey(t)
	ent := k.service(t, nil) // Community: 25
	d := discovery.NewDiscoveryAggregator()
	d.SetMonitorGate(func(current int) error {
		return entitlement.CheckCeiling(ent, entitlement.CeilingDevices, current)
	})

	src := &licFakeSource{}
	for i := 0; i < 500; i++ {
		src.devices = append(src.devices, models.Device{
			ID: "disc-" + strconv.Itoa(i), Name: "disc-" + strconv.Itoa(i),
			Address: "10.0." + strconv.Itoa(i/250) + "." + strconv.Itoa(i%250),
		})
	}
	d.PollOnceForTest(context.Background(), src)

	if got := len(d.Devices()); got != 500 {
		t.Fatalf("discovery admitted %d devices, want all 500 — finding a device is free and "+
			"must never be refused by a licence", got)
	}
	if got := d.MonitoredCount(); got != 0 {
		t.Fatalf("monitored = %d, want 0 — a subnet-scan result is a candidate, not a monitored device", got)
	}
	if got := d.MonitoringWithheldCount(); got != 0 {
		t.Fatalf("withheld = %d, want 0 — nothing was withheld because nothing asked to be monitored", got)
	}

	t.Run("enabling monitoring on five spends five", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			if _, err := d.SetMonitoring("disc-"+strconv.Itoa(i), true, "op@example.test"); err != nil {
				t.Fatalf("enable %d: %v", i, err)
			}
		}
		if got := d.MonitoredCount(); got != 5 {
			t.Fatalf("monitored = %d, want 5", got)
		}
		if got := len(d.Devices()); got != 500 {
			t.Fatalf("the inventory must be untouched, got %d", got)
		}
	})

	t.Run("a re-poll does not double count or churn", func(t *testing.T) {
		d.PollOnceForTest(context.Background(), src)
		if got := d.MonitoredCount(); got != 5 {
			t.Fatalf("rediscovery changed the count to %d, want 5", got)
		}
		if got := len(d.Devices()); got != 500 {
			t.Fatalf("rediscovery changed the fleet to %d, want 500", got)
		}
	})
}

// TestLicenceSourceMonitoringWithheld is the honest-degradation half: a SOURCE
// reporting devices that would default to monitored (an operator's devices
// file, the source of truth) past the ceiling still puts every one of them in
// the inventory — it withholds the COLLECTION and says so.
func TestLicenceSourceMonitoringWithheld(t *testing.T) {
	k := newLicTestKey(t)
	ent := k.service(t, nil) // Community: 25
	d := discovery.NewDiscoveryAggregator()
	d.SetMonitorGate(func(current int) error {
		return entitlement.CheckCeiling(ent, entitlement.CeilingDevices, current)
	})

	src := &licDeclaredSource{}
	for i := 0; i < 40; i++ {
		src.devices = append(src.devices, models.Device{
			ID: "sot-" + strconv.Itoa(i), Name: "sot-" + strconv.Itoa(i),
			Address: "10.4.0." + strconv.Itoa(i),
		})
	}
	d.PollOnceForTest(context.Background(), src)

	if got := len(d.Devices()); got != 40 {
		t.Fatalf("every device must be in the inventory, got %d — the ceiling withholds "+
			"collection, never discovery", got)
	}
	if got := d.MonitoredCount(); got != 25 {
		t.Fatalf("monitored = %d, want the Community ceiling of 25", got)
	}
	withheld := d.MonitoringWithheld()
	if len(withheld) != 15 {
		t.Fatalf("15 devices are over the ceiling and must be LISTED, got %d", len(withheld))
	}
	for _, w := range withheld {
		if !strings.Contains(w.Reason, "licence") {
			t.Fatalf("the withheld reason for %s must name the licence, got %q", w.DeviceID, w.Reason)
		}
		if !strings.Contains(w.Reason, "nothing was deleted") {
			t.Fatalf("the reason must say nothing was deleted: %q", w.Reason)
		}
	}

	t.Run("a second poll does not churn", func(t *testing.T) {
		d.PollOnceForTest(context.Background(), src)
		if got := d.MonitoredCount(); got != 25 {
			t.Fatalf("re-polling changed the monitored count to %d, want 25", got)
		}
		if got := d.MonitoringWithheldCount(); got != 15 {
			t.Fatalf("the withheld list must be stable across polls, got %d", got)
		}
	})

	t.Run("freeing a slot starts collecting from a withheld device", func(t *testing.T) {
		if _, err := d.SetMonitoring("sot-0", false, "op@example.test"); err != nil {
			t.Fatal(err)
		}
		if got := d.MonitoredCount(); got != 24 {
			t.Fatalf("turning one off must release the entitlement, monitored = %d", got)
		}
		d.PollOnceForTest(context.Background(), src)
		if got := d.MonitoredCount(); got != 25 {
			t.Fatalf("the freed slot must be taken by a withheld device on the next poll, monitored = %d", got)
		}
		if got := d.MonitoringWithheldCount(); got != 14 {
			t.Fatalf("withheld = %d, want 14", got)
		}
	})
}

// licDeclaredSource reports devices the way a source of truth or an operator's
// devices file does — DECLARED devices, which default to monitored.
type licDeclaredSource struct{ devices []models.Device }

func (f *licDeclaredSource) Name() string            { return "static" }
func (f *licDeclaredSource) Interval() time.Duration { return time.Minute }
func (f *licDeclaredSource) Poll(context.Context) ([]models.Device, error) {
	return append([]models.Device(nil), f.devices...), nil
}

// licFakeSource is a discovery source returning a fixed device list.
type licFakeSource struct{ devices []models.Device }

func (f *licFakeSource) Name() string            { return "snmp" }
func (f *licFakeSource) Interval() time.Duration { return time.Minute }
func (f *licFakeSource) Poll(context.Context) ([]models.Device, error) {
	return append([]models.Device(nil), f.devices...), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// CHOKEPOINT 2 — the watched-prefix ceiling
// ─────────────────────────────────────────────────────────────────────────────

// licWatchStore is an in-memory bgpWatchStore.
type licWatchStore struct{ rows []bgpWatchEntry }

func (s *licWatchStore) List(context.Context, string, bool) ([]bgpWatchEntry, error) {
	return append([]bgpWatchEntry(nil), s.rows...), nil
}
func (s *licWatchStore) Add(_ context.Context, _ string, e bgpWatchEntry) error {
	for i, r := range s.rows {
		if r.Resource == e.Resource {
			s.rows[i] = e
			return nil
		}
	}
	s.rows = append(s.rows, e)
	return nil
}
func (s *licWatchStore) Delete(context.Context, string, string) (bool, error) { return false, nil }

func licWatchServer(t *testing.T, ent *licence.Service, prefixes, asns int) (*server, *licWatchStore) {
	t.Helper()
	roles, err := newRoleStore(filepath.Join(t.TempDir(), "roles.json"))
	if err != nil {
		t.Fatal(err)
	}
	st := &licWatchStore{}
	for i := 0; i < prefixes; i++ {
		st.rows = append(st.rows, bgpWatchEntry{Resource: "203.0." + strconv.Itoa(i) + ".0/24", Kind: "prefix"})
	}
	for i := 0; i < asns; i++ {
		st.rows = append(st.rows, bgpWatchEntry{Resource: "AS" + strconv.Itoa(64500+i), Kind: "asn"})
	}
	return &server{roles: roles, bgpWatch: st, entitlements: ent}, st
}

func TestLicenceWatchedPrefixCeiling(t *testing.T) {
	k := newLicTestKey(t)
	const body = `{"resource":"198.51.100.0/24"}`

	t.Run("community admits the 5th", func(t *testing.T) {
		s, _ := licWatchServer(t, k.service(t, nil), 4, 0)
		w := httptest.NewRecorder()
		s.handleBGPWatchlist(w, licReq(http.MethodPost, "/api/bgp/watchlist", body, licTenantAdminClaims()))
		if w.Code != http.StatusOK {
			t.Fatalf("the 5th prefix is inside the Community ceiling and must be added: %d %s", w.Code, w.Body.String())
		}
	})

	t.Run("community refuses the 6th", func(t *testing.T) {
		s, st := licWatchServer(t, k.service(t, nil), 5, 0)
		w := httptest.NewRecorder()
		s.handleBGPWatchlist(w, licReq(http.MethodPost, "/api/bgp/watchlist", body, licTenantAdminClaims()))
		licAssertRefusal(t, w, entitlement.KindCeiling, entitlement.CeilingWatchedPrefixes, entitlement.TierTeam)
		if len(st.rows) != 5 {
			t.Fatalf("a refused add must not write, watchlist is now %d", len(st.rows))
		}
	})

	t.Run("a Team licence lifts it", func(t *testing.T) {
		s, st := licWatchServer(t, k.service(t, k.issue(t, entitlement.TierTeam, nil, nil)), 5, 0)
		w := httptest.NewRecorder()
		s.handleBGPWatchlist(w, licReq(http.MethodPost, "/api/bgp/watchlist", body, licTenantAdminClaims()))
		if w.Code != http.StatusOK {
			t.Fatalf("a Team licence covers 100 prefixes: %d %s", w.Code, w.Body.String())
		}
		if len(st.rows) != 6 {
			t.Fatalf("the prefix must actually be added, watchlist is %d", len(st.rows))
		}
	})

	t.Run("ASNs do not consume the PREFIX ceiling", func(t *testing.T) {
		// The ceiling is on prefixes. Counting ASN entries against it would
		// silently make the free tier smaller than the number on the pricing
		// page — a lie the operator cannot even see.
		s, _ := licWatchServer(t, k.service(t, nil), 4, 20)
		w := httptest.NewRecorder()
		s.handleBGPWatchlist(w, licReq(http.MethodPost, "/api/bgp/watchlist", body, licTenantAdminClaims()))
		if w.Code != http.StatusOK {
			t.Fatalf("20 watched ASNs must not consume the prefix ceiling: %d %s", w.Code, w.Body.String())
		}
	})

	t.Run("adding an ASN at the prefix ceiling is allowed", func(t *testing.T) {
		s, _ := licWatchServer(t, k.service(t, nil), 5, 0)
		w := httptest.NewRecorder()
		s.handleBGPWatchlist(w, licReq(http.MethodPost, "/api/bgp/watchlist", `{"resource":"AS64500"}`, licTenantAdminClaims()))
		if w.Code != http.StatusOK {
			t.Fatalf("an ASN is not a prefix and must not meet the prefix ceiling: %d %s", w.Code, w.Body.String())
		}
	})

	t.Run("re-adding an existing prefix at the ceiling is not refused", func(t *testing.T) {
		s, st := licWatchServer(t, k.service(t, nil), 5, 0)
		existing := st.rows[0].Resource
		w := httptest.NewRecorder()
		s.handleBGPWatchlist(w, licReq(http.MethodPost, "/api/bgp/watchlist",
			`{"resource":"`+existing+`","note":"updated"}`, licTenantAdminClaims()))
		if w.Code != http.StatusOK {
			t.Fatalf("re-adding an existing prefix only updates its note and must not be refused: %d %s", w.Code, w.Body.String())
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// CHOKEPOINT 3 — MSP / fleet management (tenant + org create)
// ─────────────────────────────────────────────────────────────────────────────

func licIdentityServer(t *testing.T, ent *licence.Service) *server {
	t.Helper()
	dir := t.TempDir()
	roles, err := newRoleStore(filepath.Join(dir, "roles.json"))
	if err != nil {
		t.Fatal(err)
	}
	tenants, err := newTenantStore(filepath.Join(dir, "tenants.json"))
	if err != nil {
		t.Fatal(err)
	}
	orgs, err := newOrgStore(filepath.Join(dir, "orgs.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &server{roles: roles, tenants: tenants, orgs: orgs, entitlements: ent}
}

// TestLicenceMSPManagement pins the line the owner drew: normal SINGLE-tenant
// operation is core and ungated; running a FLEET of tenants is the commercial
// capability.
func TestLicenceMSPManagement(t *testing.T) {
	k := newLicTestKey(t)

	t.Run("community creates its FIRST tenant", func(t *testing.T) {
		// Isolation and normal single-tenant operation are never entitlement-
		// gated. A free deployment must be able to stand up its own tenant.
		s := licIdentityServer(t, k.service(t, nil))
		w := httptest.NewRecorder()
		s.handleTenants(w, licReq(http.MethodPost, "/api/tenants", `{"name":"Acme"}`, licClaims()))
		if w.Code == http.StatusPaymentRequired {
			t.Fatalf("the first tenant is core operation, never a licensed capability: %s", w.Body.String())
		}
		if w.Code >= 400 {
			t.Fatalf("first tenant create failed: %d %s", w.Code, w.Body.String())
		}
	})

	t.Run("community refuses the SECOND tenant", func(t *testing.T) {
		s := licIdentityServer(t, k.service(t, nil))
		w := httptest.NewRecorder()
		s.handleTenants(w, licReq(http.MethodPost, "/api/tenants", `{"name":"Acme"}`, licClaims()))
		if w.Code >= 400 {
			t.Fatalf("precondition: first tenant must succeed, got %d %s", w.Code, w.Body.String())
		}
		w = httptest.NewRecorder()
		s.handleTenants(w, licReq(http.MethodPost, "/api/tenants", `{"name":"Globex"}`, licClaims()))
		licAssertRefusal(t, w, entitlement.KindFeature, string(entitlement.FeatureMSPManagement), entitlement.TierEnterprise)
	})

	t.Run("an Enterprise licence lifts it", func(t *testing.T) {
		raw := k.issue(t, entitlement.TierEnterprise, []entitlement.Feature{entitlement.FeatureMSPManagement}, nil)
		s := licIdentityServer(t, k.service(t, raw))
		for _, name := range []string{"Acme", "Globex", "Initech"} {
			w := httptest.NewRecorder()
			s.handleTenants(w, licReq(http.MethodPost, "/api/tenants", `{"name":"`+name+`"}`, licClaims()))
			if w.Code >= 400 {
				t.Fatalf("fleet management covers many tenants; %s failed: %d %s", name, w.Code, w.Body.String())
			}
		}
	})

	t.Run("community refuses org create", func(t *testing.T) {
		// An org exists to group many tenants — creating one IS fleet
		// management, so it is gated from the first one beyond the seeded root.
		s := licIdentityServer(t, k.service(t, nil))
		w := httptest.NewRecorder()
		s.handleOrgs(w, licReq(http.MethodPost, "/api/orgs", `{"name":"Partner"}`, licClaims()))
		licAssertRefusal(t, w, entitlement.KindFeature, string(entitlement.FeatureMSPManagement), entitlement.TierEnterprise)
	})

	t.Run("an Enterprise licence lifts org create", func(t *testing.T) {
		raw := k.issue(t, entitlement.TierEnterprise, []entitlement.Feature{entitlement.FeatureMSPManagement}, nil)
		s := licIdentityServer(t, k.service(t, raw))
		w := httptest.NewRecorder()
		s.handleOrgs(w, licReq(http.MethodPost, "/api/orgs", `{"name":"Partner"}`, licClaims()))
		if w.Code == http.StatusPaymentRequired {
			t.Fatalf("Enterprise includes fleet management: %s", w.Body.String())
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// CHOKEPOINT 4 — the feature-gated routes
// ─────────────────────────────────────────────────────────────────────────────

// TestLicenceFeatureRoutes drives the licenceFeature middleware exactly as the
// mux does, for every route it wraps.
func TestLicenceFeatureRoutes(t *testing.T) {
	k := newLicTestKey(t)
	reached := func(hit *bool) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { *hit = true; w.WriteHeader(http.StatusOK) }
	}

	cases := []struct {
		name    string
		feature entitlement.Feature
		lift    entitlement.Tier
		grant   entitlement.Tier
	}{
		{"security findings", entitlement.FeatureSecurityFindings, entitlement.TierTeam, entitlement.TierTeam},
		{"ldap", entitlement.FeatureLDAP, entitlement.TierEnterprise, entitlement.TierEnterprise},
	}
	for _, c := range cases {
		t.Run(c.name+" is refused under Community", func(t *testing.T) {
			s := &server{entitlements: k.service(t, nil)}
			hit := false
			w := httptest.NewRecorder()
			s.licenceFeature(c.feature, reached(&hit))(w, httptest.NewRequest(http.MethodGet, "/x", nil))
			licAssertRefusal(t, w, entitlement.KindFeature, string(c.feature), c.lift)
			if hit {
				t.Fatal("the handler must NOT run for an unlicensed caller — the gate is before, not after")
			}
		})
		t.Run(c.name+" is served with the licence", func(t *testing.T) {
			raw := k.issue(t, c.grant, []entitlement.Feature{c.feature}, nil)
			s := &server{entitlements: k.service(t, raw)}
			hit := false
			w := httptest.NewRecorder()
			s.licenceFeature(c.feature, reached(&hit))(w, httptest.NewRequest(http.MethodGet, "/x", nil))
			if !hit || w.Code != http.StatusOK {
				t.Fatalf("an entitled caller must reach the handler: hit=%v code=%d", hit, w.Code)
			}
		})
	}
}

// TestLicenceGatedRoutesAreRegistered proves the wrapping actually reached the
// mux. A perfectly correct middleware that nobody applied is decoration, and
// this is the only test that can catch that.
func TestLicenceGatedRoutesAreRegistered(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for route, feature := range map[string]entitlement.Feature{
		`"/api/security/findings"`:        entitlement.FeatureSecurityFindings,
		`"/api/security/findings/facets"`: entitlement.FeatureSecurityFindings,
		`"/api/security/findings/trend"`:  entitlement.FeatureSecurityFindings,
		`"/api/security/findings/"`:       entitlement.FeatureSecurityFindings,
		`"/api/auth/ldap/config"`:         entitlement.FeatureLDAP,
		`"/api/auth/ldap/test"`:           entitlement.FeatureLDAP,
	} {
		idx := strings.Index(text, "mux.HandleFunc("+route)
		if idx < 0 {
			t.Fatalf("route %s is no longer registered", route)
		}
		line := text[idx:]
		if nl := strings.IndexByte(line, '\n'); nl >= 0 {
			line = line[:nl]
		}
		if !strings.Contains(line, "licenceFeature") {
			t.Fatalf("route %s is registered WITHOUT the licence gate:\n\t%s", route, line)
		}
		want := "entitlement.Feature"
		if !strings.Contains(line, want) {
			t.Fatalf("route %s must name the semantic feature (%s), got:\n\t%s", route, feature, line)
		}
	}
}

// TestLicenceLoginPathsAreNeverGated is the safety invariant at the route level:
// core authentication must stay reachable at every licence state. LDAP
// CONFIGURATION is gated; LDAP LOGIN is not, and OIDC is not gated at all.
func TestLicenceLoginPathsAreNeverGated(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	for _, route := range []string{
		`"/api/auth/ldap/login"`,
		`"/api/auth/login"`,
		`"/api/auth/oidc/login"`,
		`"/api/auth/oidc/callback"`,
		`"/api/auth/refresh"`,
	} {
		idx := strings.Index(text, "mux.HandleFunc("+route)
		if idx < 0 {
			continue // not every route in this list exists in every build
		}
		line := text[idx:]
		if nl := strings.IndexByte(line, '\n'); nl >= 0 {
			line = line[:nl]
		}
		if strings.Contains(line, "licenceFeature") {
			t.Fatalf("%s is LICENCE-GATED.\n\n"+
				"Core authentication must stay reachable in every licence state (owner spec, 2026-09-04):\n"+
				"a lapsed licence that logged people out would be a licence problem touching authentication.\n"+
				"Gate the CONFIGURATION of a commercial auth method, never the sign-in path:\n\t%s", route, line)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CHOKEPOINT 6 — SAML connection type
// ─────────────────────────────────────────────────────────────────────────────

// TestLicenceSAMLGateIsRegistered: the SAML gate is on the PROTOCOL, not the
// route, because OIDC shares the route and is core.
func TestLicenceSAMLGateIsRegistered(t *testing.T) {
	src, err := os.ReadFile("oidc_config.go")
	if err != nil {
		t.Fatal(err)
	}
	body, ok := licFuncBody(string(src), "handleSSOIdPPut")
	if !ok {
		t.Fatal("handleSSOIdPPut not found — if it moved, follow the SAML gate to its new home")
	}
	if !strings.Contains(body, "entitlement.FeatureSAML") {
		t.Fatal("the SSO IdP write must gate the SAML protocol on the SAML entitlement")
	}
	if strings.Contains(body, "entitlement.FeatureLDAP") || strings.Contains(body, `"oidc"`) &&
		strings.Contains(body, "entitlement.Require(s.entitlements, entitlement.FeatureSAML)\n\t\t\treturn") {
		// Guard against the gate creeping onto OIDC.
		t.Fatal("OIDC is core and must never be gated on this route")
	}
	// The gate must be inside a saml-only branch, never unconditional.
	if !strings.Contains(body, `"saml"`) {
		t.Fatal("the gate must be scoped to the saml protocol — an unconditional gate would break OIDC, which is core")
	}
}

func licFuncBody(src, name string) (string, bool) {
	idx := strings.Index(src, ") "+name+"(")
	if idx < 0 {
		return "", false
	}
	start := strings.LastIndex(src[:idx], "\nfunc ")
	if start < 0 {
		return "", false
	}
	open := strings.IndexByte(src[start:], '{')
	if open < 0 {
		return "", false
	}
	depth := 0
	for i := start + open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[start : i+1], true
			}
		}
	}
	return "", false
}

// ─────────────────────────────────────────────────────────────────────────────
// GATE-READY, FEATURE ABSENT
// ─────────────────────────────────────────────────────────────────────────────

// TestLicenceGatesReadyForAbsentFeatures records, executably, the two
// capabilities in the owner's LOCKED Enterprise set that DO NOT EXIST in the
// product yet: SCIM and findings-export-to-SIEM.
//
// No route is invented for them. What is asserted is that the vocabulary and
// the gate helper already answer correctly, so the day either feature is built
// its gate is one `licenceFeature(...)` away and nothing about the entitlement
// model has to change.
func TestLicenceGatesReadyForAbsentFeatures(t *testing.T) {
	k := newLicTestKey(t)
	for _, f := range []entitlement.Feature{entitlement.FeatureSCIM, entitlement.FeatureSIEMExport} {
		t.Run(string(f), func(t *testing.T) {
			if !entitlement.ValidFeature(f) {
				t.Fatalf("%q must be in the closed vocabulary — the gate is ready before the feature is", f)
			}
			if entitlement.FeatureTier(f) != entitlement.TierEnterprise {
				t.Fatalf("%q is in the LOCKED Enterprise set, got tier %q", f, entitlement.FeatureTier(f))
			}
			community := k.service(t, nil)
			if entitlement.Entitled(community, f) {
				t.Fatalf("Community must not be entitled to %q", f)
			}
			ent := k.service(t, k.issue(t, entitlement.TierEnterprise, []entitlement.Feature{f}, nil))
			if !entitlement.Entitled(ent, f) {
				t.Fatalf("an Enterprise licence granting %q must entitle it", f)
			}
			// And no route claims to implement it — asserting the honest state
			// rather than pretending a gate covers something that is not there.
			src, err := os.ReadFile("main.go")
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(src), "licenceFeature(entitlement."+licFeatureConst(f)) {
				t.Fatalf("%q is gated on a route, so it is no longer 'gate ready, feature absent' — "+
					"move it out of this test and give it a real enforcement test", f)
			}
		})
	}
}

func licFeatureConst(f entitlement.Feature) string {
	switch f {
	case entitlement.FeatureSCIM:
		return "FeatureSCIM"
	case entitlement.FeatureSIEMExport:
		return "FeatureSIEMExport"
	}
	return "Feature" + string(f)
}

// ─────────────────────────────────────────────────────────────────────────────
// The platform-admin Licence route
// ─────────────────────────────────────────────────────────────────────────────

func licAPIServer(t *testing.T, k licTestKey, raw []byte) *server {
	t.Helper()
	dir := t.TempDir()
	roles, err := newRoleStore(filepath.Join(dir, "roles.json"))
	if err != nil {
		t.Fatal(err)
	}
	au, err := newAuditStore(filepath.Join(dir, "audit.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "api", "licence.json")
	if raw != nil {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	st := licence.NewFileStore(path, licence.FileStoreOptions{Verifier: k.v, Poll: time.Nanosecond})
	s := &server{roles: roles, audit: au, discovery: discovery.NewDiscoveryAggregator()}
	s.licenceStore = st
	s.entitlements = licence.NewService(st)
	s.licenceAPI = licence.New(s.licenceDeps())
	return s
}

// TestLicenceRouteGate is the §3a rule-3 assertion, per verb: the gate runs
// BEFORE the body, the WRITES refuse a TENANT admin — who holds full
// administration:admin but must never be able to license the platform — and
// every verb refuses an unauthenticated caller, including an unknown one, whose
// 405 is a fact about this surface that an anonymous caller must not learn.
func TestLicenceRouteGate(t *testing.T) {
	k := newLicTestKey(t)
	s := licAPIServer(t, k, nil)

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method+" refuses a tenant admin", func(t *testing.T) {
			w := httptest.NewRecorder()
			s.licenceAPI.Handle(w, licReq(method, "/api/system/licence", `{"licence_id":"x"}`, licTenantAdminClaims()))
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 — a tenant/org admin holds administration:admin, so a scope-blind gate on a WRITE would hand every tenant the ability to license the whole platform (§3a rule 3)", w.Code)
			}
		})
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method+" refuses an unauthenticated caller", func(t *testing.T) {
			w := httptest.NewRecorder()
			s.licenceAPI.Handle(w, httptest.NewRequest(method, "/api/system/licence", nil))
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
		})
	}
}

// licTenantAdminOfClaims is a tenant admin in an arbitrary tenant. Same shape
// as licTenantAdminClaims — full administration:admin, NOT the platform owner.
func licTenantAdminOfClaims(tenant string) jwtClaims {
	return jwtClaims{Sub: "admin@" + tenant + ".test", Role: rbac.RoleSuperAdmin, Tenant: tenant}
}

// licRead drives the real GET handler and decodes the body.
func licRead(t *testing.T, s *server, c jwtClaims) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	s.licenceAPI.Handle(w, licReq(http.MethodGet, "/api/system/licence", "", c))
	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d %s", w.Code, w.Body.String())
	}
	var v map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// licCeiling pulls one ceiling row out of a view.
func licCeiling(t *testing.T, v map[string]any, name string) map[string]any {
	t.Helper()
	rows, _ := v["ceilings"].([]any)
	for _, r := range rows {
		row, _ := r.(map[string]any)
		if row["name"] == name {
			return row
		}
	}
	t.Fatalf("ceiling %q is missing from the view", name)
	return nil
}

// TestLicenceTenantViewCrossOrgIsolation is the §3a rule-5 isolation test for
// the tenant-readable GET (2026-09-05).
//
// The read is now open to any administration:admin caller, so the isolation is
// no longer "the gate refuses you" — it is the PROJECTION: a tenant admin is
// answered with their own tenant's usage, never the platform's total and never
// another tenant's rows, and with none of the provider's commercial or key
// material. Three tenants in different orgs, one licence file, three different
// answers.
func TestLicenceTenantViewCrossOrgIsolation(t *testing.T) {
	k := newLicTestKey(t)
	s := licAPIServer(t, k, nil)

	// Six devices: three owned by acme, two by globex, one platform-owned
	// (no tenant) — which belongs to the platform and must appear in NOBODY's
	// tenant projection.
	fleet := []models.Device{
		{ID: "acme-1", Name: "acme-1", Address: "10.1.0.1", Source: "manual", TenantID: "acme"},
		{ID: "acme-2", Name: "acme-2", Address: "10.1.0.2", Source: "manual", TenantID: "acme"},
		{ID: "acme-3", Name: "acme-3", Address: "10.1.0.3", Source: "manual", TenantID: "acme"},
		{ID: "globex-1", Name: "globex-1", Address: "10.2.0.1", Source: "manual", TenantID: "globex"},
		{ID: "globex-2", Name: "globex-2", Address: "10.2.0.2", Source: "manual", TenantID: "globex"},
		{ID: "platform-1", Name: "platform-1", Address: "10.3.0.1", Source: "manual"},
	}
	for _, d := range fleet {
		if err := s.discovery.Upsert(d); err != nil {
			t.Fatal(err)
		}
	}

	devicesIn := func(t *testing.T, v map[string]any) float64 {
		t.Helper()
		row := licCeiling(t, v, entitlement.CeilingDevices)
		cur, ok := row["current"].(float64)
		if !ok {
			t.Fatalf("the device ceiling must carry a measured number for a tenant, got %+v", row)
		}
		return cur
	}

	t.Run("each tenant sees only its own devices", func(t *testing.T) {
		acme := licRead(t, s, licTenantAdminOfClaims("acme"))
		if acme["scope"] != licence.ScopeTenant || acme["tenant"] != "acme" {
			t.Fatalf("a tenant admin must get their own tenant projection, got scope=%v tenant=%v", acme["scope"], acme["tenant"])
		}
		if got := devicesIn(t, acme); got != 3 {
			t.Fatalf("acme counts %v devices, want its own 3 — a tenant must never be shown the platform total (6) or another tenant's rows (§3a rule 1)", got)
		}
		globex := licRead(t, s, licTenantAdminOfClaims("globex"))
		if got := devicesIn(t, globex); got != 2 {
			t.Fatalf("globex counts %v devices, want its own 2", got)
		}
		empty := licRead(t, s, licTenantAdminOfClaims("initech"))
		if got := devicesIn(t, empty); got != 0 {
			t.Fatalf("a tenant with no devices counts %v, want 0 — and it must be a MEASURED zero, not another tenant's number", got)
		}
	})

	t.Run("no commercial or key material reaches a tenant", func(t *testing.T) {
		raw := k.issue(t, entitlement.TierTeam, []entitlement.Feature{entitlement.FeatureSecurityFindings}, nil)
		w := httptest.NewRecorder()
		s.licenceAPI.Handle(w, licReq(http.MethodPut, "/api/system/licence", string(raw), licClaims()))
		if w.Code != http.StatusOK {
			t.Fatalf("install = %d %s", w.Code, w.Body.String())
		}
		v := licRead(t, s, licTenantAdminOfClaims("acme"))
		for _, field := range []string{"keys", "path", "verify_hint"} {
			if _, present := v[field]; present {
				t.Fatalf("%q is provider material and must be absent from the tenant projection: %v", field, v[field])
			}
		}
		state, _ := v["state"].(map[string]any)
		// grace_days is deliberately NOT in this list: it is part of the expiry
		// state the tenant needs ("inside a 30-day grace"), not of the
		// provider's commercial identity.
		for _, field := range []string{"customer", "licence_id", "issued_at", "support", "key_id"} {
			if _, present := state[field]; present {
				t.Fatalf("state.%s is the provider's commercial identity and must not reach a tenant: %v", field, state[field])
			}
		}
		// What the tenant DOES need is all there: the tier in force, what it
		// entitles them to, and who to ask to change it.
		if state["tier"] != string(entitlement.TierTeam) {
			t.Fatalf("the tenant must be told the tier in force, got %v", state["tier"])
		}
		if v["managed_by"] != licence.ManagedByProvider || v["managed_by_detail"] == "" {
			t.Fatalf("managed_by must say who may replace the licence, got %v / %v", v["managed_by"], v["managed_by_detail"])
		}
		if v["scope_note"] == "" {
			t.Fatal("the projection must say that the ceilings are the installation's and the usage is only this tenant's")
		}
		entitled := false
		for _, f := range v["features"].([]any) {
			row := f.(map[string]any)
			if row["name"] == string(entitlement.FeatureSecurityFindings) && row["entitled"] == true {
				entitled = true
			}
		}
		if !entitled {
			t.Fatal("the tenant must see the features the installation's licence entitles them to")
		}
	})

	t.Run("as_tenant can only narrow", func(t *testing.T) {
		// A NON-owner carrying an acting-tenant override is still confined to
		// its own tenant: principalTenant ignores ActingTenant for anyone but
		// the platform owner, so this cannot become a cross-org read.
		c := licTenantAdminOfClaims("acme")
		c.ActingTenant = "globex"
		v := licRead(t, s, c)
		if v["tenant"] != "acme" {
			t.Fatalf("a tenant admin selecting another tenant must stay in its own: %v", v["tenant"])
		}
		if got := devicesIn(t, v); got != 3 {
			t.Fatalf("acme still counts its own 3 devices, got %v", got)
		}
		// The platform owner narrowing INTO a tenant gets that tenant's
		// projection — the same narrowing-only rule, applied downward.
		owner := licClaims()
		owner.ActingTenant = "globex"
		nv := licRead(t, s, owner)
		if nv["scope"] != licence.ScopeTenant || nv["tenant"] != "globex" {
			t.Fatalf("the owner scoped into a tenant must see that tenant's projection: scope=%v tenant=%v", nv["scope"], nv["tenant"])
		}
		if got := devicesIn(t, nv); got != 2 {
			t.Fatalf("scoped into globex the owner counts %v devices, want 2", got)
		}
	})

	t.Run("the platform owner keeps the full view", func(t *testing.T) {
		v := licRead(t, s, licClaims())
		if v["scope"] != licence.ScopePlatform {
			t.Fatalf("scope = %v, want platform", v["scope"])
		}
		if keys, _ := v["keys"].([]any); len(keys) == 0 {
			t.Fatal("the provider view still publishes the trusted public keys")
		}
		if v["path"] == "" || v["verify_hint"] == "" {
			t.Fatal("the provider view still carries the licence path and the offline recipe")
		}
		state, _ := v["state"].(map[string]any)
		if state["customer"] == nil || state["licence_id"] == nil {
			t.Fatalf("the provider view still names the customer and the licence: %+v", state)
		}
		// Platform-wide: all six devices, including the platform-owned one that
		// belongs to no tenant.
		if got := devicesIn(t, v); got != 6 {
			t.Fatalf("the platform bar counts every device on the installation, got %v want 6", got)
		}
	})

	t.Run("un-enforced ceilings stay un-numbered in the tenant projection too", func(t *testing.T) {
		v := licRead(t, s, licTenantAdminOfClaims("acme"))
		for _, name := range entitlement.CeilingNames() {
			if entitlement.Enforced(name) {
				continue
			}
			row := licCeiling(t, v, name)
			if row["current"] != nil {
				t.Fatalf("%s is carried but not enforced: it must not show usage as if it bit (%+v)", name, row)
			}
			if row["current_reason"] == "" || row["current_reason"] == nil {
				t.Fatalf("%s shows no number, so it must say why (%+v)", name, row)
			}
		}
	})
}

// TestLicenceRouteLifecycle drives the whole page contract: read Community,
// install a Team licence, read it back, refuse a bad one without losing the
// good one, remove it.
func TestLicenceRouteLifecycle(t *testing.T) {
	k := newLicTestKey(t)
	s := licAPIServer(t, k, nil)

	read := func(t *testing.T) map[string]any {
		t.Helper()
		w := httptest.NewRecorder()
		s.licenceAPI.Handle(w, licReq(http.MethodGet, "/api/system/licence", "", licClaims()))
		if w.Code != http.StatusOK {
			t.Fatalf("GET = %d %s", w.Code, w.Body.String())
		}
		var v map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	t.Run("no licence reads as Community, not an error", func(t *testing.T) {
		v := read(t)
		state := v["state"].(map[string]any)
		if state["source"] != string(licence.SourceCommunity) {
			t.Fatalf("source = %v, want community", state["source"])
		}
		if state["tier"] != string(entitlement.TierCommunity) {
			t.Fatalf("tier = %v", state["tier"])
		}
		if _, bad := state["load_error"]; bad {
			t.Fatal("no licence installed is a supported state, never an error")
		}
		if v["days_to_expiry"] != nil {
			t.Fatal("Community has nothing to expire and must report null, not a number")
		}
		// The page must always be able to hand out the public key and the
		// offline recipe — that is the customer's independent check on us.
		if keys, _ := v["keys"].([]any); len(keys) == 0 {
			t.Fatal("the page must publish the trusted public keys")
		}
		if s, _ := v["verify_hint"].(string); !strings.Contains(s, "correlix-licence verify") {
			t.Fatalf("the offline verification recipe must be on the page: %q", s)
		}
		// The DECIDED policy (owner, 2026-09-05), stated in the product rather
		// than only in a design doc. All three halves must be there: the grace
		// window, what stops after it, and — the part an operator reads first —
		// what does NOT happen to their data.
		if s, _ := v["expiry_semantics"].(string); !strings.Contains(s, "grace period") ||
			!strings.Contains(s, "visible and exportable") || !strings.Contains(s, "nothing is disabled or deleted") {
			t.Fatalf("the page must state the expiry, grace and overage policy: %q", s)
		}
	})

	t.Run("ceilings say which ones actually bite", func(t *testing.T) {
		v := read(t)
		rows, _ := v["ceilings"].([]any)
		if len(rows) != len(entitlement.CeilingNames()) {
			t.Fatalf("every ceiling must appear, got %d", len(rows))
		}
		enforced := 0
		for _, r := range rows {
			row := r.(map[string]any)
			if row["enforced"] == true {
				enforced++
			} else if row["current"] != nil {
				t.Fatalf("an un-enforced ceiling must not show a usage number as if it bit: %v", row)
			}
		}
		if enforced != 2 {
			t.Fatalf("exactly two ceilings are enforced (devices, watched prefixes), page says %d", enforced)
		}
	})

	t.Run("install a Team licence", func(t *testing.T) {
		raw := k.issue(t, entitlement.TierTeam, []entitlement.Feature{entitlement.FeatureSecurityFindings}, nil)
		w := httptest.NewRecorder()
		s.licenceAPI.Handle(w, licReq(http.MethodPut, "/api/system/licence", string(raw), licClaims()))
		if w.Code != http.StatusOK {
			t.Fatalf("PUT = %d %s", w.Code, w.Body.String())
		}
		v := read(t)
		state := v["state"].(map[string]any)
		if state["tier"] != string(entitlement.TierTeam) || state["customer"] != "Test Customer" {
			t.Fatalf("the installed licence must be in force: %v", state)
		}
		// And it took effect on the ENTITLEMENT service, not just the display.
		if !entitlement.Entitled(s.entitlements, entitlement.FeatureSecurityFindings) {
			t.Fatal("installing a Team licence must entitle security findings immediately, with no restart")
		}
	})

	t.Run("a refused upload keeps the working licence", func(t *testing.T) {
		// The property that makes the upload button safe to press.
		stranger := newLicTestKey(t)
		bad := stranger.issue(t, entitlement.TierEnterprise, entitlement.Features(), nil)
		w := httptest.NewRecorder()
		s.licenceAPI.Handle(w, licReq(http.MethodPut, "/api/system/licence", string(bad), licClaims()))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("a licence signed by an untrusted key must be refused, got %d", w.Code)
		}
		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		// The exact reason, verbatim: an operator holding a licence we will not
		// accept needs to know WHY, not "invalid".
		if !strings.Contains(body["error"], "unknown signing key") {
			t.Fatalf("the refusal must name the actual problem: %q", body["error"])
		}
		if s.entitlements.Tier() != entitlement.TierTeam {
			t.Fatalf("a refused upload must not disturb the licence in force, tier is now %q", s.entitlements.Tier())
		}
	})

	t.Run("writes are audited on both outcomes", func(t *testing.T) {
		// A refused platform-global write that was never recorded is
		// indistinguishable from one that never happened.
		var allow, deny int
		events, _ := s.audit.List(TenantGlobal, true, audit.Query{Limit: 200})
		for _, e := range events {
			d, _ := e.Detail["action"].(string)
			if !strings.HasPrefix(d, "licence_") {
				continue
			}
			switch e.Decision {
			case "allow":
				allow++
			case "deny":
				deny++
			}
		}
		if allow == 0 {
			t.Fatal("an accepted licence install must be audited")
		}
		if deny == 0 {
			t.Fatal("a REFUSED licence install must be audited too")
		}
	})

	t.Run("remove returns to Community", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.licenceAPI.Handle(w, licReq(http.MethodDelete, "/api/system/licence", "", licClaims()))
		if w.Code != http.StatusOK {
			t.Fatalf("DELETE = %d %s", w.Code, w.Body.String())
		}
		if s.entitlements.Tier() != entitlement.TierCommunity {
			t.Fatalf("removing the licence returns to Community, got %q", s.entitlements.Tier())
		}
		if entitlement.Entitled(s.entitlements, entitlement.FeatureSecurityFindings) {
			t.Fatal("removing the licence must withdraw its features")
		}
	})
}

// TestLicenceDegradedListsOverCeilingDevices is honest degradation end to end:
// an estate ALREADY over the ceiling is COUNTED and LISTED on the page, not
// pinned at the limit and not disabled behind the operator's back.
//
// This is the shape a downgrade takes — a Team deployment monitoring 35 devices
// whose licence lapses to Community. Nothing is switched off (that would be a
// silent outage caused by a billing event); the page says 35 of 25 and names
// the excess.
func TestLicenceDegradedListsOverCeilingDevices(t *testing.T) {
	k := newLicTestKey(t)
	s := licAPIServer(t, k, nil)
	// Seeded BEFORE the ceiling exists: these devices were already being
	// collected from when the licence changed under them.
	for i := 0; i < 35; i++ {
		dev := models.Device{
			ID: "d" + strconv.Itoa(i), Name: "d" + strconv.Itoa(i),
			Address: "10.5.0." + strconv.Itoa(i), Source: "manual",
		}
		if err := s.discovery.Upsert(dev); err != nil {
			t.Fatal(err)
		}
	}
	s.discovery.SetMonitorGate(func(current int) error {
		return entitlement.CheckCeiling(s.entitlements, entitlement.CeilingDevices, current)
	})
	if got := s.discovery.MonitoredCount(); got != 35 {
		t.Fatalf("monitored = %d, want 35 — an over-ceiling estate must keep running", got)
	}

	w := httptest.NewRecorder()
	s.licenceAPI.Handle(w, licReq(http.MethodGet, "/api/system/licence", "", licClaims()))
	var v struct {
		Ceilings []struct {
			Name    string `json:"name"`
			Current *int   `json:"current"`
			Limit   int    `json:"limit"`
			Over    bool   `json:"over"`
		} `json:"ceilings"`
		Overages []struct {
			Ceiling string `json:"ceiling"`
			Current int    `json:"current"`
			Limit   int    `json:"limit"`
			Over    int    `json:"over"`
			Message string `json:"message"`
		} `json:"overages"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("%v (%s)", err, w.Body.String())
	}
	var devices *int
	for _, c := range v.Ceilings {
		if c.Name == entitlement.CeilingDevices {
			devices = c.Current
			if !c.Over {
				t.Fatal("the devices row must be marked over the ceiling")
			}
		}
	}
	if devices == nil || *devices != 35 {
		t.Fatalf("usage must count the WITHHELD devices too (25 admitted + 10 withheld = 35), got %v — "+
			"reporting 25 of 25 would be technically true and completely dishonest about a 35-device network", devices)
	}
	if len(v.Overages) != 1 || v.Overages[0].Ceiling != entitlement.CeilingDevices {
		t.Fatalf("the over-ceiling devices must be LISTED: %+v", v.Overages)
	}
	if v.Overages[0].Over != 10 {
		t.Fatalf("over = %d, want 10", v.Overages[0].Over)
	}
	if !strings.Contains(v.Overages[0].Message, "nothing has been deleted") {
		t.Fatalf("the message must say nothing was deleted: %q", v.Overages[0].Message)
	}
}

// TestLicenceMetricsAlwaysPresent: both gauges are emitted on EVERY deployment,
// so a vanished series means a scrape failure and never a state change.
func TestLicenceMetricsAlwaysPresent(t *testing.T) {
	k := newLicTestKey(t)
	render := func(t *testing.T, raw []byte) string {
		t.Helper()
		var b strings.Builder
		licence.NewService(k.store(t, raw)).WriteMetrics(&b, time.Now().UTC())
		return b.String()
	}

	t.Run("community", func(t *testing.T) {
		txt := render(t, nil)
		if !strings.Contains(txt, "# TYPE "+licence.MetricDaysToExpiry+" gauge") {
			t.Fatal("a Community deployment must still publish the expiry gauge")
		}
		if !strings.Contains(txt, licence.MetricDaysToExpiry+" 36500") {
			t.Fatalf("no licence must report the no-expiry sentinel, not 0 and not a gap:\n%s", txt)
		}
		if !strings.Contains(txt, `netops_licence_state{tier="community",degraded="false",in_grace="false"} 1`) {
			t.Fatalf("the community state series must be 1:\n%s", txt)
		}
		// Every OTHER combination must be present as 0. A series that vanishes
		// is indistinguishable from a scrape failure, and that ambiguity is
		// what the 2026-09-02 outage was made of.
		if !strings.Contains(txt, `netops_licence_state{tier="enterprise",degraded="false",in_grace="false"} 0`) {
			t.Fatalf("every other combination must be emitted as 0, not omitted:\n%s", txt)
		}
		if n := strings.Count(txt, "netops_licence_state{"); n != len(entitlement.Tiers())*4 {
			t.Fatalf("expected %d state series every scrape, got %d", len(entitlement.Tiers())*4, n)
		}
	})

	t.Run("licensed", func(t *testing.T) {
		txt := render(t, k.issue(t, entitlement.TierTeam, nil, nil))
		if !strings.Contains(txt, `netops_licence_state{tier="team",degraded="false",in_grace="false"} 1`) {
			t.Fatalf("the team state must be 1:\n%s", txt)
		}
		if strings.Contains(txt, licence.MetricDaysToExpiry+" 36500") {
			t.Fatal("an installed licence has a real expiry and must not report the no-licence sentinel")
		}
	})

	t.Run("the metrics handler delegates", func(t *testing.T) {
		// The gauges above are worthless if /metrics never renders them.
		src, err := os.ReadFile("main.go")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), "s.entitlements.WriteMetrics(w,") {
			t.Fatal("handlePromMetrics must delegate to the licence metrics — a gauge nothing scrapes is not a signal")
		}
	})

	t.Run("the alert rules match the emitted vocabulary", func(t *testing.T) {
		// promtool proves the rules fire on synthetic series; this proves the
		// synthetic series are the ones we actually emit. An expression that
		// drifted off the real vocabulary passes its own unit test forever.
		rules, err := os.ReadFile(filepath.Join("..", "config", "rules.yaml"))
		if err != nil {
			t.Skipf("rules.yaml not readable from here: %v", err)
		}
		for _, want := range []string{
			licence.MetricDaysToExpiry,
			`netops_licence_state{in_grace="true"}`,
			`netops_licence_state{degraded="true"}`,
		} {
			if !strings.Contains(string(rules), want) {
				t.Fatalf("rules.yaml does not reference %q", want)
			}
		}
		// And the sentinel must stay far above the expiry threshold, which is
		// what makes the Community exclusion structural.
		if licence.NoExpirySentinel <= 14 {
			t.Fatal("the no-expiry sentinel must stay far above the LicenceExpiringSoon threshold, or a free-tier deployment starts alerting")
		}
	})
}
