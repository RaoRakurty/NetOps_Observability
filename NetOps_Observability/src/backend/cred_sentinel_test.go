// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"netops/backend/internal/snmpcred"
	"path/filepath"
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"
)

// cred_sentinel_test.go — the credential sentinel's definition of done:
// a device whose bound profile stops answering is stickily re-bound to the
// stored profile that DOES answer (vendor-agnostic self-healing), intent is
// restored when the bound profile recovers, candidates never cross tenants,
// and failed sweeps are rate-limited.

func sentinelFixture(t *testing.T) (*credSentinel, *credOverrideStore, *snmpcred.Store) {
	t.Helper()
	dir := t.TempDir()
	ov, err := newCredOverrideStore(filepath.Join(dir, "overrides.json"))
	if err != nil {
		t.Fatal(err)
	}
	creds, err := snmpcred.NewStore(filepath.Join(dir, "creds.json"), nil, platformKV{})
	if err != nil {
		t.Fatal(err)
	}
	seed := []snmpcred.Credential{
		{ID: "vendor-v3", Name: "Vendor v3", Version: "v3", SecurityName: "mon", SecurityLevel: "authPriv", AuthProtocol: "SHA", AuthKey: "k1", PrivProtocol: "AES128", PrivKey: "k2"},
		{ID: "vendor-v2c", Name: "Vendor v2c", Version: "v2c", Community: "vendor-public"},
		{ID: "other-tenant-v2c", Name: "Other tenant", Version: "v2c", Community: "other", TenantID: "t_other"},
	}
	for _, c := range seed {
		if _, err := creds.Upsert(c); err != nil {
			t.Fatal(err)
		}
	}
	cs := snmpcred.NewSentinel(ov, creds, nil, time.Minute, 0) // zero cooldown: tests drive sweeps directly
	return cs, ov, creds
}

func dev(id, ref string) models.Device {
	return models.Device{ID: id, Name: id, Address: "192.0.2.10", PreferredProtocol: "snmp", CredentialRef: ref}
}

// answersOnly returns a probe that succeeds only for the given community/v3 user.
func answersOnly(community string) func(context.Context, collectors.Target) error {
	return func(_ context.Context, tg collectors.Target) error {
		if tg.SNMPVersion != 3 && tg.Community == community {
			return nil
		}
		return context.DeadlineExceeded
	}
}

func TestSentinelAdoptsWorkingProfileWhenBoundFails(t *testing.T) {
	cs, ov, _ := sentinelFixture(t)
	// Device bound to v3, but only v2c "vendor-public" answers (the IOS-XE
	// lost-v3-user / FortiGate-v2c-only class).
	cs.SetProbeForTest(answersOnly("vendor-public"))
	cs.CheckDevice(context.Background(), dev("dmz-fw", "vendor-v3"))

	o, ok := ov.Get("dmz-fw")
	if !ok || o.ProfileID != "vendor-v2c" || o.BoundRef != "vendor-v3" {
		t.Fatalf("expected sticky override to vendor-v2c, got %+v (ok=%v)", o, ok)
	}
}

func TestSentinelRestoresIntentWhenBoundRecovers(t *testing.T) {
	cs, ov, _ := sentinelFixture(t)
	ov.Set(credOverride{DeviceID: "dmz-fw", ProfileID: "vendor-v2c", BoundRef: "vendor-v3", Since: time.Now()})
	// Now EVERYTHING answers (device re-configured to v3 as intended).
	cs.SetProbeForTest(func(context.Context, collectors.Target) error { return nil })
	cs.CheckDevice(context.Background(), dev("dmz-fw", "vendor-v3"))

	if _, ok := ov.Get("dmz-fw"); ok {
		t.Fatal("bound profile recovered — override must be cleared (intent wins)")
	}
}

func TestSentinelNeverCrossesTenants(t *testing.T) {
	cs, ov, _ := sentinelFixture(t)
	// Global device; ONLY the other tenant's community answers. Default-closed:
	// the sentinel must NOT adopt a cross-tenant profile.
	cs.SetProbeForTest(answersOnly("other"))
	cs.CheckDevice(context.Background(), dev("dmz-fw", "vendor-v3"))

	if o, ok := ov.Get("dmz-fw"); ok {
		t.Fatalf("cross-tenant profile adopted: %+v — §3a violation", o)
	}
}

func TestSentinelCooldownRateLimitsSweeps(t *testing.T) {
	_, ov, creds := sentinelFixture(t)
	cs := snmpcred.NewSentinel(ov, creds, nil, time.Minute, time.Hour)
	calls := 0
	cs.SetProbeForTest(func(_ context.Context, tg collectors.Target) error {
		calls++
		return context.DeadlineExceeded // nothing ever answers
	})
	d := dev("dead-device", "vendor-v3")
	cs.CheckDevice(context.Background(), d)
	first := calls
	cs.CheckDevice(context.Background(), d) // within cooldown: 1 active probe only, no sweep
	if calls-first > 1 {
		t.Fatalf("sweep ran during cooldown: %d probes after first pass (want ≤1)", calls-first)
	}
	if _, ok := ov.Get("dead-device"); ok {
		t.Fatal("no profile answers — no override may be recorded")
	}
}

func TestSentinelClearsStaleOverrideWhenProfileDeleted(t *testing.T) {
	cs, ov, creds := sentinelFixture(t)
	ov.Set(credOverride{DeviceID: "dmz-fw", ProfileID: "vendor-v2c", BoundRef: "vendor-v3", Since: time.Now()})
	if err := creds.Delete("vendor-v2c"); err != nil {
		t.Fatal(err)
	}
	cs.SetProbeForTest(answersOnly("nothing-answers"))
	cs.CheckDevice(context.Background(), dev("dmz-fw", "vendor-v3"))
	if o, ok := ov.Get("dmz-fw"); ok && o.ProfileID == "vendor-v2c" {
		t.Fatal("override still references a deleted profile")
	}
}

func TestOverrideStorePersistsAcrossReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overrides.json")
	s1, err := newCredOverrideStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s1.Set(credOverride{DeviceID: "d1", ProfileID: "p1", BoundRef: "b1", Since: time.Now()})
	s2, err := newCredOverrideStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if o, ok := s2.Get("d1"); !ok || o.ProfileID != "p1" {
		t.Fatalf("override not persisted: %+v ok=%v", o, ok)
	}
}

func TestTargetBuilderHonorsOverride(t *testing.T) {
	// applyCredToTarget is the single mapping both the builder and sentinel use.
	var tgt collectors.Target
	snmpcred.ApplyCredToTarget(&tgt, snmpcred.Credential{ID: "x", Version: "v3", SecurityName: "u", SecurityLevel: "authPriv", AuthProtocol: "SHA", AuthKey: "a", PrivProtocol: "AES128", PrivKey: "p"})
	if tgt.SNMPVersion != 3 || tgt.V3User != "u" || tgt.V3PrivKey != "p" {
		t.Fatalf("v3 mapping wrong: %+v", tgt)
	}
	snmpcred.ApplyCredToTarget(&tgt, snmpcred.Credential{ID: "y", Version: "v2c", Community: "c"})
	if tgt.SNMPVersion != 0 || tgt.Community != "c" {
		t.Fatalf("v2c mapping must reset v3 state: %+v", tgt)
	}
}

func TestSentinelBindsFreshDiscoveryDevice(t *testing.T) {
	cs, ov, _ := sentinelFixture(t)
	d := dev("new-switch", "") // discovered device — no bound profile
	// Default community fails; the stored vendor-v2c profile answers.
	cs.SetProbeForTest(answersOnly("vendor-public"))
	cs.CheckDevice(context.Background(), d)
	if o, ok := ov.Get("new-switch"); !ok || o.ProfileID != "vendor-v2c" || o.BoundRef != "" {
		t.Fatalf("fresh device must bind to the answering profile, got %+v ok=%v", o, ok)
	}

	// A device the poller's DEFAULT community already reaches is left alone.
	cs2, ov2, _ := sentinelFixture(t)
	cs2.SetProbeForTest(answersOnly("")) // only the bare default target (no community set) answers
	cs2.CheckDevice(context.Background(), dev("plain-device", ""))
	if _, ok := ov2.Get("plain-device"); ok {
		t.Fatal("default-community device must not get an override")
	}
}
