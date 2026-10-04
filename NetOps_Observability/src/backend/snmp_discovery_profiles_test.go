// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"netops/backend/collectors"
	"netops/backend/internal/discovery"
	"netops/backend/internal/snmpcred"
	"netops/backend/internal/vault"
	"netops/backend/models"
)

// snmp_discovery_profiles_test.go — owner decisions (a)/(b), 2026-10-04: SNMP
// credentials live in ONE place (the SNMP profiles). The subnet sweep tries the
// platform-owned profiles in a deterministic order per host, binds each found
// device to the profile that answered, never uses a tenant's profile, and a
// community stored by an older build is migrated once into a sealed profile.

func profileStore(t *testing.T, v *vault.Vault, seed ...snmpcred.Credential) (*snmpcred.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "snmp.json")
	cs, err := snmpcred.NewStore(path, v, platformKV{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range seed {
		if _, err := cs.Upsert(c); err != nil {
			t.Fatal(err)
		}
	}
	return cs, path
}

func testVault(t *testing.T) *vault.Vault {
	t.Helper()
	v, err := vault.NewWithProvider(context.Background(), &memSealing{}, &memVaultStore{data: map[string][]byte{}}, func(string, string, map[string]any) {})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// probeKey identifies which credential a probe was made with.
func probeKey(tg collectors.Target) string {
	if tg.SNMPVersion == 3 {
		return "v3:" + tg.V3User
	}
	return "v2c:" + tg.Community
}

func TestScanTriesProfilesInNameOrderAndBindsTheAnsweringOne(t *testing.T) {
	cs, _ := profileStore(t, nil,
		snmpcred.Credential{ID: "zz-last", Name: "Zulu v2c", Version: "v2c", Community: "zulu"},
		snmpcred.Credential{ID: "aa-v3", Name: "alpha v3", Version: "v3", SecurityName: "mon", SecurityLevel: "authPriv", AuthProtocol: "SHA", AuthKey: "ak", PrivProtocol: "AES128", PrivKey: "pk"},
		snmpcred.Credential{ID: "mm-mid", Name: "Mike v2c", Version: "v2c", Community: "mike"},
		// A tenant's profile must NEVER be sprayed at platform-scanned hosts —
		// even though it sorts first by name and this host would answer it.
		snmpcred.Credential{ID: "acme-ro", Name: "Aardvark tenant", Version: "v2c", Community: "acme-secret", TenantID: "acme"},
		snmpcred.Credential{ID: "acme-global", Name: "Aaa global-tenant", Version: "v2c", Community: "global-secret", TenantID: "global"},
	)
	store := newDiscoveryConfigStore(filepath.Join(t.TempDir(), "disc.json"), nil)
	if _, err := store.set(discoveryScanConfig{Enabled: true, Ranges: []string{"10.20.0.0/30"}}); err != nil {
		t.Fatal(err)
	}
	src := newSNMPSourceFromStore(store, func() *snmpcred.Store { return cs }, nil)

	tried := map[string][]string{}
	var mu sync.Mutex // probes run on the sweep's worker pool
	src.SetProbeForTest(func(_ context.Context, tg collectors.Target) (string, string, string, bool) {
		mu.Lock()
		tried[tg.Address] = append(tried[tg.Address], probeKey(tg))
		mu.Unlock()
		switch {
		case tg.Address == "10.20.0.1" && tg.Community == "mike":
			return "edge-1", "cisco", "", true
		case tg.Address == "10.20.0.2" && tg.SNMPVersion == 3 && tg.V3User == "mon" && tg.V3PrivKey == "pk":
			return "core-1", "juniper", "", true
		case tg.Community == "acme-secret":
			return "leak", "", "", true
		}
		return "", "", "", false
	})
	devs, err := src.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	// Deterministic order: platform profiles by name ("Aaa global-tenant" is
	// platform-owned via the global tenant), case-insensitive.
	wantOrder := []string{"v2c:global-secret", "v3:mon", "v2c:mike", "v2c:zulu"}
	if got := tried["10.20.0.1"]; strings.Join(got, ",") != strings.Join(wantOrder[:3], ",") {
		t.Fatalf("host .1 tried %v, want %v (stop at the first answer)", got, wantOrder[:3])
	}
	if got := tried["10.20.0.2"]; strings.Join(got, ",") != strings.Join(wantOrder[:2], ",") {
		t.Fatalf("host .2 tried %v, want %v", got, wantOrder[:2])
	}
	for addr, keys := range tried {
		for _, k := range keys {
			if k == "v2c:acme-secret" {
				t.Fatalf("tenant profile used to scan platform host %s", addr)
			}
		}
	}
	bound := map[string]string{}
	for _, d := range devs {
		bound[d.Address] = d.CredentialRef
		if d.TenantID != "" {
			t.Fatalf("scan device must stay platform-owned: %+v", d)
		}
	}
	if bound["10.20.0.1"] != "mm-mid" || bound["10.20.0.2"] != "aa-v3" || len(devs) != 2 {
		t.Fatalf("devices must be bound to the profile that answered, got %v (%d devs)", bound, len(devs))
	}

	// Polling then uses exactly what discovery proved.
	for _, d := range devs {
		tgt := snmpcred.TargetFor(d, cs, nil)
		switch d.Address {
		case "10.20.0.1":
			if tgt.Community != "mike" {
				t.Fatalf("poll target for .1 = %+v", tgt)
			}
		case "10.20.0.2":
			if tgt.SNMPVersion != 3 || tgt.V3User != "mon" {
				t.Fatalf("poll target for .2 = %+v", tgt)
			}
		}
	}
}

func TestScanWithNoProfilesRefusesLoudlyAndNeverGuessesPublic(t *testing.T) {
	t.Setenv("SNMP_COMMUNITY", "public")
	// Only a TENANT profile exists: the sweep has nothing it may use.
	cs, _ := profileStore(t, nil, snmpcred.Credential{ID: "acme-ro", Name: "acme", Version: "v2c", Community: "x", TenantID: "acme"})
	store := newDiscoveryConfigStore(filepath.Join(t.TempDir(), "disc.json"), nil)
	if _, err := store.set(discoveryScanConfig{Enabled: true, Ranges: []string{"10.20.0.0/30"}}); err != nil {
		t.Fatal(err)
	}
	for _, creds := range []*snmpcred.Store{nil, cs} {
		src := newSNMPSourceFromStore(store, func() *snmpcred.Store { return creds }, nil)
		src.SetProbeForTest(func(context.Context, collectors.Target) (string, string, string, bool) {
			t.Fatal("no eligible profile → no probe at all")
			return "", "", "", false
		})
		_, err := src.Poll(context.Background())
		if !errors.Is(err, discovery.ErrNoScanCredentials) || !strings.Contains(err.Error(), "SNMP Profiles") {
			t.Fatalf("want a refusal naming SNMP Profiles, got %v", err)
		}
	}
}

func TestScanCredentialsMatchPollerMapping(t *testing.T) {
	cs, _ := profileStore(t, nil,
		snmpcred.Credential{ID: "b", Name: "b", Version: "v1", Community: "c1"},
		snmpcred.Credential{ID: "a", Name: "a", Version: "v3", SecurityName: "u", SecurityLevel: "noAuthNoPriv", Context: "ctx"},
		snmpcred.Credential{ID: "t", Name: "0-first", Version: "v2c", Community: "tenant", TenantID: "acme"},
	)
	got := scanCredentials(cs)
	if len(got) != 2 || got[0].ProfileID != "a" || got[1].ProfileID != "b" {
		t.Fatalf("scan credentials = %+v", got)
	}
	if got[0].Target.SNMPVersion != 3 || got[0].Target.V3User != "u" || got[0].Target.V3Context != "ctx" {
		t.Fatalf("v3 profile not mapped like the pollers: %+v", got[0].Target)
	}
	if got[1].Target.Community != "c1" || got[1].Target.SNMPVersion != 0 {
		t.Fatalf("v1 profile not mapped like the pollers: %+v", got[1].Target)
	}
	if sum := scanProfileSummary(cs); sum["total"] != 2 || sum["v3"] != 1 || sum["v2c"] != 1 {
		t.Fatalf("summary = %v", sum)
	}
	if sum := scanProfileSummary(nil); sum["total"] != 0 {
		t.Fatalf("nil store summary = %v", sum)
	}
}

// writeLegacyDiscoveryConfig writes the at-rest shape an older build produced:
// the community sealed under the discovery field id.
func writeLegacyDiscoveryConfig(t *testing.T, path string, v *vault.Vault, community string) {
	t.Helper()
	sealed, err := sealFn(v)("", fieldDiscoveryComm, community)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(map[string]any{
		"enabled": true, "ranges": []string{"10.20.0.0/24"}, "community": sealed, "interval_sec": 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyDiscoveryCommunityMigratesOnceIntoSealedProfile(t *testing.T) {
	logs := captureLogs(t)
	v := testVault(t)
	dir := t.TempDir()
	discPath := filepath.Join(dir, "disc.json")
	writeLegacyDiscoveryConfig(t, discPath, v, "corp-ro-s3cret")
	cs, credPath := profileStore(t, v)

	st := newDiscoveryConfigStore(discPath, v)
	if err := st.unavailable(); err != nil {
		t.Fatalf("legacy config must load: %v", err)
	}
	// Run twice (and once more on a fresh boot): still exactly one profile.
	for i := 0; i < 2; i++ {
		if err := st.migrateLegacyCommunity(cs); err != nil {
			t.Fatalf("migrate #%d: %v", i, err)
		}
	}
	st2 := newDiscoveryConfigStore(discPath, v)
	if err := st2.migrateLegacyCommunity(cs); err != nil {
		t.Fatal(err)
	}

	all := cs.ResolveAll()
	if len(all) != 1 {
		t.Fatalf("want exactly one migrated profile, got %d: %+v", len(all), all)
	}
	p := all[0]
	if p.Name != migratedCommunityProfileName || p.Version != "v2c" || p.Community != "corp-ro-s3cret" || !snmpcred.PlatformOwned(p.TenantID) {
		t.Fatalf("migrated profile wrong: name=%q version=%q tenant=%q", p.Name, p.Version, p.TenantID)
	}
	// Sealed at rest like every other profile secret.
	raw, err := os.ReadFile(credPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "corp-ro-s3cret") || !strings.Contains(string(raw), vault.VersionPrefix) {
		t.Fatalf("migrated community must be sealed at rest:\n%s", raw)
	}
	// The discovery config no longer carries a community, and kept its scope.
	draw, err := os.ReadFile(discPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(draw), "community") {
		t.Fatalf("discovery config still carries a community after migration: %s", draw)
	}
	if eff := st2.effective(); !eff.Enabled || len(eff.Ranges) != 1 || eff.IntervalSec != 300 {
		t.Fatalf("migration must keep the scan scope: %+v", eff)
	}
	// Logged exactly once, by profile name, never the secret.
	var n int
	for _, l := range logs() {
		if strings.Contains(l.msg, "corp-ro-s3cret") {
			t.Fatalf("secret in log message: %+v", l)
		}
		b, _ := json.Marshal(l.fields)
		if strings.Contains(string(b), "corp-ro-s3cret") {
			t.Fatalf("secret in log fields: %s", b)
		}
		if l.component == "discovery" && strings.Contains(l.msg, "migrated to SNMP profile") {
			n++
			if !strings.Contains(string(b), migratedCommunityProfileName) {
				t.Fatalf("migration log must name the profile: %s", b)
			}
		}
	}
	if n != 1 {
		t.Fatalf("want exactly one migration log line, got %d", n)
	}
}

func TestLegacyCommunityListMigratesToOrderedProfilesWithoutClobbering(t *testing.T) {
	v := testVault(t)
	discPath := filepath.Join(t.TempDir(), "disc.json")
	writeLegacyDiscoveryConfig(t, discPath, v, "arista-ro, cisco-ro")
	// An operator profile already holds the base name with a DIFFERENT secret:
	// it must never be overwritten.
	cs, _ := profileStore(t, v, snmpcred.Credential{Name: migratedCommunityProfileName, Version: "v2c", Community: "operator-own"})
	st := newDiscoveryConfigStore(discPath, v)
	if err := st.migrateLegacyCommunity(cs); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range cs.ResolveAll() {
		got[c.Name] = c.Community
	}
	want := map[string]string{
		migratedCommunityProfileName:        "operator-own",
		migratedCommunityProfileName + " 2": "arista-ro",
		migratedCommunityProfileName + " 3": "cisco-ro",
	}
	if len(got) != len(want) {
		t.Fatalf("profiles = %v, want %v", got, want)
	}
	for k, w := range want {
		if got[k] != w {
			t.Fatalf("profile %q = %q, want %q (all: %v)", k, got[k], w, got)
		}
	}
}

func TestLegacyCommunitySurvivesSaveBeforeMigration(t *testing.T) {
	v := testVault(t)
	discPath := filepath.Join(t.TempDir(), "disc.json")
	writeLegacyDiscoveryConfig(t, discPath, v, "keep-me")
	st := newDiscoveryConfigStore(discPath, v)
	// An operator save that lands before the migration succeeded must not
	// drop the not-yet-migrated community (it would be silently lost).
	if _, err := st.set(discoveryScanConfig{Enabled: false, Ranges: []string{"10.30.0.0/24"}}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(discPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "keep-me") {
		t.Fatalf("legacy community must stay sealed on disk: %s", raw)
	}
	cs, _ := profileStore(t, v)
	if err := newDiscoveryConfigStore(discPath, v).migrateLegacyCommunity(cs); err != nil {
		t.Fatal(err)
	}
	if c, ok := cs.ResolveFor(migratedCommunityProfileName, ""); !ok || c.Community != "keep-me" {
		t.Fatalf("community lost across a pre-migration save: %+v ok=%v", c, ok)
	}
}

func TestDiscoveryConfigPutRefusesCommunity(t *testing.T) {
	srv, s := newTestServerState(t)
	s.discoveryCfg = newDiscoveryConfigStore(t.TempDir()+"/disc.json", nil)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	st, b := do(t, srv, "PUT", "/api/discovery/config", admin, map[string]any{
		"enabled": true, "ranges": []string{"10.20.0.0/24"}, "community": "public",
	})
	if st != 400 || !strings.Contains(string(b), "SNMP Profiles") {
		t.Fatalf("a community in the body must be refused 400 pointing at SNMP Profiles, got %d %s", st, b)
	}
	if eff := s.discoveryCfg.effective(); eff.Enabled {
		t.Fatal("a refused PUT must not have saved anything")
	}
	// An empty community (an old client's blank field) is not a credential.
	if st, b = do(t, srv, "PUT", "/api/discovery/config", admin, map[string]any{
		"enabled": true, "ranges": []string{"10.20.0.0/24"}, "community": "",
	}); st != 200 {
		t.Fatalf("blank community should be ignored, got %d %s", st, b)
	}
}

// TestDiscoveryConfigGetShowsProfilesAndBindings — GET reports what the sweep
// will try (platform profiles only; tenant profiles are not counted, never
// named) and which profile each found device answered with.
func TestDiscoveryConfigGetShowsProfilesAndBindings(t *testing.T) {
	srv, s := newTestServerState(t)
	s.discoveryCfg = newDiscoveryConfigStore(t.TempDir()+"/disc.json", nil)
	for _, c := range []snmpcred.Credential{
		{ID: "plat-v2c", Name: "plat v2c", Version: "v2c", Community: "pc"},
		{ID: "plat-v3", Name: "plat v3", Version: "v3", SecurityName: "u", SecurityLevel: "noAuthNoPriv"},
		{ID: "tenant-secret-profile", Name: "tenant", Version: "v2c", Community: "tc", TenantID: "acme"},
	} {
		if _, err := s.snmpCreds.Upsert(c); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.discoveryCfg.set(discoveryScanConfig{Enabled: true, Ranges: []string{"10.20.0.0/30"}}); err != nil {
		t.Fatal(err)
	}
	src := newSNMPSourceFromStore(s.discoveryCfg, func() *snmpcred.Store { return s.snmpCreds }, nil)
	src.SetProbeForTest(func(_ context.Context, tg collectors.Target) (string, string, string, bool) {
		if tg.Address == "10.20.0.1" && tg.SNMPVersion == 3 {
			return "r1", "cisco", "", true
		}
		return "", "", "", false
	})
	s.discovery.PollOnceForTest(context.Background(), src)

	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	st, b := do(t, srv, "GET", "/api/discovery/config", admin, nil)
	if st != 200 {
		t.Fatalf("GET: %d %s", st, b)
	}
	var body struct {
		ScanProfiles map[string]int `json:"scan_profiles"`
		Found        []struct {
			Address       string `json:"address"`
			CredentialRef string `json:"credential_ref"`
		} `json:"found"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatal(err)
	}
	if body.ScanProfiles["total"] != 2 || body.ScanProfiles["v3"] != 1 || body.ScanProfiles["v2c"] != 1 {
		t.Fatalf("scan_profiles = %v (tenant profiles must not count)", body.ScanProfiles)
	}
	if len(body.Found) != 1 || body.Found[0].Address != "10.20.0.1" || body.Found[0].CredentialRef != "plat-v3" {
		t.Fatalf("found = %+v", body.Found)
	}
	for _, leak := range []string{"pc", "tc", "tenant-secret-profile"} {
		if strings.Contains(string(b), `"`+leak+`"`) {
			t.Fatalf("GET leaked %q: %s", leak, b)
		}
	}
}

// TestSNMPProfilesNeverCrossTenantsForScanOrPoll — §3a, end to end: the scan
// never uses a tenant's profile, polling never threads one tenant's profile to
// another tenant's device, and the profile API keeps cross-tenant ids 404.
func TestSNMPProfilesNeverCrossTenantsForScanOrPoll(t *testing.T) {
	s := snmpTenantServer(t) // acme-v2c (tenant acme) + platform-v2c
	if _, err := s.snmpCreds.Upsert(snmpcred.Credential{ID: "globex-v2c", Name: "globex-v2c", TenantID: "globex", Version: "v2c", Community: "globex-pw"}); err != nil {
		t.Fatal(err)
	}

	// Scan: only the platform profile is eligible.
	for _, c := range scanCredentials(s.snmpCreds) {
		if c.ProfileID != "platform-v2c" {
			t.Fatalf("scan would use non-platform profile %q", c.ProfileID)
		}
	}

	// Poll: globex's device can never be polled with acme's secret.
	for _, ref := range []string{"acme-v2c", "ACME-V2C"} {
		tgt := snmpcred.TargetFor(models.Device{ID: "g", Address: "10.0.0.5", TenantID: "globex", CredentialRef: ref}, s.snmpCreds, nil)
		if tgt.Community == "s3cret" {
			t.Fatalf("acme secret used for a globex device via ref %q", ref)
		}
	}
	if tgt := snmpcred.TargetFor(models.Device{ID: "a", Address: "10.0.0.6", TenantID: "acme", CredentialRef: "acme-v2c"}, s.snmpCreds, nil); tgt.Community != "s3cret" {
		t.Fatalf("own-tenant profile must apply: %+v", tgt)
	}

	// Sentinel: a globex device bound (by a hostile/edited ref) to acme's
	// profile is treated as unbound; acme's secret is never probed at it.
	ov, err := newCredOverrideStore(filepath.Join(t.TempDir(), "ov.json"))
	if err != nil {
		t.Fatal(err)
	}
	sent := snmpcred.NewSentinel(ov, s.snmpCreds, nil, 0, 0)
	sent.SetProbeForTest(func(_ context.Context, tg collectors.Target) error {
		if tg.Community == "s3cret" {
			t.Fatal("sentinel probed a globex device with acme's secret")
		}
		return context.DeadlineExceeded
	})
	sent.CheckDevice(context.Background(), models.Device{ID: "g", Address: "10.0.0.5", TenantID: "globex", CredentialRef: "acme-v2c"})

	// API: acme cannot read, overwrite or delete globex's profile (404).
	acme := jwtClaims{Sub: "a@acme", Role: RoleSuperAdmin, Tenant: "acme"}
	for _, m := range []string{"PUT", "DELETE"} {
		w := httptest.NewRecorder()
		s.handleSNMPCredByID(w, req(m, "/api/snmp/credentials/globex-v2c", `{"name":"globex-v2c","version":"v2c","community":"x"}`, acme))
		if w.Code != 404 {
			t.Fatalf("%s cross-tenant profile: want 404, got %d", m, w.Code)
		}
	}
	if c, ok := s.snmpCreds.Resolve("globex-v2c"); !ok || c.Community != "globex-pw" {
		t.Fatal("cross-tenant write must not have changed the profile")
	}
}
