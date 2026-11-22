// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// probe_paths_signed_test.go — tracker 475 end to end on the api side. A path
// set written into the prober's shared channel by anyone but the prober (here:
// an unsigned file naming tenant A as the owner) must reach NO tenant's
// /api/probe/paths, the seam bootstrap or the path-graph ingest; the prober's
// signed set reaches its owner only (§3a).

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/internal/probercontrol"
)

type fixedProberKey string

func (k fixedProberKey) Value() (string, error) { return string(k), nil }

const proberTestKey = fixedProberKey("api-test-prober-control-key-0123456789abcd")

func proberTestRing() *probercontrol.Keyring {
	return probercontrol.NewKeyring(proberTestKey, time.Now)
}

func TestProbePathsChannelRefusesAForgedSetAndServesTheSignedOne(t *testing.T) {
	srv, s := newTestServerState(t)
	s.remotePaths = newRemotePathStore()
	s.probePaths = probercontrol.NewResultVerifier(proberTestRing(), probercontrol.KindProbePaths,
		collectors.ProbePathsMaxAge, time.Now, func() bool { return false }, nil)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org Sig"})
	if st != 201 {
		t.Fatalf("create org: %d %s", st, b)
	}
	st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant Sig", "org_id": idOf(t, b)})
	if st != 201 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	tenant := idOf(t, b)
	if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "sig-op", "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenant,
	}); st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	op := login(t, srv, "sig-op", "Passw0rd!2345").Token

	file := filepath.Join(t.TempDir(), "probe_paths.json")
	t.Setenv("REDIS_HOST", "")
	t.Setenv("PROBE_PATHS_FILE", file)
	set := []collectors.PathResult{{
		Dst: "198.51.100.9", Method: "icmp", TenantID: tenant, Reached: true, TS: time.Now().UTC(),
		Hops: []collectors.Hop{{TTL: 1, IP: "10.66.0.1"}, {TTL: 2, IP: "198.51.100.9"}},
	}}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}

	read := func() []collectors.PathResult {
		t.Helper()
		st, rb := do(t, srv, "GET", "/api/probe/paths", op, nil)
		if st != 200 {
			t.Fatalf("list: %d %s", st, rb)
		}
		var got []collectors.PathResult
		if err := json.Unmarshal(rb, &got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	// 1) Forged: plain JSON in the shared file, naming the tenant as owner.
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := read(); len(got) != 0 {
		t.Fatalf("an unsigned path set reached the tenant: %+v", got)
	}
	if got, _ := s.seamFetchProbePaths(context.Background()); len(got) != 0 {
		t.Fatalf("an unsigned path set reached the seam bootstrap: %+v", got)
	}
	if s.probePaths.Count(probercontrol.ReasonUnsigned) == 0 {
		t.Fatal("the refusal was not counted")
	}

	// 2) Signed by the prober's key: served, to its owner, attributed.
	sealed, err := collectors.NewPathSealer(proberTestRing())("prober", body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(sealed), 0o600); err != nil {
		t.Fatal(err)
	}
	got := read()
	if len(got) != 1 || got[0].Dst != "198.51.100.9" || got[0].VantageID != "prober" {
		t.Fatalf("the signed path set was not served to its owner: %+v", got)
	}
	// 3) Signed by another key: refused again.
	other := probercontrol.NewKeyring(fixedProberKey("another-key-that-is-not-the-prober-control"), time.Now)
	forged, err := collectors.NewPathSealer(other)("prober", body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := read(); len(got) != 0 {
		t.Fatalf("a set signed with another key reached the tenant: %+v", got)
	}
	if s.probePaths.Count(probercontrol.ReasonBadSignature) == 0 {
		t.Fatal("the bad signature was not counted")
	}
}

// A server with no verifier wired believes no shared path set at all.
func TestProbePathsWithoutAVerifierBelieveNothing(t *testing.T) {
	s := &server{}
	file := filepath.Join(t.TempDir(), "probe_paths.json")
	t.Setenv("REDIS_HOST", "")
	t.Setenv("PROBE_PATHS_FILE", file)
	body, err := json.Marshal([]collectors.PathResult{{Dst: "10.0.0.1", TS: time.Now().UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := collectors.NewPathSealer(proberTestRing())("prober", body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(sealed), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range s.proberSharedPaths(context.Background()) {
		if p.Dst == "10.0.0.1" {
			t.Fatalf("a server with no verifier served a shared path set: %+v", p)
		}
	}
}

// The console-only switch is a real Features spec and cannot be set from the
// environment.
func TestAcceptUnsignedPathsIsConsoleOnly(t *testing.T) {
	t.Setenv(probercontrol.EnvAcceptUnsignedPaths, "true")
	v := newProbePathVerifier(nil)
	if _, why, ok := v.Open("prober", `[{"dst":"10.0.0.1"}]`); ok {
		t.Fatalf("an environment variable turned on unsigned acceptance: %s", why)
	}
}
