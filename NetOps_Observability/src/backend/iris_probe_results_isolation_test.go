// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_probe_results_isolation_test.go — CLAUDE.md §3a rule 5 for Iris's
// synthetic-probe read, get_probe_results (NetClaw ingestion Batch 3).
// org_isolation_test.go is the template; iris_wan_reads_isolation_test.go is
// the sibling.
//
// The adversarial fixture: two tenants that each declare a DNS probe with the
// SAME name, the same kind and the same site, with opposite results, plus an
// ICMP probe whose destination is an address. Every read stays inside the
// caller; the platform's "All tenants" view reads nothing; the platform owner
// narrowed into a tenant reads only that tenant; a non-owner cannot use a
// forged acting tenant to widen; a restricted tenant is unreachable; and no
// address leaves the seam.

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/dem"
)

// probeFixture seeds both tenants' catalogues and run rings on a server built
// by newRestrictedAIFixture (real tenant store, opaque tenant ids).
func probeFixture(t *testing.T) *restrictedAIFixture {
	t.Helper()
	f := newRestrictedAIFixture(t)
	f.s.demTargets = dem.NewFileStore(filepath.Join(t.TempDir(), "dem_targets.json"))
	f.s.demRuns = dem.NewRunStore()
	ctx := context.Background()
	// Recent runs: the run store prunes rings older than its grading window on
	// the wall clock, so a fixed past date would be pruned on the next intake.
	start := time.Now().UTC().Add(-5 * time.Minute)
	seed := func(tenant, name, kind, host, outcome, reason string) {
		tgt, err := f.s.demTargets.Create(ctx, dem.Target{TenantID: tenant, Name: name, Kind: kind, Host: host, Site: "hq", IntervalSec: 60})
		if err != nil {
			t.Fatalf("seed %s/%s: %v", tenant, name, err)
		}
		var runs []dem.WireRun
		for i := 0; i < 3; i++ {
			at := start.Add(time.Duration(i) * time.Minute)
			runs = append(runs, dem.WireRun{
				ID: fmt.Sprintf("%s-%s-%d", tenant, name, i), Tenant: tenant, TargetID: tgt.ID, Kind: kind,
				Vantage: "prober-1", StartedAt: at, EndedAt: at.Add(time.Second),
				Outcome: outcome, FailReason: reason, DurationMs: 20,
			})
		}
		if res := f.s.demRuns.Record(runs); res.Accepted != len(runs) {
			t.Fatalf("seed runs %s/%s: %+v", tenant, name, res)
		}
	}
	// acme: its resolver times out. globex: the SAME-named probe resolves.
	seed(f.acme, "corp-dns", "dns", "intranet.acme.example", dem.RunFailure, "timeout")
	seed(f.acme, "gw-ping", "icmp", "10.9.9.9", dem.RunSuccess, "")
	seed(f.globex, "corp-dns", "dns", "intranet.globex.example", dem.RunSuccess, "")
	return f
}

func probeRead(t *testing.T, s *server, claims jwtClaims, q ai.ProbeQuery) (ai.ProbeResults, bool) {
	t.Helper()
	deps := s.aiTroubleshootDeps(aiTSRequest(claims), claims)
	if deps.ProbeResults == nil {
		return ai.ProbeResults{}, false
	}
	// aiTSPrincipal is deliberately WRONG: the seam must scope by the token.
	res, err := deps.ProbeResults(context.Background(), aiTSPrincipal(), q)
	if err != nil {
		t.Fatalf("ProbeResults: %v", err)
	}
	return res, true
}

func TestIrisProbeResultsStayInsideTheCallersTenant(t *testing.T) {
	f := probeFixture(t)
	for _, tc := range []struct {
		name               string
		claims             jwtClaims
		ownHost, otherHost string
		wantDNS            string
	}{
		{"acme", jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme}, "intranet.acme.example", "intranet.globex.example", "state:dns=timeout"},
		{"globex", jwtClaims{Sub: "g@globex", Role: RoleOperator, Tenant: f.globex}, "intranet.globex.example", "intranet.acme.example", "state:dns=resolving"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, wired := probeRead(t, f.s, tc.claims, ai.ProbeQuery{Kind: "dns"})
			if !wired || !res.Scoped {
				t.Fatalf("the probe read must be wired and scoped for a tenant user: %+v", res)
			}
			if len(res.Probes) != 1 || res.Probes[0].Destination != tc.ownHost {
				t.Fatalf("own DNS probe only: %+v", res.Probes)
			}
			tr := ai.RenderProbeResults(res, ai.ProbeQuery{Kind: "dns"})
			text := fmt.Sprintf("%+v", tr)
			if strings.Contains(text, tc.otherHost) {
				t.Fatalf("TENANT LEAK: the other tenant's probe reached %s: %s", tc.name, text)
			}
			found := false
			for _, s := range tr.Signals {
				if s == tc.wantDNS {
					found = true
				}
			}
			if !found {
				t.Fatalf("the facts must come from the caller's OWN runs (%s): %v", tc.wantDNS, tr.Signals)
			}
		})
	}
}

// A forged acting tenant on a NON-owner token never widens its reach.
func TestIrisProbeResultsIgnoreActingTenantForANonOwner(t *testing.T) {
	f := probeFixture(t)
	forged := jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme, ActingTenant: f.globex}
	res, wired := probeRead(t, f.s, forged, ai.ProbeQuery{})
	if !wired {
		t.Fatal("the read must be wired for a tenant user")
	}
	for _, p := range res.Probes {
		if strings.Contains(p.Destination, "globex") {
			t.Fatalf("TENANT LEAK: a forged acting tenant reached globex: %+v", p)
		}
	}
	if res.Configured != 2 {
		t.Fatalf("acme's own two probes: %+v", res)
	}
}

// The platform owner's "All tenants" view reads nothing (probes are per
// workspace, as the DEM API itself refuses a cross-tenant read); narrowed into
// one tenant it reads exactly that tenant.
func TestIrisProbeResultsPlatformScopes(t *testing.T) {
	f := probeFixture(t)
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	res, wired := probeRead(t, f.s, owner, ai.ProbeQuery{})
	if !wired {
		t.Fatal("the read must be wired for the owner (it then answers per workspace)")
	}
	if res.Scoped || len(res.Probes) != 0 || res.Configured != 0 {
		t.Fatalf("the All-tenants view must read nothing: %+v", res)
	}
	tr := ai.RenderProbeResults(res, ai.ProbeQuery{})
	if len(tr.Items) != 0 || len(tr.Signals) != 0 || !strings.Contains(strings.Join(tr.Notes, " "), "read per workspace") {
		t.Fatalf("unscoped answer: %+v", tr)
	}

	provider := ownerActing(owner, TenantGlobal)
	if res, _ := probeRead(t, f.s, provider, ai.ProbeQuery{}); res.Scoped || len(res.Probes) != 0 {
		t.Fatalf("the Provider scope owns no customer probes: %+v", res)
	}

	intoGlobex := ownerActing(owner, f.globex)
	res, _ = probeRead(t, f.s, intoGlobex, ai.ProbeQuery{})
	if !res.Scoped || res.Configured != 1 || len(res.Probes) != 1 || !strings.Contains(res.Probes[0].Destination, "globex") {
		t.Fatalf("owner narrowed into globex must read globex only: %+v", res)
	}
}

// An operator-restricted tenant is unreachable for the platform owner.
func TestIrisProbeResultsHonourTheOperatorRestriction(t *testing.T) {
	f := probeFixture(t)
	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	if res, wired := probeRead(t, f.s, ownerActing(owner, f.acme), ai.ProbeQuery{}); wired && (res.Scoped || len(res.Probes) > 0) {
		t.Fatalf("RESTRICTION LEAK: the owner read acme's probes: %+v", res)
	}
	// acme's own operator is never restricted from its own data.
	own := jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme}
	if res, wired := probeRead(t, f.s, own, ai.ProbeQuery{}); !wired || res.Configured != 2 {
		t.Fatalf("acme's own operator must still read acme's probes: %+v", res)
	}
}

// §15: a probe whose destination is an address never shows it.
func TestIrisProbeResultsHideAddresses(t *testing.T) {
	f := probeFixture(t)
	acme := jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme}
	res, _ := probeRead(t, f.s, acme, ai.ProbeQuery{Kind: "icmp"})
	if len(res.Probes) != 1 || res.Probes[0].Destination != "" {
		t.Fatalf("the ICMP probe's address must be withheld: %+v", res.Probes)
	}
	text := fmt.Sprintf("%+v", ai.RenderProbeResults(res, ai.ProbeQuery{Kind: "icmp"}))
	if strings.Contains(text, "10.9.9.9") {
		t.Fatalf("ADDRESS LEAK: %s", text)
	}
	if !strings.Contains(text, "checks an address") {
		t.Fatalf("the probe must say it checks an address: %s", text)
	}
}
