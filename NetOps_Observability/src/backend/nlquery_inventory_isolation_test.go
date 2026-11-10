// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// nlquery_inventory_isolation_test.go — §3a for the inventory and lookup
// families (tracker 337 hybrid NLU plan A4): "how many devices can you see"
// counts ONLY the caller's devices (as_tenant / an ActingTenant smuggled into
// a non-owner's claims is ignored; the platform owner's Global view counts
// every tenant's); a name only another tenant has is answered exactly like a
// name nobody has, and is never offered as a candidate.

import (
	"encoding/json"
	"strings"
	"testing"
)

// countFor compiles and executes "how many devices can you see" as c.
func countFor(t *testing.T, s *server, c jwtClaims, path string) float64 {
	t.Helper()
	code, out := nlqAPI(t, s, c, "/api/ai/query/compile"+path, `{"question":"how many devices can you see?"}`)
	if code != 200 || out["ast"] == nil {
		t.Fatalf("compile: %d %v", code, out)
	}
	ast, err := json.Marshal(out["ast"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ast), `"entity_count"`) {
		t.Fatalf("an inventory count must compile to entity_count: %s", ast)
	}
	code, res := nlqAPI(t, s, c, "/api/ai/query/execute"+path, `{"ast":`+string(ast)+`}`)
	if code != 200 {
		t.Fatalf("execute: %d %v", code, res)
	}
	rows, _ := res["result"].(map[string]any)["rows"].([]any)
	if len(rows) != 1 {
		t.Fatalf("one count row expected: %v", res["result"])
	}
	n, _ := rows[0].(map[string]any)["count"].(float64)
	if strings.Contains(nlqJSON(res), "dev-b") && c.Tenant == "t-a" {
		t.Fatalf("tenant A's answer names tenant B's device: %v", res)
	}
	return n
}

func TestInventoryCountIsOwnOnly(t *testing.T) {
	t.Setenv("FEATURE_AI", "true")
	s, a, b := nlqAPIFixture(t)
	if n := countFor(t, s, a, ""); n != 1 {
		t.Fatalf("tenant A sees 1 device, counted %v", n)
	}
	if n := countFor(t, s, b, ""); n != 1 {
		t.Fatalf("tenant B sees 1 device, counted %v", n)
	}
	// as_tenant on the URL and an ActingTenant in a non-owner's claims are
	// both ignored: still only the caller's own device.
	b.ActingTenant = a.Tenant
	if n := countFor(t, s, b, "?as_tenant="+a.Tenant); n != 1 {
		t.Fatalf("as_tenant must be ignored for a non-owner: counted %v", n)
	}
	// The platform owner's Global view is cross-tenant by design.
	owner := jwtClaims{Sub: "owner", Role: "super-admin"}
	if n := countFor(t, s, owner, ""); n != 2 {
		t.Fatalf("the Global view counts every tenant's devices: %v", n)
	}
}

// A name only tenant A has is, for tenant B, exactly a name nobody has: the
// same answer shape, no candidate, no hint that it exists.
func TestNotFoundNeverRevealsAForeignName(t *testing.T) {
	t.Setenv("FEATURE_AI", "true")
	s, a, b := nlqAPIFixture(t)
	_, own := nlqAPI(t, s, a, "/api/ai/query/compile", `{"question":"where is edge-a"}`)
	if own["ast"] == nil || !strings.Contains(nlqJSON(own["ast"]), "device:dev-a") {
		t.Fatalf("tenant A finds its own device: %v", own)
	}
	_, foreign := nlqAPI(t, s, b, "/api/ai/query/compile", `{"question":"where is edge-a"}`)
	_, missing := nlqAPI(t, s, b, "/api/ai/query/compile", `{"question":"where is edge-zz"}`)
	for name, out := range map[string]map[string]any{"foreign": foreign, "missing": missing} {
		if out["ast"] != nil || out["not_found"] == nil || out["did_you_mean"] != nil {
			t.Fatalf("%s: not found, nothing offered: %v", name, out)
		}
		if strings.Contains(nlqJSON(out), "dev-a") {
			t.Fatalf("%s: tenant A's device leaked: %v", name, out)
		}
	}
	if strings.ReplaceAll(nlqJSON(foreign), "edge-a", "X") != strings.ReplaceAll(nlqJSON(missing), "edge-zz", "X") {
		t.Fatalf("foreign and missing must answer identically:\n%v\n%v", foreign, missing)
	}
}
