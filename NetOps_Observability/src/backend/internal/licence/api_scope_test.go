package licence_test

// api_scope_test.go — the READ SPLIT at the module's own boundary.
//
// licence_routes_test.go proves the WIRING (which platform gate is bound to
// which verb, and that a tenant admin's projection counts only that tenant's
// devices). This file proves the MODULE's half of the contract, with no server
// and no signing key:
//
//   1. the verb picks the gate — a write never consults the read gate, and the
//      read gate never decides a write;
//   2. the scope picks the payload — cross-tenant gets the provider view,
//      anyone else gets their own tenant's projection;
//   3. the projection drops the provider's commercial identity and key material
//      BY CONSTRUCTION, and carries what a tenant needs instead;
//   4. an unwired ReadGate is fail-closed: the route stays exactly what it was.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"netops/backend/internal/entitlement"
	"netops/backend/internal/licence"
)

// scopeAPI builds an API over the licence-neutral static store with the gates
// and usage sources a test wants. A nil gate means "not wired".
type scopeAPIOpts struct {
	gate     func(http.ResponseWriter, *http.Request) (licence.Principal, bool)
	readGate func(http.ResponseWriter, *http.Request) (licence.Principal, bool)
	usage    licence.Usage
	tenant   func(ctx context.Context, tenant string) (licence.Usage, map[string]string)
}

func scopeAPI(o scopeAPIOpts) *licence.API {
	return licence.New(licence.Deps{
		Store:    licence.NewStaticStore(licence.Unlimited()),
		Gate:     o.gate,
		ReadGate: o.readGate,
		Usage:    func(context.Context) licence.Usage { return o.usage },
		Now:      func() time.Time { return time.Unix(0, 0).UTC() },
		TenantUsage: func(ctx context.Context, tenant string) (licence.Usage, map[string]string) {
			if o.tenant == nil {
				return licence.Usage{}, map[string]string{}
			}
			return o.tenant(ctx, tenant)
		},
	})
}

func allowCross(_ http.ResponseWriter, _ *http.Request) (licence.Principal, bool) {
	return licence.Principal{Subject: "owner", Tenant: "global", CrossTenant: true}, true
}

func allowTenant(id string) func(http.ResponseWriter, *http.Request) (licence.Principal, bool) {
	return func(_ http.ResponseWriter, _ *http.Request) (licence.Principal, bool) {
		return licence.Principal{Subject: "admin@" + id, Tenant: id}, true
	}
}

func refuse(w http.ResponseWriter, _ *http.Request) (licence.Principal, bool) {
	w.WriteHeader(http.StatusForbidden)
	return licence.Principal{}, false
}

func getView(t *testing.T, a *licence.API) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	a.Handle(w, httptest.NewRequest(http.MethodGet, "/api/system/licence", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d %s", w.Code, w.Body.String())
	}
	var v map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestReadScopeChoosesThePayload — one route, two answers, chosen by the
// caller's scope and by nothing the caller can send.
func TestReadScopeChoosesThePayload(t *testing.T) {
	measured := func(t *testing.T, v map[string]any, name string) (float64, bool) {
		t.Helper()
		for _, r := range v["ceilings"].([]any) {
			row := r.(map[string]any)
			if row["name"] == name {
				cur, ok := row["current"].(float64)
				return cur, ok
			}
		}
		t.Fatalf("ceiling %q missing", name)
		return 0, false
	}

	t.Run("a cross-tenant caller gets the provider view", func(t *testing.T) {
		a := scopeAPI(scopeAPIOpts{
			gate:     allowCross,
			readGate: allowCross,
			usage:    licence.Usage{entitlement.CeilingDevices: 40},
		})
		v := getView(t, a)
		if v["scope"] != licence.ScopePlatform {
			t.Fatalf("scope = %v, want platform", v["scope"])
		}
		if keys, _ := v["keys"].([]any); len(keys) == 0 {
			t.Error("the provider view publishes the trusted keys")
		}
		if v["verify_hint"] == nil || v["path"] == nil {
			t.Error("the provider view carries the offline recipe and the licence path")
		}
		state := v["state"].(map[string]any)
		if state["customer"] == nil || state["licence_id"] == nil {
			t.Errorf("the provider view names the customer and the licence: %+v", state)
		}
		if got, ok := measured(t, v, entitlement.CeilingDevices); !ok || got != 40 {
			t.Errorf("the provider bar is platform-wide: got %v (measured=%v), want 40", got, ok)
		}
	})

	t.Run("a tenant-scoped caller gets their own projection", func(t *testing.T) {
		var askedFor string
		a := scopeAPI(scopeAPIOpts{
			gate:     allowCross,
			readGate: allowTenant("acme"),
			usage:    licence.Usage{entitlement.CeilingDevices: 40},
			tenant: func(_ context.Context, tenant string) (licence.Usage, map[string]string) {
				askedFor = tenant
				return licence.Usage{entitlement.CeilingDevices: 3}, map[string]string{}
			},
		})
		v := getView(t, a)
		if askedFor != "acme" {
			t.Fatalf("usage was measured for %q, want the caller's own tenant", askedFor)
		}
		if v["scope"] != licence.ScopeTenant || v["tenant"] != "acme" {
			t.Fatalf("scope = %v, tenant = %v", v["scope"], v["tenant"])
		}
		if got, ok := measured(t, v, entitlement.CeilingDevices); !ok || got != 3 {
			t.Errorf("the tenant bar counts THIS TENANT: got %v (measured=%v), want 3 — never the platform-wide 40", got, ok)
		}
		// Provider material is ABSENT, not blank: a key the page can omit is
		// different from a key the platform does not have.
		for _, field := range []string{"keys", "path", "verify_hint"} {
			if _, present := v[field]; present {
				t.Errorf("%q must not be in a tenant projection: %v", field, v[field])
			}
		}
		state := v["state"].(map[string]any)
		for _, field := range []string{"customer", "licence_id", "issued_at", "support", "key_id"} {
			if _, present := state[field]; present {
				t.Errorf("state.%s is the provider's commercial identity: %v", field, state[field])
			}
		}
		// …and what the tenant DOES need is there.
		if state["tier"] != string(entitlement.TierEnterprise) {
			t.Errorf("the tier in force must reach the tenant, got %v", state["tier"])
		}
		if len(state["features"].([]any)) != len(entitlement.Features()) {
			t.Errorf("the entitled features must reach the tenant, got %v", state["features"])
		}
		if v["managed_by"] != licence.ManagedByProvider || v["managed_by_detail"] == "" {
			t.Errorf("the projection must say who may replace the licence: %v", v["managed_by"])
		}
		if v["scope_note"] != licence.TenantScopeNote {
			t.Errorf("the projection must qualify its usage numbers: %v", v["scope_note"])
		}
	})

	t.Run("an unmeasured ceiling reads as not measured, never as zero", func(t *testing.T) {
		a := scopeAPI(scopeAPIOpts{
			gate:     allowCross,
			readGate: allowTenant("acme"),
			tenant: func(context.Context, string) (licence.Usage, map[string]string) {
				return licence.Usage{}, map[string]string{entitlement.CeilingDevices: "the device registry is not available"}
			},
		})
		v := getView(t, a)
		for _, r := range v["ceilings"].([]any) {
			row := r.(map[string]any)
			if row["name"] != entitlement.CeilingDevices {
				continue
			}
			if row["current"] != nil {
				t.Fatalf("nothing was measured, so nothing may be shown: %+v", row)
			}
			if row["current_reason"] != "the device registry is not available" {
				t.Fatalf("the reason must survive to the page: %+v", row)
			}
		}
	})

	t.Run("a MEASURED number can still carry a qualifier", func(t *testing.T) {
		// The withheld-devices case: "25 of 25" is true and useless on its own
		// when the ceiling is holding ten more back. A note is NOT the
		// not-measured reason — one says "we counted, and here is something
		// else", the other says "we never looked", and a page that conflated
		// them would be lying in one of the two cases.
		const note = "10 more device(s) are in the inventory and would be monitored, but the ceiling is full"
		a := scopeAPI(scopeAPIOpts{
			gate:     allowCross,
			readGate: allowTenant("acme"),
			tenant: func(context.Context, string) (licence.Usage, map[string]string) {
				return licence.Usage{entitlement.CeilingDevices: 25},
					map[string]string{entitlement.CeilingDevices: note}
			},
		})
		v := getView(t, a)
		for _, r := range v["ceilings"].([]any) {
			row := r.(map[string]any)
			if row["name"] != entitlement.CeilingDevices {
				continue
			}
			if row["current"] == nil {
				t.Fatalf("the number was measured and must be shown: %+v", row)
			}
			if row["note"] != note {
				t.Fatalf("the qualifier must reach the page: %+v", row)
			}
			if row["current_reason"] != nil {
				t.Fatalf("a measured row has no not-measured reason: %+v", row)
			}
			if row["unit"] != entitlement.UnitMonitoredDevices {
				t.Fatalf("the row must say what it counts: %+v", row)
			}
		}
	})

	t.Run("a refused licence reaches the tenant without the forensics", func(t *testing.T) {
		bad := licence.Unlimited()
		bad.LoadError = "signature does not verify against key k-lab-1 in /data/api/licence.json"
		a := licence.New(licence.Deps{
			Store:    licence.NewStaticStore(bad),
			Gate:     allowCross,
			ReadGate: allowTenant("acme"),
			Now:      func() time.Time { return time.Unix(0, 0).UTC() },
		})
		v := getView(t, a)
		state := v["state"].(map[string]any)
		got, _ := state["load_error"].(string)
		if got == "" {
			t.Fatal("a refused licence is a fact the tenant needs: their ceilings just changed")
		}
		if got == bad.LoadError {
			t.Fatalf("the verbatim reason names a key and a host path — it is provider detail: %q", got)
		}
	})
}

// TestReadGateNotWiredKeepsTheProviderRoute — fail-closed. A build that has not
// wired the tenant read must serve what it served before: the platform gate and
// the provider view, never a projection built from an unresolved scope.
func TestReadGateNotWiredKeepsTheProviderRoute(t *testing.T) {
	gateRan := false
	a := scopeAPI(scopeAPIOpts{
		gate: func(w http.ResponseWriter, r *http.Request) (licence.Principal, bool) {
			gateRan = true
			// Deliberately NOT cross-tenant: the fallback must not depend on
			// what the write gate happens to report about scope.
			return licence.Principal{Subject: "owner"}, true
		},
	})
	v := getView(t, a)
	if !gateRan {
		t.Fatal("the platform gate must still run on a GET when no read gate is wired")
	}
	if v["scope"] != licence.ScopePlatform {
		t.Fatalf("scope = %v, want the provider view", v["scope"])
	}
	if keys, _ := v["keys"].([]any); len(keys) == 0 {
		t.Error("the fallback is the whole provider view, keys included")
	}
}

// TestWritesNeverConsultTheReadGate — §3a rule 3. The read gate admits tenant
// admins; if a write could reach it, every tenant could license the platform.
func TestWritesNeverConsultTheReadGate(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			readGateRan := false
			a := scopeAPI(scopeAPIOpts{
				gate: refuse,
				readGate: func(w http.ResponseWriter, r *http.Request) (licence.Principal, bool) {
					readGateRan = true
					return licence.Principal{Subject: "tenant-admin", Tenant: "acme"}, true
				},
			})
			w := httptest.NewRecorder()
			a.Handle(w, httptest.NewRequest(method, "/api/system/licence", nil))
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want the platform gate's 403", w.Code)
			}
			if readGateRan {
				t.Fatal("a write consulted the READ gate — that gate admits tenant admins (§3a rule 3)")
			}
		})
	}
}
