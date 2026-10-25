// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rbac

import "testing"

// Tracker 365: the Provider scope is ("global", non-cross). DATA resources
// compare by owner ("" ≡ "global"), so the platform's untagged devices, saved
// objects and alerts stay visible to it; IDENTITY resources stay strict, so a
// Provider-tenant principal never reaches a "" account, key or credential (the
// platform owner's own account class — aliasing it would be an escalation).
func TestAuthorizeProviderScopeOwnerAliasing(t *testing.T) {
	provider := Principal{Subject: "root", Role: RoleSuperAdmin, Tenant: "global"} // owner narrowed to Provider
	blank := Principal{Subject: "x", Role: "admin", Tenant: ""}                     // a "" realm principal
	acme := Principal{Subject: "a", Role: RoleSuperAdmin, Tenant: "acme"}

	cases := []struct {
		name string
		p    Principal
		a    Action
		r    Resource
		want bool
	}{
		// Data: both platform spellings are the Provider's own.
		{"provider views untagged device", provider, ActionView, Resource{ResDevice, ""}, true},
		{"provider views global device", provider, ActionView, Resource{ResDevice, "global"}, true},
		{"provider deletes untagged saved", provider, ActionDelete, Resource{ResSaved, ""}, true},
		{"provider views untagged alert", provider, ActionView, Resource{ResAlert, " GLOBAL "}, true},
		// Directional: an unbound "" principal never widens to the Provider's rows.
		{"blank principal views global device", blank, ActionView, Resource{ResDevice, "global"}, false},
		{"blank principal views global saved", blank, ActionView, Resource{ResSaved, "global"}, false},
		{"blank principal views untagged device", blank, ActionView, Resource{ResDevice, ""}, true},

		// Data: a real tenant's rows are never the Provider's, nor vice versa.
		{"provider views acme device", provider, ActionView, Resource{ResDevice, "acme"}, false},
		{"provider deletes acme saved", provider, ActionDelete, Resource{ResSaved, "acme"}, false},
		{"provider views acme alert", provider, ActionView, Resource{ResAlert, "acme"}, false},
		{"acme views untagged device", acme, ActionView, Resource{ResDevice, ""}, false},
		{"acme views global device", acme, ActionView, Resource{ResDevice, "global"}, false},
		{"acme views global saved", acme, ActionView, Resource{ResSaved, "global"}, false},

		// Identity: STRICT — no "" ≡ "global" aliasing.
		{"provider views blank user", provider, ActionView, Resource{ResUser, ""}, false},
		{"provider updates blank user", provider, ActionUpdate, Resource{ResUser, ""}, false},
		{"provider views blank api key", provider, ActionView, Resource{ResAPIKey, ""}, false},
		{"provider views blank snmp cred", provider, ActionView, Resource{ResSNMPCred, ""}, false},
		{"blank principal views global user", blank, ActionView, Resource{ResUser, "global"}, false},
		{"blank principal views global api key", blank, ActionView, Resource{ResAPIKey, "global"}, false},
		// …while an exact match still works for identity.
		{"provider views global user", provider, ActionView, Resource{ResUser, "global"}, true},
		{"provider views global snmp cred", provider, ActionView, Resource{ResSNMPCred, "global"}, true},

		// Platform plumbing is never reachable through a non-cross scope.
		{"provider infra stack", provider, ActionView, Resource{ResInfraStack, ""}, false},
	}
	for _, c := range cases {
		if got := Authorize(c.p, c.a, c.r).Allow; got != c.want {
			t.Errorf("%s: allow=%v, want %v", c.name, got, c.want)
		}
	}
}

// isDataResource is a closed allowlist: every other type stays strict.
func TestIsDataResourceIsClosed(t *testing.T) {
	for _, rt := range []ResourceType{ResDevice, ResSaved, ResAlert} {
		if !isDataResource(rt) {
			t.Errorf("%s must be a data resource", rt)
		}
	}
	for _, rt := range []ResourceType{ResUser, ResTenant, ResRole, ResAPIKey, ResSNMPCred, ResInfraStack, ResourceType("contact_point"), ResourceType("")} {
		if isDataResource(rt) {
			t.Errorf("%q must NOT alias owners (identity / platform / unknown)", rt)
		}
	}
}
