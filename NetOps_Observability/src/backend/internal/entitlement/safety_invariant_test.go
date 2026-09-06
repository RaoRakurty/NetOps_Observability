// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package entitlement_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// safety_invariant_test.go — THE test this whole subsystem answers to.
//
// Owner spec, 2026-09-04 (binding):
//
//	"whatever the policy, expiry/invalid/missing licence must be technically
//	 incapable of touching tenant isolation, RLS/data separation, authorization,
//	 integrity controls, or core authentication — OIDC stays core and always
//	 available."
//
// "Technically incapable" is a stronger claim than "we do not do that", and it
// has to be checked STRUCTURALLY rather than behaviourally. A behavioural test
// ("isolation still works with an expired licence") only samples the states
// someone thought to write down; a licence bug in a state nobody enumerated
// would still slip through. What actually makes the property hold is that the
// safety paths never CONSULT the entitlement service at all — they have no way
// to ask, so there is no answer that could weaken them.
//
// So these tests assert the absence of a dependency edge, in two directions:
//
//  1. package level — the packages that IMPLEMENT isolation, RLS, RBAC, session,
//     tokens and OIDC do not (transitively) depend on internal/entitlement or
//     internal/licence;
//  2. function level — the specific helpers in the backend root package that
//     decide tenant scope, RLS scope and authorization contain no reference to
//     either package, even though other functions in the same FILES legitimately
//     do (the tenant-create chokepoint lives beside requirePerm).
//
// If either fails, the invariant is gone and no amount of licence-state testing
// restores it.

// backendRoot is the module root, derived from this file's own location so the
// test is independent of the working directory.
func backendRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this test file")
	}
	// .../src/backend/internal/entitlement/safety_invariant_test.go
	return filepath.Dir(filepath.Dir(filepath.Dir(self)))
}

// gatedPackages are the two packages a safety path must never reach.
var gatedPackages = []string{
	"netops/backend/internal/entitlement",
	"netops/backend/internal/licence",
	"netops/backend/internal/licence/signer",
}

// safetyPackages implement the properties the owner listed. Each is annotated
// with WHICH property it carries, so a future reader knows why removing an entry
// is not a refactor.
var safetyPackages = map[string]string{
	"netops/backend/internal/tenant":       "tenant isolation: the tenant/org stores and reachability",
	"netops/backend/internal/rbac":         "authorization: the role→(module,level) decision",
	"netops/backend/internal/platformdb":   "RLS / data separation: WithTenant binds the app.tenant_id GUC every tenant_iso policy reads",
	"netops/backend/internal/session":      "core authentication: session lifecycle",
	"netops/backend/internal/token":        "core authentication: token issue and validation",
	"netops/backend/internal/oidc":         "core authentication: OIDC stays core and always available",
	"netops/backend/internal/audit":        "integrity: the audit trail must record regardless of licence state",
	"netops/backend/internal/users":        "core authentication: local accounts",
	"netops/backend/internal/sealedfields": "integrity: sealed-field custody",
}

// TestSafetyPackagesDoNotDependOnEntitlement is the package-level half.
//
// It uses `go list -deps`, i.e. the REAL transitive import graph, not a grep for
// import lines — an indirect edge through a helper package would weaken the
// invariant just as much as a direct one.
func TestSafetyPackagesDoNotDependOnEntitlement(t *testing.T) {
	root := backendRoot(t)
	gated := map[string]bool{}
	for _, p := range gatedPackages {
		gated[p] = true
	}

	for pkg, property := range safetyPackages {
		t.Run(pkg, func(t *testing.T) {
			cmd := exec.Command("go", "list", "-deps", pkg)
			cmd.Dir = root
			out, err := cmd.Output()
			if err != nil {
				// A package that does not exist is a rename, not a pass. Fail
				// loudly: silently skipping is how this guard would rot.
				t.Fatalf("go list -deps %s: %v — if this package was renamed, update safetyPackages; do not delete the entry", pkg, err)
			}
			for _, dep := range strings.Fields(string(out)) {
				if gated[dep] {
					t.Fatalf("%s (%s) transitively imports %s.\n\n"+
						"A licence problem — expired, invalid, tampered, absent — must be TECHNICALLY INCAPABLE of\n"+
						"weakening isolation, RLS, authorization, integrity or core authentication (owner spec,\n"+
						"2026-09-04). That property holds because these packages cannot ASK the entitlement service.\n"+
						"Adding this edge means a licence bug can now reach a safety control. Move the gate to the\n"+
						"commercial caller instead.", pkg, property, dep)
				}
			}
		})
	}
}

// safetyFunctions are the root-package helpers that decide tenant scope and
// authorization. They live in files that also (legitimately) hold commercial
// chokepoints, so the check is per-FUNCTION.
var safetyFunctions = map[string]string{
	"tenancy.go:principalTenant":                "derives the caller's tenant scope — every list/get/search filter starts here",
	"tenancy.go:isPlatformOwner":                "the platform-owner identity decision",
	"access.go:reachesTenant":                   "bounds cross-org reach",
	"identity_handlers.go:requirePerm":          "the authorization gate on 200+ routes",
	"identity_handlers.go:requireAdmin":         "the administration gate",
	"identity_handlers.go:requirePlatformAdmin": "the platform-global gate",
	"stack_health.go:requireCrossTenant":        "the cross-tenant gate",
	"clickhouse_client.go:chTenantScope":        "the ClickHouse tenant scope injected into every query",
	"clickhouse_client.go:chTenantScopeFor":     "the same, from claims",
}

// TestSafetyFunctionsDoNotConsultEntitlement is the function-level half.
//
// It extracts each named function's body by brace matching and asserts it makes
// no reference to the entitlement or licence packages. This catches the shape
// the package-level test cannot: a licence check added INSIDE requirePerm, in a
// file that already imports entitlement for an unrelated, legitimate reason.
func TestSafetyFunctionsDoNotConsultEntitlement(t *testing.T) {
	root := backendRoot(t)
	for spec, property := range safetyFunctions {
		t.Run(spec, func(t *testing.T) {
			file, fn, ok := strings.Cut(spec, ":")
			if !ok {
				t.Fatalf("malformed spec %q", spec)
			}
			src, err := os.ReadFile(filepath.Join(root, file))
			if err != nil {
				t.Fatalf("read %s: %v — if this file was renamed, update safetyFunctions; do not delete the entry", file, err)
			}
			body, ok := functionBody(string(src), fn)
			if !ok {
				t.Fatalf("%s: func %s not found — if it was renamed or moved, update safetyFunctions; do not delete the entry", file, fn)
			}
			for _, banned := range []string{"entitlement.", "licence.", "Entitled(", "CheckCeiling(", "requireFeature("} {
				if strings.Contains(body, banned) {
					t.Fatalf("%s references %q.\n\n"+
						"%s is a SAFETY control (%s). A licence problem must be technically incapable of affecting it\n"+
						"(owner spec, 2026-09-04). Gate the commercial capability at its own call site, never inside an\n"+
						"isolation or authorization decision.", spec, banned, fn, property)
				}
			}
		})
	}
}

// functionBody returns the source of `func <name>(` or `func (recv) <name>(`,
// from the signature to its closing brace, matched by brace depth.
//
// Brace counting is crude but sufficient and, importantly, has no dependency of
// its own: a guard that needed a parser would be a guard someone disabled.
// Braces inside string or rune literals would fool it; none of the functions
// under guard contain any, and a future one that did would fail loudly (the
// extracted body would be short) rather than pass silently.
func functionBody(src, name string) (string, bool) {
	for _, prefix := range []string{"\nfunc " + name + "(", "\nfunc ("} {
		idx := 0
		for {
			rel := strings.Index(src[idx:], prefix)
			if rel < 0 {
				break
			}
			start := idx + rel + 1
			idx = start + 1
			// For a method, confirm the name follows the receiver on the same line.
			line := src[start:]
			if nl := strings.IndexByte(line, '\n'); nl >= 0 {
				line = line[:nl]
			}
			if !strings.Contains(line, " "+name+"(") && !strings.HasPrefix(line, "func "+name+"(") {
				continue
			}
			open := strings.IndexByte(src[start:], '{')
			if open < 0 {
				continue
			}
			depth, i := 0, start+open
			for ; i < len(src); i++ {
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
		}
	}
	return "", false
}

// TestOIDCStaysCore is the owner's named example, asserted directly: OIDC is
// core authentication and is never a licensed capability. SAML, SCIM and LDAP
// are the commercial additions — OIDC is not, and must never appear in the
// feature vocabulary.
func TestOIDCStaysCore(t *testing.T) {
	for _, f := range featuresUnderTest() {
		if strings.Contains(strings.ToLower(string(f)), "oidc") {
			t.Fatalf("%q gates OIDC. OIDC is CORE authentication and is always available at every tier — "+
				"a customer whose licence lapsed must still be able to sign in (owner spec, 2026-09-04).", f)
		}
	}
}
