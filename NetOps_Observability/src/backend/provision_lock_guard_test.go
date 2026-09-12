// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// provision_lock_guard_test.go — the fleet gate and the create are ONE step
// (review 3.6-03).
//
// THE DEFECT the lock closed: the MSP gate counted the real tenants and then
// created outside any lock, and the store has no ceiling of its own, so two
// platform admins creating at the same moment both read the free slot and both
// took it.
//
// WHY THIS GUARD IS STRUCTURAL. There IS a concurrency test for this
// (TestLicenceOnboardIsTheSameDoor/"concurrent tenant creates cannot both take
// the last slot"), and it is worth keeping — but it does not fail on the broken
// code: deleting provisionMu.Lock from createTenantGated leaves it green at 8
// callers and at 64, because the window between the count and the create is a
// few microseconds and the goroutines do not reliably land inside it. A guard
// that cannot fail is not a guard, so the shape is pinned instead: the ONE call
// site of tenants.Create is inside a *Locked helper, and every path that
// reaches it holds provisionMu. That is checkable with certainty, and it is
// what makes the check-then-act shape unwritable rather than unlikely.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// provisionLockedCallees are the helpers that may only run under provisionMu.
var provisionLockedCallees = []string{"createTenantLocked", "createOrgLocked", "gateFleetTenantLocked"}

// parsePackageFuncs returns every non-test function declaration in the package,
// keyed by "file:func", with its body source.
func parsePackageFuncs(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			start := fset.Position(fn.Body.Pos()).Offset
			end := fset.Position(fn.Body.End()).Offset
			out[name+":"+fn.Name.Name] = string(src[start:end])
		}
	}
	if len(out) == 0 {
		t.Fatal("the sweep parsed no package sources — it would pass vacuously")
	}
	return out
}

func TestTenantCreateIsOnlyReachableUnderTheProvisionLock(t *testing.T) {
	funcs := parsePackageFuncs(t)

	// 1. The store's Create has exactly ONE call site, and it is the *Locked
	//    helper whose contract is "the caller holds provisionMu".
	var creators []string
	for key, body := range funcs {
		if strings.Contains(body, "s.tenants.Create(") {
			creators = append(creators, key)
		}
	}
	if len(creators) != 1 || !strings.HasSuffix(creators[0], ":createTenantLocked") {
		t.Fatalf("tenants.Create is called from %v, want only createTenantLocked — a second call "+
			"site is a second place the fleet gate can be skipped or raced", creators)
	}

	// 2. Every caller of a *Locked provisioning helper holds provisionMu, or is
	//    itself one of them (they compose under one hold).
	locked := map[string]bool{}
	for _, name := range provisionLockedCallees {
		locked[name] = true
	}
	seen := 0
	for key, body := range funcs {
		fn := key[strings.IndexByte(key, ':')+1:]
		if locked[fn] {
			continue // a *Locked helper calling another runs under the caller's hold
		}
		for _, callee := range provisionLockedCallees {
			if !strings.Contains(body, callee+"(") {
				continue
			}
			seen++
			if !strings.Contains(body, "s.provisionMu.Lock()") {
				t.Errorf("%s calls %s without taking provisionMu — the count it gates on is only "+
					"true while nothing else can create", key, callee)
			}
		}
	}
	if seen == 0 {
		t.Fatal("the sweep found no caller of a *Locked provisioning helper — its names have " +
			"drifted away from the code and this guard proves nothing")
	}

	// 3. And the lock is actually released: a helper that takes it must defer
	//    the unlock rather than unlock on one path.
	for _, key := range []string{"identity_handlers.go:createTenantGated", "identity_handlers.go:createOrgGated",
		"onboard.go:provisionOrgWithTenant"} {
		body, ok := funcs[key]
		if !ok {
			t.Fatalf("%s no longer exists — the provisioning doors have moved and this guard has not", key)
		}
		if !strings.Contains(body, "s.provisionMu.Lock()") || !strings.Contains(body, "defer s.provisionMu.Unlock()") {
			t.Errorf("%s does not take provisionMu and defer its release", key)
		}
	}
}
