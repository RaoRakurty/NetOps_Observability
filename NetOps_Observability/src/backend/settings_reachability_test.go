package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// settings_reachability_test.go — the CLASS guard behind F-68.
//
// F-68 was not "a bug in seven settings". It was a shape: a settings struct can
// grow a field, the API can persist it, the SPA can render it as a working
// control, and NOTHING need ever read it. Every existing test stayed green,
// because a stored-and-ignored setting behaves exactly like a stored-and-obeyed
// one until someone audits the read sites by hand. That is what happened: seven
// fields, zero readers, shipped, and cited as compliance evidence.
//
// A setting nothing reads is a lie told to whoever set it.
//
// This guard fails the build when a SecuritySettings field has no read site
// outside its own definition. It is deliberately a *reachability* check, not a
// correctness one — it cannot prove a field is obeyed CORRECTLY (that is what
// account_policy_test.go is for). It proves only that somebody looked at it,
// which is the exact property whose absence made F-68 possible.
//
// Per the architecture_guards_test.go convention: if a field genuinely needs no
// reader, add it to settingsWithNoReader WITH a reason. Never delete the guard.

// Fields that are legitimately never read as policy inputs.
var settingsWithNoReader = map[string]string{
	"Scope": "identity of the settings row itself, not a policy knob — it is the map key, " +
		"set on write and echoed on read; there is nothing to 'enforce'",
}

// structFields returns the field names of the named struct in a Go file.
func structFields(t *testing.T, file, structName string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != structName {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, fld := range st.Fields.List {
			for _, name := range fld.Names {
				if name.IsExported() {
					out = append(out, name.Name)
				}
			}
		}
		return false
	})
	if len(out) == 0 {
		t.Fatalf("no exported fields found on %s in %s — did the struct move?", structName, file)
	}
	return out
}

// consumerSources returns the non-test Go sources that mention the settings type
// at all. Scoping the search to these files (rather than the whole tree) keeps a
// field named like a common word — Status, Scope — from being "found" in totally
// unrelated code and passing the guard for free.
func consumerSources(t *testing.T, defFile string, typeNames ...string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") || name == defFile {
			continue
		}
		b, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := stripComments(string(b))
		for _, tn := range typeNames {
			if strings.Contains(src, tn) {
				out[name] = src
				break
			}
		}
	}
	return out
}

func TestEverySecuritySettingHasAReadSite(t *testing.T) {
	const defFile = "security_settings.go"
	fields := structFields(t, defFile, "SecuritySettings")
	sources := consumerSources(t, defFile, "SecuritySettings", "securitySettings")
	if len(sources) == 0 {
		t.Fatal("no consumer files reference SecuritySettings — the guard would pass vacuously")
	}

	for _, f := range fields {
		if reason, ok := settingsWithNoReader[f]; ok {
			if reason == "" {
				t.Errorf("%s is exempted with an empty reason — state why or delete the exemption", f)
			}
			continue
		}
		found := ""
		for name, src := range sources {
			if strings.Contains(src, "."+f) {
				found = name
				break
			}
		}
		if found == "" {
			t.Errorf(`SecuritySettings.%s is stored and rendered but NEVER READ.

  This is F-68 exactly: a security setting an operator can turn on, that the
  product displays as active, and that nothing enforces. Someone will answer a
  compliance questionnaire with it.

  Fix it one of three ways:
    1. enforce it   — read it in account_policy.go (or wherever it belongs)
    2. remove it    — from the struct AND from the SPA control that shows it
    3. exempt it    — add it to settingsWithNoReader with a reason, if it is
                      genuinely not a policy input (see Scope)`, f)
		}
	}
}

// The seven fields F-68 named, pinned by name. The generic guard above would
// catch a regression, but this states the finding's own list so a future reader
// can see exactly what was broken and confirm it still is not.
func TestF68SettingsAreEnforced(t *testing.T) {
	f68 := []string{
		"PasswordExpireEnabled", "PasswordExpireDays", "PasswordHistory",
		"ResetOnFirstLogin", "AccountValidityDays", "AccountInactivityDays",
		"ConcurrentLogin",
	}
	sources := consumerSources(t, "security_settings.go", "SecuritySettings", "securitySettings")
	for _, f := range f68 {
		found := false
		for _, src := range sources {
			if strings.Contains(src, "."+f) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("F-68 regression: SecuritySettings.%s lost its enforcement read site", f)
		}
	}
}
