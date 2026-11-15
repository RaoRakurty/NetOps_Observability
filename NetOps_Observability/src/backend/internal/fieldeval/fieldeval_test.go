// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package fieldeval

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/evalsplit"
	"netops/backend/internal/iristriage"
)

var t0 = time.Date(2026, 11, 15, 9, 30, 0, 0, time.UTC)

// fakeRepo makes a directory that looks like a git work tree.
func fakeRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func export(qs ...string) iristriage.CandidateFile {
	f := iristriage.CandidateFile{Review: iristriage.ReviewNotice}
	for _, q := range qs {
		f.Candidates = append(f.Candidates, iristriage.Candidate{Question: q, Source: "miss", Route: "docs", Class: iristriage.NoTool})
	}
	return f
}

func TestOpenRefusesARootInsideTheRepository(t *testing.T) {
	repo := fakeRepo(t)
	for _, bad := range []string{
		filepath.Join(repo, "src", "backend", "testdata", "field"),
		filepath.Join(repo, "iris-eval"),
		repo,
	} {
		if _, err := Open(bad); !errors.Is(err, ErrInsideRepository) {
			t.Fatalf("Open(%s): %v — want ErrInsideRepository", bad, err)
		}
	}
	for _, ok := range []string{
		filepath.Join(repo, "data", "iris-eval"),
		filepath.Join(repo, "NetOps_Observability", "data", "iris-eval"),
		filepath.Join(t.TempDir(), "outside"), // not inside any work tree
	} {
		if _, err := Open(ok); err != nil {
			t.Fatalf("Open(%s): %v", ok, err)
		}
	}
}

func TestImportHoldsOutWritesPrivatelyAndDedupes(t *testing.T) {
	st, err := Open(filepath.Join(fakeRepo(t), "data", "iris-eval"))
	if err != nil {
		t.Fatal(err)
	}
	path, n, err := st.Import("acme", export("why is the dallas box slow", "  ", "show bgp flaps on edge-1"), t0)
	if err != nil || n != 2 || path == "" {
		t.Fatalf("import: %q %d %v", path, n, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v — want 0600", fi.Mode().Perm())
	}
	if di, _ := os.Stat(filepath.Dir(path)); di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v — want 0700", di.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Tenant != "acme" || f.Notice != Notice || len(f.Cases) != 2 {
		t.Fatalf("stored file %+v", f)
	}
	for _, c := range f.Cases {
		if c.Split != string(evalsplit.HeldOut) {
			t.Fatalf("a field case must be held out: %+v", c)
		}
		if c.ExpectedRoute != "" {
			t.Fatalf("an import must not invent a label: %+v", c)
		}
	}
	// The same questions again (different case/spacing) add nothing.
	if p, n, err := st.Import("acme", export("Why is the  Dallas box slow"), t0.Add(time.Second)); err != nil || n != 0 || p != "" {
		t.Fatalf("re-import: %q %d %v", p, n, err)
	}
	// The same question in another tenant is that tenant's own case.
	if _, n, err := st.Import("globex", export("why is the dallas box slow"), t0.Add(2*time.Second)); err != nil || n != 1 {
		t.Fatalf("globex import: %d %v", n, err)
	}
}

func TestImportRefusesABadTenant(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "../acme", "acme/x", ".hidden", strings.Repeat("a", 200)} {
		if _, _, err := st.Import(bad, export("q one two"), t0); err == nil {
			t.Fatalf("tenant %q accepted", bad)
		}
	}
}

func TestLoadLabelledAndCountsCarryNoText(t *testing.T) {
	root := t.TempDir()
	st, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	pooled := export("why is the dallas box slow")
	pooled.Candidates[0].Pooled = true
	path, _, err := st.Import("acme", pooled, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Import("acme", export("show bgp flaps on edge-1"), t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// A reviewer labels the first case.
	raw, _ := os.ReadFile(path)
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	f.Cases[0].ExpectedRoute = "data"
	b, _ := json.Marshal(f)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	ts, err := st.Load()
	if err != nil || len(ts) != 1 || len(ts[0].Cases) != 2 {
		t.Fatalf("load: %+v %v", ts, err)
	}
	if l := Labelled(ts[0].Cases); len(l) != 1 || l[0].ExpectedRoute != "data" {
		t.Fatalf("labelled %+v", l)
	}
	counts, err := st.Counts()
	if err != nil || len(counts) != 1 || counts[0] != (Count{Tenant: "acme", Cases: 2, Labelled: 1, Pooled: 1}) {
		t.Fatalf("counts %+v %v", counts, err)
	}
	if out, _ := json.Marshal(counts); strings.Contains(string(out), "dallas") {
		t.Fatalf("counts carry question text: %s", out)
	}
}

func TestATenantMismatchInAFileIsRefused(t *testing.T) {
	root := t.TempDir()
	st, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "acme")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(File{SchemaVersion: SchemaVersion, Tenant: "globex", Cases: []Case{{ID: "x", Question: "q"}}})
	if err := os.WriteFile(filepath.Join(dir, "field-20261115-000000.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(); err == nil {
		t.Fatal("a file filed under acme but naming globex was loaded")
	}
}

func TestAMissingRootIsAnEmptyStore(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "not-yet"))
	if err != nil {
		t.Fatal(err)
	}
	if ts, err := st.Load(); err != nil || len(ts) != 0 {
		t.Fatalf("%+v %v", ts, err)
	}
}
