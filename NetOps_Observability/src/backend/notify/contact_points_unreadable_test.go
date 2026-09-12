// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package notify

// contact_points_unreadable_test.go — the silent-data-loss regression. The load
// used to fold ANY error into "absent", despite a comment claiming it checked
// os.ErrNotExist. A permissions change on the file started the registry EMPTY —
// every alert delivered to nobody — and the first admin save then renamed a temp
// file over the file it never read.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnreadableContactPointFileIsAnErrorNotAnEmptyRegistry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "contact_points.json")
	seed, err := NewContactPointStore(path)
	if err != nil {
		t.Fatalf("open seed store: %v", err)
	}
	if _, err := seed.Upsert(ContactPoint{Name: "noc", Type: "email", Email: []string{"noc@acme.example"}, Enabled: true}); err != nil {
		t.Fatalf("seed contact point: %v", err)
	}
	before, rerr := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if rerr != nil {
		t.Fatalf("read seeded file: %v", rerr)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if _, err := os.ReadFile(path); err == nil { // #nosec G304 -- test-owned temp path
		t.Skip("this environment can read a 0000 file (running as root?), so the case cannot be staged")
	}

	s, oerr := NewContactPointStore(path)
	if oerr == nil {
		t.Fatal("an unreadable contact-point registry opened silently — every alert would be delivered to nobody, and the next admin save destroys the file")
	}
	if s != nil {
		t.Fatalf("a failed open still handed back a store: %+v", s)
	}

	// Nothing was written on the way out.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod back: %v", err)
	}
	after, aerr := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if aerr != nil {
		t.Fatalf("read file after: %v", aerr)
	}
	if string(after) != string(before) {
		t.Fatalf("the registry was rewritten while it could not be read:\nbefore %s\nafter  %s", before, after)
	}
	reopened, rer := NewContactPointStore(path)
	if rer != nil {
		t.Fatalf("the repaired file no longer loads: %v", rer)
	}
	if pts := reopened.List(); len(pts) != 1 || pts[0].Name != "noc" {
		t.Fatalf("the seeded contact point did not survive: %+v", pts)
	}
}

// A registry we cannot PARSE was already an error. It stays one, and it now
// names the file.
func TestCorruptContactPointFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "contact_points.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewContactPointStore(path)
	if err == nil {
		t.Fatal("a corrupt contact-point registry opened silently")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("the error does not name the file the operator must repair: %v", err)
	}
}

// A file that is ABSENT is still just an empty registry. This is the half the
// fix must NOT break.
func TestAbsentContactPointFileStaysAnEmptyRegistry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never-written.json")
	s, err := NewContactPointStore(path)
	if err != nil {
		t.Fatalf("a registry that was never written failed to open: %v", err)
	}
	if len(s.List()) != 0 {
		t.Fatalf("a fresh registry is not empty: %+v", s.List())
	}
	if _, err := s.Upsert(ContactPoint{Name: "noc", Type: "email", Email: []string{"noc@acme.example"}}); err != nil {
		t.Fatalf("the first Upsert on a fresh registry failed: %v", err)
	}
}
