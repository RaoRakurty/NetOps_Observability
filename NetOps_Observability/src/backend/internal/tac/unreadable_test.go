// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// unreadable_test.go — the silent-data-loss regression for BOTH file stores in
// this package. An unreadable file used to load as an EMPTY one: LoadErr stayed
// nil, nothing was logged, and the next write renamed a temp file over the
// original. A chmod is enough to stage it, because the directory stays writable
// so the rename still succeeds.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// stageUnreadable makes path unreadable and returns its bytes from before.
// It skips the test where a 0000 file can still be read (running as root).
func stageUnreadable(t *testing.T, path string) []byte {
	t.Helper()
	before, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read seeded file: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if _, err := os.ReadFile(path); err == nil { // #nosec G304 -- test-owned temp path
		t.Skip("this environment can read a 0000 file (running as root?), so the case cannot be staged")
	}
	return before
}

// assertUntouched proves the file on disk is byte-identical to `before`.
func assertUntouched(t *testing.T, path string, before []byte) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod back: %v", err)
	}
	after, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read file after: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("the file was rewritten while it could not be read:\nbefore %s\nafter  %s", before, after)
	}
}

// TEMPLATES: an unreadable file is not an empty template set, and the next
// Create must not destroy a tenant's authored command sets.
func TestTemplateFileUnreadableIsNotEmptyAndIsNeverOverwritten(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tac_templates.json")
	mk := func(tenant, name string) Template {
		return Template{TenantID: tenant, Dialect: "cisco-iosxe", Name: name,
			Steps: []TemplateStep{{Command: "show version"}}, CreatedBy: "u-" + tenant}
	}
	seed := NewFileTemplateStore(path)
	kept, err := seed.Create(ctx, mk("tenant-a", "A baseline"))
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
	before := stageUnreadable(t, path)

	s := NewFileTemplateStore(path)
	if s.LoadErr() == nil {
		t.Fatal("an unreadable template file loaded silently — the tenant sees no templates with no reason, and the next Create destroys the file")
	}
	_, cerr := s.Create(ctx, mk("tenant-a", "written over the top"))
	if !errors.Is(cerr, ErrStoreUnreadable) {
		t.Fatalf("a Create over an unreadable template file returned %v", cerr)
	}
	if rows, _ := s.List(ctx, "tenant-a"); len(rows) != 0 {
		t.Fatalf("the refused row stayed in memory: %+v", rows)
	}

	assertUntouched(t, path, before)
	reopened := NewFileTemplateStore(path)
	if reopened.LoadErr() != nil {
		t.Fatalf("the repaired file no longer loads: %v", reopened.LoadErr())
	}
	got, gerr := reopened.Get(ctx, "tenant-a", kept.ID)
	if gerr != nil || got.Name != "A baseline" {
		t.Fatalf("the seeded template did not survive: %v %+v", gerr, got)
	}
}

// A template file we cannot PARSE is unknown for the same reason.
func TestTemplateCorruptFileRefusesWritesAndKeepsTheBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tac_templates.json")
	before := []byte("{not json")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewFileTemplateStore(path)
	if s.LoadErr() == nil {
		t.Fatal("a corrupt template file loaded silently")
	}
	_, cerr := s.Create(context.Background(), Template{TenantID: "tenant-a", Dialect: "cisco-iosxe",
		Name: "x", Steps: []TemplateStep{{Command: "show version"}}})
	if !errors.Is(cerr, ErrStoreUnreadable) {
		t.Fatalf("a Create over an unparsable template file returned %v", cerr)
	}
	after, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("the unparsable file was overwritten: %s", after)
	}
}

// LEARNING BACKLOG: same defect, same proof.
func TestLearningFileUnreadableIsNotEmptyAndIsNeverOverwritten(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tac_learning.json")
	rec := LearningRecord{ID: NewRecordID(), TenantID: "tenant-a", IncidentID: "corr-1",
		DeviceID: "dev-1", Dialect: "cisco-iosxe", CollectedAt: time.Now().UTC()}
	seed := NewFileLearningStore(path)
	if err := seed.PutRecord(ctx, rec); err != nil {
		t.Fatalf("seed record: %v", err)
	}
	before := stageUnreadable(t, path)

	s := NewFileLearningStore(path)
	if s.LoadErr() == nil {
		t.Fatal("an unreadable learning file loaded silently — the backlog reads as empty and the next write destroys it")
	}
	next := rec
	next.ID = NewRecordID()
	if err := s.PutRecord(ctx, next); !errors.Is(err, ErrStoreUnreadable) {
		t.Fatalf("a PutRecord over an unreadable learning file returned %v", err)
	}
	if rows, _ := s.Records(ctx, "tenant-a"); len(rows) != 0 {
		t.Fatalf("the refused record stayed in memory: %+v", rows)
	}

	assertUntouched(t, path, before)
	reopened := NewFileLearningStore(path)
	if reopened.LoadErr() != nil {
		t.Fatalf("the repaired file no longer loads: %v", reopened.LoadErr())
	}
	rows, rerr := reopened.Records(ctx, "tenant-a")
	if rerr != nil || len(rows) != 1 || rows[0].ID != rec.ID {
		t.Fatalf("the seeded record did not survive: %v %+v", rerr, rows)
	}
}

// A file that is ABSENT is still just an empty store, with nothing reported and
// writes allowed. This is the half the fix must NOT break.
func TestAbsentTacFilesStayEmptyAndWritable(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ts := NewFileTemplateStore(filepath.Join(dir, "never-written.json"))
	if err := ts.LoadErr(); err != nil {
		t.Fatalf("a template file that was never written reported %v", err)
	}
	if _, err := ts.Create(ctx, Template{TenantID: "tenant-a", Dialect: "cisco-iosxe", Name: "first",
		Steps: []TemplateStep{{Command: "show version"}}}); err != nil {
		t.Fatalf("the first Create on a fresh store failed: %v", err)
	}
	ls := NewFileLearningStore(filepath.Join(dir, "never-written-learning.json"))
	if err := ls.LoadErr(); err != nil {
		t.Fatalf("a learning file that was never written reported %v", err)
	}
	if err := ls.PutRecord(ctx, LearningRecord{ID: NewRecordID(), TenantID: "tenant-a",
		IncidentID: "corr-1", CollectedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("the first PutRecord on a fresh store failed: %v", err)
	}
}
