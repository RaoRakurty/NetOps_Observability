// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// store_unreadable_test.go — the silent-data-loss regression for the three
// file-backed registers in this package. An unreadable file used to load as an
// EMPTY one: nothing was recorded, nothing was logged, and the next save renamed
// a temp file over the original. A chmod is enough to stage it, because the
// directory stays writable so the rename still succeeds.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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

// PROMOTIONS: an audited operator decision. An unreadable register must not read
// as "nothing was ever promoted", and the next Set must not destroy the file.
func TestPromotionRegisterUnreadableIsNotEmptyAndIsNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rca_promotions.json")
	seed := NewPromotionStore(path)
	if err := seed.Set("acme", "corr-1", PromotionRecord{PromotedBy: "u@acme", PromotedAt: "2026-09-10T00:00:00Z"}); err != nil {
		t.Fatalf("seed promotion: %v", err)
	}
	before := stageUnreadable(t, path)

	s := NewPromotionStore(path)
	if s.Unavailable() == nil {
		t.Fatal("an unreadable promotion register loaded silently — every promoted case reads as never promoted, and the next Set destroys the file")
	}
	err := s.Set("acme", "corr-2", PromotionRecord{PromotedBy: "u@acme", PromotedAt: "2026-09-10T01:00:00Z"})
	if !errors.Is(err, ErrStoreUnreadable) {
		t.Fatalf("a Set over an unreadable promotion register returned %v", err)
	}
	if got := s.List("acme"); len(got) != 0 {
		t.Fatalf("the refused promotion stayed in memory: %v", got)
	}

	assertUntouched(t, path, before)
	reopened := NewPromotionStore(path)
	if reopened.Unavailable() != nil {
		t.Fatalf("the repaired file no longer loads: %v", reopened.Unavailable())
	}
	if rec, ok := reopened.Get("acme", "corr-1"); !ok || rec.PromotedBy != "u@acme" {
		t.Fatalf("the seeded promotion did not survive: %+v %v", rec, ok)
	}
}

// A register we cannot PARSE is unknown for the same reason.
func TestPromotionRegisterCorruptFileRefusesWritesAndKeepsTheBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rca_promotions.json")
	before := []byte("{not json")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewPromotionStore(path)
	if s.Unavailable() == nil {
		t.Fatal("a corrupt promotion register loaded silently")
	}
	if err := s.Set("acme", "corr-1", PromotionRecord{PromotedBy: "u@acme"}); !errors.Is(err, ErrStoreUnreadable) {
		t.Fatalf("a Set over an unparsable register returned %v", err)
	}
	after, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("the unparsable file was overwritten: %s", after)
	}
}

// REPORT REVISIONS: immutable, integrity-stamped generation records.
func TestRevisionRegisterUnreadableIsNotEmptyAndIsNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rca_revisions.json")
	seed := NewRevisionStore(path)
	if _, _, err := seed.Record("acme", "corr-1", ReportRevision{Format: "html", CreatedBy: "u@acme",
		CreatedAt: "2026-09-10T00:00:00Z", Integrity: ReportIntegrity{ContentHash: "aaa"}}); err != nil {
		t.Fatalf("seed revision: %v", err)
	}
	before := stageUnreadable(t, path)

	s := NewRevisionStore(path)
	if s.Unavailable() == nil {
		t.Fatal("an unreadable revision register loaded silently — every generated report reads as never generated, and the next Record destroys the file")
	}
	_, _, err := s.Record("acme", "corr-1", ReportRevision{Format: "html", CreatedBy: "u@acme",
		CreatedAt: "2026-09-10T01:00:00Z", Integrity: ReportIntegrity{ContentHash: "bbb"}})
	if !errors.Is(err, ErrStoreUnreadable) {
		t.Fatalf("a Record over an unreadable revision register returned %v", err)
	}
	if got := s.List("acme", "corr-1"); len(got) != 0 {
		t.Fatalf("the refused revision stayed in memory: %+v", got)
	}

	assertUntouched(t, path, before)
	reopened := NewRevisionStore(path)
	if reopened.Unavailable() != nil {
		t.Fatalf("the repaired file no longer loads: %v", reopened.Unavailable())
	}
	if got := reopened.List("acme", "corr-1"); len(got) != 1 || got[0].Integrity.ContentHash != "aaa" {
		t.Fatalf("the seeded revision did not survive: %+v", got)
	}
}

// ACTION ITEMS: accountable remediation work.
func TestActionItemRegisterUnreadableIsNotEmptyAndIsNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rca_action_items.json")
	seed := NewActionItemStore(path)
	if err := seed.Put("acme", "corr-1", ActionItem{ID: "ai-1", Action: "replace the optic",
		Status: "open", Source: "human_created", CreatedAt: "2026-09-10T00:00:00Z"}); err != nil {
		t.Fatalf("seed action item: %v", err)
	}
	before := stageUnreadable(t, path)

	s := NewActionItemStore(path)
	if s.Unavailable() == nil {
		t.Fatal("an unreadable action-item register loaded silently — every open item reads as closed out, and the next Put destroys the file")
	}
	err := s.Put("acme", "corr-1", ActionItem{ID: "ai-2", Action: "second", Status: "open",
		Source: "human_created", CreatedAt: "2026-09-10T01:00:00Z"})
	if !errors.Is(err, ErrStoreUnreadable) {
		t.Fatalf("a Put over an unreadable action-item register returned %v", err)
	}
	if got := s.List("acme", "corr-1"); len(got) != 0 {
		t.Fatalf("the refused item stayed in memory: %+v", got)
	}

	assertUntouched(t, path, before)
	reopened := NewActionItemStore(path)
	if reopened.Unavailable() != nil {
		t.Fatalf("the repaired file no longer loads: %v", reopened.Unavailable())
	}
	if it, ok := reopened.Get("acme", "corr-1", "ai-1"); !ok || it.Action != "replace the optic" {
		t.Fatalf("the seeded action item did not survive: %+v %v", it, ok)
	}
}

// A file that is ABSENT is still just an empty register, with nothing reported
// and writes allowed. This is the half the fix must NOT break.
func TestAbsentRcaRegistersStayEmptyAndWritable(t *testing.T) {
	dir := t.TempDir()
	p := NewPromotionStore(filepath.Join(dir, "never-written-promotions.json"))
	if err := p.Unavailable(); err != nil {
		t.Fatalf("a promotion register that was never written reported %v", err)
	}
	if err := p.Set("acme", "corr-1", PromotionRecord{PromotedBy: "u@acme"}); err != nil {
		t.Fatalf("the first Set on a fresh register failed: %v", err)
	}
	r := NewRevisionStore(filepath.Join(dir, "never-written-revisions.json"))
	if err := r.Unavailable(); err != nil {
		t.Fatalf("a revision register that was never written reported %v", err)
	}
	if _, _, err := r.Record("acme", "corr-1", ReportRevision{Format: "html"}); err != nil {
		t.Fatalf("the first Record on a fresh register failed: %v", err)
	}
	a := NewActionItemStore(filepath.Join(dir, "never-written-items.json"))
	if err := a.Unavailable(); err != nil {
		t.Fatalf("an action-item register that was never written reported %v", err)
	}
	if err := a.Put("acme", "corr-1", ActionItem{ID: "ai-1", Action: "t", Status: "open"}); err != nil {
		t.Fatalf("the first Put on a fresh register failed: %v", err)
	}
}
