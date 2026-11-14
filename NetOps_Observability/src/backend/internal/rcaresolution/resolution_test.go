// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rcaresolution

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEveryKindHasALabelAndNoOtherKindIsValid(t *testing.T) {
	for _, k := range Kinds {
		if !Valid(k) || Label(k) == "" {
			t.Fatalf("kind %q must be valid with a label", k)
		}
	}
	if len(Kinds) != len(kindLabels) {
		t.Fatalf("Kinds (%d) and labels (%d) drifted", len(Kinds), len(kindLabels))
	}
	for _, k := range []Kind{"", "Reboot", "reboot ", "drop_table"} {
		if Valid(k) {
			t.Fatalf("%q must not be valid", k)
		}
	}
}

func TestFromRequest(t *testing.T) {
	good := []Request{
		{Kind: "reboot"},
		{Kind: " capacity_add ", Note: "  added a second 10G uplink  "},
		{Kind: "other", Note: "replaced the patch cable"},
		{Kind: "config_rollback", ChangeID: "CHG-1042"},
		{Kind: "routing_change", ChangeID: "a1b2c3d4-e5f6:7"},
		{Kind: "provider_ticket", Note: strings.Repeat("é", NoteMax)}, // runes, not bytes
	}
	for _, in := range good {
		r, err := FromRequest(in)
		if err != nil {
			t.Fatalf("%+v: unexpected error %v", in, err)
		}
		if r.Note != strings.TrimSpace(in.Note) || string(r.Kind) != strings.TrimSpace(in.Kind) {
			t.Fatalf("%+v: normalised wrong: %+v", in, r)
		}
	}
	bad := map[Request]error{
		{Kind: "nope"}:  ErrKind,
		{Kind: "other"}: ErrOther,
		{Kind: "reboot", Note: strings.Repeat("x", NoteMax+1)}: ErrNote,
		{Kind: "reboot", Note: "a\nb"}:                         ErrNote,
		{Kind: "reboot", Note: "a\tb"}:                         ErrNote,
		{Kind: "reboot", Note: "a\u200bb"}:                     ErrNote,
		{Kind: "reboot", Note: "a\u2066b"}:                     ErrNote,
		{Kind: "reboot", Note: "\xff"}:                         ErrNote,
		{Kind: "reboot", ChangeID: "-starts-with-dash"}:        ErrChange,
		{Kind: "reboot", ChangeID: "has space"}:                ErrChange,
		{Kind: "reboot", ChangeID: strings.Repeat("a", 65)}:    ErrChange,
	}
	for in, want := range bad {
		if _, err := FromRequest(in); !errors.Is(err, want) {
			t.Fatalf("%+v: err = %v, want %v", in, err, want)
		}
	}
}

func TestFileStoreIsTenantKeyed(t *testing.T) {
	ctx := context.Background()
	s := NewFileStore("")
	now := time.Now().UTC()
	add := func(tenant, id string, k Kind, at time.Time) Resolution {
		r, err := s.Add(ctx, tenant, Resolution{TenantID: tenant, CorrelationID: id, Kind: k, CreatedAt: at})
		if err != nil {
			t.Fatalf("add: %v", err)
		}
		return r
	}
	add("acme", "c1", KindReboot, now.Add(-time.Hour))
	newest := add("acme", "c1", KindConfigRollback, now)
	add("globex", "c1", KindHardwareReplace, now.Add(time.Hour))
	add("globex", "c2", KindCapacityAdd, now)

	// Writing into another tenant than the row's owner is refused.
	if _, err := s.Add(ctx, "acme", Resolution{TenantID: "globex", CorrelationID: "c9", Kind: KindReboot}); err == nil {
		t.Fatal("a row for globex was written under acme's scope")
	}

	own, _ := s.List(ctx, "acme", false, "c1")
	if len(own) != 2 || own[0].ID != newest.ID {
		t.Fatalf("own list must be acme-only, newest first: %+v", own)
	}
	all, _ := s.List(ctx, "acme", true, "c1")
	if len(all) != 3 {
		t.Fatalf("cross list = %d rows, want 3", len(all))
	}
	latest, _ := s.Latest(ctx, "acme", []string{"c1", "c2", "c1", ""})
	if len(latest) != 1 || latest["c1"].Kind != KindConfigRollback {
		t.Fatalf("Latest must be acme's newest only (no globex c2): %+v", latest)
	}
}

func TestFileStoreLimitAndPersistence(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "res.json")
	s := NewFileStore(path)
	for i := 0; i < MaxPerCase; i++ {
		if _, err := s.Add(ctx, "acme", Resolution{TenantID: "acme", CorrelationID: "c1", Kind: KindReboot}); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	if _, err := s.Add(ctx, "acme", Resolution{TenantID: "acme", CorrelationID: "c1", Kind: KindReboot}); !errors.Is(err, ErrLimit) {
		t.Fatalf("over the per-case cap: err = %v, want ErrLimit", err)
	}
	reloaded := NewFileStore(path)
	rows, _ := reloaded.List(ctx, "acme", false, "c1")
	if len(rows) != MaxPerCase || rows[0].TenantID != "acme" {
		t.Fatalf("persisted rows = %d (tenant %q), want %d acme rows", len(rows), rows[0].TenantID, MaxPerCase)
	}
	other, _ := reloaded.List(ctx, "globex", false, "c1")
	if len(other) != 0 {
		t.Fatalf("reload leaked rows into another tenant: %+v", other)
	}
}

func TestFileStoreRefusesWritesWhenTheFileIsUnreadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "res.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewFileStore(path)
	_, err := s.Add(context.Background(), "acme", Resolution{TenantID: "acme", CorrelationID: "c1", Kind: KindReboot})
	if !errors.Is(err, ErrStoreUnreadable) {
		t.Fatalf("write over an unreadable file: err = %v, want ErrStoreUnreadable", err)
	}
	b, rerr := os.ReadFile(path)
	if rerr != nil || string(b) != "{not json" {
		t.Fatalf("the unreadable file was replaced: %q err=%v", b, rerr)
	}
	if rows, _ := s.List(context.Background(), "acme", false, "c1"); len(rows) != 0 {
		t.Fatalf("a refused write still left a row in memory: %+v", rows)
	}
}

// TestRecentStaysInTheTenantAndTheWindow: the learning loop's read (N-F5)
// returns only the caller's own rows recorded since the cut, newest first.
func TestRecentStaysInTheTenantAndTheWindow(t *testing.T) {
	ctx := context.Background()
	s := NewFileStore("")
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for i, at := range []time.Time{base, base.Add(48 * time.Hour), base.Add(96 * time.Hour)} {
		if _, err := s.Add(ctx, "acme", Resolution{TenantID: "acme", CorrelationID: "c" + string(rune('1'+i)), Kind: KindReboot, CreatedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Add(ctx, "globex", Resolution{TenantID: "globex", CorrelationID: "c9", Kind: KindReboot, CreatedAt: base.Add(72 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.Recent(ctx, "acme", base.Add(24*time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].CorrelationID != "c3" || rows[1].CorrelationID != "c2" {
		t.Fatalf("recent = %+v, want c3 then c2 (acme only, since the cut)", rows)
	}
	if one, _ := s.Recent(ctx, "acme", base, 1); len(one) != 1 {
		t.Fatalf("limit 1 returned %d rows", len(one))
	}
}
