// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package maintenance

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func tp(s string) *time.Time { t := ts(s); return &t }

func TestValidateShapes(t *testing.T) {
	cases := []struct {
		name string
		w    Window
		ok   bool
	}{
		{"one-shot ok", Window{Name: "chg", StartsAt: tp("2026-08-01T22:00:00Z"), EndsAt: tp("2026-08-02T02:00:00Z")}, true},
		{"neither shape", Window{Name: "chg"}, false},
		{"one-shot missing end", Window{Name: "chg", StartsAt: tp("2026-08-01T22:00:00Z")}, false},
		{"one-shot inverted", Window{Name: "chg", StartsAt: tp("2026-08-02T02:00:00Z"), EndsAt: tp("2026-08-01T22:00:00Z")}, false},
		{"one-shot too long", Window{Name: "chg", StartsAt: tp("2026-01-01T00:00:00Z"), EndsAt: tp("2026-12-01T00:00:00Z")}, false},
		{"recurring ok", Window{Name: "patch", Schedule: &Schedule{Weekdays: []string{"sat"}, StartHour: 22, DurationMinutes: 240}}, true},
		{"recurring bad weekday", Window{Name: "patch", Schedule: &Schedule{Weekdays: []string{"caturday"}, StartHour: 22, DurationMinutes: 240}}, false},
		{"recurring bad tz", Window{Name: "patch", Schedule: &Schedule{TZ: "Mars/Olympus", StartHour: 22, DurationMinutes: 60}}, false},
		{"recurring zero duration", Window{Name: "patch", Schedule: &Schedule{StartHour: 22}}, false},
		{"recurring with ends_at", Window{Name: "patch", Schedule: &Schedule{StartHour: 22, DurationMinutes: 60}, EndsAt: tp("2026-08-02T02:00:00Z")}, false},
		{"empty name", Window{StartsAt: tp("2026-08-01T22:00:00Z"), EndsAt: tp("2026-08-02T02:00:00Z")}, false},
		{"control chars in name", Window{Name: "a\x00b", StartsAt: tp("2026-08-01T22:00:00Z"), EndsAt: tp("2026-08-02T02:00:00Z")}, false},
	}
	for _, c := range cases {
		if err := c.w.Validate(); (err == nil) != c.ok {
			t.Errorf("%s: Validate() = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestActiveAtOneShot(t *testing.T) {
	w := Window{Name: "chg", Enabled: true,
		StartsAt: tp("2026-08-01T22:00:00Z"), EndsAt: tp("2026-08-02T02:00:00Z")}
	if w.ActiveAt(ts("2026-08-01T21:59:59Z")) {
		t.Error("before start must not be active")
	}
	if !w.ActiveAt(ts("2026-08-01T22:00:00Z")) || !w.ActiveAt(ts("2026-08-02T01:59:59Z")) {
		t.Error("inside [start,end) must be active")
	}
	if w.ActiveAt(ts("2026-08-02T02:00:00Z")) {
		t.Error("end is exclusive")
	}
	w.Enabled = false
	if w.ActiveAt(ts("2026-08-01T23:00:00Z")) {
		t.Error("disabled window must never be active")
	}
}

func TestActiveAtRecurringSpansMidnight(t *testing.T) {
	// Saturday 22:00 America/Chicago for 6h — spans into Sunday local time.
	w := Window{Name: "patch", Enabled: true,
		Schedule: &Schedule{TZ: "America/Chicago", Weekdays: []string{"sat"}, StartHour: 22, DurationMinutes: 360}}
	// 2026-08-01 is a Saturday. 23:30 CDT = 04:30Z Sunday.
	if !w.ActiveAt(ts("2026-08-02T04:30:00Z")) {
		t.Error("Sat 23:30 local (inside the window) must be active")
	}
	// Sunday 02:30 CDT (07:30Z) — still inside the 6h span that STARTED Saturday.
	if !w.ActiveAt(ts("2026-08-02T07:30:00Z")) {
		t.Error("spillover past local midnight must stay active")
	}
	// Sunday 04:30 CDT — past the 6h span.
	if w.ActiveAt(ts("2026-08-02T09:30:00Z")) {
		t.Error("past the duration must not be active")
	}
	// Tuesday same wall-clock — wrong weekday.
	if w.ActiveAt(ts("2026-08-05T04:30:00Z")) {
		t.Error("a non-listed weekday must not be active")
	}
	// `until` bounds the series.
	w.Until = tp("2026-08-01T00:00:00Z")
	if w.ActiveAt(ts("2026-08-02T04:30:00Z")) {
		t.Error("past until must not be active")
	}
}

func TestScopeMatching(t *testing.T) {
	w := Window{Name: "scoped", Enabled: true,
		StartsAt: tp("2026-08-01T00:00:00Z"), EndsAt: tp("2026-08-02T00:00:00Z"),
		DeviceIDs: []string{"core-1"}, Sites: []string{"dallas"}}
	at := ts("2026-08-01T12:00:00Z")
	if !w.Covers(at, "core-1", "dallas", "AnyRule") {
		t.Error("matching device+site must be covered (empty rules list = all rules)")
	}
	if w.Covers(at, "core-2", "dallas", "AnyRule") {
		t.Error("unlisted device must not be covered")
	}
	if w.Covers(at, "core-1", "", "AnyRule") {
		t.Error("sites-scoped window must NOT cover an alert with unknown site")
	}
	tenantWide := Window{Name: "all", Enabled: true,
		StartsAt: tp("2026-08-01T00:00:00Z"), EndsAt: tp("2026-08-02T00:00:00Z")}
	if !tenantWide.Covers(at, "", "", "") {
		t.Error("scope-less window covers everything in its tenant")
	}
}

func TestFileStoreTenantIsolation(t *testing.T) {
	ctx := context.Background()
	s := NewFileStore(filepath.Join(t.TempDir(), "windows.json"))
	mk := func(tenant, name string) Window {
		w, err := s.Create(ctx, tenant, false, Window{TenantID: tenant, Name: name, Enabled: true,
			StartsAt: tp("2026-08-01T00:00:00Z"), EndsAt: tp("2026-08-02T00:00:00Z")})
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	wa := mk("acme", "acme window")
	wb := mk("globex", "globex window")

	la, _ := s.List(ctx, "acme", false)
	if len(la) != 1 || la[0].ID != wa.ID {
		t.Fatalf("acme must list only its own window: %+v", la)
	}
	if _, found, _ := s.Get(ctx, "acme", false, wb.ID); found {
		t.Fatal("TENANT LEAK: acme read globex's window")
	}
	if _, found, _ := s.Update(ctx, "acme", false, wb.ID, wb); found {
		t.Fatal("TENANT LEAK: acme updated globex's window")
	}
	if found, _ := s.Delete(ctx, "acme", false, wb.ID); found {
		t.Fatal("TENANT LEAK: acme deleted globex's window")
	}
	if all, _ := s.List(ctx, "", true); len(all) != 2 {
		t.Fatalf("cross principal must see both: %+v", all)
	}

	// Covering is strictly per-tenant.
	at := ts("2026-08-01T12:00:00Z")
	if _, cov, _ := s.Covering(ctx, "acme", "dev", "", "rule", at); !cov {
		t.Fatal("acme's tenant-wide window must cover its own alert")
	}
	if _, cov, _ := s.Covering(ctx, "initech", "dev", "", "rule", at); cov {
		t.Fatal("TENANT LEAK: another tenant's window suppressed initech")
	}

	// Persistence round-trip.
	s2 := NewFileStore(s.path)
	l2, _ := s2.List(ctx, "globex", false)
	if len(l2) != 1 || l2[0].Name != "globex window" {
		t.Fatalf("reload must keep windows: %+v", l2)
	}
}
