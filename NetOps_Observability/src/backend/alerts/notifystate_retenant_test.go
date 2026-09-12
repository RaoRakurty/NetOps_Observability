// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package alerts

// notifystate_retenant_test.go — the resolve must clear the record the FIRE
// wrote (3.8-10).
//
// THE DEFECT. MarkNotified filed the durable record under the tenant derived at
// FIRE time; Clear re-derived the tenant at RESOLVE time. Those are the same
// answer only while the device's tenancy has not changed. Delete the device, or
// move it to another tenant, between the fire and the clear, and Clear — which
// is strictly own-tenant by design (§3a) — targets a key nothing was ever
// written to. The record therefore SURVIVES its own resolution, and every
// restart inside the seven-day age-out window restores it into `active` and
// emits another resolve for an alert that ended long ago. PagerDuty and every
// other resolution-capable channel gets a close for an incident that closed
// days earlier, on every deploy, for a week.
//
// A device being deleted or re-homed while one of its alerts is firing is not
// exotic: decommissioning a device is exactly the thing that makes
// DeviceUnreachable stop firing.

import (
	"path/filepath"
	"testing"
	"time"

	"netops/backend/models"
)

// retenantRule is the alert under test: one device, one firing series.
var retenantRule = Rule{Name: "DeviceUnreachable", Expr: "up == 0", Severity: "critical"}

func retenantEval(firing *bool) func(Rule) ([]Sample, error) {
	return func(Rule) ([]Sample, error) {
		if !*firing {
			return nil, nil
		}
		return []Sample{{Labels: map[string]string{"device": "leaf1"}, Value: 0}}, nil
	}
}

func TestResolveClearsTheRecordTheFireWroteEvenAfterTheDeviceMoves(t *testing.T) {
	for _, tc := range []struct {
		name string
		// after is what TenantOf answers once the device has gone. "" is the
		// DELETED case (the engine's platform-owned default); another id is the
		// RE-TENANTED case.
		after string
	}{
		{"the device was re-tenanted", "globex"},
		{"the device was deleted", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "alert_notify_state.json")
			t0 := time.Date(2026, 9, 3, 4, 0, 0, 0, time.UTC)
			firing := true
			eval := retenantEval(&firing)

			tenant := "acme"
			r1, restored := newNotifyRig(t, path, t0, eval)
			defer r1.d.Close()
			if restored != 0 {
				t.Fatalf("a first boot restored %d records from an empty store", restored)
			}
			// The platform's device→tenant derivation. It is a LOOKUP, so it
			// answers differently once the device has moved or gone.
			r1.e.TenantOf = func(models.Alert) string { return tenant }
			r1.e.AddRule(retenantRule)

			r1.e.evaluateAll() // fires (no `for` on this rule)
			r1.waitFor(t, "the fire notification", func() bool { return len(r1.ch.sent) == 1 })
			if got := r1.store.List("acme"); len(got) != 1 {
				t.Fatalf("the fire filed %d records under acme, want 1", len(got))
			}

			// ── the device moves, and then the alert clears ─────────────────
			tenant = tc.after
			firing = false
			r1.clock.advance(time.Minute)
			r1.e.evaluateAll() // resolves
			r1.waitFor(t, "the resolve notification", func() bool { return len(r1.ch.resolved) == 1 })

			if got := r1.store.List("acme"); len(got) != 0 {
				t.Fatalf("the notified record SURVIVED its own resolution: %+v. The fire filed it under "+
					"acme; the resolve re-derived the tenant (%q) and cleared a key nothing was ever "+
					"written to. Every restart for the next seven days will restore this record and "+
					"re-emit a resolve for an alert that is long over.", got, tc.after)
			}
			if tc.after != "" {
				if got := r1.store.List(tc.after); len(got) != 0 {
					t.Fatalf("a record appeared under %q: %+v — the notified set must never be written "+
						"under a tenant the fire did not file it under", tc.after, got)
				}
			}

			// ── the restart the defect turned into a duplicate resolve ──────
			r2, restored := newNotifyRig(t, path, t0.Add(20*time.Minute), eval)
			defer r2.d.Close()
			if restored != 0 {
				t.Fatalf("a restart restored %d records for an alert that already resolved", restored)
			}
			r2.e.TenantOf = func(models.Alert) string { return tenant }
			r2.e.AddRule(retenantRule)
			r2.e.evaluateAll()
			r2.quiet(t, 0, 0)
		})
	}
}

// The ordinary case must be untouched: a device that never moves still clears
// its own record, and the notified set is still keyed by the tenant the fire
// derived — not by anything in the alert's labels (§3a rule 2).
func TestResolveStillClearsTheOrdinaryCase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alert_notify_state.json")
	t0 := time.Date(2026, 9, 3, 4, 0, 0, 0, time.UTC)
	firing := true
	r, _ := newNotifyRig(t, path, t0, retenantEval(&firing))
	defer r.d.Close()
	r.e.TenantOf = func(models.Alert) string { return "acme" }
	r.e.AddRule(retenantRule)

	r.e.evaluateAll()
	r.waitFor(t, "the fire notification", func() bool { return len(r.ch.sent) == 1 })
	if got := r.store.List("acme"); len(got) != 1 {
		t.Fatalf("records under acme = %d, want 1", len(got))
	}
	if got := r.store.List(""); len(got) != 0 {
		t.Fatalf("a device-owned alert was filed as platform-owned: %+v", got)
	}
	firing = false
	r.clock.advance(time.Minute)
	r.e.evaluateAll()
	r.waitFor(t, "the resolve notification", func() bool { return len(r.ch.resolved) == 1 })
	if got := r.store.List("acme"); len(got) != 0 {
		t.Fatalf("the record outlived its resolution: %+v", got)
	}
}

// A RESTORED record (the process restarted while the alert was firing) carries
// its own tenant, and the resolve after the restart must use THAT — the engine
// has no memory of the fire, so a re-derivation would be the same defect one
// restart later.
func TestARestoredRecordIsClearedUnderItsOwnTenant(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alert_notify_state.json")
	t0 := time.Date(2026, 9, 3, 4, 0, 0, 0, time.UTC)
	firing := true
	eval := retenantEval(&firing)

	r1, _ := newNotifyRig(t, path, t0, eval)
	r1.e.TenantOf = func(models.Alert) string { return "acme" }
	r1.e.AddRule(retenantRule)
	r1.e.evaluateAll()
	r1.waitFor(t, "the fire notification", func() bool { return len(r1.ch.sent) == 1 })
	r1.d.Close()

	// The process restarts, and only THEN does the device move away.
	r2, restored := newNotifyRig(t, path, t0.Add(10*time.Minute), eval)
	defer r2.d.Close()
	if restored != 1 {
		t.Fatalf("restored %d records across the restart, want 1", restored)
	}
	r2.e.TenantOf = func(models.Alert) string { return "globex" }
	r2.e.AddRule(retenantRule)
	firing = false
	r2.e.evaluateAll()
	r2.waitFor(t, "the resolve notification", func() bool { return len(r2.ch.resolved) == 1 })
	if got := r2.store.List("acme"); len(got) != 0 {
		t.Fatalf("a restored record was cleared under the wrong tenant and survived: %+v", got)
	}
}
