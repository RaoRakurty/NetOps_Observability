package licence_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/entitlement"
	"netops/backend/internal/licence"
)

// overage_test.go — soft overage: what it records, what it says, and the one
// thing it must never do (block anything).

// overStore returns a Store fixed at a Team state with the given device ceiling.
func overState(t *testing.T, tier entitlement.Tier, devices int) licence.State {
	t.Helper()
	c, ok := entitlement.TierCeilings(tier)
	if !ok {
		t.Fatalf("no reference ceilings for %q", tier)
	}
	c.Devices = devices
	return licence.State{
		Source: licence.SourceFile, Tier: tier, LicensedTier: tier,
		Phase: entitlement.PhaseValid, Ceilings: c,
		Features:  []entitlement.Feature{entitlement.FeatureSecurityFindings},
		Customer:  "Overage Test Ltd",
		LicenceID: "overage-test",
		IssuedAt:  time.Now().UTC().AddDate(0, -1, 0),
		ExpiresAt: time.Now().UTC().AddDate(1, 0, 0),
	}
}

// TestSoftOverageIsListedAsATrueUp: on a paid tier the overage reads as a
// billing fact, not a fault. The words matter — "blocked" or "not covered"
// would be untrue and would send an operator hunting for a device that stopped.
func TestSoftOverageIsListedAsATrueUp(t *testing.T) {
	st := overState(t, entitlement.TierTeam, 250)
	over := st.Overages(licence.Usage{entitlement.CeilingDevices: 262})
	if len(over) != 1 {
		t.Fatalf("want exactly one overage, got %+v", over)
	}
	o := over[0]
	if !o.Soft {
		t.Fatal("the monitored-device ceiling is SOFT on Team; a page that renders it as a block would be lying")
	}
	if o.Over != 12 || o.Current != 262 || o.Limit != 250 {
		t.Fatalf("overage arithmetic: %+v", o)
	}
	if o.Unit != entitlement.UnitMonitoredDevices {
		t.Fatalf("unit = %q, want monitored_devices (C4 wording)", o.Unit)
	}
	for _, want := range []string{"true-up", "Monitoring continues", "nothing has been blocked, disabled or deleted"} {
		if !strings.Contains(o.Message, want) {
			t.Fatalf("the soft-overage message must contain %q: %q", want, o.Message)
		}
	}
	// And no contractual window is invented anywhere in the sentence.
	for _, banned := range []string{"days to", "you have", "must be resolved", "will be disabled"} {
		if strings.Contains(strings.ToLower(o.Message), banned) {
			t.Fatalf("the product must not invent an overage window (%q): %q", banned, o.Message)
		}
	}
}

// TestHardOverageStillReadsAsUncovered: on Community — and after a lapse — the
// ceiling is hard, and the honest sentence is the older one: the devices are
// still here, and they are not covered.
func TestHardOverageStillReadsAsUncovered(t *testing.T) {
	st := licence.Community()
	over := st.Overages(licence.Usage{entitlement.CeilingDevices: 40})
	if len(over) != 1 {
		t.Fatalf("want one overage, got %+v", over)
	}
	if over[0].Soft {
		t.Fatal("the Community device ceiling is HARD")
	}
	if !strings.Contains(over[0].Message, "nothing has been deleted") {
		t.Fatalf("a hard overage must still say nothing was deleted: %q", over[0].Message)
	}
}

// TestOverageTrackerRemembersSince is why the register exists at all: `since`
// is the one fact a process that only sees "now" cannot recover after a
// restart.
func TestOverageTrackerRemembersSince(t *testing.T) {
	path := filepath.Join(t.TempDir(), "licence-overage.json")
	st := overState(t, entitlement.TierTeam, 250)
	t0 := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	tr := licence.NewOverageTracker(path, nil)
	first := tr.Observe(st, licence.Usage{entitlement.CeilingDevices: 260}, t0)
	if len(first) != 1 || !first[0].Since.Equal(t0) {
		t.Fatalf("the episode must be stamped with when it began: %+v", first)
	}
	later := tr.Observe(st, licence.Usage{entitlement.CeilingDevices: 275}, t0.Add(48*time.Hour))
	if !later[0].Since.Equal(t0) {
		t.Fatalf("since = %s, want the ORIGINAL start %s — a growing overage is the same episode", later[0].Since, t0)
	}

	// A restart: a brand-new tracker over the same file must not restart the
	// clock, which is the entire point of writing it down.
	reborn := licence.NewOverageTracker(path, nil)
	after := reborn.Observe(st, licence.Usage{entitlement.CeilingDevices: 270}, t0.Add(72*time.Hour))
	if !after[0].Since.Equal(t0) {
		t.Fatalf("since after a restart = %s, want %s", after[0].Since, t0)
	}
	recs := reborn.Records()
	if len(recs) != 1 || recs[0].Peak != 275 {
		t.Fatalf("the register must remember the PEAK (275), which is the number a true-up needs: %+v", recs)
	}
}

// TestOverageTrackerForgetsAClosedEpisode: this register answers "since when
// are you over". Once you are not, there is no answer, and keeping a history
// here would quietly turn it into a metering store (a different data contract,
// tracker 258).
func TestOverageTrackerForgetsAClosedEpisode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "licence-overage.json")
	st := overState(t, entitlement.TierTeam, 250)
	t0 := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	tr := licence.NewOverageTracker(path, nil)
	tr.Observe(st, licence.Usage{entitlement.CeilingDevices: 260}, t0)
	if _, ok := tr.Since(entitlement.CeilingDevices); !ok {
		t.Fatal("an open episode must have a since")
	}
	if got := tr.Observe(st, licence.Usage{entitlement.CeilingDevices: 249}, t0.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("back under the ceiling there is no overage: %+v", got)
	}
	if _, ok := tr.Since(entitlement.CeilingDevices); ok {
		t.Fatal("a closed episode must be forgotten, not archived")
	}
	// And a NEW episode starts a new clock.
	again := tr.Observe(st, licence.Usage{entitlement.CeilingDevices: 251}, t0.Add(2*time.Hour))
	if len(again) != 1 || !again[0].Since.Equal(t0.Add(2*time.Hour)) {
		t.Fatalf("a new episode starts now, not at the old start: %+v", again)
	}
}

// TestOverageTrackerFailsSoft: a register that cannot be written costs the
// start time and NOTHING else. A bookkeeping problem must never be able to
// interfere with device admission or blank a page.
func TestOverageTrackerFailsSoft(t *testing.T) {
	dir := t.TempDir()
	// A DIRECTORY where the file should be: every write fails, every read fails.
	path := filepath.Join(dir, "licence-overage.json")
	if err := os.Mkdir(path, 0o750); err != nil {
		t.Fatal(err)
	}
	st := overState(t, entitlement.TierTeam, 250)
	tr := licence.NewOverageTracker(path, nil)
	over := tr.Observe(st, licence.Usage{entitlement.CeilingDevices: 260}, time.Now().UTC())
	if len(over) != 1 || over[0].Over != 10 {
		t.Fatalf("the overage must still be reported when the register cannot be kept: %+v", over)
	}
	if tr.Err() == nil {
		t.Fatal("the problem must be recorded so an operator can be told the register is not being kept")
	}

	// A nil tracker is the no-register build and behaves the same way.
	var none *licence.OverageTracker
	if got := none.Observe(st, licence.Usage{entitlement.CeilingDevices: 260}, time.Now()); len(got) != 1 {
		t.Fatalf("a nil tracker must still list the overage: %+v", got)
	}
	if _, ok := none.Since(entitlement.CeilingDevices); ok {
		t.Fatal("a nil tracker has no since to report")
	}
}

// TestWriteUsageMetrics is the alerting contract: the three series the
// 80/90/100 % rules divide, plus the overage gauge — and the COMMUNITY GUARD,
// which is that `netops_licence_ceiling_soft` is 0 on the free tier so no
// soft-overage rule can select it.
func TestWriteUsageMetrics(t *testing.T) {
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	t.Run("paid tier over its allowance", func(t *testing.T) {
		svc := licence.NewService(licence.NewStaticStore(overState(t, entitlement.TierTeam, 250)))
		svc.SetOverageTracker(licence.NewOverageTracker(filepath.Join(t.TempDir(), "o.json"), nil))
		var b bytes.Buffer
		svc.WriteUsageMetrics(&b, licence.Usage{entitlement.CeilingDevices: 262}, now)
		out := b.String()
		for _, want := range []string{
			`netops_licence_ceiling{ceiling="devices",unit="monitored_devices"} 250`,
			`netops_licence_usage{ceiling="devices",unit="monitored_devices"} 262`,
			`netops_licence_ceiling_soft{ceiling="devices"} 1`,
			"netops_licence_overage_devices 12",
			`netops_licence_overage_since_seconds{ceiling="devices"} ` + strconv.FormatInt(now.Unix(), 10),
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("missing %q in:\n%s", want, out)
			}
		}
	})

	t.Run("community is never soft", func(t *testing.T) {
		svc := licence.NewService(licence.NewStaticStore(licence.Community()))
		var b bytes.Buffer
		svc.WriteUsageMetrics(&b, licence.Usage{entitlement.CeilingDevices: 12}, now)
		out := b.String()
		if !strings.Contains(out, `netops_licence_ceiling_soft{ceiling="devices"} 0`) {
			t.Fatalf("Community's device ceiling is HARD — the soft flag is the guard that keeps a free-tier deployment out of every overage rule:\n%s", out)
		}
		if !strings.Contains(out, "netops_licence_overage_devices 0") {
			t.Fatalf("the overage gauge must be present as a ZERO, so a vanished series means a scrape failure:\n%s", out)
		}
		if !strings.Contains(out, `netops_licence_ceiling_soft{ceiling="watched_prefixes"} 0`) {
			t.Fatalf("every enforced ceiling reports its softness every scrape:\n%s", out)
		}
	})

	t.Run("an unmeasured ceiling has no usage series", func(t *testing.T) {
		svc := licence.NewService(licence.NewStaticStore(licence.Community()))
		var b bytes.Buffer
		// Devices measured, watched prefixes NOT.
		svc.WriteUsageMetrics(&b, licence.Usage{entitlement.CeilingDevices: 3}, now)
		out := b.String()
		if strings.Contains(out, `netops_licence_usage{ceiling="watched_prefixes"`) {
			t.Fatalf("a ceiling nobody counted must have NO usage series — a fabricated 0 would be divided by the ceiling rules:\n%s", out)
		}
		if !strings.Contains(out, `netops_licence_ceiling{ceiling="watched_prefixes"`) {
			t.Fatalf("the LIMIT is always known and is always emitted:\n%s", out)
		}
	})

	t.Run("nil service writes nothing and does not panic", func(t *testing.T) {
		var svc *licence.Service
		var b bytes.Buffer
		svc.WriteUsageMetrics(&b, licence.Usage{entitlement.CeilingDevices: 3}, now)
		if b.Len() != 0 {
			t.Fatalf("a nil service must emit nothing: %s", b.String())
		}
	})
}
