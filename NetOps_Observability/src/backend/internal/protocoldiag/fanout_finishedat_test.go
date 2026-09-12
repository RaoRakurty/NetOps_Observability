// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package protocoldiag

// fanout_finishedat_test.go — the FinishedAt stamp on a collected device.
//
// collectOne records the end of a device's collection in a DEFERRED write. A
// defer can only reach what the caller sees through a NAMED result: with an
// unnamed one, `return st` copies the struct before the defer runs and the stamp
// lands on a dead local. The symptom was silent and uniform — every collected
// DeviceState carried a zero FinishedAt while the never-ran path (notRun, which
// stamps inline) looked correct — so a duration computed from these two fields
// read as "since the zero time" on every real device.

import (
	"context"
	"testing"
	"time"
)

// TestCollectOne_StampsFinishedAt covers all three of collectOne's exits: the
// normal collected device and BOTH unsupported early returns.
func TestCollectOne_StampsFinishedAt(t *testing.T) {
	assertStamped := func(t *testing.T, what string, st DeviceState) {
		t.Helper()
		if st.StartedAt.IsZero() {
			t.Fatalf("%s: StartedAt is zero", what)
		}
		if st.FinishedAt.IsZero() {
			t.Fatalf("%s: FinishedAt is the zero time — the deferred stamp never reached the returned value", what)
		}
		if st.FinishedAt.Before(st.StartedAt) {
			t.Errorf("%s: FinishedAt %v precedes StartedAt %v", what, st.FinishedAt, st.StartedAt)
		}
	}

	t.Run("collected device", func(t *testing.T) {
		r := newScriptedRunner()
		dev := devN(1, "Cisco IOS-XE 17.9")
		r.output[dev.ID] = bgpSummaryOutput
		c := newBatteryCollector(t, r, WithBatteryClock(fixedClock()))

		st := c.collectOne(context.Background(), dev, AreaBGP, Target{})
		if st.Status != DeviceStatusOK {
			t.Fatalf("status = %q (%s), want ok", st.Status, st.Note)
		}
		assertStamped(t, "collected device", st)
	})

	t.Run("unassessed platform", func(t *testing.T) {
		r := newScriptedRunner()
		c := newBatteryCollector(t, r, WithBatteryClock(fixedClock()))

		st := c.collectOne(context.Background(), devN(2, "Acme MysteryOS 1.0"), AreaBGP, Target{})
		if st.Status != DeviceStatusUnsupported {
			t.Fatalf("status = %q, want unsupported", st.Status)
		}
		assertStamped(t, "unassessed platform", st)
	})

	t.Run("no command for the area", func(t *testing.T) {
		// An EMPTY battery is the only way to reach the second early return: the
		// shipped battery authors at least one command for every (dialect, area)
		// pair, which is itself worth knowing.
		c, err := NewBatteryCollector(&StateBattery{}, newScriptedRunner(), WithBatteryClock(fixedClock()))
		if err != nil {
			t.Fatalf("NewBatteryCollector: %v", err)
		}
		st := c.collectOne(context.Background(), devN(3, "Cisco IOS-XE 17.9"), AreaBGP, Target{})
		if st.Status != DeviceStatusUnsupported {
			t.Fatalf("status = %q, want unsupported", st.Status)
		}
		if len(st.Commands) != 0 {
			t.Errorf("no command may be run when the area has none authored: %+v", st.Commands)
		}
		assertStamped(t, "no command for the area", st)
	})
}

// TestRunBattery_EveryDeviceCarriesFinishedAt is the same property observed where
// a caller actually reads it: through the whole fan-out, across every status.
func TestRunBattery_EveryDeviceCarriesFinishedAt(t *testing.T) {
	r := newScriptedRunner()
	healthy := devN(1, "Cisco IOS-XE 17.9")
	broken := devN(2, "Cisco IOS-XE 17.9")
	alien := devN(3, "Acme MysteryOS 1.0")
	r.output[healthy.ID] = bgpSummaryOutput
	r.fail[broken.ID] = context.DeadlineExceeded

	c := newBatteryCollector(t, r, WithDeviceTimeout(500*time.Millisecond))
	run, err := c.RunBattery(context.Background(), []Device{healthy, broken, alien}, AreaBGP, Target{})
	if err != nil {
		t.Fatalf("RunBattery: %v", err)
	}
	if len(run.Devices) != 3 {
		t.Fatalf("got %d device states, want 3", len(run.Devices))
	}
	for _, d := range run.Devices {
		if d.FinishedAt.IsZero() {
			t.Errorf("device %s (%s): FinishedAt is the zero time", d.DeviceID, d.Status)
			continue
		}
		if d.FinishedAt.Before(d.StartedAt) {
			t.Errorf("device %s: FinishedAt %v precedes StartedAt %v", d.DeviceID, d.FinishedAt, d.StartedAt)
		}
	}
}
