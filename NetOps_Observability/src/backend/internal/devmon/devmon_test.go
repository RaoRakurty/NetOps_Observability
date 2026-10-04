// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package devmon_test

// devmon_test.go — the DEFINITION of a monitored device.
//
// One number in the product depends on this file being right: the Community
// tier's 25. Every case below is a sentence from the owner's 2026-10-03
// decision turned into an assertion — every addressable device is monitored,
// the first N by first-seen time when the licence is full — because the failure
// mode is not a crash: it is a device quietly not collected from, or the wrong
// device holding a slot.

import (
	"strings"
	"testing"
	"time"

	"netops/backend/internal/devmon"
	"netops/backend/models"
)

func cand(id, addr string, seen time.Time) devmon.Candidate {
	return devmon.Candidate{Device: models.Device{ID: id, Address: addr}, FirstSeen: seen}
}

var t0 = time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)

func TestAddresslessIsNeverMonitoredWhateverTheLimit(t *testing.T) {
	for _, limit := range []int{devmon.NoLimit, 0, 1, 100} {
		got := devmon.Assign([]devmon.Candidate{cand("ghost", "", t0), cand("ws", "  ", t0)}, limit)
		for _, id := range []string{"ghost", "ws"} {
			v := got[id]
			if v.Monitored || v.State != devmon.StateNoAddress || v.Reason != devmon.ReasonNoAddress {
				t.Fatalf("limit %d: %s = %+v", limit, id, v)
			}
		}
	}
}

func TestFirstNByFirstSeenAreMonitored(t *testing.T) {
	cands := []devmon.Candidate{
		cand("late", "10.0.0.3", t0.Add(3*time.Hour)),
		cand("first", "10.0.0.1", t0),
		cand("noaddr", "", t0.Add(-time.Hour)), // earliest, but takes no slot
		cand("second", "10.0.0.2", t0.Add(time.Hour)),
	}
	got := devmon.Assign(cands, 2)
	if !got["first"].Monitored || !got["second"].Monitored {
		t.Fatalf("the two earliest addressable devices are monitored: %+v", got)
	}
	l := got["late"]
	if l.Monitored || l.State != devmon.StateOverLimit || l.Limit != 2 || l.Reason != devmon.OverLimitReason(2) {
		t.Fatalf("the third is over the limit of 2: %+v", l)
	}
}

func TestTiesBreakOnIDSoTwoReadsAgree(t *testing.T) {
	cands := []devmon.Candidate{cand("b", "10.0.0.2", t0), cand("a", "10.0.0.1", t0), cand("c", "10.0.0.3", t0)}
	for i := 0; i < 20; i++ {
		got := devmon.Assign(cands, 1)
		if !got["a"].Monitored || got["b"].Monitored || got["c"].Monitored {
			t.Fatalf("equal first-seen must break on id: %+v", got)
		}
		cands[0], cands[2] = cands[2], cands[0] // input order must not matter
	}
}

func TestADeletionPromotesTheNextDevice(t *testing.T) {
	cands := []devmon.Candidate{cand("a", "10.0.0.1", t0), cand("b", "10.0.0.2", t0.Add(time.Minute)), cand("c", "10.0.0.3", t0.Add(2*time.Minute))}
	if devmon.Assign(cands, 2)["c"].Monitored {
		t.Fatal("precondition: c is third")
	}
	if got := devmon.Assign(cands[1:], 2); !got["b"].Monitored || !got["c"].Monitored {
		t.Fatalf("with a gone, c is promoted: %+v", got)
	}
}

func TestLicenceGrowthPromotes(t *testing.T) {
	cands := []devmon.Candidate{cand("a", "10.0.0.1", t0), cand("b", "10.0.0.2", t0.Add(time.Minute)), cand("c", "10.0.0.3", t0.Add(2*time.Minute))}
	if got := devmon.Assign(cands, 1); got["b"].Monitored {
		t.Fatal("precondition: one slot")
	}
	if got := devmon.Assign(cands, 2); !got["b"].Monitored || got["c"].Monitored {
		t.Fatalf("a bigger licence promotes exactly the next device: %+v", got)
	}
	for _, unlimited := range []int{devmon.NoLimit, -7} {
		for id, v := range devmon.Assign(cands, unlimited) {
			if !v.Monitored {
				t.Fatalf("no ceiling (%d): %s must be monitored", unlimited, id)
			}
		}
	}
	for id, v := range devmon.Assign(cands, 0) {
		if v.Monitored || v.State != devmon.StateOverLimit {
			t.Fatalf("a zero ceiling monitors nothing: %s = %+v", id, v)
		}
	}
}

func TestWirelessDevicesSayWhyInTheirOwnTerms(t *testing.T) {
	c := cand("ap1", "10.0.0.9", t0)
	c.Device.Source = devmon.SourceWireless
	if v := devmon.Assign([]devmon.Candidate{c}, 5)["ap1"]; !v.Monitored || v.Reason != devmon.ReasonWireless {
		t.Fatalf("wireless: %+v", v)
	}
}

func TestEveryVerdictCarriesAReason(t *testing.T) {
	cands := []devmon.Candidate{cand("a", "10.0.0.1", t0), cand("b", "10.0.0.2", t0.Add(time.Minute)), cand("c", "", t0)}
	for id, v := range devmon.Assign(cands, 1) {
		if v.Reason == "" || v.State == "" {
			t.Fatalf("%s has a silent verdict: %+v", id, v)
		}
	}
	if !strings.Contains(devmon.OverLimitReason(25), "licence limit of 25 devices") ||
		!strings.Contains(devmon.OverLimitReason(1), "licence limit of 1 device ") {
		t.Fatal("the over-limit sentence names the limit in plain words")
	}
}

func TestCollectingKeepsOnlyMethodsWithARunningCollector(t *testing.T) {
	on := func(m string) bool { return m == devmon.MethodGNMI }
	got := devmon.Collecting([]string{devmon.MethodGNMI, devmon.MethodSNMP}, on)
	if len(got) != 1 || got[0] != devmon.MethodGNMI {
		t.Fatalf("Collecting = %v", got)
	}
	if devmon.Collecting([]string{devmon.MethodSNMP}, nil) != nil {
		t.Fatal("no collector status means nothing can be claimed as collecting")
	}
}

func TestMethodsAreDisplayNotACount(t *testing.T) {
	cases := []struct {
		name   string
		device models.Device
		want   []string
	}{
		{
			name:   "no preferred protocol means SNMP — the poller's own default",
			device: models.Device{Address: "10.0.0.1"},
			want:   []string{devmon.MethodSNMP},
		},
		{
			name:   "the gnmi label adds a second method to the same device",
			device: models.Device{Address: "10.0.0.1", Labels: map[string]string{"gnmi": "true"}},
			want:   []string{devmon.MethodGNMI, devmon.MethodSNMP},
		},
		{
			name:   "a device with no address has no methods — nothing can collect from it",
			device: models.Device{},
			want:   nil,
		},
		{
			name:   "a declared preferred protocol replaces the SNMP default",
			device: models.Device{Address: "10.0.0.1", PreferredProtocol: "netconf"},
			want:   []string{"netconf"},
		},
		{
			name:   "a label of anything but true is not a subscription",
			device: models.Device{Address: "10.0.0.1", Labels: map[string]string{"gnmi": "planned"}},
			want:   []string{devmon.MethodSNMP},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := devmon.Methods(tc.device)
			if len(got) != len(tc.want) {
				t.Fatalf("Methods = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("Methods = %v, want %v (order must be stable)", got, tc.want)
				}
			}
		})
	}
}

func TestHasAddressMirrorsTheCollectorSkip(t *testing.T) {
	if devmon.HasAddress(models.Device{}) {
		t.Fatal("an empty address is not reachable")
	}
	if devmon.HasAddress(models.Device{Address: "\t "}) {
		t.Fatal("whitespace is not an address")
	}
	if !devmon.HasAddress(models.Device{Address: "leaf1.example.test"}) {
		t.Fatal("a hostname is an address")
	}
}
