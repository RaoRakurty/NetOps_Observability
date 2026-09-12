// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery

// vendor_enrichment_test.go — what the SNMP enrichment pass writes onto a
// discovered device, and whether the OS-VERSION LADDER can act on it afterwards.

import (
	"context"
	"testing"
	"time"

	"netops/backend/internal/osprobe"
	"netops/backend/models"
)

// ciscoSysDescr is a Cisco sysDescr of the ordinary shape: a product sentence
// with the version phrase inside it. SYNTHETIC (authored 2026-09-10), not read
// off a device — nothing here parses it, it only has to be a non-empty
// description the enrichment can carry.
const ciscoSysDescr = "Cisco IOS Software, ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 15.2(4)S7, RELEASE SOFTWARE (fc4)"

// fakeDetector is the injected stand-in for the SNMP vendor/sysDescr read.
func fakeDetector(vendor, descr string) func(context.Context, string, string) (string, string) {
	return func(context.Context, string, string) (string, string) { return vendor, descr }
}

// TestEnrichVendors_StampsVersionProvenance is review 3.5-21.
//
// The enrichment reads the sysDescr off the device and puts it on the row's
// version leaf. It used to write the VALUE and not its PROVENANCE, and
// internal/osprobe reads an empty os_version_source as "a person typed this" —
// a value no rung is allowed to replace. So osprobe.Plan returned no rungs and
// the ladder never ran for a discovered device: permanently, for a row that
// comes back from the store already carrying the value.
func TestEnrichVendors_StampsVersionProvenance(t *testing.T) {
	t.Run("a freshly enriched row plans the SNMP rung", func(t *testing.T) {
		a := NewDiscoveryAggregator()
		a.cache["r1"] = models.Device{ID: "r1", Name: "r1", Address: "192.0.2.10", Source: "static"}
		a.detectVendor = fakeDetector("cisco", ciscoSysDescr)

		before := time.Now().UTC()
		a.enrichVendors(context.Background(), "public")

		got := a.cache["r1"]
		if got.Vendor != "cisco" {
			t.Fatalf("Vendor = %q, want cisco — the enrichment did not run", got.Vendor)
		}
		if got.OSVersion != TruncateDescr(ciscoSysDescr) {
			t.Fatalf("OSVersion = %q, want the sysDescr", got.OSVersion)
		}
		if got.OSVersionSource != string(osprobe.MethodSNMP) {
			t.Errorf("OSVersionSource = %q, want %q — the row cannot say where its version came from",
				got.OSVersionSource, osprobe.MethodSNMP)
		}
		if got.OSVersionAt.Before(before) || got.OSVersionAt.IsZero() {
			t.Errorf("OSVersionAt = %v, want the time of this read (>= %v) — the row cannot say how old its version is",
				got.OSVersionAt, before)
		}

		// THE CONSUMER. This is the assertion the defect is really about: the
		// ladder has to be able to plan a rung for this row.
		plan := osprobe.Plan(osprobe.Current{
			Version: got.OSVersion, Source: osprobe.Method(got.OSVersionSource), At: got.OSVersionAt,
		})
		if len(plan) == 0 {
			t.Fatal("osprobe.Plan returned no rungs: the version ladder is locked out for every discovered device")
		}
		if plan[0] != osprobe.MethodSNMP {
			t.Errorf("planned %v, want the SNMP rung — the rung that wrote the value is the one allowed to refresh it", plan)
		}
	})

	t.Run("the same row reaches the real candidate selection with a plan", func(t *testing.T) {
		a := NewDiscoveryAggregator()
		a.cache["r1"] = models.Device{ID: "r1", Name: "r1", Address: "192.0.2.10", Source: "static"}
		a.detectVendor = fakeDetector("cisco", ciscoSysDescr)
		a.enrichVendors(context.Background(), "public")

		cands := a.osProbeCandidatesLocked(time.Now().UTC())
		if len(cands) != 1 {
			t.Fatalf("got %d probe candidates, want 1", len(cands))
		}
		if len(osprobe.Plan(cands[0].current)) == 0 {
			t.Fatal("the candidate is dialled with NO version rung planned: the ladder can only ever read its serial")
		}
	})

	t.Run("a stored row that already holds the sysDescr gets its provenance filled in", func(t *testing.T) {
		// The permanent case: the row came back from the store carrying the
		// value a previous run wrote, and nothing would ever have stamped it.
		a := NewDiscoveryAggregator()
		a.cache["r1"] = models.Device{
			ID: "r1", Name: "r1", Address: "192.0.2.10", Source: "static",
			OSVersion: TruncateDescr(ciscoSysDescr),
		}
		a.detectVendor = fakeDetector("cisco", ciscoSysDescr)
		a.enrichVendors(context.Background(), "public")

		got := a.cache["r1"]
		if got.OSVersionSource != string(osprobe.MethodSNMP) || got.OSVersionAt.IsZero() {
			t.Fatalf("provenance = (%q at %v), want (snmp at now)", got.OSVersionSource, got.OSVersionAt)
		}
	})

	t.Run("an operator's version is never relabelled as a probe reading", func(t *testing.T) {
		// A hand-written version whose text happens to equal the sysDescr keeps
		// its manual provenance: the second arm fills an EMPTY source only.
		at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		a := NewDiscoveryAggregator()
		a.cache["r1"] = models.Device{
			ID: "r1", Name: "r1", Address: "192.0.2.10", Source: "static",
			OSVersion: TruncateDescr(ciscoSysDescr), OSVersionSource: string(osprobe.MethodManual), OSVersionAt: at,
		}
		a.detectVendor = fakeDetector("cisco", ciscoSysDescr)
		a.enrichVendors(context.Background(), "public")

		got := a.cache["r1"]
		if got.OSVersionSource != string(osprobe.MethodManual) || !got.OSVersionAt.Equal(at) {
			t.Fatalf("provenance = (%q at %v), want the operator's (manual at %v)",
				got.OSVersionSource, got.OSVersionAt, at)
		}
	})

	t.Run("a device that answers with nothing is left alone", func(t *testing.T) {
		a := NewDiscoveryAggregator()
		a.cache["r1"] = models.Device{ID: "r1", Name: "r1", Address: "192.0.2.10", Source: "static"}
		a.detectVendor = fakeDetector("", "")
		a.enrichVendors(context.Background(), "public")

		got := a.cache["r1"]
		if got.OSVersion != "" || got.OSVersionSource != "" || !got.OSVersionAt.IsZero() {
			t.Fatalf("invented (%q via %q at %v) for a device that answered with nothing",
				got.OSVersion, got.OSVersionSource, got.OSVersionAt)
		}
	})
}
