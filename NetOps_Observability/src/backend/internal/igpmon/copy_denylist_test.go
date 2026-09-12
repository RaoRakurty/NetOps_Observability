// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package igpmon

// copy_denylist_test.go — a COPY guard, not a behaviour guard.
//
// fetchLive serves BOTH the per-device handlers and the FLEET roll-up
// (handleSummary calls it with no device ids), so every sentence it can put in
// front of an operator has to be true of a set of devices as well as of one.
// D-8 was exactly that: `GET /api/protocols/ospf/summary` — a fleet answer —
// said "no live series collected for this device", while the four sibling notes
// (LSDB, SPF, areas, timers) said "these devices".
//
// The guard asserts on the RENDERED notes of the real handlers — the array the
// UI reads — not on the source text, so it keeps holding if a note is reworded,
// moved, or a sixth one is added.

import (
	"strings"
	"testing"
)

// perDevicePhrases are the singular subjects a coverage note may not use. A
// note is rendered by a fleet roll-up as readily as by a device page; naming
// one box misattributes a fleet-wide gap.
var perDevicePhrases = []string{"this device", "the device's", "on this box"}

// collectNotes walks a decoded response and returns every operator-facing note
// string in it: the top-level `notes` array plus the per-block `note` fields
// (lsdb, areas, spf_runs, timers), at any depth.
func collectNotes(v any) []string {
	var out []string
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			switch k {
			case "note":
				if s, ok := val.(string); ok {
					out = append(out, s)
				}
			case "notes":
				if arr, ok := val.([]any); ok {
					for _, e := range arr {
						if s, ok := e.(string); ok {
							out = append(out, s)
						}
					}
					continue
				}
			}
			out = append(out, collectNotes(val)...)
		}
	case []any:
		for _, e := range t {
			out = append(out, collectNotes(e)...)
		}
	}
	return out
}

// TestNoNoteUsesPerDeviceWording drives all three handlers, for both protocols,
// in the two states that produce notes — nothing collected at all, and an
// adjacency series present but every depth series absent — and asserts that no
// rendered note claims a single device.
func TestNoNoteUsesPerDeviceWording(t *testing.T) {
	type scenario struct {
		name string
		seed func(h *harness, proto Proto)
	}
	scenarios := []scenario{
		{"nothing collected", func(h *harness, proto Proto) {}},
		{"adjacency series present, depth absent", func(h *harness, proto Proto) {
			s := []Sample{{
				Labels: map[string]string{"device": "leaf1", proto.PeerLabel(): "peer1", "ifName": "ethernet-1/1"},
				Value:  3,
			}}
			// Both the fleet selector (summary) and the device-narrowed one.
			h.samples[seriesQuery(proto.AdjMetric(), nil)] = s
			h.samples[seriesQuery(proto.AdjMetric(), []string{"leaf1"})] = s
		}},
	}

	for _, sc := range scenarios {
		for _, rt := range allRoutes {
			proto := Proto(rt.proto)
			h := newHarness(t)
			h.seedDevice("leaf1", "leaf1", "acme")
			sc.seed(h, proto)

			path := pathFor(rt.proto, rt.op)
			w, body := h.get(path)
			if w.Code != 200 {
				t.Fatalf("%s [%s] = %d, want 200", path, sc.name, w.Code)
			}
			notes := collectNotes(body)
			if len(notes) == 0 {
				// A vacuous pass is the way this guard rots: assert it saw copy.
				t.Fatalf("%s [%s] rendered no notes at all — the guard would pass vacuously", path, sc.name)
			}
			for _, n := range notes {
				low := strings.ToLower(n)
				for _, bad := range perDevicePhrases {
					if strings.Contains(low, bad) {
						t.Errorf("%s [%s] note uses per-device wording %q on a surface the fleet roll-up also renders: %q",
							path, sc.name, bad, n)
					}
				}
				if strings.TrimSpace(n) == "" {
					t.Errorf("%s [%s] rendered an empty note", path, sc.name)
				}
			}
		}
	}
}

// TestFleetSummaryRendersThePluralLiveSeriesNote pins the specific defect: the
// fleet roll-up passes no device ids, and the note it renders for an absent
// adjacency series must read as the fleet sentence the other four notes use.
func TestFleetSummaryRendersThePluralLiveSeriesNote(t *testing.T) {
	for _, proto := range []Proto{ProtoOSPF, ProtoISIS} {
		h := newHarness(t)
		h.seedDevice("leaf1", "leaf1", "acme")
		w, body := h.get("/api/protocols/" + string(proto) + "/summary")
		if w.Code != 200 {
			t.Fatalf("%s summary = %d", proto, w.Code)
		}
		// The read really was fleet-wide: no device selector in the query.
		for _, c := range h.vm {
			if strings.Contains(c.query, "device=~") {
				t.Fatalf("%s summary narrowed the read to a device set: %q", proto, c.query)
			}
		}
		if !hasNote(body, "no live series collected for these devices") {
			t.Errorf("%s summary does not render the fleet live-series note: %v", proto, notesOf(body))
		}
		// All five coverage notes agree on the subject.
		plural := 0
		for _, n := range notesOf(body) {
			if strings.Contains(n, "these devices") {
				plural++
			}
		}
		if plural < 5 {
			t.Errorf("%s summary: only %d of the five coverage notes use the plural subject: %v",
				proto, plural, notesOf(body))
		}
	}
}
