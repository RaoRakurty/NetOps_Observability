// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpfsm

import (
	"encoding/json"
	"os"
	"testing"
)

// The table every lane shares: the receiver, the controller connectors and the
// engine all read this one file (tracker 387).
const pinned = "../../collectors/testdata/bgp_transition_classes.json"

func TestClassify_PinnedTable(t *testing.T) {
	b, err := os.ReadFile(pinned)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rows []struct{ Prev, State, Class string } `json:"rows"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rows) != 42 {
		t.Fatalf("rows %d, want the full 7x6 table", len(doc.Rows))
	}
	for _, r := range doc.Rows {
		if got := Classify(r.Prev, r.State); got != r.Class {
			t.Errorf("%q -> %q: %q, want %q", r.Prev, r.State, got, r.Class)
		}
	}
}

func TestClassify_OwnerRule(t *testing.T) {
	// Only established -> lower is a session failure.
	for _, prev := range []string{"idle", "connect", "active", "opensent", "openconfirm"} {
		for _, to := range []string{"idle", "connect", "active", "opensent", "openconfirm"} {
			if Classify(prev, to) == SessionLost {
				t.Errorf("%s -> %s is a session failure; it never was established", prev, to)
			}
			if !NotASessionFailure(Classify(prev, to)) {
				t.Errorf("%s -> %s: %q must not build a session failure", prev, to, Classify(prev, to))
			}
		}
		if got := Classify("established", "idle"); got != SessionLost || NotASessionFailure(got) {
			t.Errorf("established -> idle: %q", got)
		}
	}
}

func TestClassify_LabelsAndJunk(t *testing.T) {
	if got := Classify("Established", " IDLE "); got != SessionLost {
		t.Errorf("labels are case-insensitive: %q", got)
	}
	for _, c := range []struct{ prev, state string }{{"idle", ""}, {"idle", "clearing"}, {"", "6"}} {
		if got := Classify(c.prev, c.state); got != "" {
			t.Errorf("%q -> %q: %q, want no class", c.prev, c.state, got)
		}
	}
	if NotASessionFailure(Unknown) || NotASessionFailure("") || NotASessionFailure(SessionUp) {
		t.Error("unknown / empty / up never suppress a reading")
	}
}
