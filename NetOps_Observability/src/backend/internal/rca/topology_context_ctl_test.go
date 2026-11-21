// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

import (
	"strings"
	"testing"
)

// Engine 3.6.0 (tracker 397) grounds an edge's control-connection loss to the
// controller on a "ctl:" edge — rank 3, observed by the management plane. The
// report must read it as authoritative and word it in plain language, never
// fall through to "joined by the engine".
func TestControlSessionEdgeReadsAsAuthoritativePlainWords(t *testing.T) {
	ref := "ctl:10.255.255.2--vedge-20"
	if !topoCtxAuthoritative("topo", ref, nil) {
		t.Fatal("a control-session edge is rank 3 by construction")
	}
	if topoCtxAuthoritative("seam", ref, nil) {
		t.Fatal("only a topo-kind grounding carries the ctl: meaning")
	}
	got := topoCtxCausalBasis("none", 0, "topo", ref, true)
	if !strings.Contains(got, "control session the controller reports") || !strings.Contains(got, "(authoritative)") {
		t.Fatalf("wording: %q", got)
	}
	if strings.Contains(got, "ctl:") || strings.Contains(got, "joined by the engine") {
		t.Fatalf("engine vocabulary leaked or fell through: %q", got)
	}
}
