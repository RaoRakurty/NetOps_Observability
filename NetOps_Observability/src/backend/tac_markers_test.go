// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// tac_markers_test.go — the TAC-ROUTES marker guard.
//
// The root package is at its growth ceiling (package_growth_guard_test.go), so
// the escalation pack's HTTP adapter lives inside an existing file rather than
// its own. That is a deliberate trade, and it has a cost: without a boundary,
// "the TAC adapter" stops being a thing anyone can point at, and the next change
// leaks escalation logic into the diagnostics handlers beside it.
//
// The markers ARE that boundary, and this test is what makes them real:
//
//	· every TAC route registration is inside the markers in main.go
//	· every TAC handler and helper is inside the markers in
//	  protocol_diagnostics.go
//	· the adapter stays THIN — it may not grow into a second engine
//
// When this fails, the fix is to move the code inside the markers, or (better)
// into internal/tac where the logic belongs.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// markerBlock returns the text between BEGIN/END markers, and whether both were
// found exactly as many times as they pair.
func markerBlocks(t *testing.T, path, marker string) (inside string, outside string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	begin, end := "// "+marker+"-BEGIN", "// "+marker+"-END"
	var in, out strings.Builder
	depth := 0
	opens, closes := 0, 0
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, begin):
			depth++
			opens++
			continue
		case strings.HasPrefix(trimmed, end):
			depth--
			closes++
			continue
		}
		if depth > 0 {
			in.WriteString(line + "\n")
		} else {
			out.WriteString(line + "\n")
		}
	}
	if opens == 0 {
		t.Fatalf("%s carries no %s-BEGIN marker", path, marker)
	}
	if opens != closes {
		t.Fatalf("%s has %d %s-BEGIN markers and %d -END markers", path, opens, marker, closes)
	}
	if depth != 0 {
		t.Fatalf("%s has unbalanced %s markers", path, marker)
	}
	return in.String(), out.String()
}

func TestTACRoutesLiveInsideTheirMarkers(t *testing.T) {
	// main.go: every /tac route registration, and the server field, and the
	// construction call, are inside the markers.
	in, out := markerBlocks(t, "main.go", "TAC-ROUTES")
	routeRE := regexp.MustCompile(`mux\.HandleFunc\("(/api/[^"]*/tac(?:/[a-z]+)?)"`)
	if got := routeRE.FindAllStringSubmatch(out, -1); len(got) > 0 {
		t.Errorf("TAC routes registered OUTSIDE the markers in main.go: %v", got)
	}
	inside := routeRE.FindAllStringSubmatch(in, -1)
	want := map[string]bool{
		"/api/incidents/{id}/tac":          false,
		"/api/incidents/{id}/tac/classify": false,
		"/api/incidents/{id}/tac/plan":     false,
		"/api/incidents/{id}/tac/collect":  false,
		"/api/incidents/{id}/tac/bundle":   false,
		"/api/incidents/{id}/tac/case":     false,
		"/api/troubleshoot/tac/knowledge":  false,
	}
	for _, m := range inside {
		if _, ok := want[m[1]]; !ok {
			t.Errorf("unexpected TAC route %q — add it to this guard and to the isolation ledger", m[1])
			continue
		}
		want[m[1]] = true
	}
	for route, seen := range want {
		if !seen {
			t.Errorf("route %s is not registered inside the TAC-ROUTES markers", route)
		}
	}
	// The per-tenant command-template routes (tracker 250) sit under /api/tac/
	// rather than /api/incidents/{id}/tac, so they need their own pattern: a
	// template belongs to a TENANT, not to one incident, and burying it under an
	// incident id would have made "list my templates" an incident-scoped read.
	tplRE := regexp.MustCompile(`mux\.HandleFunc\("(/api/tac/[^"]*)"`)
	if got := tplRE.FindAllStringSubmatch(out, -1); len(got) > 0 {
		t.Errorf("TAC template routes registered OUTSIDE the markers in main.go: %v", got)
	}
	wantTpl := map[string]bool{
		"/api/tac/templates":          false,
		"/api/tac/templates/defaults": false,
		"/api/tac/templates/validate": false,
		"/api/tac/templates/":         false,
		// The learning backlog (tracker 243) is per-TENANT for the same reason
		// the templates are: a learning record holds redacted excerpts of that
		// tenant's own device output, and a candidate holds what a vendor told
		// that tenant. Neither belongs under one incident id.
		"/api/tac/learning":  false,
		"/api/tac/learning/": false,
		// The case-connector list. Per-TENANT for the `configured` flag alone —
		// everything else on it is platform reference data — and deliberately
		// NOT under an incident id: Administration → Ticket delivery asks the
		// question without one.
		"/api/tac/connectors": false,
		// And the settings behind it: the routes a customer brings its own
		// vendor/ITSM credentials through. Per-TENANT for the whole row, not
		// just a flag, and still not under an incident id — credentials are
		// brought in Administration, long before anything is escalated.
		"/api/tac/connectors/{id}":      false,
		"/api/tac/connectors/{id}/test": false,
	}
	for _, m := range tplRE.FindAllStringSubmatch(in, -1) {
		if _, ok := wantTpl[m[1]]; !ok {
			t.Errorf("unexpected TAC template route %q — add it to this guard and to the isolation ledger", m[1])
			continue
		}
		wantTpl[m[1]] = true
	}
	for route, seen := range wantTpl {
		if !seen {
			t.Errorf("route %s is not registered inside the TAC-ROUTES markers", route)
		}
	}
	if !strings.Contains(in, "tacService *tac.Service") {
		t.Error("the tacService field is not inside the TAC-ROUTES markers in main.go")
	}
	if !strings.Contains(in, "srv.buildTACService()") {
		t.Error("buildTACService is not called inside the TAC-ROUTES markers in main.go")
	}
}

func TestTACAdapterLivesInsideItsMarkers(t *testing.T) {
	in, out := markerBlocks(t, "protocol_diagnostics.go", "TAC-ROUTES")
	// Every TAC identifier is inside the block.
	idRE := regexp.MustCompile(`(?m)^func (?:\(s \*server\) )?(handleTAC\w+|tac\w+|buildTACService|newTACTemplateStore)\b`)
	if got := idRE.FindAllStringSubmatch(out, -1); len(got) > 0 {
		names := make([]string, 0, len(got))
		for _, m := range got {
			names = append(names, m[1])
		}
		t.Errorf("TAC adapter functions OUTSIDE the markers: %v", names)
	}
	for _, want := range []string{
		"handleTACState", "handleTACClassify", "handleTACPlan",
		"handleTACCollect", "handleTACBundle", "handleTACCase",
		"handleTACKnowledge", "buildTACService",
		// tracker 250 — the command-review + template wiring.
		"handleTACTemplates", "handleTACTemplateItem", "handleTACTemplateDefaults",
		"handleTACTemplateValidate", "tacTemplateAuthz", "tacApplyReview", "newTACTemplateStore",
		// tracker 243 — the learning backlog wiring.
		"handleTACLearning", "handleTACLearningSubtree", "newTACLearningStore",
	} {
		if !strings.Contains(in, "func (s *server) "+want) && !strings.Contains(in, "func "+want) {
			t.Errorf("%s is not inside the TAC-ROUTES markers", want)
		}
	}

	// THIN ADAPTER. The escalation's decisions live in internal/tac; this block
	// resolves the caller's own incident and device, hands ids over, and renders
	// the answers. A ceiling on its size is the mechanical form of that rule.
	//
	// It was raised from 900 to 1100 when the command-review + template surface
	// landed (tracker 250), and NOT raised again when the learning backlog
	// landed (tracker 243): that feature's gap detection, candidate model,
	// export, store and HTTP surface are internal/tac/learning*.go and
	// candidate.go, and what arrived here was a store picker, two one-line
	// handler entry points and one service option. Its gate is literally the
	// template gate — the surfaces are the same kind of per-tenant data, so
	// there is one mapping, not two. The RULE did not move: that feature's model,
	// validation, store, defaults and its whole HTTP surface are
	// internal/tac/templates*.go — roughly 1,600 lines that never touched this
	// file. What arrived here is wiring and nothing else: the backend picker,
	// the RBAC gate mapping, the audit adapter, four one-line handler entry
	// points and the review call that hands an untrusted list to the package
	// and renders its refusal. If a future change needs this ceiling raised
	// again, the question to answer first is which DECISION leaked in here.
	const adapterLineCeiling = 1100
	if n := strings.Count(in, "\n"); n > adapterLineCeiling {
		t.Errorf("the TAC adapter block is %d lines (ceiling %d) — move logic into internal/tac rather than growing it here", n, adapterLineCeiling)
	}
	// And it must not re-implement what the package already decides.
	for _, forbidden := range []string{
		"func matchTemplate", "func classify", "ValidateReadOnly(", "regexp.MustCompile(`show",
	} {
		if strings.Contains(in, forbidden) {
			t.Errorf("the adapter contains %q — that decision belongs in internal/tac", forbidden)
		}
	}
}
