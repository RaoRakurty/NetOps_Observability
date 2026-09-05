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
	idRE := regexp.MustCompile(`(?m)^func (?:\(s \*server\) )?(handleTAC\w+|tac\w+|buildTACService)\b`)
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
	} {
		if !strings.Contains(in, "func (s *server) "+want) && !strings.Contains(in, "func "+want) {
			t.Errorf("%s is not inside the TAC-ROUTES markers", want)
		}
	}

	// THIN ADAPTER. The escalation's decisions live in internal/tac; this block
	// resolves the caller's own incident and device, hands ids over, and renders
	// the answers. A ceiling on its size is the mechanical form of that rule.
	const adapterLineCeiling = 900
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
