// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// DEBUG-ROUTES-BEGIN

import (
	"net/http"
	"testing"

	"netops/backend/internal/pipedebug"
)

// The UI-query stage lifts ONE clause from the SPA's log scope: the
// `cx_synthetic=true` exclusion. The lift lives in internal/pipedebug and is
// handed the clause through the UIQueryHost seam, so THIS test is the link that
// keeps the two ends from drifting: the clause package backend actually adds
// has to be the one the debugger believes it is lifting.
func TestTheLiftedClauseIsTheOneLogsScopeAdds(t *testing.T) {
	want := syntheticDebugExclusion()
	phrase, ok := want["match_phrase"].(map[string]any)
	if !ok || phrase["message"] != pipedebug.SyntheticTag {
		t.Fatalf("the synthetic exclusion is no longer a match_phrase on %q: %v", pipedebug.SyntheticTag, want)
	}
	if got := (debugUIHost{}).SyntheticExclusion(); got["match_phrase"] == nil {
		t.Fatalf("the host adapter no longer forwards the real exclusion: %v", got)
	}
}

// debugUIHost is an ADAPTER: it must satisfy the seam and forward, so a trace
// exercises the production handlers rather than a copy of them.
func TestDebugUIHostSatisfiesTheSeam(t *testing.T) {
	var _ pipedebug.UIQueryHost = debugUIHost{}
	var _ http.Handler = http.HandlerFunc((debugUIHost{}).ServeFlowsTopTalkers)
	var _ http.Handler = http.HandlerFunc((debugUIHost{}).ServeMetricsQueryRange)
}

// DEBUG-ROUTES-END
