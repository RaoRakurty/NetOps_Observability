// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// pipedebug_synthetic_test.go — the customer-facing log search must NEVER show
// a pipeline-debug probe (docs/design/PIPELINE_DEBUGGER_2026-09-04.md §4).
//
// WHY THIS GUARD MATTERS. correlix-debug injects a REAL record through the REAL
// ingress so the real path is exercised end to end. That means the probe IS in
// the tenant's OpenSearch index, indistinguishable from device traffic except
// for its `cx_synthetic=true` tag — and the only thing standing between it and
// an operator's log search is the must_not clause in logsScope. If that clause
// is ever dropped, the feature starts writing fake device logs into customer
// views, which is worse than not having the feature at all.
//
// The guard is placed on logsScope, the ONE chokepoint the interactive search
// and the retention read both resolve through, so a future log surface inherits
// the exclusion instead of having to remember it.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/pipedebug"
)

// syntheticInMustNot reports whether the resolved scope excludes debug probes.
func syntheticInMustNot(mustNot []any) bool {
	for _, clause := range mustNot {
		m, ok := clause.(map[string]any)
		if !ok {
			continue
		}
		phrase, ok := m["match_phrase"].(map[string]any)
		if !ok {
			continue
		}
		if phrase["message"] == pipedebug.SyntheticTag {
			return true
		}
	}
	return false
}

func TestLogsScopeExcludesSyntheticDebugProbesForEveryCaller(t *testing.T) {
	s := logsTestServer(t)
	cases := []struct {
		name   string
		claims jwtClaims
		signal string
	}{
		{"scoped tenant, syslog", acme(), "syslog"},
		{"scoped tenant, traps", acme(), "snmptrap"},
		{"scoped tenant, all signals", acme(), ""},
		{"platform owner, syslog", superA(), "syslog"},
		{"platform owner, applogs", superA(), "applogs"},
	}
	for _, c := range cases {
		_, _, mustNot, denyAll, forbidden := s.logsScope(req(http.MethodGet, "/api/logs/search", "", c.claims), c.signal)
		if forbidden || denyAll {
			t.Fatalf("%s: scope refused the read (forbidden=%v denyAll=%v)", c.name, forbidden, denyAll)
		}
		if !syntheticInMustNot(mustNot) {
			t.Errorf("%s: the log scope does NOT exclude cx_synthetic=true probes — a debug injection would appear as device traffic", c.name)
		}
	}
}

// End to end through the handler: the exclusion must reach the wire, not just
// the scope struct.
func TestLogSearchQuerySentToOpenSearchCarriesTheSyntheticExclusion(t *testing.T) {
	_, bodies := fakeOS(t, `{"hits":{"total":{"value":0,"relation":"eq"},"hits":[]}}`)
	s := logsTestServer(t)
	w := httptest.NewRecorder()
	s.handleLogsSearch(w, req(http.MethodPost, "/api/logs/search", `{"signal":"syslog","query":"*"}`, acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if len(*bodies) != 1 {
		t.Fatalf("want 1 OpenSearch request, got %d", len(*bodies))
	}
	body := (*bodies)[0]
	if !strings.Contains(body, `"must_not"`) || !strings.Contains(body, pipedebug.SyntheticTag) {
		t.Errorf("the search query does not exclude debug probes:\n%s", body)
	}
}

// The retention floor reads the SAME surface, so it must inherit the exclusion:
// a probe must not shift a tenant's reported oldest-log timestamp either.
func TestLogsRetentionQueryCarriesTheSyntheticExclusion(t *testing.T) {
	_, bodies := fakeOS(t, osAggReply)
	s := logsTestServer(t)
	w := httptest.NewRecorder()
	s.handleLogsRetention(w, req(http.MethodGet, "/api/logs/retention?signal=syslog", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains((*bodies)[0], pipedebug.SyntheticTag) {
		t.Errorf("the retention query does not exclude debug probes:\n%s", (*bodies)[0])
	}
}

// The tag the exclusion matches and the tag the injector stamps must be the
// SAME string — two constants that drift are a silent leak.
func TestTheExcludedTagIsTheTagTheInjectorStamps(t *testing.T) {
	frame := pipedebug.BuildSyslogFrame("01j9abcdefghjkmnpqrstvwxyz", "spine1", time.Now().UTC())
	if !strings.Contains(frame, pipedebug.SyntheticTag) {
		t.Fatal("the injected frame does not carry the tag the UI query excludes")
	}
	clause := syntheticDebugExclusion()
	phrase, _ := clause["match_phrase"].(map[string]any)
	if phrase == nil || phrase["message"] != pipedebug.SyntheticTag {
		t.Errorf("the exclusion clause does not match on the injector's tag: %v", clause)
	}
}
