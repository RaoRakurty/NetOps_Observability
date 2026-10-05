// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package modelc

// view_suggest_test.go — the reply's optional "view" (tracker 337 N-E1) is
// carried through RAW and never decides whether the query is accepted: the
// closed-enum check is present.Select's, so a malformed suggestion costs the
// operator nothing but the suggestion.

import (
	"strings"
	"testing"
)

func TestTheViewSuggestionIsCarriedRawAndNeverCostsTheQuery(t *testing.T) {
	for _, c := range []struct {
		name, view, want string
	}{
		{"absent", "", ""},
		{"enum member", `"BAR"`, `"BAR"`},
		{"unknown name", `"PIE"`, `"PIE"`},
		{"markup", `"<img src=x onerror=alert(1)>"`, `"<img src=x onerror=alert(1)>"`},
		{"number", `7`, `7`},
		{"null", `null`, `null`},
	} {
		t.Run(c.name, func(t *testing.T) {
			reply := env(cpuEdge1)
			if c.view != "" {
				reply = `{"ast":` + cpuEdge1 + `,"unmatched_names":[],"view":` + c.view + `}`
			}
			m := &stubModel{replies: []string{reply}}
			out := run(t, fb(m), "how hot is the cpu running on edge-1 lately", unparsed)
			if !out.Accepted() || len(m.calls) != 1 {
				t.Fatalf("a view suggestion must not cost the query: %+v (calls %d)", out.Refusal, len(m.calls))
			}
			if string(out.ViewSuggestion) != c.want {
				t.Fatalf("view = %q, want %q", out.ViewSuggestion, c.want)
			}
		})
	}
}

func TestARefusedReplyCarriesNoViewSuggestion(t *testing.T) {
	m := &stubModel{replies: []string{`{"ast":null,"unmatched_names":[],"view":"BAR"}`}}
	out := run(t, fb(m), "how hot is the cpu running on edge-1 lately", unparsed)
	if out.Accepted() || out.ViewSuggestion != nil {
		t.Fatalf("a declined reply must carry no suggestion: %+v", out)
	}
}

func TestAScopeKeyInsideTheViewStillEndsTheFallback(t *testing.T) {
	m := &stubModel{replies: []string{`{"ast":` + cpuEdge1 + `,"unmatched_names":[],"view":{"tenant":"t-b"}}`}}
	out := run(t, fb(m), "how hot is the cpu running on edge-1 lately", unparsed)
	if out.Accepted() || out.Refusal != RefuseForbiddenField {
		t.Fatalf("a tenant key anywhere in the reply must end the fallback: %+v", out.Refusal)
	}
}

func TestAnUnknownEnvelopeKeyIsStillRepaired(t *testing.T) {
	m := &stubModel{replies: []string{`{"ast":` + cpuEdge1 + `,"unmatched_names":[],"layout":"BAR"}`, env(cpuEdge1)}}
	out := run(t, fb(m), "how hot is the cpu running on edge-1 lately", unparsed)
	if !out.Accepted() || len(m.calls) != 2 {
		t.Fatalf("an unknown envelope key must still go to repair: %+v (calls %d)", out.Refusal, len(m.calls))
	}
	if fix := m.calls[1].msgs[2].Content; !strings.Contains(fix, CodeBadEnvelope) {
		t.Fatalf("repair must name the envelope problem: %s", fix)
	}
}
