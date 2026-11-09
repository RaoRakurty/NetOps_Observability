// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

import (
	"encoding/json"
	"strings"
	"testing"
)

const fabricatedCommunity = "fabricated-community-7f3a"

// A trace of a stored trap must not show the credential a pre-fix document holds.
func TestOpenSearchStageNeverShowsTheStoredCommunity(t *testing.T) {
	f := newFakeBackend()
	f.osBody = `{"hits":{"total":{"value":1},"hits":[{"_index":"netops-snmptrap-t1-2026.11.09","_id":"e1","_source":{` +
		`"timestamp":"2026-11-09T02:25:00Z","message":"linkDown cx_debug=` + testMarker + `","snmp_community":"` + fabricatedCommunity + `"}}]}}`
	e := stageOf(t, New(f.deps()), "/api/debug/stage/opensearch?marker="+testMarker+"&kind=trap")
	if e.Verdict != VerdictSeen {
		t.Fatalf("verdict %s: %s", e.Verdict, e.Reason)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), fabricatedCommunity) {
		t.Fatalf("the stage holds the stored community: %s", raw)
	}
	if !strings.Contains(string(raw), "linkDown") {
		t.Fatalf("the rest of the document must stay: %s", raw)
	}
}

// A bus record from an older receiver may still hold the value for the retention
// window, and its excerpt may be cut anywhere.
func TestKafkaStageNeverShowsTheCommunity(t *testing.T) {
	for name, excerpt := range map[string]string{
		"whole": `{"message":"cx_debug=` + testMarker + `","snmp_community":"` + fabricatedCommunity + `","a":1}`,
		"cut":   `{"message":"cx_debug=` + testMarker + `","snmp_community":"` + fabricatedCommunity,
	} {
		f := newFakeBackend()
		f.peek = PeekResult{Records: []PeekRecord{{Topic: "netops.snmptrap", Excerpt: excerpt}}, Scanned: 1}
		e := stageOf(t, New(f.deps()), "/api/debug/stage/kafka?marker="+testMarker+"&kind=trap")
		if e.Verdict != VerdictSeen {
			t.Fatalf("%s: verdict %s: %s", name, e.Verdict, e.Reason)
		}
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), fabricatedCommunity) {
			t.Errorf("%s: the stage holds the value: %s", name, raw)
		}
	}
}
