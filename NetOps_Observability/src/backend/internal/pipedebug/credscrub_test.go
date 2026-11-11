// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/credscrub"
)

// The debugger serves what the store and the bus hold. A configured SNMP
// community in device text (ConfD names an SNMP session by its community) is
// masked there by value, after the redaction pass.
func TestStoreAndBusStagesMaskAConfiguredCommunity(t *testing.T) {
	comm := "fixture-comm-" + strings.Repeat("q", 6)
	cs := credscrub.New(func(context.Context) ([]string, error) { return []string{comm}, nil })
	if err := cs.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	f := newFakeBackend()
	f.osBody = `{"hits":{"total":{"value":1},"hits":[{"_index":"netops-syslog-t1-2026.11.11","_id":"x","_source":{` +
		`"timestamp":"2026-11-11T09:00:00Z","audit_user":"` + comm + `","message":"cx_synthetic=true cx_debug=` + testMarker +
		` audit user: ` + comm + `/1 assigned to groups: basic","nested":{"who":["` + comm + `"]}}}]}}`
	f.peek = PeekResult{Records: []PeekRecord{{
		Topic: "netops.syslog", Partition: 1, Offset: 7,
		Timestamp: time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC).UnixMilli(),
		Excerpt:   "cx_debug=" + testMarker + " audit user: " + comm + "/1 terminated session (reason: normal)",
	}}, Scanned: 3}
	d := f.deps()
	d.MaskValue = cs.MaskValue
	api := New(d)

	for _, path := range []string{
		"/api/debug/stage/opensearch?marker=" + testMarker + "&tenant=t1",
		"/api/debug/stage/kafka?marker=" + testMarker,
	} {
		e := stageOf(t, api, path)
		if e.Verdict != VerdictSeen {
			t.Fatalf("%s: verdict %s (%s)", path, e.Verdict, e.Reason)
		}
		b, err := json.Marshal(e.Detail)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), comm) {
			t.Errorf("%s served a configured community: %s", path, b)
		}
		if !strings.Contains(string(b), credscrub.Mask) {
			t.Errorf("%s: no mask in %s", path, b)
		}
	}

	// Without the seam the debugger behaves exactly as before.
	plain := New(f.deps())
	e := stageOf(t, plain, "/api/debug/stage/opensearch?marker="+testMarker+"&tenant=t1")
	if b, _ := json.Marshal(e.Detail); !strings.Contains(string(b), comm) {
		t.Error("the fixture no longer carries the value, so the test above proves nothing")
	}
}
