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
// masked there by value, after the redaction pass, with the CALLER's set.
func TestStoreAndBusStagesMaskTheCallersCommunities(t *testing.T) {
	own := "fixture-comm-" + strings.Repeat("q", 6)
	other := "fixture-other-" + strings.Repeat("z", 4)
	cs := credscrub.New(func(context.Context) ([]credscrub.Value, error) {
		return []credscrub.Value{{Tenant: "t1", Text: own}, {Tenant: "t9", Text: other}}, nil
	})
	if err := cs.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	mask := func(tenant string, cross bool, v any) (any, bool) { return cs.For(tenant, cross).MaskValue(v) }

	f := newFakeBackend()
	f.osBody = `{"hits":{"total":{"value":1},"hits":[{"_index":"netops-syslog-t1-2026.11.11","_id":"x","_source":{` +
		`"timestamp":"2026-11-11T09:00:00Z","audit_user":"` + own + `","message":"cx_synthetic=true cx_debug=` + testMarker +
		` audit user: ` + own + `/1 assigned to groups: basic","nested":{"who":["` + own + `","` + other + `"]}}}]}}`
	f.peek = PeekResult{Records: []PeekRecord{{
		Topic: "netops.syslog", Partition: 1, Offset: 7,
		Timestamp: time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC).UnixMilli(),
		Excerpt:   "cx_debug=" + testMarker + " audit user: " + own + "/1 terminated session (reason: normal) " + other,
	}}, Scanned: 3}
	d := f.deps()
	d.MaskValue = mask

	for _, c := range []struct {
		name       string
		p          Principal
		otherShown bool
	}{
		{"scoped into t1", Principal{Subject: "owner", Tenant: "t1"}, true},
		{"cross-tenant", Principal{Subject: "owner", Cross: true}, false},
	} {
		f.principal = c.p
		api := New(d)
		for _, path := range []string{
			"/api/debug/stage/opensearch?marker=" + testMarker + "&tenant=t1",
			"/api/debug/stage/kafka?marker=" + testMarker,
		} {
			e := stageOf(t, api, path)
			if e.Verdict != VerdictSeen {
				t.Fatalf("%s %s: verdict %s (%s)", c.name, path, e.Verdict, e.Reason)
			}
			b, err := json.Marshal(e.Detail)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), own) {
				t.Errorf("%s %s served the caller's community: %s", c.name, path, b)
			}
			if got := strings.Contains(string(b), other); got != c.otherShown {
				t.Errorf("%s %s: another tenant's value shown=%v, want %v (masking it for a scoped caller is a cross-tenant oracle)", c.name, path, got, c.otherShown)
			}
		}
	}

	// Without the seam the debugger behaves exactly as before.
	f.principal = Principal{Subject: "owner", Cross: true}
	plain := New(f.deps())
	e := stageOf(t, plain, "/api/debug/stage/opensearch?marker="+testMarker+"&tenant=t1")
	if b, _ := json.Marshal(e.Detail); !strings.Contains(string(b), own) {
		t.Error("the fixture no longer carries the value, so the test above proves nothing")
	}
}
