// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// security_findings_filter_test.go — the proof that each findings FILTER
// actually narrows the answer.
//
// It exists because of tracker 283. The security lane's OpenSearch stand-in
// (secFakeOS, defined in security_findings_isolation_test.go) used to ignore the
// request body and reply with the same canned hits to every query, so a test
// could assert a 200 and a row count but never that `severity=critical` had
// excluded anything: a broken severity clause and a working one produced byte
// identical answers. The double now reads the emitted body, and these are the
// tests that USE that — a double able to catch a break with no test exercising
// it is only half the fix.
//
// Every case below asserts on the ROWS THAT CAME BACK, deliberately, not on the
// emitted body. secapi/query_test.go already byte-pins the bodies; what was
// missing is the other half — that the clause those bodies carry actually
// selects. Break BuildFilters (drop the severity terms clause, swap the status
// field, widen the seam anyOf) and these fail.
//
// WHAT IS STILL NOT PROVEN HERE, because the double does not honour it: any
// AGGREGATION. Facets, the CTEM funnel, coverage, the trend histogram and the
// compliance fold all read canned `aggregations` regardless of the query, so no
// test in the lane shows a filter narrowing a facet count. That is named in the
// double's own comment and is the honest boundary of this change.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// secFilterDoc is one document of the shared filter corpus. It carries the
// fields every clause under test reads, which the leaner secDoc does not.
type secFilterDoc struct {
	ID           string
	Tenant       string
	Severity     string
	Status       string
	SeamType     string
	SeamID       string
	Device       string
	Tokens       []string
	Standards    []string
	ControlTitle string
	RuleID       string
	StatusDetail string
	NativeID     string
	ScanID       string
	TS           int64
	// EvidenceClass is the lane the finding belongs to. Empty means "posture",
	// which is what every document in the shared corpus is.
	EvidenceClass string
}

// render writes the document in the shape the router indexes and the shape
// query.go's field constants name.
func (d secFilterDoc) render() string {
	list := func(vals []string) string {
		out := make([]string, 0, len(vals))
		for _, v := range vals {
			out = append(out, strconv.Quote(v))
		}
		return "[" + strings.Join(out, ",") + "]"
	}
	ts := strconv.FormatInt(d.TS, 10)
	class := d.EvidenceClass
	if class == "" {
		class = "posture"
	}
	return `{"_index":"netops-secfindings-` + d.Tenant + `-2026.09.01","_id":"` + d.ID + `",` +
		`"_source":{"tenant_id":"` + d.Tenant + `","ts":` + ts + `,"severity":"` + d.Severity + `",` +
		`"entity_id":"` + d.Device + `","entity_tokens":` + list(d.Tokens) + `,` +
		`"native_id":"` + d.NativeID + `","seam_type":"` + d.SeamType + `","seam_id":"` + d.SeamID + `",` +
		`"attrs":{"status":"` + d.Status + `","scan_id":"` + d.ScanID + `","evidence_class":"` + class + `",` +
		`"control_id":"AC-17","control_title":"` + d.ControlTitle + `",` +
		`"raw_rule_id":"` + d.RuleID + `","status_detail":"` + d.StatusDetail + `",` +
		`"standards":` + list(d.Standards) + `}},` +
		`"sort":[` + ts + `,"` + d.NativeID + `","` + d.ScanID + `"]}`
}

// secFilterCorpus is three acme findings, stamped inside the default window so
// the `ts` range keeps them. d1 and d3 are two scans of the SAME finding
// identity (n-1), which is what the current-state collapse folds.
func secFilterCorpus(now time.Time) []secFilterDoc {
	ms := func(d time.Duration) int64 { return now.Add(-d).UnixMilli() }
	return []secFilterDoc{
		{
			ID: "d1", Tenant: "acme", Severity: "critical", Status: "Fail",
			SeamType: "ISP", SeamID: "seam-isp-1", Device: "acme-core",
			Tokens: []string{"device:acme-core", "host:core1"}, Standards: []string{"CIS:1.2", "NIST:AC-17"},
			ControlTitle: "Remote access over telnet", RuleID: "telnet-vty-enabled",
			StatusDetail: "telnet is enabled on the VTY lines",
			NativeID:     "n-1", ScanID: "scan-2", TS: ms(time.Hour),
		},
		{
			ID: "d2", Tenant: "acme", Severity: "high", Status: "Pass",
			SeamType: "internet", SeamID: "seam-inet-9", Device: "acme-edge",
			Tokens: []string{"device:acme-edge", "host:edge1"}, Standards: []string{"PCI:2.2"},
			ControlTitle: "TLS transmission protection", RuleID: "weak-tls-cipher",
			StatusDetail: "cipher suite acceptable",
			NativeID:     "n-2", ScanID: "scan-2", TS: ms(2 * time.Hour),
		},
		{
			ID: "d3", Tenant: "acme", Severity: "low", Status: "Fail",
			SeamType: "ISP", SeamID: "seam-isp-1", Device: "acme-core",
			Tokens: []string{"device:acme-core", "host:core1"}, Standards: []string{"CIS:1.2"},
			ControlTitle: "Remote access over telnet", RuleID: "telnet-vty-enabled",
			StatusDetail: "telnet is enabled on the VTY lines",
			NativeID:     "n-1", ScanID: "scan-1", TS: ms(3 * time.Hour),
		},
	}
}

// secStartFilterOS stands the corpus up behind a window-honouring double.
func secStartFilterOS(t *testing.T, docs []secFilterDoc) *secFakeOS {
	t.Helper()
	rows := make([]string, 0, len(docs))
	for _, d := range docs {
		rows = append(rows, d.render())
	}
	fake := &secFakeOS{
		windowAware: true,
		docs:        map[string]string{secPatternFor("acme"): "[" + strings.Join(rows, ",") + "]"},
	}
	secStartFakeOS(t, fake)
	return fake
}

// secListIDs runs one findings request and returns the ids that came back, in
// the order they were served, plus the reported total.
func secListIDs(t *testing.T, s *server, query string) ([]string, int64) {
	t.Helper()
	w := httptest.NewRecorder()
	s.secAPI.HandleFindings(w, req(http.MethodGet, "/api/security/findings?"+query, "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("?%s = %d (%s)", query, w.Code, w.Body.String())
	}
	var page struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode ?%s: %v (%s)", query, err, w.Body.String())
	}
	ids := make([]string, 0, len(page.Items))
	for _, it := range page.Items {
		ids = append(ids, it.ID)
	}
	return ids, page.Total
}

func secSameSet(got, want []string) bool {
	a := append([]string(nil), got...)
	b := append([]string(nil), want...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, ",") == strings.Join(b, ",")
}

// TestSecurityFindingsFiltersNarrowTheResultSet is tracker 283's point, one
// clause at a time: each filter must EXCLUDE the rows it does not name. Before
// the double read the request body every one of these would have returned all
// three documents and no assertion in the lane could have told the difference.
func TestSecurityFindingsFiltersNarrowTheResultSet(t *testing.T) {
	now := time.Now().UTC()
	secStartFilterOS(t, secFilterCorpus(now))
	s := secTestServer(t)

	cases := []struct {
		name  string
		query string
		want  []string
	}{
		{"no filter returns the whole corpus", "", []string{"d1", "d2", "d3"}},
		{"severity", "severity=critical", []string{"d1"}},
		{"severity multi-valued", "severity=critical,low", []string{"d1", "d3"}},
		{"severity matching nothing", "severity=info", nil},
		{"status", "status=fail", []string{"d1", "d3"}},
		{"status alias folds onto the stored token", "status=pass", []string{"d2"}},
		{"seam by type", "seam=internet", []string{"d2"}},
		{"seam by id", "seam=seam-isp-1", []string{"d1", "d3"}},
		{"framework", "framework=PCI:2.2", []string{"d2"}},
		{"framework picks one tag out of several", "framework=NIST:AC-17", []string{"d1"}},
		{"device by entity id", "device=acme-edge", []string{"d2"}},
		{"device by co-location token", "device=host:core1", []string{"d1", "d3"}},
		{"free text q", "q=telnet", []string{"d1", "d3"}},
		{"free text q over the control title", "q=transmission", []string{"d2"}},
		{"free text q ANDs its terms", "q=telnet+transmission", nil},
		{"filters combine", "severity=low&status=fail", []string{"d3"}},
		{"filters combine to nothing", "severity=critical&seam=internet", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ids, total := secListIDs(t, s, tc.query)
			if !secSameSet(ids, tc.want) {
				t.Fatalf("?%s returned %v, want %v — the clause did not narrow", tc.query, ids, tc.want)
			}
			if total != int64(len(tc.want)) {
				t.Errorf("?%s total = %d, want %d", tc.query, total, len(tc.want))
			}
		})
	}
}

// TestSecurityFindingsWindowNarrowsTheResultSet is the `ts` range half, at the
// HTTP boundary. H2 was a query whose window matched nothing reading as a full
// result set; this is the same property in the other direction.
func TestSecurityFindingsWindowNarrowsTheResultSet(t *testing.T) {
	now := time.Now().UTC()
	secStartFilterOS(t, secFilterCorpus(now))
	s := secTestServer(t)

	// Everything older than 90 minutes: d1 (one hour old) must fall outside.
	until := now.Add(-90 * time.Minute).Format(time.RFC3339)
	since := now.Add(-6 * time.Hour).Format(time.RFC3339)
	ids, total := secListIDs(t, s, "since="+since+"&until="+until)
	if !secSameSet(ids, []string{"d2", "d3"}) {
		t.Fatalf("the window returned %v, want [d2 d3] — the `ts` range did not narrow", ids)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
}

// TestSecurityFindingsSortIsNewestFirst proves the emitted sort is applied, not
// merely emitted: the corpus is stood up oldest-last on purpose and the answer
// must come back newest first, which is the order the keyset cursor rides on.
func TestSecurityFindingsSortIsNewestFirst(t *testing.T) {
	now := time.Now().UTC()
	corpus := secFilterCorpus(now)
	// Shuffle the fixture order so a double that simply echoed it would fail.
	corpus[0], corpus[2] = corpus[2], corpus[0]
	secStartFilterOS(t, corpus)
	s := secTestServer(t)

	ids, _ := secListIDs(t, s, "")
	want := []string{"d1", "d2", "d3"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v, want %v (ts desc)", ids, want)
	}
}

// TestSecurityFindingsPagingWalksTheCorpusExactlyOnce proves the keyset is
// applied as well as emitted: page 2 must start where page 1 stopped, and the
// two pages together must cover the corpus with no row served twice.
func TestSecurityFindingsPagingWalksTheCorpusExactlyOnce(t *testing.T) {
	now := time.Now().UTC()
	secStartFilterOS(t, secFilterCorpus(now))
	s := secTestServer(t)

	w := httptest.NewRecorder()
	s.secAPI.HandleFindings(w, req(http.MethodGet, "/api/security/findings?limit=2", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("page 1 = %d (%s)", w.Code, w.Body.String())
	}
	var page struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
		NextCursor *string `json:"next_cursor"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(page.Items) != 2 || page.Items[0].ID != "d1" || page.Items[1].ID != "d2" {
		t.Fatalf("page 1 = %+v, want d1 then d2 — `size` was not honoured", page.Items)
	}
	if page.NextCursor == nil {
		t.Fatal("a full page must advertise a cursor")
	}

	second, _ := secListIDs(t, s, "limit=2&cursor="+*page.NextCursor)
	if !secSameSet(second, []string{"d3"}) {
		t.Fatalf("page 2 = %v, want [d3] — search_after did not advance the walk", second)
	}
}

// TestSecurityFindingsCurrentCollapsesToTheNewestVerdict proves the collapse is
// applied, on the same corpus every other filter case uses: d1 and d3 are two
// scans of ONE finding identity, and the current view must keep only the newer.
func TestSecurityFindingsCurrentCollapsesToTheNewestVerdict(t *testing.T) {
	now := time.Now().UTC()
	secStartFilterOS(t, secFilterCorpus(now))
	s := secTestServer(t)

	ids, _ := secListIDs(t, s, "current=true")
	if !secSameSet(ids, []string{"d1", "d2"}) {
		t.Fatalf("current=true returned %v, want [d1 d2] — the older verdict of n-1 was not superseded", ids)
	}

	// The history is still there without the collapse.
	all, _ := secListIDs(t, s, "")
	if len(all) != 3 {
		t.Fatalf("the retained history was lost: %v", all)
	}

	// A filter and the collapse compose: only the ISP seam, current state.
	seam, _ := secListIDs(t, s, "current=true&seam=seam-isp-1")
	if !secSameSet(seam, []string{"d1"}) {
		t.Fatalf("current=true&seam=seam-isp-1 returned %v, want [d1]", seam)
	}
}

// ── 3.3-03: the threat lane is selected at the STORE, not in the browser ─────
//
// The Detections tab used to fetch the newest 200 CURRENT findings of every lane
// and keep the threat ones in JavaScript. A posture scan is a burst: one pass
// over a few hundred devices writes thousands of posture verdicts, all newer
// than the detection that fired an hour ago. Page one is then entirely posture,
// the browser filter keeps nothing, and the screen prints "No detection fired in
// this window" over a live detection. next_cursor was ignored, so nothing ever
// went looking for it, and the count above the table was the size of the kept
// slice rather than the number of detections.
//
// The fix is one terms clause on evidence_class, asked of OpenSearch. This is
// the test that proves the clause selects: 250 posture findings, every one newer
// than the single detection, and the detection must still come back.

// secBurstCorpus is one threat detection buried under `posture` newer posture
// findings — the shape of a posture scan burst.
func secBurstCorpus(now time.Time, posture int) []secFilterDoc {
	docs := []secFilterDoc{{
		ID: "detection-1", Tenant: "acme", Severity: "high", Status: "Fail",
		SeamType: "internet", SeamID: "seam-inet-9", Device: "acme-edge",
		Tokens: []string{"device:acme-edge"}, Standards: []string{"ATTACK:T1071"},
		ControlTitle: "Outbound beacon to a rare destination", RuleID: "beacon-rare-dst",
		StatusDetail: "periodic outbound connections to a destination seen nowhere else",
		NativeID:     "n-detect-1", ScanID: "scan-t1", TS: now.Add(-time.Hour).UnixMilli(),
		EvidenceClass: "signal",
	}}
	for i := 0; i < posture; i++ {
		docs = append(docs, secFilterDoc{
			ID: "p" + strconv.Itoa(i), Tenant: "acme", Severity: "medium", Status: "Fail",
			SeamType: "ISP", SeamID: "seam-isp-1", Device: "acme-core",
			Tokens: []string{"device:acme-core"}, Standards: []string{"CIS:1.2"},
			ControlTitle: "Remote access over telnet", RuleID: "telnet-vty-enabled",
			StatusDetail: "telnet is enabled on the VTY lines",
			NativeID:     "n-p" + strconv.Itoa(i), ScanID: "scan-p1",
			// Every posture row is NEWER than the detection.
			TS: now.Add(-time.Duration(i+1) * time.Second).UnixMilli(),
		})
	}
	return docs
}

func TestThreatLaneSurvivesAPostureBurst(t *testing.T) {
	now := time.Now().UTC()
	secStartFilterOS(t, secBurstCorpus(now, 250))
	s := secTestServer(t)

	// The failure this replaces, pinned so the fixture is known to reproduce it:
	// the newest 200 findings of ALL lanes hold no detection at all, so a browser
	// filter over that page keeps nothing.
	unfiltered, _ := secListIDs(t, s, "current=true&limit=200")
	if len(unfiltered) != 200 {
		t.Fatalf("the burst fixture served %d rows, want a full page of 200", len(unfiltered))
	}
	for _, id := range unfiltered {
		if id == "detection-1" {
			t.Fatal("the fixture does not reproduce the burst: the detection is still on page one")
		}
	}

	// Asked of the STORE, the detection comes back — and it is the only row.
	for _, query := range []string{
		"current=true&limit=200&evidence_class=threat",
		"current=true&limit=200&evidence_class=signal",
		"current=true&limit=200&evidence_class=threat,signal",
		"limit=200&evidence_class=threat",
	} {
		ids, total := secListIDs(t, s, query)
		if !secSameSet(ids, []string{"detection-1"}) {
			t.Errorf("?%s returned %d rows %v, want just the detection — "+
				"a real detection is invisible behind the posture burst", query, len(ids), ids)
		}
		if total != 1 {
			t.Errorf("?%s total = %d, want 1 — the count above the table must be the number of "+
				"detections, not the size of a slice the browser kept", query, total)
		}
	}
}

// The lane filter must also EXCLUDE, or "evidence_class=posture" would be a
// parameter accepted and ignored (the F-61 failure this API refuses elsewhere).
func TestEvidenceClassFilterExcludesTheOtherLanes(t *testing.T) {
	now := time.Now().UTC()
	secStartFilterOS(t, secBurstCorpus(now, 3))
	s := secTestServer(t)

	ids, _ := secListIDs(t, s, "evidence_class=posture")
	if !secSameSet(ids, []string{"p0", "p1", "p2"}) {
		t.Errorf("?evidence_class=posture returned %v, want the three posture rows", ids)
	}
	ids, _ = secListIDs(t, s, "evidence_class=exposure")
	if len(ids) != 0 {
		t.Errorf("?evidence_class=exposure returned %v, want nothing", ids)
	}

	// An unknown lane is a 400, never 200-with-nothing: an empty answer to
	// "?evidence_class=thret" reads exactly like "nothing has been detected".
	w := httptest.NewRecorder()
	s.secAPI.HandleFindings(w, req(http.MethodGet, "/api/security/findings?evidence_class=thret", "", acme()))
	if w.Code != http.StatusBadRequest {
		t.Errorf("an unknown evidence_class = %d (%s), want 400", w.Code, w.Body.String())
	}
}
