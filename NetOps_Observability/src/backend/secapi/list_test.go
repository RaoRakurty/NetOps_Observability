// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package secapi

// list_test.go — the NON-HTTP findings read (list.go).
//
// These assert on the EMITTED QUERY BODY, not on a canned response. That is the
// whole point of the file: the bug it pins (H2, review 2026-09-08) was a query
// that matched nothing, and every double in the repo answered it with the same
// canned hits it answers everything with. A test that reads the double's reply
// cannot see a broken query at all.

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// listRecorder is an OpenSearch stand-in that KEEPS the request body. It answers
// with a fixed one-hit response regardless of the query, exactly like the real
// cluster's other doubles — which is why the assertions below read `body`.
type listRecorder struct {
	path string
	body string
	hits string // `hits.hits` JSON array; "" means one canned finding
}

func (rec *listRecorder) search(_, path string, body any) (*http.Response, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	rec.path, rec.body = path, string(raw)
	hits := rec.hits
	if hits == "" {
		hits = "[" + listCannedDoc + "]"
	}
	n := strings.Count(hits, `"_id"`)
	payload := `{"took":1,"timed_out":false,"hits":{"total":{"value":` +
		strconv.Itoa(n) + `,"relation":"eq"},"hits":` + hits + `}}`
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(payload)),
	}, nil
}

// listCannedDoc is one findings document in the shape the router writes.
const listCannedDoc = `{"_index":"netops-secfindings-acme-2026.09.01","_id":"a1",` +
	`"_source":{"tenant_id":"acme","ts":1788220800000,"severity":"critical",` +
	`"entity_id":"acme-core","native_id":"n-a1","seam_type":"ISP",` +
	`"attrs":{"status":"Fail","scan_id":"scan-1","evidence_class":"posture",` +
	`"control_id":"AC-17","standards":["CIS:1.2"]}},` +
	`"sort":[1788220800000,"n-a1","scan-1"]}`

// listNow is the fixed clock every test below reads, so the defaulted window is
// an exact expected string rather than an approximation.
var listNow = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

func listTestAPI(t *testing.T, rec *listRecorder) *API {
	t.Helper()
	return New(Deps{
		Search:  rec.search,
		Metrics: NewMetrics(),
		Now:     func() time.Time { return listNow },
	})
}

func listPrincipal() Principal {
	return Principal{Tenant: "acme", Subject: "op@acme", DeviceKeys: []string{"acme-core"}}
}

// tsRange pulls the `ts` range clause out of an emitted body. It walks the same
// path the engine does (query.bool.filter), so a clause that moved somewhere the
// engine ignores fails this helper rather than quietly passing.
func tsRange(t *testing.T, body string) (gte, lte string) {
	t.Helper()
	var q struct {
		Query struct {
			Bool struct {
				Filter []struct {
					Range map[string]struct {
						GTE string `json:"gte"`
						LTE string `json:"lte"`
					} `json:"range"`
				} `json:"filter"`
			} `json:"bool"`
		} `json:"query"`
	}
	if err := json.Unmarshal([]byte(body), &q); err != nil {
		t.Fatalf("emitted body is not valid JSON: %v\n%s", err, body)
	}
	for _, clause := range q.Query.Bool.Filter {
		if r, ok := clause.Range[FieldTime]; ok {
			return r.GTE, r.LTE
		}
	}
	t.Fatalf("the emitted body carries no range on %q: %s", FieldTime, body)
	return "", ""
}

// H2: the assistant builds `Filters{Current: …}` as a struct literal, because
// ai.FindingsQuery has no time fields at all. ListFindings must default the
// window the same way ParseFilters does for an HTTP caller. Without that,
// BuildFilters renders `ts` between 0001-01-01T00:00:00Z and 0001-01-01T00:00:00Z
// — a legal point range that matches nothing — and the operator is told they
// have no findings over a tenant with failing criticals.
func TestListFindingsDefaultsTheTimeWindow(t *testing.T) {
	rec := &listRecorder{}
	api := listTestAPI(t, rec)

	if _, err := api.ListFindings(listPrincipal(), Filters{Current: true}, 10); err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if strings.Contains(rec.body, "0001-01-01") {
		t.Fatalf("FALSE CLEAR: the emitted query carries a zero time bound, which matches nothing: %s", rec.body)
	}
	gte, lte := tsRange(t, rec.body)
	if gte == lte {
		t.Fatalf("the emitted `ts` range is a zero-width point (%s), which matches nothing: %s", gte, rec.body)
	}
	wantLTE := listNow.Format(time.RFC3339)
	wantGTE := listNow.Add(-DefaultWindow).Format(time.RFC3339)
	if gte != wantGTE || lte != wantLTE {
		t.Fatalf("defaulted window = [%s, %s], want [%s, %s] (the same default ParseFilters applies)", gte, lte, wantGTE, wantLTE)
	}
}

// A finding inside the default window must actually come back. This is the
// end-to-end half: the query is sane AND the rows decode.
func TestListFindingsReturnsAFindingInsideTheDefaultWindow(t *testing.T) {
	rec := &listRecorder{}
	api := listTestAPI(t, rec)

	rows, err := api.ListFindings(listPrincipal(), Filters{Current: true}, 10)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(rows) != 1 || rows[0].DocID != "a1" {
		t.Fatalf("want the one canned finding back, got %+v", rows)
	}
	// The document's own stamp has to sit inside the window the query asked
	// for, or the assertion above is proving nothing about the real cluster.
	docAt := time.UnixMilli(1788220800000).UTC()
	gte, lte := tsRange(t, rec.body)
	lo, _ := time.Parse(time.RFC3339, gte)
	hi, _ := time.Parse(time.RFC3339, lte)
	if docAt.Before(lo) || docAt.After(hi) {
		t.Fatalf("the canned finding (%s) is outside the emitted window [%s, %s] — a real cluster would not have returned it", docAt.Format(time.RFC3339), gte, lte)
	}
}

// A caller that DOES name a window keeps it. The defaulting must fill gaps, not
// overwrite an explicit request.
func TestListFindingsHonoursAnExplicitWindow(t *testing.T) {
	rec := &listRecorder{}
	api := listTestAPI(t, rec)

	since := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	if _, err := api.ListFindings(listPrincipal(), Filters{Since: since, Until: until}, 10); err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	gte, lte := tsRange(t, rec.body)
	if gte != since.Format(time.RFC3339) || lte != until.Format(time.RFC3339) {
		t.Fatalf("explicit window was not honoured: got [%s, %s], want [%s, %s]", gte, lte, since.Format(time.RFC3339), until.Format(time.RFC3339))
	}
}

// Half a window is filled from the other half, exactly as parseWindow does for
// an HTTP caller: `until` alone anchors a DefaultWindow that ends there.
func TestListFindingsFillsTheMissingHalfOfAWindow(t *testing.T) {
	until := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	rec := &listRecorder{}
	api := listTestAPI(t, rec)
	if _, err := api.ListFindings(listPrincipal(), Filters{Until: until}, 10); err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	gte, lte := tsRange(t, rec.body)
	if lte != until.Format(time.RFC3339) || gte != until.Add(-DefaultWindow).Format(time.RFC3339) {
		t.Fatalf("until-only window = [%s, %s], want [%s, %s]", gte, lte, until.Add(-DefaultWindow).Format(time.RFC3339), until.Format(time.RFC3339))
	}

	since := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	rec2 := &listRecorder{}
	api2 := listTestAPI(t, rec2)
	if _, err := api2.ListFindings(listPrincipal(), Filters{Since: since}, 10); err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	gte, lte = tsRange(t, rec2.body)
	if gte != since.Format(time.RFC3339) || lte != listNow.Format(time.RFC3339) {
		t.Fatalf("since-only window = [%s, %s], want [%s, %s]", gte, lte, since.Format(time.RFC3339), listNow.Format(time.RFC3339))
	}
}

// A programmatic caller must not reach a range an HTTP caller could not: the
// same inverted / over-wide refusals ParseFilters applies, as ERRORS rather
// than a silently empty page.
func TestListFindingsRefusesAnUnusableWindow(t *testing.T) {
	cases := []struct {
		name string
		f    Filters
		want string
	}{
		{
			name: "inverted",
			f:    Filters{Since: listNow, Until: listNow.Add(-time.Hour)},
			want: "since must be strictly before until",
		},
		{
			name: "zero width",
			f:    Filters{Since: listNow, Until: listNow},
			want: "since must be strictly before until",
		},
		{
			name: "wider than MaxWindow",
			f:    Filters{Since: listNow.Add(-2 * MaxWindow), Until: listNow},
			want: "time range must span at most",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &listRecorder{}
			api := listTestAPI(t, rec)
			_, err := api.ListFindings(listPrincipal(), tc.f, 10)
			if err == nil {
				t.Fatalf("want an error, got a 200-shaped answer over %s", rec.body)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to say %q", err, tc.want)
			}
			if rec.body != "" {
				t.Fatalf("a refused window must not have reached OpenSearch at all: %s", rec.body)
			}
		})
	}
}
