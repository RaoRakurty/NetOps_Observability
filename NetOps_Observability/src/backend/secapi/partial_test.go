// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package secapi

// partial_test.go — the completeness contract (3.3-01, review 2026-09-08).
//
// Every read this package issues carries `?timeout=20s`. OpenSearch honours that
// by ANSWERING: it returns HTTP 200, sets `timed_out: true`, and hands back
// whatever it managed to fold before the clock ran out. It does the same with
// `_shards.failed` when a shard of the caller's wildcard pattern is unreachable.
//
// Before this file, the flag was decoded and read by nobody and `_shards` was
// not decoded at all, so a half-finished fold became the CTEM funnel, the
// coverage numbers, the facet counts, the trend and the compliance score — each
// printed as measured fact. A fold that loses buckets reads as an IMPROVEMENT in
// posture, which is the false clear this package exists to prevent.
//
// The tests below drive every read through a cluster that answers exactly that
// way and require a refusal. They also pin the OTHER direction: a healthy answer
// with skipped shards (the can_match pre-filter, normal on a date-partitioned
// wildcard) must NOT be refused, or the security pages would be down for a
// working cluster.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// partialReply is the reply shape a cluster gives when it gave up early. `hits`
// and `aggregations` are populated exactly as a healthy reply's are, because
// that is the whole difficulty: nothing but the two completeness fields
// distinguishes a piece of an answer from the whole of one.
type partialReply struct {
	timedOut     bool
	shardsTotal  int
	shardsFailed int
	shardsSkip   int
}

func (p partialReply) body() string {
	aggs := `{"current_total":{"value":1},"native_total":{"value":1},` +
		`"assessed_devices":{"value":1},` +
		`"severity":{"buckets":[{"key":"critical","doc_count":1}]},` +
		`"status":{"buckets":[{"key":"Fail","doc_count":1}]},` +
		`"seam":{"buckets":[]},"framework":{"buckets":[]},"evidence_class":{"buckets":[]},` +
		`"trend":{"buckets":[{"key":1788220800000,"key_as_string":"2026-09-01T00:00:00Z",` +
		`"status":{"buckets":[{"key":"Fail","doc_count":1}]}}]},` +
		`"last_scan":{"hits":{"hits":[` + listCannedDoc + `]}},` +
		`"by_native":{"buckets":[{"key":"n-a1","latest":{"hits":{"hits":[` + listCannedDoc + `]}}}]}}`
	out := `{"took":1,"timed_out":` + boolText(p.timedOut) + `,` +
		`"_shards":{"total":` + intText(p.shardsTotal) +
		`,"successful":` + intText(p.shardsTotal-p.shardsFailed-p.shardsSkip) +
		`,"skipped":` + intText(p.shardsSkip) +
		`,"failed":` + intText(p.shardsFailed) + `},` +
		`"hits":{"total":{"value":1,"relation":"eq"},"hits":[` + listCannedDoc + `]},` +
		`"aggregations":` + aggs + `}`
	return out
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func intText(n int) string {
	return json.Number(itoa(n)).String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func (p partialReply) search(_, _ string, _ any) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(p.body())),
	}, nil
}

// partialAPI builds an API whose every dependency is a stub, so the only thing
// under test is what the handlers do with an incomplete cluster answer.
func partialAPI(reply partialReply, status *int, errBody *string, jsonBody *string) *API {
	return New(Deps{
		Authz: func(_ http.ResponseWriter, _ *http.Request, _ Gate) (Principal, bool) {
			return listPrincipal(), true
		},
		Search:          reply.search,
		RegistryDevices: func(*http.Request) int { return 3 },
		Store:           NewFileStore(""),
		FrameworkStore:  partialFrameworkStore{},
		Metrics:         NewMetrics(),
		Now:             func() time.Time { return listNow },
		WriteJSON: func(w http.ResponseWriter, code int, body any) {
			*status = code
			raw, _ := json.Marshal(body)
			*jsonBody = string(raw)
			w.WriteHeader(code)
		},
		WriteError: func(w http.ResponseWriter, code int, err error) {
			*status = code
			*errBody = err.Error()
			w.WriteHeader(code)
		},
	})
}

// partialFrameworkStore is the smallest FrameworkStore that lets
// HandleCompliance reach its fold: the tenant has not chosen, so the shipped
// default set is scored.
type partialFrameworkStore struct{}

func (partialFrameworkStore) FrameworkStates(context.Context, Principal) (map[string]bool, bool, error) {
	return map[string]bool{}, false, nil
}

func (partialFrameworkStore) SetFrameworkStates(context.Context, string, bool, string, []FrameworkState) error {
	return nil
}

// partialReads is every read surface this package serves off the findings index,
// with the request each one needs.
var partialReads = []struct {
	name    string
	path    string
	handler func(a *API) http.HandlerFunc
}{
	{"findings-list", "/api/security/findings?limit=10", func(a *API) http.HandlerFunc { return a.HandleFindings }},
	{"findings-current", "/api/security/findings?limit=10&current=true", func(a *API) http.HandlerFunc { return a.HandleFindings }},
	{"finding-by-id", "/api/security/findings/a1", func(a *API) http.HandlerFunc { return a.HandleFindingByID }},
	{"facets", "/api/security/findings/facets", func(a *API) http.HandlerFunc { return a.HandleFacets }},
	{"facets-current", "/api/security/findings/facets?current=true", func(a *API) http.HandlerFunc { return a.HandleFacets }},
	{"trend", "/api/security/findings/trend?bucket=1d", func(a *API) http.HandlerFunc { return a.HandleTrend }},
	{"posture", "/api/security/posture", func(a *API) http.HandlerFunc { return a.HandlePosture }},
	{"compliance", "/api/security/compliance", func(a *API) http.HandlerFunc { return a.HandleCompliance }},
}

// A cluster that ran out of time must not have its half-answer rendered as a
// measured number. Every read refuses with 502 and says what happened.
func TestTimedOutSearchIsNeverRenderedAsAWholeAnswer(t *testing.T) {
	for _, tc := range partialReads {
		t.Run(tc.name, func(t *testing.T) {
			var status int
			var errBody, jsonBody string
			a := partialAPI(partialReply{timedOut: true, shardsTotal: 30}, &status, &errBody, &jsonBody)
			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			tc.handler(a)(httptest.NewRecorder(), r)

			if status != http.StatusBadGateway {
				t.Fatalf("status = %d (body %s), want 502: OpenSearch timed out and answered "+
					"only part of the query, so this screen is stating a number it did not measure",
					status, jsonBody)
			}
			if !strings.Contains(errBody, "ran out of time") {
				t.Errorf("the refusal must say what happened, got %q", errBody)
			}
		})
	}
}

// The same for a shard that could not be read. Every index template ships
// number_of_shards: 1, but every read here names a WILDCARD over the tenant's
// daily indices, so one unassigned daily index is one failed shard.
func TestFailedShardIsNeverRenderedAsAWholeAnswer(t *testing.T) {
	for _, tc := range partialReads {
		t.Run(tc.name, func(t *testing.T) {
			var status int
			var errBody, jsonBody string
			a := partialAPI(partialReply{shardsTotal: 30, shardsFailed: 1}, &status, &errBody, &jsonBody)
			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			tc.handler(a)(httptest.NewRecorder(), r)

			if status != http.StatusBadGateway {
				t.Fatalf("status = %d (body %s), want 502: 1 of 30 shards failed, so the fold "+
					"behind this answer is missing rows nobody was told about", status, jsonBody)
			}
			if !strings.Contains(errBody, "1 of 30 shards") {
				t.Errorf("the refusal must name the shards it could not read, got %q", errBody)
			}
		})
	}
}

// The non-HTTP read the AI assistant calls has no envelope to carry a caveat, so
// it must return the error rather than a short list the assistant will describe
// as the device's complete security position.
func TestListFindingsRefusesAPartialAnswer(t *testing.T) {
	var status int
	var errBody, jsonBody string
	a := partialAPI(partialReply{timedOut: true, shardsTotal: 30}, &status, &errBody, &jsonBody)

	out, err := a.ListFindings(listPrincipal(), Filters{Current: true}, 10)
	if err == nil {
		t.Fatalf("ListFindings returned %d findings and no error over a timed-out cluster — "+
			"the assistant would report that as the whole answer", len(out))
	}
	var pe *PartialAnswerError
	if !errors.As(err, &pe) {
		t.Fatalf("error = %v, want a *PartialAnswerError the caller can recognise", err)
	}
	if !pe.TimedOut {
		t.Errorf("the refusal must record WHICH kind of partiality it saw: %+v", pe)
	}
}

// The other direction, and the reason partiality is not simply "successful <
// total": a healthy wildcard read over a date-partitioned index SKIPS the daily
// indices the window cannot contain. Refusing those would take the security
// pages down for a cluster that answered the question perfectly.
func TestSkippedShardsAreNotAPartialAnswer(t *testing.T) {
	for _, tc := range partialReads {
		t.Run(tc.name, func(t *testing.T) {
			var status int
			var errBody, jsonBody string
			a := partialAPI(partialReply{shardsTotal: 365, shardsSkip: 335}, &status, &errBody, &jsonBody)
			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			tc.handler(a)(httptest.NewRecorder(), r)

			if status != http.StatusOK {
				t.Fatalf("status = %d (%s), want 200: 335 skipped shards is the can_match "+
					"pre-filter working, not a lost answer", status, errBody)
			}
		})
	}
}

// partialAnswer is the one decision point, so it is pinned directly too.
func TestPartialAnswerDecision(t *testing.T) {
	cases := []struct {
		name string
		resp osResponse
		want bool
	}{
		{"whole answer", osResponse{}, false},
		{"timed out", osResponse{TimedOut: true}, true},
		{"failed shard", osResponse{Shards: osShards{Total: 4, Failed: 1}}, true},
		{"skipped only", osResponse{Shards: osShards{Total: 4, Skipped: 3, Successful: 1}}, false},
		{"both", osResponse{TimedOut: true, Shards: osShards{Total: 4, Failed: 2}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.resp.partialAnswer()
			if (err != nil) != tc.want {
				t.Fatalf("partialAnswer() = %v, want partial=%v", err, tc.want)
			}
		})
	}
}

// The completeness fields must actually be DECODED off the wire. `_shards` was
// absent from the struct entirely, so this pins the mapping rather than the
// decision above it.
func TestSearchDecodesTheCompletenessFields(t *testing.T) {
	var status int
	var errBody, jsonBody string
	reply := partialReply{timedOut: true, shardsTotal: 30, shardsFailed: 2, shardsSkip: 3}
	a := partialAPI(reply, &status, &errBody, &jsonBody)

	resp, err := a.search("netops-secfindings-acme-*", map[string]any{})
	if err == nil {
		t.Fatal("search() reported a whole answer over a timed-out, shard-failed reply")
	}
	if !resp.TimedOut {
		t.Error("timed_out was not decoded")
	}
	if resp.Shards.Total != 30 || resp.Shards.Failed != 2 || resp.Shards.Skipped != 3 {
		t.Errorf("_shards decoded as %+v, want total 30 / failed 2 / skipped 3", resp.Shards)
	}
	if len(resp.Hits.Hits) != 1 {
		t.Errorf("the decoded response must still be returned alongside the error, got %d hits", len(resp.Hits.Hits))
	}
}
