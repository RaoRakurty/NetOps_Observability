// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// cloud_live_states_test.go — the Service View's live provider read is bounded
// by the caller's own inventory (tracker 392).
//
// cloudLiveStates read each provider metric FLEET-WIDE under a 1 MiB body cap
// and joined afterwards. The join kept foreign values out of the answer, but
// once the whole platform's cloud fleet outgrew the cap the body was cut, the
// JSON stopped parsing and every tenant's resources read "unknown". The fake
// store below behaves like VictoriaMetrics: an unscoped selector returns the
// whole (large) fleet, a resource_id selector returns only those resources.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"netops/backend/cloud"
)

var cloudLiveSelectorRe = regexp.MustCompile(`resource_id=~"([^"]*)"`)

// cloudFleetVM serves instant queries over a synthetic fleet. status maps a
// resource id to its cloud_status_check_failed value; every other metric
// answers 1 for every resource. It records each query.
type cloudFleetVM struct {
	mu      sync.Mutex
	queries []string
	fleet   []string
	status  map[string]float64
}

func (f *cloudFleetVM) start(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		f.mu.Lock()
		f.queries = append(f.queries, q)
		f.mu.Unlock()
		ids := f.fleet
		if m := cloudLiveSelectorRe.FindStringSubmatch(q); m != nil {
			ids = nil
			for _, raw := range strings.Split(m[1], "|") {
				id, err := strconv.Unquote(`"` + raw + `"`)
				if err != nil {
					http.Error(w, "bad selector", http.StatusBadRequest)
					return
				}
				ids = append(ids, regexp.MustCompile(`\\(.)`).ReplaceAllString(id, "$1"))
			}
		}
		var b strings.Builder
		b.WriteString(`{"status":"success","data":{"resultType":"vector","result":[`)
		for i, id := range ids {
			v := 1.0
			if strings.Contains(q, "cloud_status_check_failed") {
				v = f.status[id]
			}
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `{"metric":{"resource_id":%q,"device":"name-%s","provider":"aws","tenant_id":""},"value":[1700000000,"%g"]}`, id, id, v)
		}
		b.WriteString(`]}}`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(b.String())) // best-effort: test fixture
	}))
	t.Cleanup(srv.Close)
	t.Setenv("VICTORIA_URL", srv.URL)
	t.Setenv("METRICS_URL", srv.URL)
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(ch.Close)
	t.Setenv("CLICKHOUSE_URL", ch.URL)
}

func (f *cloudFleetVM) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

func TestCloudLiveStatesReadOnlyTheCallersResourcesWhateverTheFleetSize(t *testing.T) {
	// Another tenant's fleet is large enough that one fleet-wide answer is far
	// past the 1 MiB read cap.
	fleet := make([]string, 0, 20002)
	for i := 0; i < 20000; i++ {
		fleet = append(fleet, fmt.Sprintf("i-0globex%09d", i))
	}
	fleet = append(fleet, "i-0acme00000001", "i-0acme00000002")
	vm := &cloudFleetVM{fleet: fleet, status: map[string]float64{"i-0acme00000001": 0, "i-0acme00000002": 1}}
	vm.start(t)

	mine := []cloud.CloudResource{
		{ResourceID: "i-0acme00000001", ResourceName: "acme-web-01"},
		{ResourceID: "i-0acme00000002", ResourceName: "acme-web-02"},
	}
	got := (&server{}).cloudLiveStates(context.Background(), "t_acme", "", mine)

	if st := got["i-0acme00000001"]; st.Health != "healthy" || st.CPUPct == nil || st.TrafficBytes == nil {
		t.Fatalf("acme-web-01 must read healthy with measured CPU and traffic despite a large foreign fleet, got %+v", st)
	}
	if st := got["i-0acme00000002"]; st.Health != "down" {
		t.Fatalf("acme-web-02's failed provider status check must read down, got %+v", st)
	}
	if len(got) != len(mine) {
		t.Fatalf("the live view must cover exactly the caller's resources, got %d entries", len(got))
	}

	qs := vm.all()
	if len(qs) != len(cloudLiveMetricNames) {
		t.Fatalf("want one read per live metric for a one-batch view, got %d: %q", len(qs), qs)
	}
	for _, q := range qs {
		m := cloudLiveSelectorRe.FindStringSubmatch(q)
		if m == nil {
			t.Fatalf("a live read went out FLEET-WIDE: %s", q)
		}
		if strings.Contains(q, "globex") {
			t.Fatalf("a live read named a foreign resource: %s", q)
		}
		if !strings.Contains(m[1], "i-0acme00000001") || !strings.Contains(m[1], "i-0acme00000002") {
			t.Fatalf("a live read lost one of the caller's resources: %s", q)
		}
	}
}

func TestCloudLiveStatesAskNothingForAnEmptyView(t *testing.T) {
	vm := &cloudFleetVM{fleet: []string{"i-0globex000000001"}}
	vm.start(t)
	if got := (&server{}).cloudLiveStates(context.Background(), "t_acme", "", nil); len(got) != 0 {
		t.Fatalf("no resources must mean no live states, got %v", got)
	}
	// An empty alternation would match every series with no resource_id; an
	// empty view must not ask the store anything at all.
	if qs := vm.all(); len(qs) != 0 {
		t.Fatalf("an empty view asked the metric store %d question(s): %q", len(qs), qs)
	}
	// An id that is not a valid resource id is dropped, never rendered as an
	// empty branch.
	bad := []cloud.CloudResource{{ResourceID: ""}}
	if got := readCloudLiveMetrics(context.Background(), bad); len(got[cloudLiveStatus]) != 0 {
		t.Fatalf("an invalid id produced values: %v", got)
	}
	if qs := vm.all(); len(qs) != 0 {
		t.Fatalf("an invalid-only view asked the metric store: %q", qs)
	}
}

func TestCloudLiveMetricsBoundedPastTheBatchCap(t *testing.T) {
	var res []cloud.CloudResource
	for i := 0; i < 6000; i++ {
		res = append(res, cloud.CloudResource{ResourceID: fmt.Sprintf("i-0acme%012d", i)})
	}
	vm := &cloudFleetVM{status: map[string]float64{}}
	vm.start(t)
	got := readCloudLiveMetrics(context.Background(), res)
	qs := vm.all()
	if want := cloudMetricProofMaxBatches * len(cloudLiveMetricNames); len(qs) != want {
		t.Fatalf("an over-budget view must read exactly the batch cap (%d reads), got %d", want, len(qs))
	}
	if _, ok := got[cloudLiveStatus][res[0].ResourceID]; !ok {
		t.Fatal("the first batches must still be measured when the view exceeds the cap")
	}
	if _, ok := got[cloudLiveStatus][res[len(res)-1].ResourceID]; ok {
		t.Fatal("a resource past the batch cap was measured — the read is not bounded")
	}
}

func TestCloudLiveQueryNamesOnlyTheGivenIDs(t *testing.T) {
	q := cloudLiveQuery("cloud_cpu_util", regexAlternation([]string{"i-a", "i-b"}))
	if q != `last_over_time(cloud_cpu_util{resource_id=~"i-a|i-b"}[30m])` {
		t.Fatalf("unexpected live query %q", q)
	}
}
