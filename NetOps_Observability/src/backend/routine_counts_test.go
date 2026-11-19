// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// routine_counts_test.go — tracker 410 PR 4: the routine count over a window
// that reaches past the originals' counted part. Routine-family originals are
// counted from logroutine.RollupCut onward; older sessions come from the
// caller's OWN roll-ups (§3a: own roll-up index pattern, own tenant filter,
// as_tenant ignored), and a text query is told why it gets no older count.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/logroutine"
)

// fakeRoutineOS answers log searches with the routine aggregation, and the
// roll-up sum query with a per-index-pattern total (so a foreign pattern would
// be VISIBLE in the answer if it were ever named).
func fakeRoutineOS(t *testing.T) (paths, bodies *[]string) {
	t.Helper()
	var mu sync.Mutex
	var gotPaths, gotBodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotPaths, gotBodies = append(gotPaths, r.URL.Path), append(gotBodies, string(b))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "netops-syslogrollup-") {
			n := 5000
			if strings.Contains(r.URL.Path, "globex") {
				n = 777777 // a leak would show up as this number
			}
			_, _ = w.Write([]byte(`{"hits":{"total":{"value":0}},"aggregations":{"n":{"value":` + strconv.Itoa(n) + `}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"hits":{"total":{"value":1},"hits":[{"_index":"netops-syslog-acme-x","_id":"a","_source":{"message":"x"}}]},"aggregations":{"cx_routine_mgmt":{"doc_count":12}}}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("OPENSEARCH_URL", srv.URL)
	return &gotPaths, &gotBodies
}

func routineSummaryOf(t *testing.T, body []byte) logroutine.Summary {
	t.Helper()
	var resp struct {
		Routine logroutine.Summary `json:"routine_mgmt"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("answer is not JSON: %v\n%s", err, body)
	}
	return resp.Routine
}

func TestLogsSearchCountsOlderRoutineSessionsFromTheCallersOwnRollups(t *testing.T) {
	paths, bodies := fakeRoutineOS(t)
	s := logsTestServer(t)
	from := time.Now().UTC().Add(-7 * 24 * time.Hour).Format(time.RFC3339)
	for _, claims := range []jwtClaims{acme(), func() jwtClaims { c := acme(); c.ActingTenant = "globex"; return c }()} {
		*paths, *bodies = nil, nil
		w := httptest.NewRecorder()
		s.handleLogsSearch(w, req(http.MethodPost, "/api/logs/search",
			`{"query":"*","signal":"syslog","from":"`+from+`"}`, claims))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d (%s)", w.Code, w.Body.String())
		}
		got := routineSummaryOf(t, w.Body.Bytes())
		if got.Count != 12 || got.Summarised != 5000 || got.SummarisedNote != "" {
			t.Fatalf("routine summary = %+v, want count 12 + 5000 summarised (as_tenant=%q)", got, claims.ActingTenant)
		}
		var rollupPath, rollupBody string
		for i, p := range *paths {
			if strings.Contains(p, "syslogrollup") {
				rollupPath, rollupBody = p, (*bodies)[i]
			}
			if strings.Contains(p, "globex") {
				t.Errorf("CROSS-TENANT LEAK: acme's search named %q", p)
			}
		}
		if !strings.Contains(rollupPath, "netops-syslogrollup-acme-*") || !strings.Contains(rollupPath, "netops-syslogrollup-untagged-*") {
			t.Errorf("the roll-up count read %q, want acme's own roll-up pattern", rollupPath)
		}
		if !strings.Contains(rollupBody, `"tenant_id":"acme"`) || !strings.Contains(rollupBody, `"occurrence_count"`) {
			t.Errorf("the roll-up count carries no acme tenant filter: %s", rollupBody)
		}
		// The originals' count leaves routine-family originals before the cut
		// to the roll-ups: no session is counted twice.
		if !strings.Contains((*bodies)[0], `"netops-syslogroutine-"`) {
			t.Errorf("the search's routine aggregation does not exclude old routine originals: %s", (*bodies)[0])
		}
	}
}

func TestLogsSearchRoutineOlderPartHonestCases(t *testing.T) {
	paths, _ := fakeRoutineOS(t)
	s := logsTestServer(t)
	from := time.Now().UTC().Add(-7 * 24 * time.Hour).Format(time.RFC3339)
	// A text query: the roll-ups hold no message text, so no number, a reason.
	w := httptest.NewRecorder()
	s.handleLogsSearch(w, req(http.MethodPost, "/api/logs/search", `{"query":"vmanage","signal":"syslog","from":"`+from+`"}`, acme()))
	if got := routineSummaryOf(t, w.Body.Bytes()); got.Summarised != 0 || got.SummarisedNote != logroutine.NoteTextQuery {
		t.Errorf("text query summary = %+v, want the text_query note", got)
	}
	// The default 15-minute window: nothing older than the cut, no roll-up read.
	*paths = nil
	w = httptest.NewRecorder()
	s.handleLogsSearch(w, req(http.MethodPost, "/api/logs/search", `{"query":"*","signal":"syslog"}`, acme()))
	for _, p := range *paths {
		if strings.Contains(p, "syslogrollup") {
			t.Errorf("a window inside the last day read the roll-ups: %s", p)
		}
	}
	if got := routineSummaryOf(t, w.Body.Bytes()); got.Summarised != 0 || got.SummarisedNote != "" {
		t.Errorf("a recent window carries an older part: %+v", got)
	}
}

func TestIrisSearchLogsSaysHowManyOlderRoutineSessionsAreCounted(t *testing.T) {
	paths, bodies := fakeRoutineOS(t)
	s := logsTestServer(t)
	d := aiDataSource{srv: s, ctx: context.Background(), scope: "acme", claims: acme()}
	now := time.Now().UTC()
	out, err := d.syslogSearch(ai.Principal{Tenant: "acme"}, syslogSpec{
		query: "*", start: now.Add(-7 * 24 * time.Hour), end: now, size: 10,
		deviceIDs: []string{"acme-core"}, auditPath: "/test", auditAction: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.summarised != 5000 {
		t.Fatalf("summarised = %d, want 5000", out.summarised)
	}
	notes := strings.Join(out.routineNote(true), " | ")
	if !strings.Contains(notes, "another 5000 routine management sessions older than a day") {
		t.Errorf("notes = %q", notes)
	}
	for i, p := range *paths {
		if strings.Contains(p, "syslogrollup") && !strings.Contains((*bodies)[i], `"acme-core"`) {
			t.Errorf("Iris's roll-up count is not narrowed to the asked device: %s", (*bodies)[i])
		}
	}
	// A severity filter cannot apply to roll-ups (they carry none): no older part.
	out, err = d.syslogSearch(ai.Principal{Tenant: "acme"}, syslogSpec{
		query: "*", start: now.Add(-7 * 24 * time.Hour), end: now, size: 10, severities: []string{"error"},
		auditPath: "/test", auditAction: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.summarised != 0 || out.summarisedNote != "" {
		t.Errorf("a severity-filtered read got a roll-up count: %d %q", out.summarised, out.summarisedNote)
	}
}
