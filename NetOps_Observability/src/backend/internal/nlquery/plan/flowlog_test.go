// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/validate"
)

// flowLogScope is fakeScope plus the optional flow and syslog seams.
type flowLogScope struct {
	fakeScope
	flowQs []FlowQuery
	logQs  []LogQuery
}

func (f *flowLogScope) FlowTop(_ context.Context, q FlowQuery) (FlowAnswer, error) {
	f.flowQs = append(f.flowQs, q)
	return FlowAnswer{Rows: []FlowRow{{A: "192.0.2.10", B: "198.51.100.1", Bytes: 24000, Flows: 60}}, Sampling: "not_reported",
		Notes: []string{"the exporters did not report a sampling rate, so these totals read 1:1 and are low if they sample"}}, nil
}

func (f *flowLogScope) LogSearch(_ context.Context, q LogQuery) (LogAnswer, error) {
	f.logQs = append(f.logQs, q)
	return LogAnswer{Rows: []LogRow{{At: now.Add(-5 * time.Minute), Device: "edge-1", Severity: "error", EventType: "bgp_neighbor_down", Text: "BGP neighbor down"}},
		Total: 4, Notes: []string{"left out 9 routine management-session lines (monitoring polls and controller sessions)"}}, nil
}

func execute(t *testing.T, sc Scope, js string) (*ResultSet, error) {
	t.Helper()
	a, err := ast.Decode([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	v, res := validate.Validate(context.Background(), cat, visAll{}, a)
	if !res.Valid {
		t.Fatalf("fixture invalid: %+v", res.Errors)
	}
	return Planner{Cat: cat}.Execute(context.Background(), sc, v, res.Constraints)
}

func TestFlowTopResolvesSitesToVisibleDevicesAndRanks(t *testing.T) {
	sc := &flowLogScope{}
	rs, err := execute(t, sc, `{"v":1,"query_type":"flow_top","target":"device","entities":[{"type":"site","id":"site:dfw-hq"}],"time_range":{"kind":"relative","last":"1h"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.flowQs) != 1 {
		t.Fatalf("want one flow read, got %d", len(sc.flowQs))
	}
	q := sc.flowQs[0]
	if strings.Join(q.Devices, ",") != "d1,d2" || q.By != ast.FlowGroupTalker || q.Limit != validate.DefaultFlowTop || q.To.Sub(q.From).Hours() != 1 {
		t.Fatalf("flow query = %+v", q)
	}
	if len(rs.Rows) != 1 || rs.Rows[0]["talker_a"] != "192.0.2.10" || rs.Rows[0]["bytes"] != 24000.0 || rs.Provenance.Source != "flows" {
		t.Fatalf("rows = %+v source %q", rs.Rows, rs.Provenance.Source)
	}
	sum := Summarize(cat, mustAST(t, `{"v":1,"query_type":"flow_top","target":"device","group_by":["talker"]}`), rs)
	if !strings.Contains(sum, "The heaviest conversation") || !strings.Contains(sum, "192.0.2.10 ↔ 198.51.100.1 — 23.4 KiB, 60 flows") || !strings.Contains(sum, "1:1") {
		t.Fatalf("summary = %q", sum)
	}
}

func TestFlowAndLogEmptyResolutionNeverReadsUnscoped(t *testing.T) {
	for _, js := range []string{
		`{"v":1,"query_type":"flow_top","target":"device","entities":[{"type":"site","id":"site:aus"}]}`,
		`{"v":1,"query_type":"log_search","target":"device","entities":[{"type":"site","id":"site:aus"}]}`,
	} {
		sc := &flowLogScope{}
		rs, err := execute(t, sc, js)
		if err != nil {
			t.Fatal(err)
		}
		if len(sc.flowQs)+len(sc.logQs) != 0 {
			t.Fatalf("an empty scope read data: %+v %+v", sc.flowQs, sc.logQs)
		}
		if len(rs.Notes) == 0 || !strings.Contains(rs.Notes[0], "nothing visible") {
			t.Fatalf("notes = %v", rs.Notes)
		}
	}
}

func TestLogSearchMapsClosedFiltersOnly(t *testing.T) {
	sc := &flowLogScope{}
	rs, err := execute(t, sc, `{"v":1,"query_type":"log_search","target":"device","entities":[{"type":"device","id":"device:d1"}],
		"filters":[{"field":"severity","op":"gte","values":["error"]},{"field":"topic","op":"in","values":["bgp","bfd"]}],"time_range":{"kind":"relative","last":"6h"}}`)
	if err != nil {
		t.Fatal(err)
	}
	q := sc.logQs[0]
	if strings.Join(q.Devices, ",") != "d1" || q.MinSeverity != "error" || len(q.Severities) != 0 || strings.Join(q.Topics, ",") != "bgp,bfd" || q.Limit != validate.DefaultLogRows {
		t.Fatalf("log query = %+v", q)
	}
	if len(rs.Rows) != 1 || rs.Rows[0]["device"] != "edge-1" || !rs.Truncated || rs.Provenance.Source != "syslog" {
		t.Fatalf("rows = %+v truncated %v", rs.Rows, rs.Truncated)
	}
	if !strings.Contains(strings.Join(rs.Notes, " "), "routine management-session") {
		t.Fatalf("notes = %v", rs.Notes)
	}
}

func TestFlowAndLogWithoutTheSeamSayUnavailable(t *testing.T) {
	_, err := execute(t, &fakeScope{}, `{"v":1,"query_type":"flow_top","target":"device"}`)
	if !errors.Is(err, ErrFlowsUnavailable) {
		t.Fatalf("flow_top on a scope without flows: %v", err)
	}
	_, err = execute(t, &fakeScope{}, `{"v":1,"query_type":"log_search","target":"device"}`)
	if !errors.Is(err, ErrLogsUnavailable) {
		t.Fatalf("log_search on a scope without syslog: %v", err)
	}
}

func TestSeveritiesAtOrAbove(t *testing.T) {
	if got := strings.Join(SeveritiesAtOrAbove("warning"), ","); got != "critical,error,warning" {
		t.Fatalf("warning floor = %q", got)
	}
	if SeveritiesAtOrAbove("catastrophic") != nil {
		t.Fatal("an unknown level admits nothing")
	}
}

func mustAST(t *testing.T, js string) *ast.AST {
	t.Helper()
	a, err := ast.Decode([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return a
}
