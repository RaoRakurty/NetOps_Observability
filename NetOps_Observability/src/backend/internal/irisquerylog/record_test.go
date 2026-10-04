// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisquerylog

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/compile"
	"netops/backend/internal/nlquery/plan"
	"netops/backend/internal/nlquery/resolve"
	"netops/backend/internal/nlquery/validate"
)

var bg = context.Background()

func rec(principal, q string) Record {
	return Record{Principal: principal, Source: SourceRouter, Outcome: OutcomeAnswered, Question: q}
}

// ---- normalization -----------------------------------------------------------

func TestNormalizeBoundsEverything(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	r := rec("alice", "  "+strings.Repeat("é", MaxQuestionLen+50)+"  ")
	for i := 0; i < MaxEntities+5; i++ {
		r.Entities = append(r.Entities, Entity{Type: "device", ID: "device:d" + strings.Repeat("x", i), Method: "inventory_name", Confidence: 2})
	}
	r.Entities = append(r.Entities, Entity{Type: "device", ID: strings.Repeat("y", MaxIDLen+1)})
	for i := 0; i < MaxCodes+5; i++ {
		r.ValidationCodes = append(r.ValidationCodes, "code_"+strings.Repeat("z", i))
	}
	r.ValidationCodes = append(r.ValidationCodes, "code_", "", "  ")
	r.Rows, r.Series, r.DurationMs = -3, -1, -9
	r.Corrections = []Correction{{Kind: KindOther, Note: "smuggled"}}
	got, err := Normalize("acme", r, now)
	if err != nil {
		t.Fatal(err)
	}
	if n := len([]rune(got.Question)); n != MaxQuestionLen {
		t.Errorf("question clipped to %d runes, want %d", n, MaxQuestionLen)
	}
	if len(got.Entities) != MaxEntities || len(got.ValidationCodes) != MaxCodes {
		t.Errorf("entities %d codes %d", len(got.Entities), len(got.ValidationCodes))
	}
	if got.Entities[0].Confidence != 0 {
		t.Errorf("an out-of-range confidence must be zeroed: %v", got.Entities[0].Confidence)
	}
	if got.Rows != 0 || got.Series != 0 || got.DurationMs != 0 {
		t.Errorf("negative counts must clamp to zero: %+v", got)
	}
	if len(got.Corrections) != 0 {
		t.Error("a record is born without corrections — they arrive only through Correct")
	}
	if !ValidID(got.ID) || !got.At.Equal(now) || got.TenantID != "acme" {
		t.Errorf("id/at/tenant not assigned: %+v", got)
	}
}

func TestNormalizeRefusesWhatIsNotClosed(t *testing.T) {
	now := time.Now()
	cases := map[string]func(r *Record) string{
		"no tenant":        func(*Record) string { return "" },
		"no principal":     func(r *Record) string { r.Principal = " "; return "acme" },
		"unknown outcome":  func(r *Record) string { r.Outcome = "great"; return "acme" },
		"unknown source":   func(r *Record) string { r.Source = "sql"; return "acme" },
		"bad id":           func(r *Record) string { r.ID = "x' OR 1=1"; return "acme" },
		"bad conversation": func(r *Record) string { r.ConversationID = "not-a-uuid"; return "acme" },
	}
	for name, mut := range cases {
		r := rec("alice", "q")
		tenant := mut(&r)
		if _, err := Normalize(tenant, r, now); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

func TestNormalizeCorrection(t *testing.T) {
	now := time.Now()
	if _, err := NormalizeCorrection(Correction{Kind: "retrain_me", By: "alice"}, now); !errors.Is(err, ErrInvalid) {
		t.Errorf("an unknown kind must be refused: %v", err)
	}
	if _, err := NormalizeCorrection(Correction{Kind: KindWrongEntity}, now); !errors.Is(err, ErrInvalid) {
		t.Errorf("a correction needs an author: %v", err)
	}
	if _, err := NormalizeCorrection(Correction{Kind: KindOther, By: "alice", Note: "   "}, now); !errors.Is(err, ErrInvalid) {
		t.Errorf("'other' with nothing said must be refused: %v", err)
	}
	c, err := NormalizeCorrection(Correction{Kind: KindWrongWindow, By: "alice", Note: strings.Repeat("n", MaxNoteLen+10), CorrectedHash: "forged"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Note) != MaxNoteLen || c.CorrectedHash != "" {
		t.Errorf("note must be clipped and a supplied hash ignored: %d %q", len(c.Note), c.CorrectedHash)
	}
	q := &ast.AST{V: 1, Type: ast.ChangeList, Target: "change"}
	c, err = NormalizeCorrection(Correction{Kind: KindWrongFilter, By: "alice", CorrectedAST: q}, now)
	if err != nil || c.CorrectedHash != q.Hash() || c.CorrectedAST == q {
		t.Errorf("the corrected query is copied and hashed by the store: %v %+v", err, c)
	}
}

// ---- building from the pipeline ------------------------------------------------

func TestFromCompileOutcomes(t *testing.T) {
	q := &ast.AST{V: 1, Type: ast.MetricSeries, Target: "device", Metric: "cpu_util_pct"}
	ref := resolve.Ref{EntityID: "device:edge-1", EntityType: "device", Method: "tenant_alias", Confidence: 0.9}
	bad := &validate.Result{Errors: []validate.Error{{Code: validate.CodeUnknownEntity}}}
	ok := &validate.Result{Valid: true}
	cases := []struct {
		name    string
		res     compile.Result
		checked *ast.AST
		vr      *validate.Result
		want    string
	}{
		{"declined", compile.Result{Decline: "not_a_query"}, nil, nil, OutcomeDeclined},
		{"clarify", compile.Result{Clarify: []resolve.Ref{ref}}, nil, nil, OutcomeClarify},
		{"unparsed", compile.Result{Unparsed: true}, nil, nil, OutcomeUnparsed},
		{"no ast", compile.Result{Intent: "x"}, nil, nil, OutcomeUnparsed},
		{"invalid", compile.Result{AST: q}, nil, bad, OutcomeInvalid},
		{"compiled", compile.Result{AST: q, Entities: []resolve.Ref{ref}}, q, ok, OutcomeCompiled},
	}
	for _, c := range cases {
		r := FromCompile(SourceQueryCompile, "q", c.res, c.checked, c.vr)
		if r.Outcome != c.want {
			t.Errorf("%s: outcome %q, want %q", c.name, r.Outcome, c.want)
		}
	}
	r := FromCompile(SourceRouter, "q", compile.Result{AST: q, Entities: []resolve.Ref{ref}}, nil, bad)
	if len(r.ValidationCodes) != 1 || r.ValidationCodes[0] != validate.CodeUnknownEntity || r.ASTHash != q.Hash() || r.QueryType != "metric_series" {
		t.Errorf("codes/hash/type: %+v", r)
	}
	if len(r.Entities) != 1 || r.Entities[0].Method != "tenant_alias" {
		t.Errorf("entities keep their resolution method: %+v", r.Entities)
	}
	rs := &plan.ResultSet{ASTHash: "h", CatalogVersion: "v1-abc", Rows: []plan.Row{{}, {}}, Series: []plan.OutSeries{{}}}
	r.Answered(rs)
	if r.Outcome != OutcomeAnswered || r.Rows != 2 || r.Series != 1 || r.ASTHash != "h" || r.CatalogVersion != "v1-abc" {
		t.Errorf("answered: %+v", r)
	}
}

func TestFromQueryMarksSuppliedEntities(t *testing.T) {
	q := &ast.AST{V: 1, Type: ast.MetricSeries, Target: "device", Refs: []ast.EntityRef{{Type: "device", ID: "device:edge-1"}}}
	checked := q.Clone()
	checked.Time = ast.TimeRange{Kind: ast.TimeRelative, Last: "1h"} // the validator's default window
	r := FromQuery(q, checked, validate.Result{Valid: true})
	if r.Source != SourceQueryExecute || r.Outcome != OutcomeCompiled || r.Entities[0].Method != MethodSupplied || r.Question != "" {
		t.Fatalf("%+v", r)
	}
	// The record keeps the VALIDATED query (constraints applied), marked as
	// supplied by the client, and its hash is that query's.
	if r.Query != checked || r.CompiledBy != CompiledBySupplied || r.ASTHash != checked.Hash() {
		t.Fatalf("supplied query: %+v", r)
	}
	bad := FromQuery(q, nil, validate.Result{})
	if bad.Outcome != OutcomeInvalid || bad.Query != nil || bad.CompiledBy != "" {
		t.Fatalf("an invalid supplied query is recorded invalid, without a query: %+v", bad)
	}
}

func TestTheStoredQueryAndItsAuthor(t *testing.T) {
	q := &ast.AST{V: 1, Type: ast.MetricSeries, Target: "device", Metric: "cpu_util_pct",
		Time: ast.TimeRange{Kind: ast.TimeRelative, Last: "1h"}}
	ok := &validate.Result{Valid: true}
	r := FromCompile(SourceQueryCompile, "q", compile.Result{AST: q}, q, ok)
	if r.Query != q || r.CompiledBy != CompiledByGrammar {
		t.Fatalf("a grammar-compiled query is kept and attributed to the grammar: %+v", r)
	}
	r.ByModel()
	if r.CompiledBy != CompiledByModel {
		t.Fatalf("ByModel: %+v", r)
	}
	// No query → no author, whatever the caller claimed.
	none := FromCompile(SourceQueryCompile, "q", compile.Result{AST: q}, nil, &validate.Result{})
	none.ByModel()
	if none.Query != nil || none.CompiledBy != "" {
		t.Fatalf("an invalid question keeps no query and no author: %+v", none)
	}
	got, err := Normalize("acme", Record{Principal: "alice", Source: SourceRouter, Outcome: OutcomeUnparsed, CompiledBy: CompiledByModel}, time.Now())
	if err != nil || got.CompiledBy != "" {
		t.Fatalf("an author without a query is dropped: %v %+v", err, got)
	}
	// A query needs a known author.
	for _, by := range []string{"", "llm", "Grammar"} {
		bad := rec("alice", "q")
		bad.Query, bad.CompiledBy = q, by
		if _, err := Normalize("acme", bad, time.Now()); !errors.Is(err, ErrInvalid) {
			t.Errorf("author %q: want ErrInvalid, got %v", by, err)
		}
	}
	// Normalize stores a COPY, and fills the hash from it when absent.
	keep := rec("alice", "q")
	keep.Query, keep.CompiledBy = q, CompiledByModel
	got, err = Normalize("acme", keep, time.Now())
	if err != nil || got.Query == q || got.Query.Hash() != q.Hash() || got.ASTHash != q.Hash() || got.CompiledBy != CompiledByModel {
		t.Fatalf("normalized query: %v %+v", err, got)
	}
}

// ---- the corrected query is never trusted --------------------------------------

type fakeScope struct{}

var visible = map[string]bool{"site:dfw-hq": true, "device:edge-1": true}

func (fakeScope) Visible(_ context.Context, r ast.EntityRef) (bool, error) { return visible[r.ID], nil }
func (fakeScope) Count(context.Context, string, []ast.EntityRef) (int, error) {
	return 3, nil
}
func (fakeScope) CrossTenant() bool                                    { return false }
func (fakeScope) ProviderMapped(context.Context, string) (bool, error) { return true, nil }
func (fakeScope) Now() time.Time                                       { return time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC) }

const goodAST = `{"v":1,"query_type":"metric_series","target":"device","metric":"cpu_util_pct","entities":[{"type":"site","id":"site:dfw-hq"}],"time_range":{"kind":"relative","last":"2h"}}`

func TestCorrectedASTIsDecodedStrictlyAndValidatedInScope(t *testing.T) {
	cat := catalog.MustLoad()
	got, vr, err := CheckCorrectedAST(bg, cat, fakeScope{}, []byte(goodAST))
	if err != nil || got == nil || !vr.Valid || got.Agg == "" {
		t.Fatalf("a valid query is accepted as the VALIDATED form: %v %+v %+v", err, vr, got)
	}
	for _, blank := range []string{"", "  ", "null"} {
		if q, _, err := CheckCorrectedAST(bg, cat, fakeScope{}, []byte(blank)); q != nil || err != nil {
			t.Errorf("%q: an absent query is not an error: %v", blank, err)
		}
	}
	// A foreign entity and a missing one are refused the SAME way (§3a).
	foreign := strings.Replace(goodAST, "site:dfw-hq", "site:tenant-b-hq", 1)
	missing := strings.Replace(goodAST, "site:dfw-hq", "site:no-such", 1)
	var codes [2]string
	for i, js := range []string{foreign, missing} {
		q, vr, err := CheckCorrectedAST(bg, cat, fakeScope{}, []byte(js))
		if !errors.Is(err, ErrRejected) || q != nil || len(vr.Errors) == 0 {
			t.Fatalf("a query naming an entity the caller cannot see must be rejected: %v %+v", err, vr)
		}
		codes[i] = vr.Errors[0].Code
	}
	if codes[0] != validate.CodeUnknownEntity || codes[0] != codes[1] {
		t.Errorf("foreign and missing must be indistinguishable: %v", codes)
	}
	for name, js := range map[string]string{
		"tenant field":    strings.Replace(goodAST, `"v":1`, `"v":1,"tenant":"t-b"`, 1),
		"as_tenant field": strings.Replace(goodAST, `"v":1`, `"v":1,"as_tenant":"t-b"`, 1),
		"trailing data":   goodAST + `{"v":1}`,
		"not json":        `DROP TABLE x`,
		"too large":       `{"v":1,"target":"` + strings.Repeat("a", ast.MaxBytes) + `"}`,
	} {
		if q, _, err := CheckCorrectedAST(bg, cat, fakeScope{}, []byte(js)); !errors.Is(err, ErrInvalid) || q != nil {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

// ---- the in-memory store ---------------------------------------------------------

func TestMemStoreIsTenantAndPrincipalScoped(t *testing.T) {
	m := NewMemStore()
	a, err := m.Record(bg, "acme", rec("alice", "cpu on edge-1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Record(bg, "acme", rec("bob", "memory on edge-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Record(bg, "globex", rec("alice", "globex question")); err != nil {
		t.Fatal(err)
	}
	mine, _ := m.List(bg, "acme", ListFilter{Principal: "alice"})
	if len(mine) != 1 || mine[0].ID != a.ID {
		t.Fatalf("own list: %+v", mine)
	}
	all, _ := m.List(bg, "acme", ListFilter{})
	if len(all) != 2 || all[0].Principal != "bob" {
		t.Fatalf("tenant list is the tenant's only, newest first: %+v", all)
	}
	for _, r := range all {
		if r.Question == "globex question" {
			t.Fatal("CROSS-TENANT LEAK: another tenant's record listed")
		}
	}
	c := Correction{Kind: KindWrongEntity, By: "alice", Note: "I meant edge-2"}
	for _, who := range [][2]string{{"globex", "alice"}, {"acme", "bob"}, {"acme", ""}} {
		if _, err := m.Correct(bg, who[0], who[1], a.ID, c); !errors.Is(err, ErrNotFound) {
			t.Errorf("%v must not correct alice's record: %v", who, err)
		}
	}
	got, err := m.Correct(bg, "acme", "alice", a.ID, c)
	if err != nil || len(got.Corrections) != 1 || got.Corrections[0].Kind != KindWrongEntity {
		t.Fatalf("own correction: %v %+v", err, got)
	}
}

func TestMemStoreGetIsTenantAndPrincipalScoped(t *testing.T) {
	m := NewMemStore()
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	q := &ast.AST{V: 1, Type: ast.ChangeList, Target: "change", Time: ast.TimeRange{Kind: ast.TimeRelative, Last: "24h"}}
	in := rec("alice", "what changed")
	in.Query, in.CompiledBy = q, CompiledByModel
	a, err := m.Record(bg, "acme", in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.Get(bg, "acme", "alice", a.ID)
	if err != nil || got.Query == nil || got.Query.Hash() != q.Hash() || got.CompiledBy != CompiledByModel || got.Question != "what changed" {
		t.Fatalf("own get: %v %+v", err, got)
	}
	// principal "" is the tenant-wide read (the handler decides who may).
	if _, err := m.Get(bg, "acme", "", a.ID); err != nil {
		t.Fatalf("tenant-wide get: %v", err)
	}
	for _, who := range [][2]string{{"globex", "alice"}, {"globex", ""}, {"acme", "bob"}} {
		if _, err := m.Get(bg, who[0], who[1], a.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("%v must not read alice's record: %v", who, err)
		}
	}
	for _, id := range []string{"", "not-a-uuid", "11111111-2222-4333-8444-555555555555", strings.ToUpper(a.ID)} {
		if _, err := m.Get(bg, "acme", "alice", id); !errors.Is(err, ErrNotFound) {
			t.Errorf("id %q: %v", id, err)
		}
	}
	// The returned query is a copy.
	got.Query.Metric = "mutated"
	if again, _ := m.Get(bg, "acme", "alice", a.ID); again.Query.Metric != "" {
		t.Fatal("a returned query aliases the store")
	}
	// Expired is gone.
	now = now.Add(Retention + time.Minute)
	if _, err := m.Get(bg, "acme", "alice", a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an expired record: %v", err)
	}
}

func TestMemStoreBounds(t *testing.T) {
	m := NewMemStore()
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }

	// Age: a record older than the retention window is gone.
	old := rec("alice", "old")
	old.At = now.Add(-Retention - time.Minute)
	if _, err := m.Record(bg, "acme", old); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Record(bg, "acme", rec("alice", "new")); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.List(bg, "acme", ListFilter{Limit: MaxListLimit}); len(got) != 1 || got[0].Question != "new" {
		t.Fatalf("an expired record must be pruned: %+v", got)
	}

	// Per-tenant cap: the oldest go first, other tenants are untouched.
	if _, err := m.Record(bg, "globex", rec("carol", "keep me")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxPerTenant+10; i++ {
		if _, err := m.Record(bg, "acme", rec("alice", "q")); err != nil {
			t.Fatal(err)
		}
	}
	m.mu.Lock()
	n, g := len(m.recs["acme"]), len(m.recs["globex"])
	first := m.recs["acme"][0].Question
	m.mu.Unlock()
	if n != MaxPerTenant || g != 1 || first == "new" {
		t.Fatalf("cap: acme=%d globex=%d first=%q", n, g, first)
	}

	// List limits are clamped.
	if got, _ := m.List(bg, "acme", ListFilter{Limit: 100000}); len(got) != MaxListLimit {
		t.Fatalf("limit clamp: %d", len(got))
	}
	if got, _ := m.List(bg, "acme", ListFilter{}); len(got) != DefaultListLimit {
		t.Fatalf("default limit: %d", len(got))
	}

	// Corrections per record are capped.
	r, _ := m.Record(bg, "acme", rec("alice", "c"))
	for i := 0; i < MaxCorrections; i++ {
		if _, err := m.Correct(bg, "acme", "alice", r.ID, Correction{Kind: KindWrongMetric, By: "alice"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Correct(bg, "acme", "alice", r.ID, Correction{Kind: KindWrongMetric, By: "alice"}); !errors.Is(err, ErrFull) {
		t.Fatalf("past the correction cap: %v", err)
	}

	// An expired record cannot be corrected.
	now = now.Add(Retention + time.Hour)
	if _, err := m.Correct(bg, "acme", "alice", r.ID, Correction{Kind: KindWrongMetric, By: "alice"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an expired record: %v", err)
	}
}

func TestMemStoreReturnsCopies(t *testing.T) {
	m := NewMemStore()
	r := rec("alice", "q")
	r.Entities = []Entity{{Type: "device", ID: "device:edge-1", Method: "canonical_id"}}
	got, _ := m.Record(bg, "acme", r)
	got.Entities[0].ID = "device:mutated"
	list, _ := m.List(bg, "acme", ListFilter{})
	if list[0].Entities[0].ID != "device:edge-1" {
		t.Fatal("a returned record aliases the store")
	}
}

func TestMemStoreConcurrentCorrectionsRespectTheCap(t *testing.T) {
	m := NewMemStore()
	r, _ := m.Record(bg, "acme", rec("alice", "q"))
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < MaxCorrections+10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.Correct(bg, "acme", "alice", r.ID, Correction{Kind: KindWrongWindow, By: "alice"}); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != MaxCorrections {
		t.Fatalf("%d corrections stored, want %d", ok, MaxCorrections)
	}
}

// ---- metrics ------------------------------------------------------------------------

func TestMetricsRenderEverySeries(t *testing.T) {
	m := NewMetrics()
	m.Captured(true)
	m.Captured(false)
	m.Corrected(KindWrongEntity)
	m.Corrected("not-a-kind") // ignored, never a new series
	var b bytes.Buffer
	m.Write(&b)
	out := b.String()
	for _, want := range []string{
		`netops_iris_query_capture_total{result="recorded"} 1`,
		`netops_iris_query_capture_total{result="failed"} 1`,
		`netops_iris_query_corrections_total{kind="wrong_entity"} 1`,
		`netops_iris_query_corrections_total{kind="other"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "not-a-kind") {
		t.Error("an unknown kind must not create a series")
	}
	var nilM *Metrics
	nilM.Captured(true)
	nilM.Corrected(KindOther)
	nilM.Write(&b) // nil-safe
}
