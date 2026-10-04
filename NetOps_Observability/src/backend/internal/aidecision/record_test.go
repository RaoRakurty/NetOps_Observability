// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package aidecision

// record_test.go — the ledger's own rules, without a database: the closed
// vocabulary matches the migration's CHECK, free text never survives
// normalization, a batch is one decision, the per-request Recorder is bounded
// and nil-safe, the in-memory store is tenant-keyed and bounded, and the
// metrics render every series (zeros included).

import (
	"bytes"
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const testHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // SHA-256 of ""

func TestEventTypesMatchTheMigrationCheck(t *testing.T) {
	b, err := os.ReadFile("../platformdb/migrations/0055_ai_decision_ledger.sql")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)event_type IN \((.*?)\)\)`).FindSubmatch(b)
	if m == nil {
		t.Fatal("migration 0055 has no event_type CHECK")
	}
	var inSQL []string
	for _, q := range regexp.MustCompile(`'([A-Z_]+)'`).FindAllSubmatch(m[1], -1) {
		inSQL = append(inSQL, string(q[1]))
	}
	if strings.Join(inSQL, ",") != strings.Join(EventTypes, ",") {
		t.Fatalf("migration CHECK %v\n      vocabulary %v", inSQL, EventTypes)
	}
	if len(EventTypes) != 17 {
		t.Fatalf("Part 1 §35's sixteen + ANSWER_RETURNED = 17, got %d", len(EventTypes))
	}
}

func TestTheMigrationIsAppendOnly(t *testing.T) {
	b, err := os.ReadFile("../platformdb/migrations/0055_ai_decision_ledger.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(b)
	for _, want := range []string{
		"FORCE ROW LEVEL SECURITY",
		"CREATE POLICY tenant_iso ON ai_decision_ledger",
		"REVOKE UPDATE, DELETE, TRUNCATE ON ai_decision_ledger FROM PUBLIC",
		"REVOKE UPDATE, DELETE, TRUNCATE ON ai_decision_ledger FROM CURRENT_USER",
		"BEFORE UPDATE OR DELETE ON ai_decision_ledger",
		"BEFORE TRUNCATE ON ai_decision_ledger",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("migration 0055 lacks %q", want)
		}
	}
	code := regexp.MustCompile(`(?m)--.*$`).ReplaceAllString(sql, "") // statements, not the commentary
	if regexp.MustCompile(`(?i)\bGRANT\b`).MatchString(code) {
		t.Error("migration 0055 must not GRANT anything on the ledger")
	}
	down, err := os.ReadFile("../platformdb/migrations/rollback/0055_ai_decision_ledger.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(down), "DELETE FROM schema_migrations WHERE version = '0055_ai_decision_ledger.sql'") {
		t.Error("rollback must forget the applied version")
	}
}

func valid(over func(*Entry)) Entry {
	e := Entry{DecisionID: "11111111-2222-4333-8444-555555555555", EventType: ToolExecuted,
		Principal: "alice", Surface: SurfaceAsk, Tool: "bgp_peers", ArgsSHA256: testHash, ResultSHA256: testHash}
	if over != nil {
		over(&e)
	}
	return e
}

func TestNormalizeRefusesWhatIsNotAnEntry(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for name, c := range map[string]struct {
		tenant string
		over   func(*Entry)
	}{
		"no tenant":     {"", nil},
		"no principal":  {"t", func(e *Entry) { e.Principal = " " }},
		"newline sub":   {"t", func(e *Entry) { e.Principal = "a\nb" }},
		"long sub":      {"t", func(e *Entry) { e.Principal = strings.Repeat("a", MaxPrincipalLen+1) }},
		"event type":    {"t", func(e *Entry) { e.EventType = "TOOL_DELETED" }},
		"surface":       {"t", func(e *Entry) { e.Surface = "copilot" }},
		"decision id":   {"t", func(e *Entry) { e.DecisionID = "x' OR 1=1" }},
		"entry id":      {"t", func(e *Entry) { e.ID = "not-a-uuid" }},
		"negative seq":  {"t", func(e *Entry) { e.Seq = -1 }},
		"seq too big":   {"t", func(e *Entry) { e.Seq = MaxEntriesPerDecision }},
		"args hash":     {"t", func(e *Entry) { e.ArgsSHA256 = "the raw arguments" }},
		"upper hash":    {"t", func(e *Entry) { e.ResultSHA256 = strings.ToUpper(testHash) }},
		"short hash":    {"t", func(e *Entry) { e.ResultSHA256 = testHash[:63] }},
		"question text": {"t", func(e *Entry) { e.ArgsSHA256 = "show cpu on edge-a" }},
	} {
		if _, err := Normalize(c.tenant, valid(c.over), now); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

func TestNormalizeDropsFreeTextAndStampsTheScope(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.FixedZone("x", 3600))
	e, err := Normalize("t-a", valid(func(e *Entry) {
		e.TenantID = "t-b" // a caller-supplied tenant never survives
		e.Intent = "query_metric"
		e.Outcome = "the device edge-a is down because" // prose: dropped
		e.Skill = "<script>"                            // not a token: dropped
		e.ModelName = strings.Repeat("m", MaxTokenLen+1)
		e.ToolVersion = "1.2.3+abcdef"
		e.IncidentRef = "P-00AB"
		e.ItemCount = -4
	}), now)
	if err != nil {
		t.Fatal(err)
	}
	if e.TenantID != "t-a" || e.Intent != "query_metric" || e.Outcome != "" || e.Skill != "" || e.ModelName != "" ||
		e.ToolVersion != "1.2.3+abcdef" || e.IncidentRef != "p-00ab" || e.ItemCount != 0 {
		t.Fatalf("normalized: %+v", e)
	}
	if !ValidID(e.ID) || !e.At.Equal(now) || e.At.Location() != time.UTC {
		t.Fatalf("id/time not stamped: %q %v", e.ID, e.At)
	}
	if got := IncidentRef("anything else"); got != "" {
		t.Fatalf("a free-text incident ref must be dropped, got %q", got)
	}
}

func TestNormalizeBatchIsOneDecision(t *testing.T) {
	now := time.Now()
	if out, err := NormalizeBatch("t", nil, now); err != nil || out != nil {
		t.Fatalf("empty batch: %v %v", out, err)
	}
	other := valid(func(e *Entry) { e.DecisionID = "22222222-2222-4333-8444-555555555555"; e.Seq = 1 })
	if _, err := NormalizeBatch("t", []Entry{valid(nil), other}, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("two decisions in one batch: %v", err)
	}
	if _, err := NormalizeBatch("t", []Entry{valid(nil), valid(nil)}, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate seq: %v", err)
	}
	big := make([]Entry, MaxEntriesPerDecision+1)
	for i := range big {
		big[i] = valid(func(e *Entry) { e.Seq = i })
	}
	if _, err := NormalizeBatch("t", big, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized batch: %v", err)
	}
	if _, err := NormalizeBatch("t", []Entry{valid(nil), valid(func(e *Entry) { e.Seq = 1; e.EventType = "X" })}, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("one bad entry must refuse the batch: %v", err)
	}
}

func TestSHA256HexAndToken(t *testing.T) {
	if SHA256Hex(nil) != testHash || !ValidSHA256(SHA256Hex([]byte("x"))) {
		t.Fatal("SHA256Hex")
	}
	for in, want := range map[string]string{
		"  ok_token-1.2:3@a/b+c ": "ok_token-1.2:3@a/b+c",
		"two words":               "",
		"quote'":                  "",
		"":                        "",
		"line\nbreak":             "",
	} {
		if got := Token(in); got != want {
			t.Errorf("Token(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRecorderIsBoundedOrderedAndNilSafe(t *testing.T) {
	var nilRec *Recorder
	nilRec.Add(Entry{EventType: QuestionReceived})
	nilRec.StartInvestigation("s", "entry")
	nilRec.NoteModel(ModelUse{Name: "m"})
	if nilRec.DecisionID() != "" || nilRec.Entries() != nil || nilRec.Dropped() != 0 {
		t.Fatal("a nil Recorder must be a no-op")
	}
	if m, n := nilRec.Model(); m != (ModelUse{}) || n != 0 {
		t.Fatal("nil Model")
	}
	if FromContext(context.Background()) != nil {
		t.Fatal("no recorder on a plain context")
	}

	rec, err := NewRecorder("alice", SurfaceAsk)
	if err != nil {
		t.Fatal(err)
	}
	if FromContext(WithRecorder(context.Background(), rec)) != rec {
		t.Fatal("context round trip")
	}
	rec.Add(Entry{EventType: QuestionReceived, ArgsSHA256: testHash})
	rec.StartInvestigation("bgp-peer-down", "entry")
	rec.StartInvestigation("other", "rule_selected") // once per decision
	rec.NoteModel(ModelUse{Provider: "anthropic", Name: "m1", Tier: "fast"})
	rec.NoteModel(ModelUse{Provider: "openai", Name: "m2", Tier: "strong"})
	if m, n := rec.Model(); m.Name != "m2" || n != 2 {
		t.Fatalf("model: %+v %d", m, n)
	}
	es := rec.Entries()
	if len(es) != 2 || es[1].EventType != InvestigationStarted || es[1].Skill != "bgp-peer-down" {
		t.Fatalf("entries: %+v", es)
	}
	for i, e := range es {
		if e.Seq != i || e.DecisionID != rec.DecisionID() || e.Principal != "alice" || e.Surface != SurfaceAsk || e.At.IsZero() {
			t.Fatalf("entry %d not stamped: %+v", i, e)
		}
	}

	// Concurrent adds past the bound: exactly the bound is kept, the rest counted.
	var wg sync.WaitGroup
	for i := 0; i < MaxEntriesPerDecision+10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); rec.Add(Entry{EventType: ToolExecuted}) }()
	}
	wg.Wait()
	if got := len(rec.Entries()); got != MaxEntriesPerDecision {
		t.Fatalf("kept %d entries, want %d", got, MaxEntriesPerDecision)
	}
	if rec.Dropped() != 12 {
		t.Fatalf("dropped %d, want 12", rec.Dropped())
	}
	if _, err := NormalizeBatch("t", rec.Entries(), time.Now()); err != nil {
		t.Fatalf("a full recorder must still be one valid batch: %v", err)
	}
}

func TestMemStoreIsTenantKeyedOrderedAndBounded(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	decision := func(tenant, id string, at time.Time) {
		t.Helper()
		es := []Entry{
			{DecisionID: id, Seq: 0, EventType: QuestionReceived, Principal: "u", Surface: SurfaceAsk, At: at},
			{DecisionID: id, Seq: 1, EventType: AnswerReturned, Principal: "u", Surface: SurfaceAsk, At: at.Add(time.Millisecond)},
		}
		if err := m.Append(ctx, tenant, es); err != nil {
			t.Fatal(err)
		}
	}
	d1, d2, d3 := "11111111-2222-4333-8444-555555555555", "22222222-2222-4333-8444-555555555555", "33333333-2222-4333-8444-555555555555"
	decision("t-a", d1, base)
	decision("t-a", d2, base.Add(time.Minute))
	decision("t-b", d3, base.Add(2*time.Minute))

	own, err := m.List(ctx, "t-a", false, ListFilter{})
	if err != nil || len(own) != 4 || own[0].DecisionID != d2 || own[0].Seq != 1 || own[3].DecisionID != d1 {
		t.Fatalf("own list newest first: %v %+v", err, own)
	}
	for _, e := range own {
		if e.TenantID != "t-a" {
			t.Fatalf("CROSS-TENANT LEAK: %+v", e)
		}
	}
	if got, _ := m.List(ctx, "t-a", false, ListFilter{DecisionID: d3}); len(got) != 0 {
		t.Fatalf("CROSS-TENANT LEAK by id: %+v", got)
	}
	if got, _ := m.List(ctx, "t-a", false, ListFilter{DecisionID: "garbage"}); len(got) != 0 {
		t.Fatalf("a malformed id lists nothing: %+v", got)
	}
	one, _ := m.List(ctx, "t-a", false, ListFilter{DecisionID: d1})
	if len(one) != 2 || one[0].Seq != 0 || one[1].Seq != 1 {
		t.Fatalf("one decision in seq order: %+v", one)
	}
	all, _ := m.List(ctx, "*", true, ListFilter{Limit: MaxListLimit})
	if len(all) != 6 || all[0].TenantID != "t-b" {
		t.Fatalf("platform view: %+v", all)
	}
	older, _ := m.List(ctx, "t-a", false, ListFilter{Before: base.Add(time.Minute)})
	if len(older) != 2 || older[0].DecisionID != d1 {
		t.Fatalf("before cursor: %+v", older)
	}
	if lim, _ := m.List(ctx, "t-a", false, ListFilter{Limit: 1}); len(lim) != 1 {
		t.Fatalf("limit: %+v", lim)
	}
	if err := m.Append(ctx, "t-a", []Entry{{DecisionID: d1, EventType: "NOPE", Principal: "u", Surface: SurfaceAsk}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an invalid batch must be refused: %v", err)
	}

	// The per-tenant bound evicts the oldest and counts them.
	for i := 0; i < MaxMemPerTenant/2+1; i++ {
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		decision("t-c", id, base.Add(time.Duration(i)*time.Second))
	}
	if m.Evicted() != 2 {
		t.Fatalf("evicted %d, want 2", m.Evicted())
	}
	if got, _ := m.List(ctx, "t-b", false, ListFilter{}); len(got) != 2 {
		t.Fatalf("another tenant's bound must not evict t-b: %+v", got)
	}
}

func TestMetricsRenderEverySeries(t *testing.T) {
	var nilM *Metrics
	nilM.Appended(3)
	nilM.Failed()
	nilM.Dropped(2)
	nilM.Write(&bytes.Buffer{})

	m := NewMetrics()
	var zero bytes.Buffer
	m.Write(&zero)
	for _, want := range []string{
		`netops_ai_decision_ledger_decisions_total{result="stored"} 0`,
		`netops_ai_decision_ledger_decisions_total{result="failed"} 0`,
		`netops_ai_decision_ledger_entries_total 0`,
		`netops_ai_decision_ledger_dropped_entries_total 0`,
	} {
		if !strings.Contains(zero.String(), want) {
			t.Errorf("zero series missing %q", want)
		}
	}
	m.Appended(5)
	m.Appended(-1)
	m.Failed()
	m.Dropped(0)
	m.Dropped(3)
	if d, e, f, dr := m.Snapshot(); d != 2 || e != 5 || f != 1 || dr != 3 {
		t.Fatalf("snapshot %d %d %d %d", d, e, f, dr)
	}
}
