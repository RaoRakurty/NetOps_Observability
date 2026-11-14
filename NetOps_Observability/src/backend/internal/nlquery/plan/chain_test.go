// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

// chain_test.go — N-S3: "what changed 30 minutes before every SD-WAN incident
// this week" keeps correlated and causal apart. A row is "temporal" unless the
// engine's own chain for that incident names a change step of the row's KIND,
// and even then the answer never says the row caused the incident.

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/mql"
	"netops/backend/internal/nlquery/validate"
)

const (
	incA = "aaaaaaaa-0000-0000-0000-000000000001" // chain names a config change, established
	incB = "bbbbbbbb-0000-0000-0000-000000000002" // chain has no change step
	incC = "cccccccc-0000-0000-0000-000000000003" // analysis unreadable
	incD = "dddddddd-0000-0000-0000-000000000004" // chain contradicted
)

// chainScope adds the optional ChangeChainScope seam to fakeScope, with a
// per-incident change list so each incident gets its own rows.
type chainScope struct {
	fakeScope
	chains     map[string]ChangeChain
	chainReads []string
	perInc     map[time.Time][]ChangeRow // keyed by the window END (incident onset + after)
}

func (c *chainScope) ChangeChain(_ context.Context, id string) (ChangeChain, error) {
	c.chainReads = append(c.chainReads, id)
	ch, ok := c.chains[id]
	if !ok {
		return ChangeChain{}, ErrNotFound
	}
	return ch, nil
}

func (c *chainScope) Changes(_ context.Context, q ChangeQuery) ([]ChangeRow, bool, error) {
	c.changeQs = append(c.changeQs, q)
	return c.perInc[q.To], false, nil
}

const s3Query = `{"v":1,"query_type":"change_list","target":"change",
 "time_range":{"kind":"incidents","anchor":{"incidents":{"time_range":{"kind":"relative","last":"7d"},
   "filters":[{"field":"seam_class","op":"eq","values":["sdwan"]}]},"before":"30m","after":"1m"}},
 "order_by":[{"field":"event_at","dir":"desc"}]}`

func s3Fixture() *chainScope {
	onsetA := now.Add(-2 * time.Hour)
	onsetB := now.Add(-26 * time.Hour)
	onsetC := now.Add(-50 * time.Hour)
	onsetD := now.Add(-74 * time.Hour)
	end := func(t time.Time) time.Time { return t.Add(time.Minute) }
	sc := &chainScope{
		chains: map[string]ChangeChain{
			incA: {Read: true, Kinds: []string{"device_config_change"}, Step: 1, Established: true},
			incB: {Read: true},
			incD: {Read: true, Kinds: []string{"config_change"}, Step: 2, Contradicted: true},
		},
		perInc: map[time.Time][]ChangeRow{
			end(onsetA): {
				{ID: "chg-1042", Type: "CONFIG_CHANGE", Actor: "John Smith", Object: "cEdge-80", At: onsetA.Add(-12 * time.Minute)},
				{ID: "chg-1043", Type: "INFRASTRUCTURE_CHANGE", Actor: "ops-bot", Object: "alert-rule-7", At: onsetA.Add(-20 * time.Minute)},
			},
			end(onsetB): {{ID: "chg-1049", Type: "CONFIG_CHANGE", Actor: "Ana Ruiz", Object: "vEdge-51", At: onsetB.Add(-5 * time.Minute)}},
			end(onsetC): {{ID: "chg-1054", Type: "CONFIG_CHANGE", Actor: "John Smith", Object: "cEdge-81", At: onsetC.Add(-29 * time.Minute)}},
			end(onsetD): {{ID: "chg-1060", Type: "CONFIG_CHANGE", Actor: "Ana Ruiz", Object: "vEdge-52", At: onsetD.Add(-3 * time.Minute)}},
		},
	}
	sc.incs = []IncidentRow{
		{ID: incA, DisplayID: "P-AAA001", Title: "SD-WAN tunnels down at site 80", SeamType: "sdwan", CreatedAt: onsetA},
		{ID: incB, DisplayID: "P-BBB002", Title: "BFD flaps on mpls", SeamType: "sdwan", CreatedAt: onsetB},
		{ID: incC, DisplayID: "P-CCC003", Title: "Overlay loss at site 50", SeamType: "sdwan", CreatedAt: onsetC},
		{ID: incD, DisplayID: "P-DDD004", Title: "Control connections lost", SeamType: "sdwan", CreatedAt: onsetD},
	}
	return sc
}

func rowByID(t *testing.T, rs *ResultSet, id string) Row {
	t.Helper()
	for _, r := range rs.Rows {
		if r["change_id"] == id {
			return r
		}
	}
	t.Fatalf("row %s missing from %d rows", id, len(rs.Rows))
	return nil
}

func TestS3_ChainKindOnlyWhereTheEngineNamesThatKind(t *testing.T) {
	sc := s3Fixture()
	rs := runScope(t, sc, s3Query)

	if len(rs.Rows) != 5 {
		t.Fatalf("rows = %d, want 5 (2 + 1 + 1 + 1)", len(rs.Rows))
	}
	a := rowByID(t, rs, "chg-1042")
	if a["relation"] != RelationChainKind || a["chain_kind"] != "device_config_change" || a["chain_step"] != 1 || a["chain_established"] != true {
		t.Fatalf("chg-1042 should be same-kind as the established chain step: %+v", a)
	}
	if a["relation_class"] != "CORRELIX_RCA" || a["incident_display_id"] != "P-AAA001" || a["minutes_before_incident"] != 12 {
		t.Fatalf("chg-1042 fields: %+v", a)
	}
	// A change made through Correlix itself is never an engine change kind.
	if r := rowByID(t, rs, "chg-1043"); r["relation"] != RelationTemporal || r["relation_class"] != "DERIVED" {
		t.Fatalf("an INFRASTRUCTURE_CHANGE must stay temporal: %+v", r)
	}
	// No change step in the chain → temporal.
	if r := rowByID(t, rs, "chg-1049"); r["relation"] != RelationTemporal {
		t.Fatalf("no change step → temporal: %+v", r)
	}
	// Analysis unreadable → temporal, never guessed.
	if r := rowByID(t, rs, "chg-1054"); r["relation"] != RelationTemporal {
		t.Fatalf("unreadable analysis → temporal: %+v", r)
	}
	// Contradicted primary sequence → its change step is not used.
	if r := rowByID(t, rs, "chg-1060"); r["relation"] != RelationTemporal {
		t.Fatalf("contradicted chain → temporal: %+v", r)
	}
	notes := strings.Join(rs.Notes, " | ")
	for _, want := range []string{
		"correlated in time, not established as causes",
		"1 incident's root-cause analysis could not be read",
		"1 incident's causal chain names no change step",
		"1 incident has a contradicted causal chain",
		"the chain does not name the individual change",
		"the engine established a change as the root cause of P-AAA001 (the kind of change, not which record)",
	} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes missing %q:\n%s", want, notes)
		}
	}
	if len(sc.chainReads) != 4 {
		t.Errorf("one chain read per incident that has changes, got %v", sc.chainReads)
	}
}

func TestS3_NoChainSeamMeansEveryRowTemporalAndSaysSo(t *testing.T) {
	sc := s3Fixture()
	// The plain fakeScope has no ChangeChain method: wrap the per-incident rows.
	plain := &plainScope{chainScope: sc}
	rs := runScope(t, plain, s3Query)
	for _, r := range rs.Rows {
		if r["relation"] != RelationTemporal {
			t.Fatalf("without the seam every row is temporal: %+v", r)
		}
	}
	if !strings.Contains(strings.Join(rs.Notes, " "), "4 incidents' root-cause analyses could not be read") {
		t.Fatalf("the unread chains must be disclosed: %v", rs.Notes)
	}
}

func TestS3_IncidentWithoutChangesIsNotReadForItsChain(t *testing.T) {
	sc := s3Fixture()
	sc.perInc = map[time.Time][]ChangeRow{} // no changes anywhere
	rs := runScope(t, sc, s3Query)
	if len(rs.Rows) != 0 || len(sc.chainReads) != 0 {
		t.Fatalf("no rows → no chain reads; rows=%d reads=%v", len(rs.Rows), sc.chainReads)
	}
}

// causalWord finds wording that claims cause. "not established that this
// change caused it" is the one allowed negated form.
var causalWord = regexp.MustCompile(`(?i)\b(caused|causes|because of|due to|led to|root cause of)\b`)

func TestS3_SummaryNeverClaimsCause(t *testing.T) {
	sc := s3Fixture()
	q, rs := runScopeAST(t, sc, s3Query)
	sum := Summarize(cat, q, rs)
	for _, want := range []string{
		"5 changes were found before 4 incidents.",
		"1 is the same kind as a change step in that incident's causal chain (the chain names the kind, not the individual change); the rest are correlated in time only.",
		"P-AAA001 SD-WAN tunnels down at site 80:",
		"12 min before onset, same kind as step 1 of the engine's causal chain (device_config_change) — not established that this change caused it",
		"5 min before onset, correlated in time, not established as a cause",
	} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary missing %q:\n%s", want, sum)
		}
	}
	// Every causal word must sit inside an explicit negation.
	allowed := strings.NewReplacer(
		"not established that this change caused it", "",
		"so it is not established that this change caused it", "",
		"the engine established a change as the root cause of", "",
		"not established as causes", "",
		"not established as a cause", "",
	)
	if m := causalWord.FindString(allowed.Replace(sum)); m != "" {
		t.Fatalf("summary claims cause (%q):\n%s", m, sum)
	}
}

func TestS3_EmptySummaryIsHonest(t *testing.T) {
	sc := s3Fixture()
	sc.perInc = map[time.Time][]ChangeRow{}
	q, rs := runScopeAST(t, sc, s3Query)
	if s := Summarize(cat, q, rs); !strings.HasPrefix(s, "No changes were recorded in the window before any matching incident.") {
		t.Fatalf("empty summary: %q", s)
	}
}

func TestEngineKindsForTypeAreEngineChangeKinds(t *testing.T) {
	// The planner-side copy of ai/statement_class.go engineChangeKinds; the root
	// drift test pins the two lists together, this one pins the mapping's shape.
	engine := map[string]bool{"config_change": true, "device_config_change": true, "cloud_change": true,
		"cloud_audit": true, "deploy_event": true, "controller_policy_change": true}
	for typ, kinds := range EngineKindsForType() {
		if len(kinds) == 0 {
			t.Errorf("%s maps to no kind — drop it instead", typ)
		}
		for _, k := range kinds {
			if !engine[k] {
				t.Errorf("%s maps to %q, not an engine change kind", typ, k)
			}
		}
	}
	if _, ok := EngineKindsForType()["INFRASTRUCTURE_CHANGE"]; ok {
		t.Error("INFRASTRUCTURE_CHANGE (made through Correlix) must never match a chain step")
	}
}

func TestChainKindForRefusesUnreadAndContradicted(t *testing.T) {
	cases := []struct {
		name string
		ch   ChangeChain
		want string
	}{
		{"unread", ChangeChain{Kinds: []string{"config_change"}}, ""},
		{"contradicted", ChangeChain{Read: true, Contradicted: true, Kinds: []string{"config_change"}}, ""},
		{"no step", ChangeChain{Read: true}, ""},
		{"match", ChangeChain{Read: true, Kinds: []string{" Config_Change "}}, "config_change"},
		{"other kind", ChangeChain{Read: true, Kinds: []string{"cloud_audit"}}, ""},
	}
	for _, c := range cases {
		if got := chainKindFor("CONFIG_CHANGE", c.ch); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	if chainKindFor("", ChangeChain{Read: true, Kinds: []string{"config_change"}}) != "" {
		t.Error("an untyped change matches nothing")
	}
}

func TestChainReadErrorIsNotAFailure(t *testing.T) {
	sc := s3Fixture()
	sc.chains = map[string]ChangeChain{}
	errScope := &erroringChains{chainScope: sc}
	rs := runScope(t, errScope, s3Query)
	if len(rs.Rows) != 5 {
		t.Fatalf("a failing chain read must not lose the change rows: %d", len(rs.Rows))
	}
}

// ---- helpers ------------------------------------------------------------------

// plainScope hides the ChangeChain method (Scope only).
type plainScope struct{ chainScope *chainScope }

func (p *plainScope) MetricRange(ctx context.Context, e mql.Expr, from, to time.Time, step time.Duration, n int) ([]Series, bool, error) {
	return p.chainScope.MetricRange(ctx, e, from, to, step, n)
}
func (p *plainScope) MetricInstant(ctx context.Context, e mql.Expr, at time.Time, n int) ([]Sample, bool, error) {
	return p.chainScope.MetricInstant(ctx, e, at, n)
}
func (p *plainScope) Incidents(ctx context.Context, q IncidentQuery) ([]IncidentRow, bool, error) {
	return p.chainScope.Incidents(ctx, q)
}
func (p *plainScope) Incident(ctx context.Context, id string) (IncidentDetail, error) {
	return p.chainScope.Incident(ctx, id)
}
func (p *plainScope) Changes(ctx context.Context, q ChangeQuery) ([]ChangeRow, bool, error) {
	return p.chainScope.Changes(ctx, q)
}
func (p *plainScope) Devices(ctx context.Context, f DeviceFilter) ([]DeviceRef, error) {
	return p.chainScope.Devices(ctx, f)
}
func (p *plainScope) Circuits(ctx context.Context, f CircuitFilter) ([]CircuitRef, error) {
	return p.chainScope.Circuits(ctx, f)
}
func (p *plainScope) Now() time.Time { return now }

// erroringChains fails every chain read with a transport error.
type erroringChains struct{ *chainScope }

func (e *erroringChains) ChangeChain(context.Context, string) (ChangeChain, error) {
	return ChangeChain{}, errors.New("clickhouse unavailable")
}

// runScope runs one fixture query against any Scope (run() takes *fakeScope).
func runScope(t *testing.T, sc Scope, js string) *ResultSet {
	t.Helper()
	_, rs := runScopeAST(t, sc, js)
	return rs
}

func runScopeAST(t *testing.T, sc Scope, js string) (*ast.AST, *ResultSet) {
	t.Helper()
	a, err := ast.Decode([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	v, res := validate.Validate(context.Background(), cat, visAll{}, a)
	if !res.Valid {
		t.Fatalf("fixture invalid: %+v", res.Errors)
	}
	rs, err := Planner{Cat: cat}.Execute(context.Background(), sc, v, res.Constraints)
	if err != nil {
		t.Fatal(err)
	}
	return v, rs
}
