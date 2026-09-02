package parsercov

// stats_test.go — the replica fold.
//
// The interesting assertions are the two aggregations that are easy to get
// silently wrong: a RATIO summed across replicas instead of weighted, and a
// half-upgraded fleet reported as if it were uniform. Both are pinned.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var foldNow = time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)

const sampleMetrics = `# HELP corr_ingest_prefilter_total Raw syslog lines by ingest pre-filter verdict.
# TYPE corr_ingest_prefilter_total counter
corr_ingest_prefilter_total{outcome="passed"} 240000
corr_ingest_prefilter_total{outcome="rejected"} 18422
# TYPE corr_parser_rule_hits_total counter
corr_parser_rule_hits_total{rule_id="syslog.link.updown"} 9120
corr_parser_rule_hits_total{rule_id="syslog.bgp.adjacency_change"} 431
# TYPE corr_parser_shadow_hits_total counter
corr_parser_shadow_hits_total{rule_id="syslog.ospf.candidate"} 77
# TYPE corr_parser_generic_fallback_total counter
corr_parser_generic_fallback_total{source="syslog"} 1204
corr_parser_generic_fallback_total{source="trap"} 87
# TYPE corr_semantic_promotion_rate gauge
corr_semantic_promotion_rate 0.8125
# TYPE corr_parser_info gauge
corr_parser_info{parser_rev="2026.09.02-a6",rules_hash="9f3c1b7ad2e5",rules="41"} 1
# unrelated series this surface must ignore
corr_versions{outcome="persisted"} 5
`

func TestParsePromLine(t *testing.T) {
	name, labels, value, ok := parsePromLine(`corr_parser_rule_hits_total{rule_id="a.b"} 12`)
	if !ok || name != "corr_parser_rule_hits_total" || labels["rule_id"] != "a.b" || value != 12 {
		t.Fatalf("got (%q, %v, %v, %v)", name, labels, value, ok)
	}
	name, _, value, ok = parsePromLine(`corr_semantic_promotion_rate 0.5`)
	if !ok || name != "corr_semantic_promotion_rate" || value != 0.5 {
		t.Fatalf("bare gauge: (%q, %v, %v)", name, value, ok)
	}
	// A comma INSIDE a quoted label value must not forge a label boundary.
	_, labels, _, ok = parsePromLine(`corr_parser_info{parser_rev="a,b",rules_hash="c"} 1`)
	if !ok || labels["parser_rev"] != "a,b" || labels["rules_hash"] != "c" {
		t.Fatalf("quoted comma mis-split: %v", labels)
	}
	// Anything it cannot fully read is REFUSED, not half-read.
	for _, bad := range []string{"", "novalue", `name{unterminated="x" 1`, "name{a=1} notanumber"} {
		if _, _, _, ok := parsePromLine(bad); ok {
			t.Errorf("parsePromLine(%q) accepted a malformed line", bad)
		}
	}
}

func TestApplyMetricsReadsOnlyTheNamedSeries(t *testing.T) {
	s := newSnapshot()
	applyMetrics(s, sampleMetrics)
	if s.parserRev != "2026.09.02-a6" || s.rulesHash != "9f3c1b7ad2e5" {
		t.Fatalf("corr_parser_info not read: %q / %q", s.parserRev, s.rulesHash)
	}
	if s.preFilter != (Prefilter{Passed: 240000, Rejected: 18422}) {
		t.Fatalf("prefilter = %+v", s.preFilter)
	}
	if s.generic != (GenericFallback{Syslog: 1204, Trap: 87}) {
		t.Fatalf("generic fallback = %+v", s.generic)
	}
	if s.ruleHits["syslog.link.updown"] != 9120 || s.shadowHits["syslog.ospf.candidate"] != 77 {
		t.Fatalf("rule hits = %v shadow = %v", s.ruleHits, s.shadowHits)
	}
	if !s.meta["syslog.ospf.candidate"].Shadow {
		t.Fatal("a rule present in the shadow series must be marked shadow even without the metadata series")
	}
	if !s.promoRateO || s.promoRate != 0.8125 {
		t.Fatalf("promotion rate = %v (ok=%v)", s.promoRate, s.promoRateO)
	}
}

// TestRuleMetadataIsReadWhenTheEngineExportsIt exercises the series the engine
// does NOT emit today (see stats.go's header for the exact hunk): the reader is
// already in place, so the columns populate the day it lands.
func TestRuleMetadataIsReadWhenTheEngineExportsIt(t *testing.T) {
	s := newSnapshot()
	applyMetrics(s, sampleMetrics+
		`corr_parser_rule_info{rule_id="syslog.link.updown",lane="syslog",kind="link_state_change",fidelity="live_validated",shadow="false"} 1`+"\n"+
		`corr_parser_rule_info{rule_id="syslog.ospf.candidate",lane="syslog",kind="ospf_adjacency_change",fidelity="doc_claimed",shadow="true"} 1`+"\n")
	m := s.meta["syslog.link.updown"]
	if m.Lane != "syslog" || m.Kind != "link_state_change" || m.Fidelity != "live_validated" || m.Shadow {
		t.Fatalf("metadata = %+v", m)
	}
	if !s.meta["syslog.ospf.candidate"].Shadow {
		t.Fatal("shadow=\"true\" was not read")
	}
}

// TestNoRuleMetadataMeansEmptyFieldsNeverGuesses is the honesty rule: with no
// engine-published metadata, lane/kind/fidelity come back EMPTY. Deriving a
// lane from the spelling of a rule_id would be an invented catalog fact.
func TestNoRuleMetadataMeansEmptyFieldsNeverGuesses(t *testing.T) {
	s := newSnapshot()
	applyMetrics(s, sampleMetrics)
	st := fold([]*snapshot{s}, foldNow)
	for _, r := range st.Rules {
		if r.Lane != "" || r.Kind != "" || r.Fidelity != "" {
			t.Fatalf("rule %q carries invented metadata %+v", r.RuleID, r)
		}
	}
	if len(st.Rules) != 3 {
		t.Fatalf("expected 3 rules (2 hit + 1 shadow), got %d", len(st.Rules))
	}
	// Shadow is still known — it comes from the SERIES the rule appears in.
	var sawShadow bool
	for _, r := range st.Rules {
		if r.RuleID == "syslog.ospf.candidate" {
			sawShadow = r.Shadow && r.Hits == 77
		}
	}
	if !sawShadow {
		t.Fatalf("shadow rule not folded correctly: %+v", st.Rules)
	}
}

func TestApplyHealthPrefersStructuredCounters(t *testing.T) {
	body := []byte(`{
	  "ingest": {"syslog_prefilter_passed": 10, "syslog_prefilter_rejected": 4},
	  "parser": {
	    "parser_rev": "2026.09.02-a6", "rules_hash": "9f3c1b7ad2e5", "rules": 41,
	    "rule_hits": {"r.a": 3}, "shadow_hits": {"r.b": 2},
	    "generic_fallbacks": {"syslog": 7, "trap": 1},
	    "semantic_promotion_rate": 0.75,
	    "promotion_window": 10000, "promotion_window_used": 4000,
	    "rules_meta": [{"rule_id": "r.a", "lane": "syslog", "kind": "link_state_change", "fidelity": "code", "shadow": false}]
	  }}`)
	s := newSnapshot()
	if !applyHealth(s, body) {
		t.Fatal("applyHealth refused a well-formed body")
	}
	if s.preFilter != (Prefilter{Passed: 10, Rejected: 4}) {
		t.Fatalf("prefilter = %+v", s.preFilter)
	}
	if s.promoUsed != 4000 || !s.promoRateO || s.promoRate != 0.75 {
		t.Fatalf("promotion = %v/%v used=%d", s.promoRate, s.promoRateO, s.promoUsed)
	}
	if s.meta["r.a"].Kind != "link_state_change" {
		t.Fatalf("rules_meta not read: %+v", s.meta)
	}
	if !s.meta["r.b"].Shadow {
		t.Fatal("shadow_hits membership did not mark the rule shadow")
	}
	// An engine with no `parser` block at all still contributes its ingest
	// counters and does not fail the scrape.
	s2 := newSnapshot()
	if !applyHealth(s2, []byte(`{"ingest":{"syslog_prefilter_passed":5}}`)) {
		t.Fatal("a body with no parser block must still be accepted")
	}
	if s2.preFilter.Passed != 5 {
		t.Fatalf("ingest-only body: %+v", s2.preFilter)
	}
	if applyHealth(newSnapshot(), []byte(`not json`)) {
		t.Fatal("a non-JSON body must be refused")
	}
}

// TestPromotionRateIsWeightedNotSummed is the aggregation that a naive fold
// gets wrong. Two replicas, one with a nearly-full ring at 90 % and one with a
// tiny ring at 10 %: the platform figure must be the weighted mean (~88.4 %),
// never the sum (100 %) and never the unweighted mean (50 %).
func TestPromotionRateIsWeightedNotSummed(t *testing.T) {
	a, b := newSnapshot(), newSnapshot()
	a.promoRate, a.promoRateO, a.promoUsed = 0.9, true, 10000
	b.promoRate, b.promoRateO, b.promoUsed = 0.1, true, 1000
	st := fold([]*snapshot{a, b}, foldNow)
	if st.PromotionRate == nil {
		t.Fatal("promotion rate is nil although both replicas reported one")
	}
	want := (0.9*10000 + 0.1*1000) / 11000
	if diff := *st.PromotionRate - want; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("promotion rate = %v, want the weighted mean %v", *st.PromotionRate, want)
	}
	if st.WindowLines != 11000 {
		t.Fatalf("window_lines = %d, want 11000", st.WindowLines)
	}
}

// TestPromotionRateIsNilNotZeroWhenNothingWasAdmitted is the honest-empty rule
// the UI depends on: "no data" and "0 % promoted" are different facts.
func TestPromotionRateIsNilNotZeroWhenNothingWasAdmitted(t *testing.T) {
	s := newSnapshot()
	s.promoRate, s.promoRateO, s.promoUsed = 1.0, true, 0 // engine defaults to 1.0 on an empty ring
	st := fold([]*snapshot{s}, foldNow)
	if st.PromotionRate != nil {
		t.Fatalf("promotion rate = %v, want nil for an empty window", *st.PromotionRate)
	}
	if st.WindowLines != 0 {
		t.Fatalf("window_lines = %d, want 0", st.WindowLines)
	}
	// And it must marshal as a JSON null, which is what the contract types.
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"promotion_rate":null`) {
		t.Fatalf("promotion_rate did not marshal as null: %s", raw)
	}
	if !strings.Contains(string(raw), `"rules":[]`) {
		t.Fatalf("rules must marshal as [] and never null: %s", raw)
	}
}

// TestDisagreeingReplicasAreReportedNotHidden: during a rolling deploy the
// replicas run different corpora. Picking one would hide it.
func TestDisagreeingReplicasAreReportedNotHidden(t *testing.T) {
	a, b := newSnapshot(), newSnapshot()
	a.parserRev, a.rulesHash = "2026.09.02-a6", "9f3c1b7ad2e5"
	b.parserRev, b.rulesHash = "2026.08.30-a5", "0538afc1b47c"
	st := fold([]*snapshot{a, b}, foldNow)
	if st.ParserRev != "2026.08.30-a5, 2026.09.02-a6" {
		t.Fatalf("parser_rev = %q — a split fleet must be visible", st.ParserRev)
	}
	if st.RulesHash != "0538afc1b47c, 9f3c1b7ad2e5" {
		t.Fatalf("rules_hash = %q", st.RulesHash)
	}
}

func TestFoldSumsCountersAcrossReplicas(t *testing.T) {
	a, b := newSnapshot(), newSnapshot()
	applyMetrics(a, sampleMetrics)
	applyMetrics(b, sampleMetrics)
	st := fold([]*snapshot{a, b}, foldNow)
	if st.Prefilter != (Prefilter{Passed: 480000, Rejected: 36844}) {
		t.Fatalf("prefilter = %+v", st.Prefilter)
	}
	if st.GenericFallback != (GenericFallback{Syslog: 2408, Trap: 174}) {
		t.Fatalf("generic fallback = %+v", st.GenericFallback)
	}
	var updown int64
	for _, r := range st.Rules {
		if r.RuleID == "syslog.link.updown" {
			updown = r.Hits
		}
	}
	if updown != 18240 {
		t.Fatalf("summed rule hits = %d, want 18240", updown)
	}
	// Rule order is sorted, never map-iteration order.
	for i := 1; i < len(st.Rules); i++ {
		if st.Rules[i-1].RuleID >= st.Rules[i].RuleID {
			t.Fatalf("rules are not sorted by id: %+v", st.Rules)
		}
	}
	if st.GeneratedAt != "2026-09-02T10:00:00Z" {
		t.Fatalf("generated_at = %q", st.GeneratedAt)
	}
}

func TestReplicaListPrefersTheExplicitListAndFallsBack(t *testing.T) {
	got := ReplicaList("https://correlation:8443", " https://c1:8443 , https://c2:8443/ ,, ")
	if len(got) != 2 || got[0] != "https://c1:8443" || got[1] != "https://c2:8443" {
		t.Fatalf("explicit list = %v", got)
	}
	if got := ReplicaList("https://correlation:8443/", ""); len(got) != 1 || got[0] != "https://correlation:8443" {
		t.Fatalf("fallback = %v", got)
	}
	if got := ReplicaList("", ""); got != nil {
		t.Fatalf("nothing configured must yield nil, got %v", got)
	}
}

func TestJoinURL(t *testing.T) {
	for _, c := range []struct{ base, want string }{
		{"https://correlation:8443", "https://correlation:8443/metrics"},
		{"https://correlation:8443/", "https://correlation:8443/metrics"},
		{"https://correlation:8443///", "https://correlation:8443/metrics"},
	} {
		if got := joinURL(c.base, "/metrics"); got != c.want {
			t.Errorf("joinURL(%q) = %q, want %q", c.base, got, c.want)
		}
	}
}
