package parsercov

// stats.go — the parser engine's own numbers, summed across the correlation
// replicas.
//
// The correlation service is scaled with `docker compose up --scale
// correlation=N` (docs/scale-correlation.md); each replica owns a disjoint
// slice of tenants and keeps its OWN parser counters in process memory. A
// single scrape of the round-robin service name therefore reports ONE slice's
// counters — so this file scrapes every replica the deployment names and folds
// them together. Which replicas exist is deployment knowledge, so it arrives
// through Deps.Replicas (§5) rather than being discovered here.
//
// TWO SOURCES, DELIBERATELY:
//
//	/healthz  → the `parser` block (producers.parser_stats) and the ingest
//	            pre-filter counters, already structured. Preferred: no text
//	            parsing, and it carries `promotion_window_used`, which /metrics
//	            does not expose at all and which is the denominator behind
//	            `window_lines`.
//	/metrics  → corr_parser_info, corr_parser_rule_hits_total,
//	            corr_parser_shadow_hits_total, corr_parser_generic_fallback_total,
//	            corr_semantic_promotion_rate, corr_ingest_prefilter_total, and
//	            (once the engine exports it) corr_parser_rule_info — the ONLY
//	            place per-rule lane/kind/fidelity could come from.
//
// Neither is trusted to be present: a replica that answers only one of the two
// still contributes everything that one carries.
//
// ── MISSING TODAY: PER-RULE CATALOG METADATA ────────────────────────────────
//
// `lane`, `kind` and `fidelity` are catalog facts (telemetry-catalog/
// events.yaml, baked into src/correlation/parser_rules.py). The engine exports
// NEITHER a `corr_parser_rule_info` series NOR a `rules_meta` list in the
// /healthz parser block — verified against the checked-in engine and against
// the running replicas. The API cannot import Python and must not infer a
// rule's lane from the spelling of its id, so those three fields come back
// EMPTY and the UI renders empty cells rather than invented ones.
//
// The engine-side fix is one block in `producers.parser_stats()`:
//
//	"rules_meta": [
//	    {"rule_id": r.rule_id, "lane": r.lane, "kind": r.kind,
//	     "fidelity": r.fidelity, "shadow": bool(r.shadow)}
//	    for r in RULES
//	],
//
// and, for the /metrics half, one loop beside corr_parser_rule_hits_total in
// `main._metrics_text`:
//
//	lines += ["# HELP corr_parser_rule_info The parser rule corpus, one series per rule (always 1).",
//	          "# TYPE corr_parser_rule_info gauge"]
//	for _r in producers.RULES:
//	    lines.append(f'corr_parser_rule_info{{rule_id="{_r.rule_id}",lane="{_r.lane}",'
//	                 f'kind="{_r.kind}",fidelity="{_r.fidelity}",'
//	                 f'shadow="{str(bool(_r.shadow)).lower()}"}} 1')
//
// Label cardinality is len(RULES), fixed at import — the same bound every other
// rule-labelled series already carries. Both halves are read below; whichever
// lands first starts populating the columns with no change to this package.

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Contract types. Field names are the frontend contract
// (src/frontend/src/services/api.ts: ParserStats / ParserRuleStat) and must not
// drift from it.
type (
	// RuleStat is one parser rule's row.
	RuleStat struct {
		RuleID   string `json:"rule_id"`
		Lane     string `json:"lane"`
		Kind     string `json:"kind"`
		Fidelity string `json:"fidelity"`
		Hits     int64  `json:"hits"`
		Shadow   bool   `json:"shadow"`
	}

	// Prefilter is the ingest screen's verdict split.
	Prefilter struct {
		Passed   int64 `json:"passed"`
		Rejected int64 `json:"rejected"`
	}

	// GenericFallback counts signals that fell through to the generic
	// device_alarm net, per lane.
	GenericFallback struct {
		Syslog int64 `json:"syslog"`
		Trap   int64 `json:"trap"`
	}

	// Stats is the /api/admin/parser/stats body.
	Stats struct {
		ParserRev   string `json:"parser_rev"`
		RulesHash   string `json:"rules_hash"`
		GeneratedAt string `json:"generated_at"`
		// PromotionRate is nil when the window admitted nothing. It is NEVER
		// coerced to 0: "no data" and "0 % promoted" are different facts and
		// the UI renders them differently (coverageModel.promotionDisplay).
		PromotionRate   *float64        `json:"promotion_rate"`
		WindowLines     int64           `json:"window_lines"`
		Prefilter       Prefilter       `json:"prefilter"`
		GenericFallback GenericFallback `json:"generic_fallback"`
		Rules           []RuleStat      `json:"rules"`
	}
)

// ruleMeta is the per-rule catalog metadata, when the engine publishes it.
type ruleMeta struct {
	Lane     string `json:"lane"`
	Kind     string `json:"kind"`
	Fidelity string `json:"fidelity"`
	Shadow   bool   `json:"shadow"`
}

// snapshot is one replica's contribution.
type snapshot struct {
	parserRev  string
	rulesHash  string
	promoRate  float64
	promoUsed  int64
	promoRateO bool
	preFilter  Prefilter
	ruleHits   map[string]int64
	shadowHits map[string]int64
	generic    GenericFallback
	meta       map[string]ruleMeta
}

func newSnapshot() *snapshot {
	return &snapshot{
		ruleHits:   map[string]int64{},
		shadowHits: map[string]int64{},
		meta:       map[string]ruleMeta{},
	}
}

// healthParser is the /healthz `parser` block. Every field is optional: an
// engine that predates a field simply contributes nothing for it.
type healthParser struct {
	ParserRev       string           `json:"parser_rev"`
	RulesHash       string           `json:"rules_hash"`
	RuleHits        map[string]int64 `json:"rule_hits"`
	ShadowHits      map[string]int64 `json:"shadow_hits"`
	GenericFallback map[string]int64 `json:"generic_fallbacks"`
	PromotionRate   *float64         `json:"semantic_promotion_rate"`
	PromotionUsed   *int64           `json:"promotion_window_used"`
	// RulesMeta is the engine hunk described in this file's header. Absent
	// today; read here so it works the day it lands.
	RulesMeta []struct {
		RuleID   string `json:"rule_id"`
		Lane     string `json:"lane"`
		Kind     string `json:"kind"`
		Fidelity string `json:"fidelity"`
		Shadow   bool   `json:"shadow"`
	} `json:"rules_meta"`
}

type healthBody struct {
	Parser *healthParser `json:"parser"`
	Ingest struct {
		PrefilterPassed   *int64 `json:"syslog_prefilter_passed"`
		PrefilterRejected *int64 `json:"syslog_prefilter_rejected"`
	} `json:"ingest"`
}

// scrapeReplica reads one replica's /healthz and /metrics. A failure on either
// half is NOT fatal — the other half still contributes — but a replica that
// answers neither returns an error so the caller can tell "summed 2 of 3" from
// "summed 3 of 3".
func (a *API) scrapeReplica(ctx context.Context, base string) (*snapshot, error) {
	s := newSnapshot()
	okAny := false

	if body, err := a.d.Fetch(ctx, joinURL(base, "/healthz")); err == nil {
		if applyHealth(s, body) {
			okAny = true
		}
	} else {
		a.warn("parser stats: replica /healthz unreadable", map[string]any{"error": err.Error()})
	}

	if body, err := a.d.Fetch(ctx, joinURL(base, "/metrics")); err == nil {
		applyMetrics(s, string(body))
		okAny = true
	} else {
		a.warn("parser stats: replica /metrics unreadable", map[string]any{"error": err.Error()})
	}

	if !okAny {
		return nil, errUnreachableReplica
	}
	return s, nil
}

// applyHealth folds the /healthz body into the snapshot. Returns false when the
// body could not be decoded at all.
func applyHealth(s *snapshot, body []byte) bool {
	var h healthBody
	if err := json.Unmarshal(body, &h); err != nil {
		return false
	}
	if h.Ingest.PrefilterPassed != nil {
		s.preFilter.Passed = *h.Ingest.PrefilterPassed
	}
	if h.Ingest.PrefilterRejected != nil {
		s.preFilter.Rejected = *h.Ingest.PrefilterRejected
	}
	p := h.Parser
	if p == nil {
		return true
	}
	s.parserRev = strings.TrimSpace(p.ParserRev)
	s.rulesHash = strings.TrimSpace(p.RulesHash)
	for id, n := range p.RuleHits {
		s.ruleHits[id] += n
	}
	for id, n := range p.ShadowHits {
		s.shadowHits[id] += n
		// A rule that appears in the shadow series IS a shadow rule; the
		// engine pre-seeds every id at zero, so presence (not the count) is
		// the signal, and it holds even before the metadata hunk lands.
		m := s.meta[id]
		m.Shadow = true
		s.meta[id] = m
	}
	s.generic.Syslog += p.GenericFallback["syslog"]
	s.generic.Trap += p.GenericFallback["trap"]
	if p.PromotionUsed != nil {
		s.promoUsed = *p.PromotionUsed
	}
	if p.PromotionRate != nil {
		s.promoRate = *p.PromotionRate
		s.promoRateO = true
	}
	for _, r := range p.RulesMeta {
		if r.RuleID == "" {
			continue
		}
		s.meta[r.RuleID] = ruleMeta{Lane: r.Lane, Kind: r.Kind, Fidelity: r.Fidelity, Shadow: r.Shadow}
	}
	return true
}

// applyMetrics folds a Prometheus text exposition into the snapshot. Only the
// series this surface names are read; everything else on the endpoint is
// ignored, so an engine adding metrics can never change this answer.
func applyMetrics(s *snapshot, text string) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		name, labels, value, ok := parsePromLine(line)
		if !ok {
			continue
		}
		switch name {
		case "corr_parser_info":
			if v := labels["parser_rev"]; v != "" && s.parserRev == "" {
				s.parserRev = v
			}
			if v := labels["rules_hash"]; v != "" && s.rulesHash == "" {
				s.rulesHash = v
			}
		case "corr_parser_rule_info":
			id := labels["rule_id"]
			if id == "" {
				continue
			}
			s.meta[id] = ruleMeta{
				Lane:     labels["lane"],
				Kind:     labels["kind"],
				Fidelity: labels["fidelity"],
				Shadow:   labels["shadow"] == "true" || labels["shadow"] == "1",
			}
		case "corr_parser_rule_hits_total":
			if id := labels["rule_id"]; id != "" {
				if _, seen := s.ruleHits[id]; !seen {
					s.ruleHits[id] = int64(value)
				}
			}
		case "corr_parser_shadow_hits_total":
			if id := labels["rule_id"]; id != "" {
				if _, seen := s.shadowHits[id]; !seen {
					s.shadowHits[id] = int64(value)
				}
				m := s.meta[id]
				m.Shadow = true
				s.meta[id] = m
			}
		case "corr_parser_generic_fallback_total":
			switch labels["source"] {
			case "syslog":
				if s.generic.Syslog == 0 {
					s.generic.Syslog = int64(value)
				}
			case "trap":
				if s.generic.Trap == 0 {
					s.generic.Trap = int64(value)
				}
			}
		case "corr_semantic_promotion_rate":
			if !s.promoRateO {
				s.promoRate, s.promoRateO = value, true
			}
		case "corr_ingest_prefilter_total":
			switch labels["outcome"] {
			case "passed":
				if s.preFilter.Passed == 0 {
					s.preFilter.Passed = int64(value)
				}
			case "rejected":
				if s.preFilter.Rejected == 0 {
					s.preFilter.Rejected = int64(value)
				}
			}
		}
	}
}

// parsePromLine splits `name{k="v",...} 12.5` into its parts. It is a
// deliberately small reader for the exposition subset the engine emits (no
// timestamps, no exemplars, no escaped label values beyond \" and \\), and it
// REFUSES anything it does not fully understand rather than half-reading it.
func parsePromLine(line string) (name string, labels map[string]string, value float64, ok bool) {
	sp := strings.LastIndexByte(line, ' ')
	if sp <= 0 {
		return "", nil, 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(line[sp+1:]), 64)
	if err != nil {
		return "", nil, 0, false
	}
	head := strings.TrimSpace(line[:sp])
	labels = map[string]string{}
	if i := strings.IndexByte(head, '{'); i >= 0 {
		if !strings.HasSuffix(head, "}") {
			return "", nil, 0, false
		}
		name = head[:i]
		for _, kv := range splitLabels(head[i+1 : len(head)-1]) {
			eq := strings.IndexByte(kv, '=')
			if eq <= 0 {
				continue
			}
			k := strings.TrimSpace(kv[:eq])
			val := strings.TrimSpace(kv[eq+1:])
			val = strings.TrimPrefix(val, `"`)
			val = strings.TrimSuffix(val, `"`)
			val = strings.ReplaceAll(val, `\"`, `"`)
			val = strings.ReplaceAll(val, `\\`, `\`)
			labels[k] = val
		}
	} else {
		name = head
	}
	if name == "" {
		return "", nil, 0, false
	}
	return name, labels, v, true
}

// splitLabels splits on commas that are OUTSIDE a quoted label value, so a
// label whose value contains a comma cannot forge a label boundary.
func splitLabels(s string) []string {
	var out []string
	var cur strings.Builder
	inQ, esc := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case esc:
			esc = false
			cur.WriteByte(c)
		case c == '\\' && inQ:
			esc = true
			cur.WriteByte(c)
		case c == '"':
			inQ = !inQ
			cur.WriteByte(c)
		case c == ',' && !inQ:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// fold sums the per-replica snapshots into the wire body.
//
// THE TWO NON-OBVIOUS AGGREGATIONS:
//
//   - promotion_rate is a RATIO, so it is combined as a mean WEIGHTED by each
//     replica's `promotion_window_used`, not averaged and not summed. A replica
//     whose ring is empty contributes no weight and therefore cannot drag the
//     platform figure toward its own default. When the total weight is zero the
//     result is nil — the honest "no admitted lines yet", never 0 %.
//   - parser_rev / rules_hash: replicas SHOULD agree, and during a rolling
//     deploy they do not. Disagreement is reported by joining the distinct
//     values rather than picking one, so a half-upgraded fleet is visible in
//     the header instead of hidden behind whichever replica answered first.
func fold(snaps []*snapshot, now time.Time) Stats {
	st := Stats{
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Rules:       []RuleStat{}, // never nil: the UI unwraps with Array.isArray
	}
	revs := map[string]struct{}{}
	hashes := map[string]struct{}{}
	hits := map[string]int64{}
	meta := map[string]ruleMeta{}
	var weighted float64
	var weight int64

	for _, s := range snaps {
		if s == nil {
			continue
		}
		if s.parserRev != "" {
			revs[s.parserRev] = struct{}{}
		}
		if s.rulesHash != "" {
			hashes[s.rulesHash] = struct{}{}
		}
		st.Prefilter.Passed += s.preFilter.Passed
		st.Prefilter.Rejected += s.preFilter.Rejected
		st.GenericFallback.Syslog += s.generic.Syslog
		st.GenericFallback.Trap += s.generic.Trap
		st.WindowLines += s.promoUsed
		if s.promoRateO && s.promoUsed > 0 {
			weighted += s.promoRate * float64(s.promoUsed)
			weight += s.promoUsed
		}
		// rule_hits and shadow_hits are DISJOINT by construction (a hit is an
		// emitted signal; a shadow hit is a match the parser chose not to
		// promote), so summing them gives "times this rule matched" — the
		// number an operator judging a shadow rule's readiness needs.
		for id, n := range s.ruleHits {
			hits[id] += n
		}
		for id, n := range s.shadowHits {
			hits[id] += n
		}
		for id, m := range s.meta {
			cur := meta[id]
			if m.Lane != "" {
				cur.Lane = m.Lane
			}
			if m.Kind != "" {
				cur.Kind = m.Kind
			}
			if m.Fidelity != "" {
				cur.Fidelity = m.Fidelity
			}
			cur.Shadow = cur.Shadow || m.Shadow
			meta[id] = cur
		}
	}

	st.ParserRev = joinDistinct(revs)
	st.RulesHash = joinDistinct(hashes)
	if weight > 0 {
		r := weighted / float64(weight)
		st.PromotionRate = &r
	}

	ids := make([]string, 0, len(hits))
	for id := range hits {
		ids = append(ids, id)
	}
	for id := range meta {
		if _, ok := hits[id]; !ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids) // stable output order, independent of map iteration
	for _, id := range ids {
		m := meta[id]
		st.Rules = append(st.Rules, RuleStat{
			RuleID:   id,
			Lane:     m.Lane,
			Kind:     m.Kind,
			Fidelity: m.Fidelity,
			Hits:     hits[id],
			Shadow:   m.Shadow,
		})
	}
	return st
}

func joinDistinct(set map[string]struct{}) string {
	if len(set) == 0 {
		return ""
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// joinURL concatenates a base URL and an absolute path without doubling the
// separator. The base comes from configuration, the path from a constant here
// — no caller-supplied text ever reaches it.
func joinURL(base, path string) string {
	return strings.TrimRight(base, "/") + path
}
