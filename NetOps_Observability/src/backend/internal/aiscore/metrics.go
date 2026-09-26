// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package aiscore

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// ── small counter primitives ─────────────────────────────────────────────────
//
// A map built ONCE from a closed vocabulary and never written again, so reads
// need no lock and a label that is not in the vocabulary has nowhere to land.
// That is deliberate: a mislabelled series is worse than a dropped observation,
// and every caller of these is a server-side enum, not user input.

type labelCounter struct {
	order []string
	vals  map[string]*atomic.Int64
}

func newLabelCounter(order []string) *labelCounter {
	c := &labelCounter{order: order, vals: make(map[string]*atomic.Int64, len(order))}
	for _, k := range order {
		c.vals[k] = new(atomic.Int64)
	}
	return c
}

// add increments a label. An unknown label is DROPPED, never bucketed into a
// neighbouring series. Reports whether it landed, so a caller that wants to know
// can (nothing in this package needs to — every caller passes an enum).
func (c *labelCounter) add(label string, n int64) bool {
	v, ok := c.vals[label]
	if !ok {
		return false
	}
	v.Add(n)
	return true
}

func (c *labelCounter) get(label string) int64 {
	if v, ok := c.vals[label]; ok {
		return v.Load()
	}
	return 0
}

// write emits one counter family, EVERY label on EVERY scrape including zeros:
// an absent series and a zero series mean different things to an alert.
func (c *labelCounter) write(w io.Writer, name, help, label string) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s counter\n", name)
	for _, k := range c.order {
		fmt.Fprintf(w, "%s{%s=%q} %d\n", name, label, k, c.vals[k].Load())
	}
}

// histogram is a fixed-bucket Prometheus histogram over LatencyBuckets.
type histogram struct {
	counts []atomic.Int64 // per-bucket (non-cumulative); len == len(LatencyBuckets)+1 for +Inf
	sum    atomic.Uint64  // milliseconds, so the accumulator stays integral
	n      atomic.Int64
}

func newHistogram() *histogram {
	return &histogram{counts: make([]atomic.Int64, len(LatencyBuckets)+1)}
}

// observe records one duration in seconds. A negative value is clamped to zero:
// a clock that went backwards must not make a latency histogram unreadable.
func (h *histogram) observe(seconds float64) {
	if seconds < 0 {
		seconds = 0
	}
	idx := len(LatencyBuckets) // +Inf
	for i, b := range LatencyBuckets {
		if seconds <= b {
			idx = i
			break
		}
	}
	h.counts[idx].Add(1)
	h.sum.Add(uint64(seconds * 1000))
	h.n.Add(1)
}

func (h *histogram) write(w io.Writer, name, help string) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s histogram\n", name)
	var cum int64
	for i, b := range LatencyBuckets {
		cum += h.counts[i].Load()
		fmt.Fprintf(w, "%s_bucket{le=%q} %d\n", name, strconv.FormatFloat(b, 'g', -1, 64), cum)
	}
	cum += h.counts[len(LatencyBuckets)].Load()
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", name, cum)
	fmt.Fprintf(w, "%s_sum %.3f\n", name, float64(h.sum.Load())/1000)
	fmt.Fprintf(w, "%s_count %d\n", name, h.n.Load())
}

// ── configuration ────────────────────────────────────────────────────────────

// Price is the configured model price used to turn measured tokens into money.
// UNSET BY DEFAULT and deliberately so: a cost number derived from a price
// nobody configured is an invented number, and this package does not invent
// numbers. With no price the token counters still flow and
// netops_ai_scorecard_censored{metric="ai_cost_per_investigation"} reports why
// there is no money series.
type Price struct {
	// InputUSDPerMTok / OutputUSDPerMTok are US dollars per MILLION tokens,
	// which is the unit every provider publishes. Zero = not configured.
	InputUSDPerMTok  float64
	OutputUSDPerMTok float64
}

// Configured reports whether a usable price was supplied. A negative or NaN
// price is not configured — it is a misconfiguration, and pricing off it would
// produce a number worse than none.
func (p Price) Configured() bool {
	if p.InputUSDPerMTok < 0 || p.OutputUSDPerMTok < 0 {
		return false
	}
	if p.InputUSDPerMTok != p.InputUSDPerMTok || p.OutputUSDPerMTok != p.OutputUSDPerMTok { // NaN
		return false
	}
	return p.InputUSDPerMTok > 0 || p.OutputUSDPerMTok > 0
}

// ── observations ─────────────────────────────────────────────────────────────

// Investigation is one finished skill-chain turn — the "agent" layer of the
// scorecard. Every field is something the chain ALREADY computed for its own
// routing and disclosure; nothing here is a second derivation.
type Investigation struct {
	// Outcome is one of InvestigationOutcomes.
	Outcome string
	// Seconds is the wall time of the whole turn.
	Seconds float64
	// Hops are the per-hop selection origins, one of HopOrigins each.
	Hops []string
	// HopsRejected counts model-proposed next skills refused because they were
	// not in the closed candidate set. A hard tool-selection ERROR, not a taste
	// judgement — the model named something it was not offered.
	HopsRejected int
	// ToolCalls are the per-call outcomes, one of ToolOutcomes each.
	ToolCalls []string
	// Cutoffs are the bounded-budget cut-offs that ended the chain early, each
	// one of CutoffBudgets.
	Cutoffs []string
	// EvidenceBacked is true when the finished answer carried at least one
	// citation. It is what decides `recovered` vs `unrecovered` for a turn that
	// hit a failing tool.
	EvidenceBacked bool
}

// ProviderCall is one completion attempt against a model provider.
type ProviderCall struct {
	// InputTokens / OutputTokens are the PROVIDER'S OWN accounting. They are
	// meaningful only when Reported is true.
	InputTokens  int64
	OutputTokens int64
	// Reported is true only when the provider returned a usage block. When it
	// is false the token fields are ignored entirely — this package never
	// estimates tokens from character counts, because an estimated token is an
	// invented number and every cost derived from it inherits that.
	Reported bool
	// Investigation is true when this call narrated a skill-chain
	// investigation, so tokens-per-investigation has an honest numerator.
	Investigation bool
}

// ── the metric set ───────────────────────────────────────────────────────────

// Metrics holds the live scorecard counters and the cached store sample, and
// renders both. Safe for concurrent use. A nil *Metrics is a no-op on every
// method, so a deployment that never wires it behaves exactly as before.
type Metrics struct {
	price Price

	answers      *labelCounter // {grounded}
	citations    atomic.Int64
	guards       *labelCounter // {guard} — guard FIRINGS (one per answer)
	guardItems   *labelCounter // {guard} — individual claims/refs the guard removed
	answerSecs   *histogram
	investSecs   *histogram
	invOutcomes  *labelCounter // {outcome}
	recovery     *labelCounter // {result}
	hops         *labelCounter // {selected}
	hopsRejected atomic.Int64
	toolCalls    *labelCounter // {outcome}
	cutoffs      *labelCounter // {budget}

	providerCalls *labelCounter // {usage_reported}
	tokens        *labelCounter // {direction}
	invTokens     *labelCounter // {direction}

	mu       sync.RWMutex
	sample   Sample
	sampleAt time.Time
	passes   int64
}

// NewMetrics builds the counter set. price may be the zero value, which means
// "no price configured" and censors the cost metric rather than inventing one.
func NewMetrics(price Price) *Metrics {
	return &Metrics{
		price:         price,
		answers:       newLabelCounter(GroundedValues),
		guards:        newLabelCounter(GuardNames),
		guardItems:    newLabelCounter(GuardNames),
		answerSecs:    newHistogram(),
		investSecs:    newHistogram(),
		invOutcomes:   newLabelCounter(InvestigationOutcomes),
		recovery:      newLabelCounter(RecoveryResults),
		hops:          newLabelCounter(HopOrigins),
		toolCalls:     newLabelCounter(ToolOutcomes),
		cutoffs:       newLabelCounter(CutoffBudgets),
		providerCalls: newLabelCounter(UsageReportedValues),
		tokens:        newLabelCounter(TokenDirections),
		invTokens:     newLabelCounter(TokenDirections),
	}
}

// ObserveAnswer records one finished Iris answer: whether it shipped citations,
// how many, and how long the whole turn took. This is the Grounding layer's
// coverage numerator and the Performance layer's latency.
func (m *Metrics) ObserveAnswer(grounded bool, citations int, seconds float64) {
	if m == nil {
		return
	}
	label := "no"
	if grounded {
		label = "yes"
	}
	m.answers.add(label, 1)
	if citations > 0 {
		m.citations.Add(int64(citations))
	}
	m.answerSecs.observe(seconds)
}

// ObserveGuard records one firing of a deterministic grounding guard, and how
// many individual references/claims it removed. The UNSUPPORTED-CLAIM RATE is
// netops_ai_grounding_guard_total / netops_ai_answers_total in PromQL — this
// package does not precompute it, because two counters divide correctly across
// restarts and a precomputed ratio does not.
func (m *Metrics) ObserveGuard(guard string, removed int) {
	if m == nil {
		return
	}
	if !m.guards.add(guard, 1) {
		return // unknown guard: dropped rather than mislabelled
	}
	if removed > 0 {
		m.guardItems.add(guard, int64(removed))
	}
}

// ObserveInvestigation records one finished skill-chain turn — the Agent layer.
func (m *Metrics) ObserveInvestigation(inv Investigation) {
	if m == nil {
		return
	}
	m.invOutcomes.add(inv.Outcome, 1)
	m.investSecs.observe(inv.Seconds)
	for _, h := range inv.Hops {
		m.hops.add(h, 1)
	}
	if inv.HopsRejected > 0 {
		m.hopsRejected.Add(int64(inv.HopsRejected))
	}
	failed := 0
	for _, o := range inv.ToolCalls {
		m.toolCalls.add(o, 1)
		if o != "ok" {
			failed++
		}
	}
	for _, c := range inv.Cutoffs {
		m.cutoffs.add(c, 1)
	}
	// Tool-error RECOVERY is only defined for a turn that actually hit a failing
	// tool call. A turn where every tool succeeded is not "recovered" and is not
	// "unrecovered" — it is not in the population at all, and counting it as a
	// success would inflate the rate with turns that were never tested.
	if failed > 0 {
		if inv.EvidenceBacked {
			m.recovery.add("recovered", 1)
		} else {
			m.recovery.add("unrecovered", 1)
		}
	}
}

// ObserveProviderCall records one model-provider completion attempt and, ONLY
// when the provider reported its own usage, the tokens it charged for.
func (m *Metrics) ObserveProviderCall(c ProviderCall) {
	if m == nil {
		return
	}
	if !c.Reported {
		m.providerCalls.add("no", 1)
		return
	}
	m.providerCalls.add("yes", 1)
	if c.InputTokens > 0 {
		m.tokens.add("input", c.InputTokens)
	}
	if c.OutputTokens > 0 {
		m.tokens.add("output", c.OutputTokens)
	}
	if c.Investigation {
		if c.InputTokens > 0 {
			m.invTokens.add("input", c.InputTokens)
		}
		if c.OutputTokens > 0 {
			m.invTokens.add("output", c.OutputTokens)
		}
	}
}

// Snapshot returns the cached store sample, when it was taken, and how many
// sampler passes have completed. Test seam and the HTTP-free read path.
func (m *Metrics) Snapshot() (Sample, time.Time, int64) {
	if m == nil {
		return Sample{}, time.Time{}, 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sample, m.sampleAt, m.passes
}

// setSample replaces the cached store sample. Called by the sampler only.
func (m *Metrics) setSample(s Sample, at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.sample = s
	m.sampleAt = at
	m.passes++
	m.mu.Unlock()
}

// ── censor state ─────────────────────────────────────────────────────────────

// censorState resolves, for every scorecard metric, the reason currently in
// force. ReasonNone means the metric IS being produced.
func (m *Metrics) censorState() map[string]string {
	sample, sampledAt, _ := m.Snapshot()
	out := map[string]string{}

	// Alert compression: sampler-backed.
	switch {
	case sampledAt.IsZero():
		out[MetricAlertCompressionRatio] = ReasonNeverSampled
	case sample.Err != "":
		out[MetricAlertCompressionRatio] = ReasonStoreUnreadable
	case sample.Objects <= 0:
		out[MetricAlertCompressionRatio] = ReasonNoObjectsInWindow
	default:
		out[MetricAlertCompressionRatio] = ReasonNone
	}

	// Top-3 RCA accuracy: structurally unavailable in production, and saying so
	// is the whole point. The reason is CONSTANT — it is a property of what the
	// product records, not of today's traffic — so it is stated on every scrape
	// rather than being inferred from an empty result.
	out[MetricRCATop3Accuracy] = ReasonNoRankLabelledGroundTruth

	// Time to evidence-backed diagnosis. Two distinct censors, reported in the
	// order an operator would fix them: first the workload (is any answer
	// evidence-backed at all?), then the store shape (can the FIRST such moment
	// be located?). Reporting only the store reason on a single-modality
	// workload would send someone to add a column that still would not produce
	// a number.
	switch {
	case sampledAt.IsZero():
		out[MetricTimeToEvidenceBackedDiagnosis] = ReasonNeverSampled
	case sample.Err != "":
		out[MetricTimeToEvidenceBackedDiagnosis] = ReasonStoreUnreadable
	case sample.EvidenceBacked <= 0:
		out[MetricTimeToEvidenceBackedDiagnosis] = ReasonSingleModalityWorkload
	default:
		out[MetricTimeToEvidenceBackedDiagnosis] = ReasonNoPerVersionModalityColumn
	}

	// Cost per investigation: needs BOTH a configured price and a measured token
	// base. The price is checked first because it is the one an operator can fix.
	switch {
	case !m.price.Configured():
		out[MetricAICostPerInvestigation] = ReasonNoTokenPrice
	case m.providerCalls.get("yes") == 0:
		out[MetricAICostPerInvestigation] = ReasonNoProviderUsage
	default:
		out[MetricAICostPerInvestigation] = ReasonNone
	}
	return out
}

// ── exposition ───────────────────────────────────────────────────────────────

// Write renders the whole scorecard in Prometheus text format. nil-safe.
//
// EVERY family is written on EVERY scrape, including as zeros. A vanished series
// must mean a scrape failure, never a state change — the rule the 2026-09-02
// post-mortem turned into a standing convention across this file's siblings.
func (m *Metrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	m.writeGrounding(w)
	m.writeAgent(w)
	m.writePerformance(w)
	m.writeEconomics(w)
	m.writeCorrelation(w)
	m.writeCensors(w)
}

func (m *Metrics) writeGrounding(w io.Writer) {
	m.answers.write(w,
		"netops_ai_answers_total",
		"Iris answers returned, by whether the answer shipped at least one citation. The GROUNDING COVERAGE denominator.",
		"grounded")
	fmt.Fprintf(w, "# HELP netops_ai_citations_total Evidence citations shipped on Iris answers.\n")
	fmt.Fprintf(w, "# TYPE netops_ai_citations_total counter\n")
	fmt.Fprintf(w, "netops_ai_citations_total %d\n", m.citations.Load())
	m.guards.write(w,
		"netops_ai_grounding_guard_total",
		"Answers on which a DETERMINISTIC grounding guard fired. Divided by netops_ai_answers_total this is the UNSUPPORTED-CLAIM RATE. A guard that is not wired in this build reports a flat zero, which is not the same as an absent series.",
		"guard")
	m.guardItems.write(w,
		"netops_ai_unsupported_claims_total",
		"Individual unsupported references or claims removed by a grounding guard (an answer can carry several).",
		"guard")
}

func (m *Metrics) writeAgent(w io.Writer) {
	m.invOutcomes.write(w,
		"netops_ai_investigations_total",
		"Skill-chain investigations that ran to completion, by outcome. answered/(answered+no_evidence) is the TASK-COMPLETION RATE.",
		"outcome")
	m.hops.write(w,
		"netops_ai_skill_hops_total",
		"Skill-chain hops, by how the next skill was chosen. `model` is the only origin the model had a say in, and it is bounded to a closed candidate set.",
		"selected")
	fmt.Fprintf(w, "# HELP netops_ai_skill_hops_rejected_total Model-proposed next skills refused because they were not in the closed candidate set — a hard TOOL-SELECTION ERROR, not a taste judgement.\n")
	fmt.Fprintf(w, "# TYPE netops_ai_skill_hops_rejected_total counter\n")
	fmt.Fprintf(w, "netops_ai_skill_hops_rejected_total %d\n", m.hopsRejected.Load())
	m.toolCalls.write(w,
		"netops_ai_tool_calls_total",
		"Governed tool executions inside an investigation, by outcome. ok/total is the TOOL-SELECTION SUCCESS rate; denied and not_wired are selection errors of different kinds.",
		"outcome")
	m.recovery.write(w,
		"netops_ai_tool_error_recovery_total",
		"Investigations that hit at least one FAILING tool call, by whether they still produced an evidence-backed finding. Turns where every tool succeeded are not in this population at all.",
		"result")
	m.cutoffs.write(w,
		"netops_ai_investigation_cutoffs_total",
		"Investigations cut short by a bounded budget, by which budget bound first. These are the limits the chain already discloses to the operator in prose.",
		"budget")
}

func (m *Metrics) writePerformance(w io.Writer) {
	m.answerSecs.write(w,
		"netops_ai_answer_seconds",
		"Wall time of one Iris answer, end to end. p50/p95 via histogram_quantile. This is RESPONSE latency — it is NOT time to evidence-backed diagnosis, which is censored; see netops_ai_scorecard_censored.")
	m.investSecs.write(w,
		"netops_ai_investigation_seconds",
		"Wall time of one skill-chain INVESTIGATION, end to end — the p50/p95 investigation latency of the scorecard's Performance layer.")
}

func (m *Metrics) writeEconomics(w io.Writer) {
	m.providerCalls.write(w,
		"netops_ai_provider_calls_total",
		"Model-provider completion attempts, by whether the provider returned its own token accounting. usage_reported=\"no\" is the share of spend this platform CANNOT see.",
		"usage_reported")
	m.tokens.write(w,
		"netops_ai_model_tokens_total",
		"Model tokens as REPORTED BY THE PROVIDER. Never estimated from character counts: an estimated token is an invented number and every cost derived from it inherits that.",
		"direction")
	m.invTokens.write(w,
		"netops_ai_investigation_tokens_total",
		"Provider-reported tokens spent narrating skill-chain investigations. Divided by netops_ai_investigations_total this is TOKENS PER INVESTIGATION.",
		"direction")

	// The price is CONFIGURATION, and its presence is itself a fact an operator
	// needs: a zero cost series and an unpriced deployment must not look alike.
	priced := 0
	if m.price.Configured() {
		priced = 1
	}
	fmt.Fprintf(w, "# HELP netops_ai_model_price_configured Whether a model price is configured (1) so token spend can be turned into money, or not (0).\n")
	fmt.Fprintf(w, "# TYPE netops_ai_model_price_configured gauge\n")
	fmt.Fprintf(w, "netops_ai_model_price_configured %d\n", priced)
	if priced == 1 {
		cost := float64(m.tokens.get("input"))/1e6*m.price.InputUSDPerMTok +
			float64(m.tokens.get("output"))/1e6*m.price.OutputUSDPerMTok
		fmt.Fprintf(w, "# HELP netops_ai_model_cost_usd_total Model spend in USD, derived from PROVIDER-REPORTED tokens and the configured price. Absent entirely when no price is configured.\n")
		fmt.Fprintf(w, "# TYPE netops_ai_model_cost_usd_total counter\n")
		fmt.Fprintf(w, "netops_ai_model_cost_usd_total %.6f\n", cost)
	}
}

func (m *Metrics) writeCorrelation(w io.Writer) {
	sample, sampledAt, passes := m.Snapshot()

	// Staleness first, and with a -1 sentinel: "never sampled" and "sampled this
	// instant" are opposite states and a zero renders them identically.
	age := float64(-1)
	if !sampledAt.IsZero() {
		age = time.Since(sampledAt).Seconds()
		if age < 0 {
			age = 0
		}
	}
	fmt.Fprintf(w, "# HELP netops_ai_scorecard_sample_age_seconds Age of the cached correlation-store sample. -1 means NEVER SAMPLED, which is not the same as fresh.\n")
	fmt.Fprintf(w, "# TYPE netops_ai_scorecard_sample_age_seconds gauge\n")
	fmt.Fprintf(w, "netops_ai_scorecard_sample_age_seconds %.0f\n", age)
	fmt.Fprintf(w, "# HELP netops_ai_scorecard_sample_passes_total Completed correlation-store sampling passes since start.\n")
	fmt.Fprintf(w, "# TYPE netops_ai_scorecard_sample_passes_total counter\n")
	fmt.Fprintf(w, "netops_ai_scorecard_sample_passes_total %d\n", passes)
	fmt.Fprintf(w, "# HELP netops_corr_compression_window_seconds Span the compression numbers below are computed over.\n")
	fmt.Fprintf(w, "# TYPE netops_corr_compression_window_seconds gauge\n")
	fmt.Fprintf(w, "netops_corr_compression_window_seconds %d\n", sample.WindowSeconds)

	// A sample that could not be taken emits NO value gauges at all. A zero
	// object count and an unreadable store must not render identically — the
	// presentation bug tracker 204 was filed about, applied here.
	if sampledAt.IsZero() || sample.Err != "" {
		return
	}
	fmt.Fprintf(w, "# HELP netops_corr_signals_ingested Signals written to the correlation store in the window, across every tenant.\n")
	fmt.Fprintf(w, "# TYPE netops_corr_signals_ingested gauge\n")
	fmt.Fprintf(w, "netops_corr_signals_ingested %d\n", sample.SignalsIngested)
	fmt.Fprintf(w, "# HELP netops_corr_signals_folded Signals folded INTO a correlation object in the window (the sum of per-object signal_count).\n")
	fmt.Fprintf(w, "# TYPE netops_corr_signals_folded gauge\n")
	fmt.Fprintf(w, "netops_corr_signals_folded %d\n", sample.SignalsFolded)
	fmt.Fprintf(w, "# HELP netops_corr_objects Correlation objects (incidents) in the window, excluding merged, debug-excluded and named chaos fixtures.\n")
	fmt.Fprintf(w, "# TYPE netops_corr_objects gauge\n")
	fmt.Fprintf(w, "netops_corr_objects %d\n", sample.Objects)

	fmt.Fprintf(w, "# HELP netops_corr_objects_by_tier Correlation objects in the window by verdict tier.\n")
	fmt.Fprintf(w, "# TYPE netops_corr_objects_by_tier gauge\n")
	tiers := make([]string, 0, len(sample.ByTier))
	for t := range sample.ByTier {
		tiers = append(tiers, t)
	}
	sort.Strings(tiers)
	for _, t := range tiers {
		fmt.Fprintf(w, "netops_corr_objects_by_tier{tier=%q} %d\n", t, sample.ByTier[t])
	}

	// The evidence-backed precondition. On a single-modality workload this is
	// zero, and that zero is the MEASURED reason the headline KPI is censored —
	// it is emitted so the censor is diagnosable rather than merely absent.
	fmt.Fprintf(w, "# HELP netops_corr_objects_evidence_backed Objects in the window whose CURRENT state satisfies the engine's own independence test (verdict tier above undetermined AND two or more modality classes).\n")
	fmt.Fprintf(w, "# TYPE netops_corr_objects_evidence_backed gauge\n")
	fmt.Fprintf(w, "netops_corr_objects_evidence_backed %d\n", sample.EvidenceBacked)
	fmt.Fprintf(w, "# HELP netops_corr_objects_single_modality Objects in the window carrying fewer than two modality classes — every one of them is an answer no independence test can back.\n")
	fmt.Fprintf(w, "# TYPE netops_corr_objects_single_modality gauge\n")
	fmt.Fprintf(w, "netops_corr_objects_single_modality %d\n", sample.SingleModality)

	// THE NUMBER A BUYER ASKS FOR. Two bases, because they answer two different
	// questions and quoting one as the other is the error this split prevents:
	//   ingest — every signal the correlation store took in over the window,
	//            divided by the incidents it produced. The end-to-end noise
	//            reduction an operator experiences.
	//   folded — signals that actually joined an object, per object. The
	//            engine's own folding factor, and a LOWER BOUND on `ingest`.
	// Emitted only when there is a denominator: a ratio of 0 on an empty window
	// would read as "no compression", the opposite of what it means.
	if sample.Objects > 0 {
		fmt.Fprintf(w, "# HELP netops_corr_compression_ratio Alert compression ratio over the window: signals in / incidents out. basis=\"ingest\" counts every signal the store took in; basis=\"folded\" counts only signals that joined an object and is therefore a lower bound.\n")
		fmt.Fprintf(w, "# TYPE netops_corr_compression_ratio gauge\n")
		fmt.Fprintf(w, "netops_corr_compression_ratio{basis=%q} %.4f\n", "ingest", float64(sample.SignalsIngested)/float64(sample.Objects))
		fmt.Fprintf(w, "netops_corr_compression_ratio{basis=%q} %.4f\n", "folded", float64(sample.SignalsFolded)/float64(sample.Objects))
	}
}

func (m *Metrics) writeCensors(w io.Writer) {
	state := m.censorState()
	fmt.Fprintf(w, "# HELP netops_ai_scorecard_available Whether a scorecard metric is being PRODUCED (1) or is censored (0). A censored metric is never emitted as a number — see netops_ai_scorecard_censored for the reason.\n")
	fmt.Fprintf(w, "# TYPE netops_ai_scorecard_available gauge\n")
	for _, metric := range ScorecardMetrics {
		v := 0
		if state[metric] == ReasonNone {
			v = 1
		}
		fmt.Fprintf(w, "netops_ai_scorecard_available{metric=%q} %d\n", metric, v)
	}
	fmt.Fprintf(w, "# HELP netops_ai_scorecard_censored Why a scorecard metric is not being produced. Every (metric,reason) pair in the closed vocabulary is emitted on every scrape as a 0 or a 1, so \"censored for reason X\" is distinguishable from \"censored and nobody said why\".\n")
	fmt.Fprintf(w, "# TYPE netops_ai_scorecard_censored gauge\n")
	for _, metric := range ScorecardMetrics {
		for _, reason := range censorReasons[metric] {
			v := 0
			if state[metric] == reason {
				v = 1
			}
			fmt.Fprintf(w, "netops_ai_scorecard_censored{metric=%q,reason=%q} %d\n", metric, reason, v)
		}
	}
}
