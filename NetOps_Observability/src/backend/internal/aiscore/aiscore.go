// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package aiscore is the PRODUCTION AI scorecard (Iris commercial programme
// item 19): the layer-by-layer numbers a buyer asks for, emitted from the
// running product as Prometheus series on the api's /metrics — not from a rig
// report, and not from a spreadsheet.
//
// THE ONE RULE THIS PACKAGE EXISTS TO HOLD. A metric that cannot be honestly
// computed on the workload in front of it is emitted as CENSORED, with the
// reason, and NEVER as a number. That is the precedent set by
// `scripts/scale-rca-latency.py --ground-truth`, whose `time_to_useful` reports
// `n: 0` and `null` percentiles rather than a 0.0 that would read as "instant"
// (docs/scale/USEFUL_RCA_DEFINITION_2026-09-02.md §2). A censored metric here
// is a visible 1 on netops_ai_scorecard_censored{metric,reason}, so the gap is
// alertable and diagnosable instead of merely absent (§10: no silent failure).
//
// THE TENANT QUESTION (§3a). Nothing in this package carries a tenant label, a
// device name, a correlation id or any other entity id. Every series is a
// PLATFORM AGGREGATE. The reasoning is rcafeedback/metrics.go's, applied to a
// wider surface: /metrics is not itself a tenant-scoped surface, so a per-tenant
// label would leak tenant existence, tenant cardinality and per-tenant incident
// volume to anyone who can scrape it. An aggregate over every tenant answers the
// buyer's question ("what is your compression ratio?") without naming one.
// Do NOT add a tenant label here without re-deriving that argument.
//
// TWO SOURCES, ONE EXPOSITION.
//
//   - LIVE counters, incremented in-process by the ai package through the
//     ScoreSink seam (grounding, agent/tool outcomes, latency, tokens). They are
//     process-wide and reset on restart, like every other netops_* counter.
//   - A SAMPLED snapshot of the correlation store, refreshed by a background
//     worker and formatted from cache by the scrape. A Prometheus scrape must
//     never issue the ClickHouse query — that is the storagemeter lesson
//     (internal/storagemeter/metrics.go rule 1) and it is not re-litigated here.
package aiscore

import "time"

// ── closed label vocabularies ────────────────────────────────────────────────
//
// Every label value below comes from one of these lists. A value that is not in
// its list is dropped rather than emitted, because a mislabelled series is worse
// than a missing observation — the same stance rcafeedback.Metrics.Inc takes.

// GroundedValues labels an answer by whether it shipped at least one citation.
var GroundedValues = []string{"yes", "no"}

// ToolOutcomes is the outcome vocabulary of one skill-chain gather step. It is
// exactly the set the chain already records for its own routing decisions
// (ai/skill_run.go: ok | error | not_found | not_wired | denied), reused rather
// than re-derived so the metric and the router can never disagree.
var ToolOutcomes = []string{"ok", "error", "not_found", "not_wired", "denied"}

// GuardNames is the closed set of DETERMINISTIC grounding guards. A guard is a
// post-check in code that the model cannot talk its way past.
//
//   - fabricated_citation — ai.VerifyGrounding stripped a bracketed evidence id
//     the model invented (an id not in the bundle it was given).
//   - uncertain_claim — a certainty-marker post-check refused a narrative that
//     asserted an established cause under an unconfirmed verdict.
//
// uncertain_claim is declared here and emitted as a zero on every scrape even
// where that check is not wired in this build: an absent series and a zero
// series mean different things to an alert, and "this build runs no certainty
// check" must be readable as a flat zero rather than as a gap.
var GuardNames = []string{"fabricated_citation", "uncertain_claim"}

// HopOrigins is how a skill-chain hop was chosen. `model` is the only origin
// where the model had a say, and it is bounded to a CLOSED candidate set.
var HopOrigins = []string{"entry", "rule", "model"}

// InvestigationOutcomes is the task-completion vocabulary of one skill-chain
// turn. `answered` means the chain gathered evidence and produced a finding;
// `no_evidence` means it ran and gathered nothing, so the turn fell back.
var InvestigationOutcomes = []string{"answered", "no_evidence"}

// RecoveryResults grades an investigation that hit at least one failing tool
// call. `recovered` means it still produced an evidence-backed finding;
// `unrecovered` means it did not. This is the tool-error-recovery rate.
var RecoveryResults = []string{"recovered", "unrecovered"}

// CutoffBudgets is the closed set of bounded-budget cut-offs the chain already
// discloses to the operator in prose. Counting them makes "the investigation
// stopped early" a number instead of a sentence nobody aggregates.
var CutoffBudgets = []string{"rounds", "tool_calls", "time", "evidence_chars"}

// TokenDirections splits provider-reported usage.
var TokenDirections = []string{"input", "output"}

// UsageReportedValues labels a provider call by whether the provider returned
// its own token accounting. It is the DENOMINATOR HONESTY of every token number
// here: tokens are counted only from what a provider actually reported, never
// estimated from character counts.
var UsageReportedValues = []string{"yes", "no"}

// ── the censor registry ──────────────────────────────────────────────────────

// Scorecard metric ids. These are the metrics whose availability is declared on
// every scrape, whether or not they can be produced.
const (
	// MetricAlertCompressionRatio — signals in / incidents out over the window.
	MetricAlertCompressionRatio = "alert_compression_ratio"
	// MetricRCATop3Accuracy — top-3 root-cause accuracy.
	MetricRCATop3Accuracy = "rca_top3_accuracy"
	// MetricTimeToEvidenceBackedDiagnosis — onset to an answer that CARRIES
	// EVIDENCE, not chat response latency.
	MetricTimeToEvidenceBackedDiagnosis = "time_to_evidence_backed_diagnosis"
	// MetricAICostPerInvestigation — model spend per investigation.
	MetricAICostPerInvestigation = "ai_cost_per_investigation"
)

// Censor reasons. Each is a statement about the WORKLOAD or the STORE, never an
// excuse: every one names the specific thing that would have to change.
const (
	// ReasonNone is the sentinel for "this metric is being produced".
	ReasonNone = "none"
	// ReasonNeverSampled — the background sampler has not completed a pass yet.
	ReasonNeverSampled = "never_sampled"
	// ReasonStoreUnreadable — the sampler's last pass could not read the
	// correlation store. NOT the same as "there were no incidents".
	ReasonStoreUnreadable = "store_unreadable"
	// ReasonNoObjectsInWindow — nothing correlated in the window, so the ratio
	// has a zero denominator. A ratio of 0 would read as "no compression",
	// which is the opposite of what an empty window means.
	ReasonNoObjectsInWindow = "no_objects_in_window"
	// ReasonNoRankLabelledGroundTruth — top-K accuracy needs to know WHICH
	// ranked hypothesis was the true one. Production records no such label: the
	// operator verdict vocabulary (rcafeedback: correct|wrong|partial ×
	// wrong_part) judges the OBJECT, not a position in its ranking, and
	// netops.corr_objects carries the ranking but no truth column. Top-1 is
	// answerable from the operator verdict (netops_rca_feedback_total); top-3
	// is not answerable at all without a rank-labelled corpus.
	ReasonNoRankLabelledGroundTruth = "no_rank_labelled_ground_truth"
	// ReasonNoPerVersionModalityColumn — the §1(d) "sufficient evidence" clause
	// reads len(verdict.modality_coverage), which is projected as plane_count
	// onto netops.corr_current (the LATEST version) and onto nothing else. The
	// per-version history table netops.corr_objects does not carry it, so the
	// FIRST moment an object became evidence-backed cannot be located without
	// decompressing the ~26 KB `hypotheses` blob per version — the exact read
	// shape this codebase's own query-shape rules forbid on a recurring path.
	// Projecting plane_count onto corr_objects is what would make this
	// measurable.
	ReasonNoPerVersionModalityColumn = "no_per_version_modality_column"
	// ReasonSingleModalityWorkload — no object in the window carries two
	// independent modality classes, so no answer in it is evidence-backed under
	// the engine's OWN independence test. Measured, not assumed: it is read off
	// plane_count. A multi-modality workload is what would make this measurable
	// (USEFUL_RCA_DEFINITION_2026-09-02.md §4, finding 1).
	ReasonSingleModalityWorkload = "single_modality_workload"
	// ReasonNoTokenPrice — no model price is configured, so spend cannot be
	// derived from tokens. Tokens are emitted unconditionally either way.
	ReasonNoTokenPrice = "no_token_price_configured"
	// ReasonNoProviderUsage — no provider call has reported its own token
	// accounting, so there is no measured token base to price.
	ReasonNoProviderUsage = "no_provider_usage_reported"
)

// censorReasons is the CLOSED set of reasons each scorecard metric may report.
// Every (metric, reason) pair is emitted on every scrape as a 0 or a 1, the same
// shape corr_rca_degradation_reason uses, so an operator can tell "unavailable
// for reason X" from "unavailable and nobody said why" without reading a second
// metric. ReasonNone is deliberately NOT a member of any list: "not censored" is
// netops_ai_scorecard_available{metric} = 1 with every reason at 0, and a series
// literally named censored{reason="none"}=1 would be a contradiction on a
// dashboard.
var censorReasons = map[string][]string{
	MetricAlertCompressionRatio: {
		ReasonNeverSampled, ReasonStoreUnreadable, ReasonNoObjectsInWindow,
	},
	MetricRCATop3Accuracy: {
		ReasonNoRankLabelledGroundTruth,
	},
	MetricTimeToEvidenceBackedDiagnosis: {
		ReasonNeverSampled, ReasonStoreUnreadable,
		ReasonNoPerVersionModalityColumn, ReasonSingleModalityWorkload,
	},
	MetricAICostPerInvestigation: {
		ReasonNoTokenPrice, ReasonNoProviderUsage,
	},
}

// ScorecardMetrics is censorReasons' key set in a stable presentation order.
var ScorecardMetrics = []string{
	MetricAlertCompressionRatio,
	MetricRCATop3Accuracy,
	MetricTimeToEvidenceBackedDiagnosis,
	MetricAICostPerInvestigation,
}

// ── latency histogram buckets ────────────────────────────────────────────────

// LatencyBuckets are the upper bounds (seconds) of the answer/investigation
// latency histograms. They straddle the range the product actually occupies: a
// deterministic evidence-only answer lands in the first two buckets, a chained
// investigation with a provider narration in the middle, and anything past 60 s
// is at or over the turn budget (ai.SkillTurnBudget) and is the tail that
// matters. p50/p95 are read off these in PromQL with histogram_quantile.
var LatencyBuckets = []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 30, 60, 120}

// DefaultWindow is the span the sampled correlation numbers are computed over.
// A day is what a buyer means by "your compression ratio" and it is long enough
// that a quiet hour does not swing it.
const DefaultWindow = 24 * time.Hour

// DefaultSampleEvery is the sampler cadence. The query it issues measured 108 ms
// against a 923k-row corr_current on the lab box, so this is deliberately
// conservative rather than forced.
const DefaultSampleEvery = 5 * time.Minute

// DefaultSampleTimeout bounds one sampling pass (§9: all IO has a timeout).
const DefaultSampleTimeout = 30 * time.Second
