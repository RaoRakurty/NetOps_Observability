// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// honest.tsx — the small shared primitives of the Digital Experience surface.
//
// THE ONE RULE THIS FILE EXISTS FOR: an absent measurement is never rendered as
// a healthy one, and never as a 0 or a 100. Wherever the server sends
// `measured:false` it also sends the sentence that explains the absence, and
// these components render that sentence in the place a number would have gone.
//
// The second rule: every number carries how it was made. A score shows its
// band, its policy version and its dimensions with their weights and each
// one's contribution to the change; a confidence shows the factors it is the
// product of and, when it is not confirmed, exactly what is blocking it.
//
// The third: inferred and observed must LOOK different. `provenance.observation`
// drives a chip with a different shape (dashed, italic) as well as a different
// colour, so the distinction survives a colourblind reader and a screenshot.

import { ReactNode } from "react";

import type {
  DemBand, DemExperienceScore, DemFactor, DemObservation, DemSeverity,
  DemVerdictTier,
} from "../../services/api";
import { DEM_BAND_GOOD_AT, DEM_BAND_POOR_AT } from "../../services/api";

// ── reason vocabulary ───────────────────────────────────────────────────────
//
// The server's reason tokens are machine words. They are switched on, never
// printed: an operator reads the sentence, not the enum. A token we do not know
// falls through as itself rather than being swallowed — a silent "" would hide
// the very absence this file exists to show.

const REASON_TEXT: Record<string, string> = {
  feature_off: "Experience collection is switched off for this deployment, so nothing on this screen was measured.",
  no_targets: "No experience check is declared for this tenant, so there is nothing to measure yet.",
  paused: "This check is paused, so nothing was measured in this window.",
  no_prober: "No prober is reporting for this tenant.",
  no_samples: "No measurement was recorded in this window.",
  query_failed: "The measurement store did not answer, so there is no score. This is not a healthy result.",
  window_too_new: "The check was created inside this window, so there is not enough history to score it.",
  no_dimensions_measured: "Not one dimension of the score had an observation behind it.",
  below_evidence_minimum: "Too few dimensions were measured to publish a score — a number made from one dimension is not the experience.",
  no_score_policy: "No score policy is loaded, so the weights that make the number are unknown.",
  step_not_bound: "This step is declared but nothing measures it yet.",
  step_no_measurement: "This step is bound to a check that produced nothing in this window.",
  journey_not_measured: "No required step of this journey is measured in this window.",
  no_journeys: "No journey is declared for this tenant. A workflow nobody described cannot be reported on, and it will not be guessed.",
  not_configured: "This source is not configured.",
  no_data: "This source is configured but produced nothing in this window.",
  stale: "This source last reported longer ago than its own cadence allows.",
  permission_denied: "This source refused the read — the credential it uses is not permitted.",
  error: "This source returned an error.",
  not_supported: "This source cannot be collected in this deployment.",
  // Set when a figure EXISTS but cannot be summed (more than one currency).
  // Distinct from "nobody declared one", which the caller's own detail says.
  not_totalled: "The figures exist but cannot be added up.",
};

/** The operator sentence for a server reason token. Unknown tokens survive. */
export function reasonText(reason?: string): string {
  if (!reason) return "";
  return REASON_TEXT[reason] ?? reason;
}

/**
 * NOT MEASURED, in the place a number would have been.
 *
 * `reason` is the server's token (turned into its sentence) and `detail` is the
 * server's own longer wording, which is rendered VERBATIM — it usually says
 * something more specific than the token can.
 */
export function NotMeasured({ reason, detail, compact }: {
  reason?: string;
  detail?: string;
  /** Chip only — for a table cell where the sentence sits in a neighbouring column. */
  compact?: boolean;
}) {
  const why = reasonText(reason);
  const title = [why, detail].filter(Boolean).join(" ");
  if (compact) {
    return (
      <span className="dx-nm">
        <span className="dx-nm-tag" title={title || undefined}>Not measured</span>
      </span>
    );
  }
  return (
    <span className="dx-nm">
      <span className="dx-nm-tag">Not measured</span>
      {why && <span className="dx-nm-why">{why}</span>}
      {detail && detail !== why && <span className="dx-nm-detail">{detail}</span>}
    </span>
  );
}

// ── bands ───────────────────────────────────────────────────────────────────

const BAND_LABEL: Record<DemBand, string> = {
  good: "Good", fair: "Fair", poor: "Poor", not_measured: "Not measured",
};

/** The band edges never move: good ≥ 70, fair 31–69, poor ≤ 30. */
export function bandFor(score: number | undefined): DemBand {
  if (score === undefined || Number.isNaN(score)) return "not_measured";
  if (score >= DEM_BAND_GOOD_AT) return "good";
  if (score <= DEM_BAND_POOR_AT) return "poor";
  return "fair";
}

export function BandChip({ band, title }: { band?: string; title?: string }) {
  const b = (band && band in BAND_LABEL ? band : "not_measured") as DemBand;
  return (
    <span className={`dx-band dx-band--${b}`} title={title}>
      {BAND_LABEL[b]}
    </span>
  );
}

export function SeverityChip({ severity }: { severity: DemSeverity | string }) {
  const s = String(severity || "info").toLowerCase();
  return <span className={`dx-sev dx-sev--${s}`}>{s}</span>;
}

// ── provenance ──────────────────────────────────────────────────────────────

const OBSERVATION_LABEL: Record<DemObservation, string> = {
  observed: "Observed",
  inferred: "Inferred",
  unknown: "Origin unknown",
  simulated: "Simulated",
};

const OBSERVATION_HELP: Record<DemObservation, string> = {
  observed: "An instrument recorded this.",
  inferred: "This was worked out from other observations — nobody measured it directly.",
  unknown: "How this was obtained was not recorded, so it cannot be weighed as an observation.",
  simulated: "A replay or a fixture. Never a live verdict.",
};

/** Observed and inferred must be distinguishable without colour: the inferred
 *  chip is dashed AND italic, and its help text says what it means. */
export function ProvenanceChip({ observation }: { observation?: string }) {
  const o = (observation && observation in OBSERVATION_LABEL
    ? observation : "unknown") as DemObservation;
  return (
    <span className={`dx-prov dx-prov--${o}`} title={OBSERVATION_HELP[o]}>
      {OBSERVATION_LABEL[o]}
    </span>
  );
}

// ── confidence ──────────────────────────────────────────────────────────────

const TIER_LABEL: Record<DemVerdictTier, string> = {
  confirmed: "Confirmed",
  suspected: "Suspected",
  undetermined: "Undetermined",
};

/**
 * Confidence, always with the breakdown that produced it, and — when it is not
 * confirmed — with the mechanical reasons the gate is closed. A bare "62%"
 * teaches an operator to ignore the number; the factors are the number.
 */
export function ConfidenceChip({ confidence, tier, factors, gateReasons, label }: {
  confidence: number;
  tier?: string;
  factors?: DemFactor[];
  gateReasons?: string[];
  label?: string;
}) {
  const t = (tier && tier in TIER_LABEL ? tier : "undetermined") as DemVerdictTier;
  const pct = Math.round((Number.isFinite(confidence) ? confidence : 0) * 100);
  const name = label ?? "Confidence";
  return (
    <div className="dx-conf" role="group" aria-label={`${name} ${pct}%, ${TIER_LABEL[t]}`}>
      <span className="dx-conf-head">
        <span className="dx-conf-num">{pct}%</span>
        <span className={`dx-conf-tier dx-conf-tier--${t}`}>{TIER_LABEL[t]}</span>
      </span>
      <span className="dx-conf-bar" aria-hidden="true">
        <span className="dx-conf-fill" style={{ width: `${Math.max(0, Math.min(100, pct))}%` }} />
      </span>
      {factors && factors.length > 0 && (
        <ul className="dx-conf-factors">
          {factors.map((f) => (
            <li key={f.name}>
              <b>{f.value.toFixed(2)}</b> · {f.name.replace(/_/g, " ")} — {f.reason}
            </li>
          ))}
        </ul>
      )}
      {t !== "confirmed" && gateReasons && gateReasons.length > 0 && (
        <ul className="dx-gate" aria-label="Why this is not confirmed">
          {gateReasons.map((r, i) => <li key={i}>{r}</li>)}
        </ul>
      )}
    </div>
  );
}

// ── the published score ─────────────────────────────────────────────────────

const DIMENSION_LABEL: Record<string, string> = {
  journey_success: "Journey success",
  availability: "Availability",
  responsiveness: "Responsiveness",
  error_free_interaction: "Error-free interaction",
  network_quality: "Network quality",
  user_friction: "User friction",
};

export function dimensionLabel(name: string): string {
  return DIMENSION_LABEL[name] ?? name.replace(/_/g, " ");
}

/**
 * How the per-subject points were folded into one number, in words.
 *
 * The fold matters as much as the weights: a plain mean is how one dead check
 * disappears into a green tile, and a pure worst-of would make one paused check
 * the whole story. Naming the fold is the difference between a score an
 * operator can argue with and one they can only accept.
 */
const AGGREGATION_TEXT: Record<string, string> = {
  worst_weighted: "a worst-weighted mean — the worst subject carries 40% of the weight, so one failing subject cannot average away",
  worst_of: "taking the worst observer's result",
  p95_of: "the 95th percentile across the observers",
};

export function aggregationText(aggregation?: string): string {
  if (!aggregation) return "a fold this score did not record";
  return AGGREGATION_TEXT[aggregation] ?? aggregation.replace(/_/g, " ");
}

/**
 * "How this number was made", as one string, for a `title` tooltip: every
 * dimension, its weight, its points and what it contributed to the change.
 * A dimension nothing measured is listed with its reason, not omitted — an
 * omitted dimension is an invisible hole in a published score.
 */
export function scoreTooltip(score: DemExperienceScore): string {
  const head = score.measured && score.score !== undefined
    ? `Score ${score.score.toFixed(1)} (${score.band}) · policy ${score.policy_name} v${score.policy_version}`
    : `Not published · policy ${score.policy_name} v${score.policy_version}`;
  const gate = `${score.measured_dimensions} of ${score.declared_dimensions} dimensions measured`;
  const fold = `Subjects folded by ${aggregationText(score.aggregation)}`;
  const lines = (score.dimensions ?? []).map((d) => {
    if (!d.measured) return `${dimensionLabel(d.name)}: not measured — ${reasonText(d.reason)}`;
    const delta = d.delta_contribution === undefined
      ? "no previous window to compare with"
      : `${d.delta_contribution >= 0 ? "+" : ""}${d.delta_contribution.toFixed(1)} pts of the change`;
    return `${dimensionLabel(d.name)}: ${d.points.toFixed(1)}/100 × weight ${(d.weight * 100).toFixed(0)}% → ${d.score.toFixed(1)} · ${delta}`;
  });
  return [head, gate, fold, ...lines].join("\n");
}

/** The visible breakdown, for the panels that have room for it. */
export function ScoreBreakdown({ score }: { score: DemExperienceScore }) {
  const dims = score.dimensions ?? [];
  return (
    <ul className="dx-dims">
      {dims.map((d) => {
        const band = d.measured ? bandFor(d.points) : "not_measured";
        return (
          <li className="dx-dim" key={d.name}>
            <span className="dx-dim-head">
              <span className="dx-dim-name">{dimensionLabel(d.name)}</span>
              <span className="dx-dim-w">
                {d.measured
                  ? `${d.points.toFixed(1)} × ${(d.weight * 100).toFixed(0)}% = ${d.score.toFixed(1)}`
                  : "weight redistributed"}
              </span>
            </span>
            {d.measured ? (
              <>
                <span className="dx-dim-track" aria-hidden="true">
                  <span className={`dx-dim-fill dx-dim-fill--${band}`}
                    style={{ width: `${Math.max(0, Math.min(100, d.points))}%` }} />
                </span>
                <span className="dx-cap">
                  {d.samples} observation{d.samples === 1 ? "" : "s"}
                  {d.delta_contribution === undefined
                    ? " · no previous window to compare with"
                    : ` · ${d.delta_contribution >= 0 ? "+" : ""}${d.delta_contribution.toFixed(1)} pts of the change since the previous window`}
                  {d.detail ? ` · ${d.detail}` : ""}
                </span>
              </>
            ) : (
              <NotMeasured reason={d.reason} />
            )}
          </li>
        );
      })}
    </ul>
  );
}

// ── formatting ──────────────────────────────────────────────────────────────

/** A percentage, or the honest absence. Never a 0 standing in for "unknown". */
export function pct(v: number | undefined, digits = 1): string {
  return v === undefined || !Number.isFinite(v) ? "" : `${v.toFixed(digits)}%`;
}

export function fmtDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "";
  const s = Math.floor(seconds);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

/** Money, only when the operator declared a value. There is no default currency
 *  and no zero: a value nobody declared is absent, not free. */
export function Money({ value, currency }: { value?: number; currency?: string }) {
  if (value === undefined || !currency) {
    return (
      <NotMeasured
        reason="not_declared"
        detail="No value per successful traversal is declared for the affected journeys, so the loss cannot be valued."
      />
    );
  }
  return (
    <span className="dx-mono">
      {value.toLocaleString(undefined, { maximumFractionDigits: 0 })} {currency}
    </span>
  );
}

// ── generic states ──────────────────────────────────────────────────────────

export function Loading({ what }: { what: string }) {
  return <p className="dx-loading" role="status">Reading {what}…</p>;
}

export function LoadError({ what, error, onRetry }: {
  what: string; error: string; onRetry?: () => void;
}) {
  return (
    <div className="dx-error" role="alert">
      <p className="dx-note">
        {what} could not be read, so whether it is healthy is unknown — this is not
        an empty result. {error}
      </p>
      {onRetry && (
        <div className="dx-actions">
          <button type="button" className="btn" onClick={onRetry}>Try again</button>
        </div>
      )}
    </div>
  );
}

/** A named landmark with a heading, used by every panel on this surface. */
export function Panel({ title, label, actions, children }: {
  title: string; label?: string; actions?: ReactNode; children: ReactNode;
}) {
  return (
    <section className="card dx-section" role="region" aria-label={label ?? title}>
      <div className="dx-section-head">
        <h2 className="dx-h2">{title}</h2>
        {actions}
      </div>
      {children}
    </section>
  );
}
