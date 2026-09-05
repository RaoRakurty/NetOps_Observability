// licence.model.ts — the pure half of the platform Licence page.
//
// Everything here is a total function over the wire contract in
// src/backend/internal/licence/api.go (+ state.go): no fetch, no React, no
// clock of its own. That is what makes this page's rules testable as rules
// rather than as rendered pixels — the same split the Data Protection console
// uses (pages/dataProtection.model.ts).
//
// THE THREE RULES THIS FILE EXISTS TO ENFORCE.
//
//  1. A CEILING NOBODY MEASURED IS NOT A ZERO. The server sends `current: null`
//     plus a sibling `current_reason` for anything it does not count.
//     `measured()` is the only door those come through, and there is no path
//     that turns an absent count into a 0, a dash, or a full-looking bar.
//  2. AN UNLIMITED CEILING HAS NO PERCENTAGE. A bar drawn against "no limit" is
//     a made-up number. `usageBar()` answers "unlimited" for those, and the
//     page prints the count in use instead of a fill.
//  3. A LIMIT NOTHING GATES MUST NOT LOOK LIKE ONE THAT BITES. The contract
//     carries seven ceilings and enforces two; `enforced: false` rows are
//     labelled "carried, not enforced" and never rendered as a live gate.
//
// It also keeps a refusal VERBATIM. When an install is rejected the operator is
// holding a file we will not accept, and the exact reason is the only thing
// that helps them; `refusalReason()` unwraps the transport envelope and changes
// not one character of what the server said.

import type {
  LicenceCeiling,
  LicenceFeature,
  LicenceOverage,
  LicencePhase,
  LicenceState,
  LicenceTier,
  LicenceView,
} from "../services/api";

// ── measured-or-not ─────────────────────────────────────────────────────────

/** A value the platform measured, or the reason it did not. */
export type Measured<T> =
  | { measured: true; value: T }
  | { measured: false; reason: string };

/** The sentence an absent count renders as when the server sent no reason. */
export const NOT_MEASURED_FALLBACK = "the platform does not count this yet";

/**
 * Wraps a nullable contract value with the reason it is absent.
 *
 * `null`/`undefined` is ALWAYS absent — and `0` is ALWAYS a measurement. Zero
 * devices in use is a fact; "we never counted" is silence, and the two must
 * never render the same way.
 */
export function measured<T>(value: T | null | undefined, reason?: string): Measured<T> {
  if (value === null || value === undefined) {
    return { measured: false, reason: (reason ?? "").trim() || NOT_MEASURED_FALLBACK };
  }
  return { measured: true, value };
}

/** The rendered text for an absent value: "not measured — <reason>". */
export function notMeasuredText(reason: string): string {
  return `not measured — ${reason}`;
}

// ── tone ────────────────────────────────────────────────────────────────────

export type Tone = "good" | "warn" | "near" | "bad" | "muted";

// ── ceilings ────────────────────────────────────────────────────────────────

/** The contract's "no limit" sentinel. Mirrors entitlement.Unlimited. */
export const UNLIMITED = -1;

/** A limit as a person reads it. -1 is a sentinel, never a number on screen. */
export function fmtLimit(limit: number): string {
  return limit === UNLIMITED ? "unlimited" : String(limit);
}

/**
 * What a usage row can honestly show.
 *
 *   measured   — a real count against a real limit, so a fill is meaningful;
 *   unlimited  — a real count against no limit, so there is nothing to fill;
 *   unmeasured — nobody counted, so there is no bar and no number at all.
 */
export type UsageBar =
  | { kind: "measured"; percent: number; current: number; limit: number; over: boolean; text: string }
  | { kind: "unlimited"; current: number; text: string }
  | { kind: "unmeasured"; reason: string };

/**
 * The bar for one ceiling row.
 *
 * The percentage is clamped to 0…100 for the FILL only — the text keeps the
 * true numbers, so an over-ceiling row reads "30 of 25" beside a full bar
 * rather than a quietly truncated "25 of 25".
 */
export function usageBar(row: LicenceCeiling): UsageBar {
  const m = measured(row.current, row.current_reason);
  if (!m.measured) return { kind: "unmeasured", reason: m.reason };
  const current = m.value;
  if (row.limit === UNLIMITED) {
    return { kind: "unlimited", current, text: `${current} in use · no limit` };
  }
  // A limit of zero cannot be divided into. Anything in use against it is
  // wholly over, and nothing in use is wholly empty.
  const raw = row.limit <= 0 ? (current > 0 ? 100 : 0) : (current / row.limit) * 100;
  const percent = Math.max(0, Math.min(100, Math.round(raw)));
  return {
    kind: "measured",
    percent,
    current,
    limit: row.limit,
    over: row.over,
    text: `${current} of ${fmtLimit(row.limit)}`,
  };
}

/**
 * The 80 / 90 / 100 % usage bands (owner decision, 2026-09-05 — TIERING_PLAN
 * §9, "Soft overage + alerts (80/90/100 %)").
 *
 * Five bands and not three, because 100 % and "past 100 %" are different
 * sentences: at the allowance nothing has happened yet; past it, something has,
 * and on a paid tier that something is a true-up rather than a block.
 *
 * A row nobody measured, one with no limit, and one nothing enforces have NO
 * band at all — inventing a percentage for any of them would be the page making
 * up a number.
 */
export type UsageBand = "unrated" | "ok" | "approaching" | "near" | "full" | "over";

export function usageBand(row: LicenceCeiling): UsageBand {
  if (!row.enforced) return "unrated";
  const bar = usageBar(row);
  if (bar.kind !== "measured") return "unrated";
  // The band is computed from the EXACT ratio, not from the bar's rounded fill.
  // 249 of 250 is 99.6 %, and rounding it to 100 would put a deployment that is
  // still inside its allowance in the band that says it has reached it — and
  // would also disagree with the alert rules, which divide exactly.
  if (row.over || bar.current > bar.limit) return "over";
  if (bar.current >= bar.limit) return "full";
  const pct = bar.limit > 0 ? (bar.current / bar.limit) * 100 : 100;
  if (pct >= 90) return "near";
  if (pct >= 80) return "approaching";
  return "ok";
}

/**
 * The tone of a band. The three severity tokens carry all five bands: the ramp
 * agrees with every other severity on the page rather than introducing a
 * private palette (`near` is a warn/crit mix declared once in styles.css).
 */
export function bandTone(band: UsageBand): Tone {
  switch (band) {
    case "ok":
      return "good";
    case "approaching":
      return "warn";
    case "near":
      return "near";
    case "full":
    case "over":
      return "bad";
    default:
      return "muted";
  }
}

/** The pill beside a bar that has entered a warning band, or null below 80 %. */
export function bandLabel(band: UsageBand): string | null {
  switch (band) {
    case "approaching":
      return "80% of the allowance";
    case "near":
      return "90% of the allowance";
    case "full":
      return "at the allowance";
    case "over":
      return "over the allowance";
    default:
      return null;
  }
}

/** The tone of a usage row. An un-enforced row is muted: nothing gates on it. */
export function ceilingTone(row: LicenceCeiling): Tone {
  if (!row.enforced) return "muted";
  return bandTone(usageBand(row));
}

/**
 * What happens at this ceiling when you go past it — the sentence under a bar
 * in a warning band.
 *
 * SOFT and HARD are not the same statement and must never be phrased alike: a
 * soft ceiling never blocks anything, and telling a paid customer they are
 * about to be cut off would be false. A hard one does block, and softening that
 * would be equally false.
 */
export function ceilingConsequence(row: LicenceCeiling): string {
  if (!row.enforced) return NOT_ENFORCED_REASON;
  if (row.soft) {
    return "This allowance does not block. Going past it is allowed and recorded for true-up — nothing is disabled and nothing is deleted.";
  }
  return "This is a hard limit: the next one past it is refused. Nothing already here is disabled or deleted.";
}

/** The standing note beside a limit no code gates on. */
export const NOT_ENFORCED_NOTE = "carried, not enforced";

/**
 * Why an un-enforced ceiling is on the page at all. It is part of the licence
 * file's documented shape so an issued file stays forward-compatible; saying so
 * is cheaper than an operator discovering it the hard way.
 */
export const NOT_ENFORCED_REASON =
  "This limit is carried in the licence so an issued file is complete, but nothing in the product gates on it today.";

/** "Included in Team" — the upgrade half of a row, or null when none lifts it. */
export function liftedByText(tier: LicenceTier | string | undefined): string | null {
  const label = tierLabel(tier);
  return label ? `Included in ${label}` : null;
}

// ── tiers and features ──────────────────────────────────────────────────────

/** The tier's display name. An unknown tier shows its own name, never blank. */
export function tierLabel(tier: LicenceTier | string | undefined | null): string {
  switch (tier) {
    case "community":
      return "Community";
    case "team":
      return "Team";
    case "enterprise":
      return "Enterprise";
    default:
      return (tier ?? "").trim();
  }
}

/** The word for a feature row: entitled, or the tier that would grant it. */
export function featureStatus(f: LicenceFeature): { tone: Tone; text: string } {
  if (f.entitled) return { tone: "good", text: "Included" };
  const lifted = tierLabel(f.included_in);
  return { tone: "muted", text: lifted ? `Included in ${lifted}` : "Not included" };
}

// ── the headline verdict ────────────────────────────────────────────────────
//
// There is no server-side "headline" field, and inventing one in the API would
// hide the arithmetic. It is derived here, in one place, from facts the server
// does publish — and the reason it returns is the specific condition that
// decided it, never a mood.

export type HeadlineState = "community" | "licensed" | "grace" | "degraded" | "refused";

export type Headline = { state: HeadlineState; label: string; reason: string; tone: Tone };

export function headline(state: LicenceState): Headline {
  // Worst true statement first. A licence we refused is the loudest fact on the
  // page: the operator believes they have one, and they do not.
  if (state.load_error) {
    return {
      state: "refused",
      label: "Installed licence refused",
      reason: state.load_error,
      tone: "bad",
    };
  }
  if (state.degraded || state.phase === "post_grace") {
    return {
      state: "degraded",
      label: "Past grace — running at Community ceilings",
      reason:
        state.reason ||
        "The installed licence is past its grace period, so the Community ceilings are the ones in force. " +
          "Everything already here stays visible and exportable; only creating and configuring paid capability is refused.",
      tone: "bad",
    };
  }
  if (state.in_grace || state.phase === "in_grace") {
    return {
      state: "grace",
      label: "In grace",
      reason:
        state.reason ||
        "The licence has expired and the issuer's grace period is still running. Nothing has changed: the licensed ceilings and capabilities stay in force until it ends.",
      tone: "warn",
    };
  }
  if (state.source === "community") {
    return {
      state: "community",
      label: "Community",
      reason:
        "No licence is installed. Community is the free tier, not a fault state — the ceilings below are the ones in force.",
      tone: "muted",
    };
  }
  return {
    state: "licensed",
    label: state.trial
      ? `${tierLabel(state.licensed_tier || state.tier)} evaluation licence`
      : `${tierLabel(state.licensed_tier || state.tier)} licence`,
    reason: `Issued to ${state.customer || "an unnamed customer"} and in force.`,
    tone: "good",
  };
}

// ── the state chip ──────────────────────────────────────────────────────────

/**
 * The one-glance chip: valid · trial · in grace, N days left · past grace.
 *
 * It is derived, like the headline, from facts the server publishes — the phase
 * and the two counts — rather than from a server-side "chip" field, so the
 * arithmetic stays visible and testable here instead of being hidden in a
 * string the API happened to send.
 *
 * The days come from the server's own clock (`grace_days_left`,
 * `days_to_expiry`), so the chip and the metric can never disagree by a
 * timezone. A count the server did not send is simply not shown: a chip reading
 * "0 days left" that meant "we do not know" would be the worst possible lie on
 * this page.
 */
export type StateChip = { phase: LicencePhase | "community"; label: string; tone: Tone; detail: string };

export function stateChip(view: Pick<LicenceView, "state" | "days_to_expiry" | "grace_days_left">): StateChip {
  const st = view.state;
  const phase = st.phase ?? (st.degraded ? "post_grace" : st.in_grace ? "in_grace" : "valid");

  if (phase === "post_grace") {
    return {
      phase,
      label: "Past grace",
      tone: "bad",
      detail:
        "Creating and configuring paid capability is refused. Everything already here stays visible and exportable, and nothing has been disabled or deleted.",
    };
  }
  if (phase === "in_grace") {
    const left = view.grace_days_left;
    const days = left === null || left === undefined ? null : left;
    return {
      phase,
      label: days === null ? "In grace" : `In grace · ${days} ${days === 1 ? "day" : "days"} left`,
      tone: "warn",
      detail:
        "The licence has expired and nothing has changed yet. Install a renewal before the grace period ends.",
    };
  }
  if (st.source === "community") {
    return {
      phase: "community",
      label: "Community",
      tone: "muted",
      detail: "The free tier. No licence is installed, and that is a supported state, not a fault.",
    };
  }
  const days = view.days_to_expiry;
  if (st.trial) {
    return {
      phase,
      label: days === null || days === undefined ? "Evaluation licence" : `Evaluation licence · ${days} ${days === 1 ? "day" : "days"} left`,
      tone: days !== null && days !== undefined && days <= 7 ? "warn" : "good",
      detail:
        "A trial grants exactly what its tier, ceilings and capabilities say. Nothing about it is a reduced version of the product.",
    };
  }
  return {
    phase,
    label: days === null || days === undefined ? "Valid" : `Valid · expires in ${days} ${days === 1 ? "day" : "days"}`,
    tone: days !== null && days !== undefined && days <= EXPIRY_SOON_DAYS ? "warn" : "good",
    detail: "The licence is in force.",
  };
}

// ── expiry ──────────────────────────────────────────────────────────────────

/**
 * How an expiry reads.
 *
 * `none` is the Community answer and is NOT a gap: there is nothing to expire.
 * The days come straight from the server's own arithmetic (`days_to_expiry`),
 * so this page and the metric can never disagree by a timezone.
 */
export type ExpiryVerdict =
  | { state: "none"; text: string }
  | { state: "active" | "soon" | "grace" | "expired"; days: number; text: string; tone: Tone };

/** How near an expiry has to be before the page says so rather than whispers. */
export const EXPIRY_SOON_DAYS = 30;

export function expiryVerdict(view: Pick<LicenceView, "state" | "days_to_expiry">): ExpiryVerdict {
  const st = view.state;
  const m = measured(view.days_to_expiry, "this licence carries no expiry");
  if (!m.measured || !st.expires_at) {
    return { state: "none", text: "No expiry — Community ceilings do not lapse" };
  }
  const days = m.value;
  if (st.degraded || st.phase === "post_grace") {
    return { state: "expired", days, text: `expired ${Math.abs(days)} days ago — past its grace period`, tone: "bad" };
  }
  if (st.in_grace || st.phase === "in_grace") {
    const grace = st.grace_days ?? 0;
    return {
      state: "grace",
      days,
      text: `expired ${Math.abs(days)} days ago — inside a ${grace}-day grace period`,
      tone: "warn",
    };
  }
  if (days < 0) {
    return { state: "expired", days, text: `expired ${Math.abs(days)} days ago`, tone: "bad" };
  }
  if (days <= EXPIRY_SOON_DAYS) {
    return { state: "soon", days, text: `expires in ${days} days`, tone: "warn" };
  }
  return { state: "active", days, text: `expires in ${days} days`, tone: "good" };
}

// ── overages ────────────────────────────────────────────────────────────────

/**
 * The one-line summary above the overage list.
 *
 * It says what is NOT happening as loudly as what is: nothing has been deleted
 * and nothing has been hidden. An operator reading a degraded licence needs to
 * know their data is still there before they read anything else.
 */
export function overageSummary(overages: readonly LicenceOverage[]): string | null {
  if (overages.length === 0) return null;
  const total = overages.reduce((n, o) => n + o.over, 0);
  const what = overages.map((o) => o.label).join(", ");
  // SOFT and HARD overages are different facts and get different sentences.
  // "Not covered" would be wrong for a paid customer whose ceiling never
  // blocks, and "recorded for true-up" would be wrong for a free one whose next
  // activation is refused.
  if (overages.every((o) => o.soft)) {
    return `${total} above the licensed ${what}. Everything is still being collected from — nothing has been blocked, disabled or deleted; the overage is recorded for true-up.`;
  }
  return `${total} over the licensed ${what}. Everything is still here and nothing has been removed — what is over a ceiling is listed below, not deleted.`;
}

/**
 * How long an overage has been running, as a sentence, or null when the
 * platform does not know.
 *
 * It states the START and stops. NO deadline, no countdown, no consequence:
 * how long an overage may run is an order-form term, and a page that invented
 * one would be the product writing commercial policy.
 */
export function overageSince(o: Pick<LicenceOverage, "since">, now: Date = new Date()): string | null {
  if (!o.since) return null;
  const started = new Date(o.since);
  if (Number.isNaN(started.getTime())) return null;
  const days = Math.floor((now.getTime() - started.getTime()) / 86_400_000);
  const when = started.toISOString().slice(0, 10);
  if (days <= 0) return `Recorded since today (${when}).`;
  return `Recorded since ${when} — ${days} ${days === 1 ? "day" : "days"}.`;
}

// ── keys ────────────────────────────────────────────────────────────────────

/** The filename a downloaded public key lands under. */
export function keyFileName(id: string): string {
  // Anything a path could read as a traversal or a separator becomes a dash.
  // The id comes from the platform, not from a person, but a filename handed to
  // a browser is not the place to find out that assumption was wrong.
  const safe = (id || "key").replace(/[^A-Za-z0-9._-]/g, "-").replace(/\.{2,}/g, "-");
  return `correlix-licence-${safe}.pub`;
}

/**
 * The file body: the key, plus the two facts that make it usable a year from
 * now — which key it is, and what it is for.
 */
export function keyFileBody(key: { id: string; role: string; note?: string; base64: string }): string {
  const lines = [
    `# Correlix licence signing key`,
    `# id: ${key.id}`,
    `# role: ${key.role}`,
  ];
  if (key.note) lines.push(`# note: ${key.note}`);
  lines.push(key.base64, "");
  return lines.join("\n");
}

/** The word for a key's role in the trusted set. */
export function keyRoleLabel(role: string): string {
  switch (role) {
    case "current":
      return "Signs new licences";
    case "previous":
      return "Retired — still verifies licences already issued";
    default:
      return role || "Role not stated";
  }
}

// ── installing ──────────────────────────────────────────────────────────────

/** The largest document the route accepts. Mirrors licence.MaxDocumentBytes. */
export const MAX_DOCUMENT_BYTES = 64 * 1024;

export type DocumentCheck = { ok: true; document: string } | { ok: false; reason: string };

/**
 * The only checks worth doing in a browser: that there IS a document, and that
 * it is inside the bound the route will accept. Everything else — the
 * signature, the key, the tier, the dates — is the server's to judge, and
 * pre-judging it here would mean two implementations of the same policy and a
 * page that can refuse a file the platform would have taken.
 */
export function checkDocument(text: string): DocumentCheck {
  const document = text.trim();
  if (!document) return { ok: false, reason: "There is no licence document to install." };
  const bytes = new TextEncoder().encode(document).length;
  if (bytes > MAX_DOCUMENT_BYTES) {
    return {
      ok: false,
      reason: `That document is ${bytes} bytes; the platform accepts at most ${MAX_DOCUMENT_BYTES}.`,
    };
  }
  return { ok: true, document };
}

/**
 * The server's refusal, VERBATIM.
 *
 * The transport wraps a rejection as "<status> <statusText>: <body>"; this
 * unwraps it and returns exactly the sentence the server wrote. It deliberately
 * does not capitalize, punctuate or soften: an operator holding a licence we
 * will not accept needs the precise reason, and "That request was not accepted"
 * would send them to us instead of to the fix.
 */
export function refusalReason(e: unknown, fallback: string): string {
  const raw = (e instanceof Error ? e.message : typeof e === "string" ? e : String(e ?? ""))
    .replace(/^Error:\s*/, "")
    .trim();
  if (!raw) return fallback;
  const envelope = raw.match(/^\d{3}\s+[^:]*:\s*([\s\S]*)$/);
  const body = (envelope ? envelope[1] : raw).trim();
  if (!body) return fallback;
  if (body.startsWith("{")) {
    try {
      const parsed: unknown = JSON.parse(body);
      if (parsed && typeof parsed === "object") {
        const v = (parsed as Record<string, unknown>).error;
        if (typeof v === "string" && v.trim()) return v.trim();
      }
    } catch {
      /* not JSON after all — fall through and show the body as sent */
    }
    return fallback;
  }
  return body;
}

/** Type-to-confirm: an exact, case-sensitive match after trimming whitespace. */
export function confirmMatches(typed: string, expected: string): boolean {
  return typed.trim() === expected.trim() && expected.trim() !== "";
}

// ── ordering ────────────────────────────────────────────────────────────────

/**
 * Usage rows: what actually gates first, then what is merely carried. Inside
 * each half the server's own vocabulary order is preserved, so two reads of the
 * page never shuffle the table under the operator.
 */
export function sortedCeilings(rows: readonly LicenceCeiling[]): LicenceCeiling[] {
  return [...rows]
    .map((row, i) => ({ row, i }))
    .sort((a, b) => Number(b.row.enforced) - Number(a.row.enforced) || a.i - b.i)
    .map((x) => x.row);
}
