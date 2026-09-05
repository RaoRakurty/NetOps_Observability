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

export type Tone = "good" | "warn" | "bad" | "muted";

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

/** The tone of a usage row. An un-enforced row is muted: nothing gates on it. */
export function ceilingTone(row: LicenceCeiling): Tone {
  if (!row.enforced) return "muted";
  if (row.over) return "bad";
  const bar = usageBar(row);
  if (bar.kind === "measured" && bar.percent >= 90) return "warn";
  return "good";
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
  if (state.degraded) {
    return {
      state: "degraded",
      label: "Running at Community ceilings",
      reason:
        state.reason ||
        "The installed licence is past its grace period, so the Community ceilings are the ones in force.",
      tone: "bad",
    };
  }
  if (state.in_grace) {
    return {
      state: "grace",
      label: "In grace",
      reason:
        state.reason ||
        "The licence has expired and the issuer's grace period is still running. The licensed ceilings stay in force until it ends.",
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
    label: `${tierLabel(state.licensed_tier || state.tier)} licence`,
    reason: `Issued to ${state.customer || "an unnamed customer"} and in force.`,
    tone: "good",
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
  if (st.degraded) {
    return { state: "expired", days, text: `expired ${Math.abs(days)} days ago — past its grace period`, tone: "bad" };
  }
  if (st.in_grace) {
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
  return `${total} over the licensed ${what}. Everything is still here and nothing has been removed — what is over a ceiling is listed below, not deleted.`;
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
