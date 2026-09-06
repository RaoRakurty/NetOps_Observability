// dataProtection.model.ts — the pure half of the Data Protection console.
//
// Everything here is a total function over the wire contract in
// src/backend/system_backup_contract.go: no fetch, no React, no clock of its
// own (a `now` is always passed in). That is what makes the page's rules
// testable as rules rather than as rendered pixels.
//
// THE ONE RULE THIS FILE EXISTS TO ENFORCE. A backup console that prints a
// confident zero for something nobody measured is worse than one that prints
// nothing: an operator reads "0 failures" as proof and stops looking. The
// server encodes that as "null plus a sibling *_detail saying why"; `measured()`
// is the only door those values come through, and there is no path that turns
// an absent number into a 0, a dash, or a green tick.
//
// It also distinguishes two things a naive renderer collapses:
//   NOT MEASURED — nobody looked (null + detail). Styled as absence.
//   NEVER        — we looked, and it has not happened (an empty last_success_at,
//                  a null restorable_verified). That is a measurement, and a bad
//                  one; it is styled as a gap, not as a shrug.
//
// The vocabulary is the operator's, not the storage engine's: a row is
// "Metrics history", never the name of the database underneath it.

import type {
  BackupCoverageView,
  CoverageTargetKind,
  CoverageVerdict,
  EngineCoverage,
  SnapshotRepositoryView,
  SnapshotView,
} from "../services/api";

// ── measured-or-not ─────────────────────────────────────────────────────────

/** A value the platform measured, or the reason it did not. */
export type Measured<T> =
  | { measured: true; value: T }
  | { measured: false; reason: string };

/** The sentence a missing value renders as when the server sent no detail. */
export const NOT_MEASURED_FALLBACK = "the platform does not report this yet";

/**
 * Wraps a nullable contract value with its `*_detail`.
 *
 * `null`/`undefined` is ALWAYS absent — including `0` and `false` being real
 * measured values, which is why the check is against null, not falsiness.
 */
export function measured<T>(value: T | null | undefined, detail?: string): Measured<T> {
  if (value === null || value === undefined) {
    return { measured: false, reason: (detail ?? "").trim() || NOT_MEASURED_FALLBACK };
  }
  return { measured: true, value };
}

/** The rendered text for an absent value: "not measured — <reason>". */
export function notMeasuredText(reason: string): string {
  return `not measured — ${reason}`;
}

// ── formatting ──────────────────────────────────────────────────────────────

/** Binary size with one decimal. Only ever called on a MEASURED byte count. */
export function fmtBytes(n: number): string {
  const abs = Math.abs(n);
  if (abs >= 1 << 30) return (n / (1 << 30)).toFixed(1) + " GiB";
  if (abs >= 1 << 20) return (n / (1 << 20)).toFixed(1) + " MiB";
  if (abs >= 1 << 10) return (n / (1 << 10)).toFixed(1) + " KiB";
  return n + " B";
}

/** A duration an operator reads at a glance: 2m 14s, 3h 07m, 4d 06h. */
export function fmtDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${String(s % 60).padStart(2, "0")}s`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${String(m % 60).padStart(2, "0")}m`;
  return `${Math.floor(h / 24)}d ${String(h % 24).padStart(2, "0")}h`;
}

/** The achieved recovery point, which the server reports in hours. */
export function fmtHours(h: number): string {
  return fmtDuration(Math.round(h * 3600));
}

/**
 * How long ago an RFC3339 stamp was, relative to `now`.
 * Returns null for an unreadable stamp — the caller then says so, rather than
 * rendering "NaN ago" or silently dropping the field.
 */
export function ageSeconds(iso: string | null | undefined, now: number): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.max(0, Math.round((now - t) / 1000));
}

/** "3h 07m ago", or null when the stamp could not be read. */
export function fmtAgo(iso: string | null | undefined, now: number): string | null {
  const a = ageSeconds(iso, now);
  return a === null ? null : `${fmtDuration(a)} ago`;
}

/** "in 5h 20m", or null when the stamp could not be read. */
export function fmtUntil(iso: string | null | undefined, now: number): string | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  const d = Math.round((t - now) / 1000);
  return d <= 0 ? "now" : `in ${fmtDuration(d)}`;
}

// ── vocabulary ──────────────────────────────────────────────────────────────

/**
 * The operator's name for each protected engine.
 *
 * Rows are named for the DATA they hold, not for the product that stores it —
 * an operator restores "metrics history", not a time-series database. An id we
 * do not know falls back to the platform's own name, so a new engine appears
 * with a real label instead of being dropped.
 */
const ENGINE_LABELS: Record<string, string> = {
  opensearch: "Log & event search",
  system_bundle: "Correlix system bundle",
  clickhouse: "Flows & correlation history",
  postgres: "Application state",
  victoriametrics: "Metrics history",
  secrets_tls: "Secrets & TLS material",
  device_configs: "Device configurations",
};

export function engineLabel(engine: { id: string; name?: string }): string {
  return ENGINE_LABELS[engine.id] ?? (engine.name || engine.id);
}

// ── bytes on disk (measured) ────────────────────────────────────────────────
//
// The same vocabulary rule as above, applied to the six stores the platform can
// weigh: a row is named for the DATA it holds. Four of the six already have a
// name in ENGINE_LABELS and reuse it verbatim — the coverage matrix and the
// footprint table must never call the same data two different things.

/** The scope of a reading that belongs to the installation, not to a tenant. */
export const SCOPE_PLATFORM = "__platform__";
/** Real bytes ingest could not attribute to a tenant. Never folded into one. */
export const SCOPE_UNTAGGED = "untagged";

/** The two stores the coverage matrix has no row for, in the operator's words. */
const STORE_LABELS: Record<string, string> = {
  filestore: "Files kept on the platform host",
  kafka: "Events queued on the bus",
};

/** The operator's name for a weighed store, shared with the coverage matrix. */
export function storeLabel(store: string): string {
  return STORE_LABELS[store] ?? ENGINE_LABELS[store] ?? store;
}

/** Platform, the shared untagged bucket, or the tenant the bytes belong to. */
export function scopeLabel(scope: string): string {
  if (scope === SCOPE_PLATFORM) return "Platform";
  if (scope === SCOPE_UNTAGGED) return "Untagged (shared)";
  return scope.trim() || "Scope not reported";
}

/**
 * The sentence beside a byte count nobody took.
 *
 * The server already writes it in this page's voice ("not measured — <why>"),
 * so it is rendered verbatim; the prefix is only supplied for a reading that
 * arrives without one, and never doubled onto a reading that has it.
 */
export function unmeasuredBytesText(detail: string | null | undefined): string {
  const d = (detail ?? "").trim();
  if (!d) return notMeasuredText(NOT_MEASURED_FALLBACK);
  return /^not measured\b/i.test(d) ? d : notMeasuredText(d);
}

/**
 * Uncompressed ÷ on-disk for one component, or null when the store reports no
 * uncompressed size. NULL, never 1.0 — a ratio of one is the claim "this data
 * does not compress", which is a measurement we did not make.
 */
export function compressionRatio(c: {
  bytes_on_disk: number;
  uncompressed_bytes: number | null | undefined;
}): number | null {
  const u = c.uncompressed_bytes;
  if (u === null || u === undefined) return null;
  if (!(c.bytes_on_disk > 0) || !(u > 0)) return null;
  return u / c.bytes_on_disk;
}

/** A measured ratio on screen: "4.9×". Only ever called on a real ratio. */
export function fmtRatio(r: number): string {
  return `${r.toFixed(1)}×`;
}

/**
 * What the total is allowed to call itself. While any store contributes
 * nothing, the sum is a floor and says so — an operator who reads a partial
 * sum as the footprint will size the disk for it.
 */
export function measuredTotalLabel(unmeasuredStores: readonly string[]): string {
  return unmeasuredStores.length > 0 ? "measured total (lower bound)" : "measured total";
}

/** What each destination class actually protects against. */
export function targetMeaning(kind: CoverageTargetKind): string {
  switch (kind) {
    case "none":
      return "Nowhere. There is no copy of this to restore from.";
    case "local":
      return "Same host as the live data — one disk failure loses both.";
    case "remote":
      return "Copied off this host.";
    case "offsite":
      return "Copied to a separate failure domain.";
  }
}

export type Tone = "good" | "warn" | "bad" | "muted";

/** Coverage verdict → tone. "unknown" is a warning, never a pass. */
export function coverageTone(v: CoverageVerdict): Tone {
  switch (v) {
    case "yes":
      return "good";
    case "no":
      return "bad";
    case "not_applicable":
      return "muted";
    default:
      return "warn";
  }
}

/** Coverage verdict → the word on screen. */
export function coverageLabel(v: CoverageVerdict): string {
  switch (v) {
    case "yes":
      return "Covered";
    case "no":
      return "Not covered";
    case "not_applicable":
      return "Not protected here";
    default:
      return "Coverage unknown";
  }
}

/** An engine the GUI does not govern is shown as external, never as ours. */
export function isExternal(e: EngineCoverage): boolean {
  return e.schedule !== null && !e.schedule.governed_by_gui;
}

// ── the repository's honest state ───────────────────────────────────────────

/**
 * The four states an operator has to tell apart, derived from the two facts the
 * server carries separately (registered, verified) plus whether the list read
 * at all. They are separate because each one has a DIFFERENT first action —
 * collapsing them into "repository problem" is what let the 2026-08-27 window
 * stay open for a week.
 */
export type RepositoryState = "ok" | "unregistered" | "damaged" | "unverified" | "unreachable";

export function repositoryState(repo: SnapshotRepositoryView | null, readFailed: boolean): RepositoryState {
  if (readFailed || !repo) return "unreachable";
  if (!repo.registered) return "unregistered";
  if (repo.verified === false) return "damaged";
  if (repo.verified === null) return "unverified";
  return "ok";
}

/**
 * The state, preferring the more ACTIONABLE fact when two reads disagree.
 *
 * The policy read carries the repository's registration even when the restore-
 * point list read failed, and "it is not registered" is a better first sentence
 * than "it could not be read" — the operator's next action differs.
 */
export function repositoryStateFrom(
  listRepo: SnapshotRepositoryView | null | undefined,
  policyRepo: SnapshotRepositoryView | null | undefined,
  listFailed: boolean,
): RepositoryState {
  const known = listRepo ?? policyRepo ?? null;
  if (known && !known.registered) return "unregistered";
  if (listFailed || !listRepo) return "unreachable";
  return repositoryState(listRepo, false);
}

export type RepositoryAdvice = { headline: string; remedy: string; doc: string; tone: Tone };

/** Where the backup and restore procedure lives in the bundled documentation. */
export const BACKUP_DOC = "/docs/deploy/back-up-and-restore";

/** The remedy for each repository state. Returns null when there is nothing wrong. */
export function repositoryAdvice(state: RepositoryState, detail: string): RepositoryAdvice | null {
  switch (state) {
    case "unregistered":
      return {
        headline: "The snapshot repository is not registered.",
        remedy:
          "Nothing is being snapshotted and there is nothing to restore from. Run the storage " +
          "bootstrap on the host (scripts/opensearch-init) so the repository exists, then take a " +
          "restore point here.",
        doc: BACKUP_DOC, tone: "bad",
      };
    case "unreachable":
      return {
        headline: "The snapshot repository cannot be read.",
        remedy:
          detail ||
          "Existing restore points are neither listable nor restorable right now. Check that the " +
          "search tier is running and that its snapshot volume is still mounted, then read this page again.",
        doc: BACKUP_DOC, tone: "bad",
      };
    case "damaged":
      return {
        headline: "The repository failed verification.",
        remedy:
          "This is the 2026-08-27 state: a repository that still lists restore points but cannot " +
          "produce them. Treat every restore point in it as unproven, take a fresh one to a healthy " +
          "repository, and delete nothing until a verification passes.",
        doc: BACKUP_DOC, tone: "bad",
      };
    case "unverified":
      return {
        headline: "The repository has not been verified on this read.",
        remedy:
          "Registration is not restorability. Run a restore drill to prove the newest restore point " +
          "can actually be restored.",
        doc: BACKUP_DOC, tone: "warn",
      };
    default:
      return null;
  }
}

// ── the overall posture, derived ────────────────────────────────────────────
//
// There is no server-side "posture" field, and inventing one in the API would
// hide the arithmetic. It is derived here, in one place, from facts the server
// does publish — and the reason it returns is the specific condition that
// decided it, never a mood.

export type PostureState = "protected" | "at_risk" | "unprotected" | "unknown";

export type Posture = { state: PostureState; reason: string };

export function postureTone(state: PostureState): Tone {
  switch (state) {
    case "protected":
      return "good";
    case "at_risk":
      return "warn";
    case "unprotected":
      return "bad";
    default:
      return "muted";
  }
}

export function postureLabel(state: PostureState): string {
  switch (state) {
    case "protected":
      return "Protected";
    case "at_risk":
      return "At risk";
    case "unprotected":
      return "Unprotected";
    default:
      return "Posture unknown";
  }
}

/**
 * The headline verdict.
 *
 * Order matters: the WORST true statement wins, and the reason names it. An
 * unreadable coverage table is "unknown", not "protected" — the absence of bad
 * news is not good news.
 */
export function posture(
  coverage: BackupCoverageView | null,
  repoState: RepositoryState,
): Posture {
  if (!coverage) {
    return { state: "unknown", reason: "The coverage table could not be read, so nothing here is a claim about the posture." };
  }
  // The repository's own sentence, not the remedy banner's headline: the two sit
  // one above the other, and repeating the identical string twice reads as a
  // rendering bug rather than as emphasis.
  if (repoState === "unregistered") {
    return { state: "unprotected", reason: "The snapshot repository is not registered, so nothing is being snapshotted." };
  }
  if (repoState === "unreachable") {
    return { state: "unprotected", reason: "The snapshot repository could not be read, so no restore point can be listed or restored right now." };
  }
  if (repoState === "damaged") {
    return { state: "unprotected", reason: "The snapshot repository failed verification, so every restore point in it is unproven." };
  }
  const relevant = coverage.engines.filter((e) => e.covered !== "not_applicable");
  if (relevant.length === 0) {
    return { state: "unknown", reason: "The platform reported no engine it is responsible for protecting." };
  }
  const uncovered = relevant.filter((e) => e.covered === "no");
  if (uncovered.length === relevant.length) {
    return { state: "unprotected", reason: `No engine is covered. ${uncovered[0].covered_reason}` };
  }
  if (uncovered.length > 0) {
    return {
      state: "unprotected",
      reason: `${engineLabel(uncovered[0])} is not covered — ${uncovered[0].covered_reason}`,
    };
  }
  const unknown = relevant.filter((e) => e.covered === "unknown");
  if (unknown.length > 0) {
    return {
      state: "at_risk",
      reason: `${engineLabel(unknown[0])} could not be measured — ${unknown[0].covered_reason}`,
    };
  }
  const neverSucceeded = relevant.filter((e) => !e.last_success_at);
  if (neverSucceeded.length > 0) {
    return {
      state: "at_risk",
      reason: `${engineLabel(neverSucceeded[0])} is scheduled but has never produced a successful copy.`,
    };
  }
  if (repoState === "unverified" || !relevant.some((e) => e.last_verified?.result === "pass")) {
    return {
      state: "at_risk",
      reason: "Every engine has a recent copy, but no restore has been proved. A copy nobody has restored is a copy nobody knows is good.",
    };
  }
  return {
    state: "protected",
    reason: "Every engine has a recent copy and at least one restore has been proved.",
  };
}

/** The newest proven-restorable moment across every engine, or why there is none. */
export function lastProvenRestore(coverage: BackupCoverageView | null): Measured<{ at: string; engine: string }> {
  if (!coverage) return { measured: false, reason: "the coverage table could not be read" };
  let best: { at: string; engine: string } | null = null;
  for (const e of coverage.engines) {
    if (e.last_verified?.result !== "pass") continue;
    if (!best || e.last_verified.at > best.at) best = { at: e.last_verified.at, engine: engineLabel(e) };
  }
  if (!best) return { measured: false, reason: "no restore has ever been proved on this platform" };
  return { measured: true, value: best };
}

// ── recovery-point objective ────────────────────────────────────────────────

export type RpoVerdict =
  | { state: "met" | "missed"; text: string }
  | { state: "achieved_only"; text: string; reason: string }
  | { state: "unmeasured"; reason: string };

/**
 * Achieved against the objective it is held to.
 *
 * TWO numbers can play that role and they are NOT the same claim:
 *   - `rpo_target_hours` is MEASURED from the engine's own schedule ("the cron
 *     runs daily, so 24h"). It is null wherever no schedule is in force.
 *   - `rpo_objective_hours` is DECLARED policy ("24h is acceptable for a data
 *     store; 0 for the custody material"). It exists for every engine.
 *
 * The schedule-derived target wins when it exists, because evidence beats
 * intent; the declared objective is the fallback. Either way the rendered text
 * NAMES which one it judged against — conflating them would tell an operator
 * their backups comply with a number the platform invented for itself, which is
 * the exact dishonesty this page exists to remove. With neither available the
 * answer stays `achieved_only`: show the measured age, name the missing half.
 */
export function rpoVerdict(e: EngineCoverage): RpoVerdict {
  const achieved = measured(e.rpo_hours, e.rpo_detail);
  if (!achieved.measured) return { state: "unmeasured", reason: achieved.reason };
  const scheduled = measured(e.rpo_target_hours, "no schedule-derived recovery-point target is published for this engine");
  const declared = measured(
    e.rpo_objective_hours,
    e.rpo_objective_detail || "no recovery-point objective is declared for this engine",
  );
  if (!scheduled.measured && !declared.measured) {
    // Neither number exists. Name the missing DECLARED objective: an engine
    // with no schedule is the common case, and "nobody decided what good looks
    // like here" is the more actionable half of the answer.
    return {
      state: "achieved_only",
      text: `last good copy ${fmtHours(achieved.value)} old`,
      reason: declared.reason,
    };
  }
  const objective = scheduled.measured
    ? { value: scheduled.value, label: "scheduled" }
    : { value: (declared as { measured: true; value: number }).value, label: "declared" };
  const met = achieved.value <= objective.value;
  return {
    state: met ? "met" : "missed",
    text: `${fmtHours(achieved.value)} against a ${fmtHours(objective.value)} ${objective.label} objective`,
  };
}

// ── restore points ──────────────────────────────────────────────────────────

/** State word → tone. An in-progress copy is not yet a restore point. */
export function snapshotTone(state: string): Tone {
  switch ((state || "").toUpperCase()) {
    case "SUCCESS":
      return "good";
    case "IN_PROGRESS":
      return "muted";
    case "PARTIAL":
      return "warn";
    case "FAILED":
    case "INCOMPATIBLE":
      return "bad";
    default:
      return "muted";
  }
}

/** Sentence-cased state for the screen ("In progress", not "IN_PROGRESS"). */
export function snapshotStateLabel(state: string): string {
  const s = (state || "").toUpperCase();
  if (!s) return "State not reported";
  const words = s.toLowerCase().split("_");
  return words[0].charAt(0).toUpperCase() + words[0].slice(1) + (words.length > 1 ? " " + words.slice(1).join(" ") : "");
}

/** Only a completed copy can be restored from. */
export function isRestorable(p: SnapshotView): boolean {
  const s = (p.state || "").toUpperCase();
  return s === "SUCCESS" || s === "PARTIAL";
}

/**
 * The restorability verdict, which has THREE outcomes, not two. `null` is
 * "never probed" — a measurement, and a bad one — not "not measured".
 */
export type RestorableVerdict =
  | { state: "verified" | "failed"; at: string; detail: string }
  | { state: "never"; detail: string };

export function restorableVerdict(p: SnapshotView): RestorableVerdict {
  if (p.restorable_verified === null || p.restorable_verified === undefined) {
    return { state: "never", detail: p.restorable_detail || "no restorability probe has ever run on this restore point" };
  }
  return {
    state: p.restorable_verified ? "verified" : "failed",
    at: p.restorable_verified_at ?? "",
    detail: p.restorable_detail,
  };
}

/** The one-line shard summary, or null when there is nothing to report. */
export function shardSummary(p: SnapshotView): string | null {
  const sh = p.shards;
  if (!sh || sh.total === 0) return null;
  if (sh.failed === 0) return null;
  return `${sh.failed} of ${sh.total} shards failed`;
}

// ── restore wizard ──────────────────────────────────────────────────────────

/** The namespace a renamed restore lands in (mirrors defaultRestorePrefix). */
export const DEFAULT_RESTORE_PREFIX = "restored-";

/** Index names may not start with these; the same set the engine refuses. */
const BAD_PREFIX_CHARS = /[\s\\/*?"<>|,#:]/;

/** The name a renamed restore produces, or null when the prefix is unusable. */
export function restorePreview(index: string, prefix: string): string | null {
  const p = prefix.trim();
  if (!p) return null;                       // an empty prefix is an overwrite
  if (BAD_PREFIX_CHARS.test(p)) return null; // the engine would refuse it
  if (p.startsWith("_") || p.startsWith("-") || p.startsWith("+")) return null;
  return p + index;
}

/** True when the prefix is valid for every index in the selection. */
export function prefixUsable(indices: readonly string[], prefix: string): boolean {
  return indices.length > 0 && indices.every((n) => restorePreview(n, prefix) !== null);
}

/** Type-to-confirm: an exact, case-sensitive match after trimming whitespace. */
export function confirmMatches(typed: string, expected: string): boolean {
  return typed.trim() === expected.trim() && expected.trim() !== "";
}

// ── operations feed ─────────────────────────────────────────────────────────

export function operationTone(state: string): Tone {
  switch (state) {
    case "succeeded":
      return "good";
    case "failed":
      return "bad";
    default:
      return "warn";
  }
}

/** The operator's phrase for each operation kind. */
export function operationLabel(kind: string): string {
  switch (kind) {
    case "snapshot_create":
      return "Take restore point";
    case "snapshot_delete":
      return "Delete restore point";
    case "snapshot_restore":
      return "Restore";
    case "snapshot_verify":
      return "Restore drill";
    default:
      return kind;
  }
}

/** A drill is a verification; the drill history is that slice of the feed. */
export function isDrill(kind: string): boolean {
  return kind === "snapshot_verify";
}

/**
 * The drill's evidence in one sentence. Counts, not a claim: "the restore
 * returned 200" is not proof, matching document counts against the live source is.
 */
export function verifyEvidence(op: { verify?: { source_docs: number; restored_docs: number; match: boolean; index: string } }): string | null {
  const v = op.verify;
  if (!v) return null;
  return v.match
    ? `${v.restored_docs} of ${v.source_docs} documents matched on ${v.index}`
    : `${v.restored_docs} documents restored against ${v.source_docs} in ${v.index} — they do not match`;
}

// ── coverage matrix ordering ────────────────────────────────────────────────

/**
 * Sort order: real gaps first, then unknowns, then never-succeeded, then
 * healthy, then the rows that are deliberately not protected here. An operator
 * opening this page during an incident reads the top of the table.
 */
export function coverageRank(e: EngineCoverage): number {
  if (e.covered === "not_applicable") return 4;
  if (e.covered === "no") return 0;
  if (e.covered === "unknown") return 1;
  if (!e.last_success_at) return 2;
  return 3;
}

export function sortedEngines(engines: readonly EngineCoverage[]): EngineCoverage[] {
  return [...engines].sort((a, b) => coverageRank(a) - coverageRank(b) || engineLabel(a).localeCompare(engineLabel(b)));
}
