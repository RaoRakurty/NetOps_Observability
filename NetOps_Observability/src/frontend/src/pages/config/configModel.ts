// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// configModel.ts — the PURE adapters behind the configuration-backup surfaces
// (the device Configuration panel and the fleet Config drift list).
//
// Every judgement an operator reads about a device configuration is computed
// here, never inline in a component, so the honesty rules live in ONE place:
//
//  · "unknown" is a real answer. A device that was never captured, or that has
//    no golden baseline to compare against, is UNKNOWN — never silently
//    "in sync". An absence of assessment is never rendered as a clean result.
//  · A failed capture is not a passing state: it colours as a failure and
//    carries the reason the backend gave.
//  · Nothing here trusts the payload. The transport is an external boundary
//    (§3 zero trust), so every field is coerced and any unrecognised drift or
//    state value collapses to "unknown" rather than being displayed verbatim.
//  · Config TEXT is device-authored and untrusted. These helpers only ever
//    return DATA — line records tagged with a kind. Rendering is escaped React
//    text; nothing here produces markup and no consumer may use an HTML sink.

import type { ConfigDrift, ConfigStatus } from "../../services/api";

export type Tone = "" | "good" | "warn" | "bad";

// ── drift vocabulary ────────────────────────────────────────────────────────

const DRIFT_VALUES: readonly string[] = ["in_sync", "changed", "drifted", "unknown"];

/** Coerce an untrusted wire value to one of the four drift verdicts. */
export function driftOf(v: unknown): ConfigDrift {
  const s = String(v ?? "");
  return DRIFT_VALUES.includes(s) ? (s as ConfigDrift) : "unknown";
}

export const DRIFT_LABEL: Record<ConfigDrift, string> = {
  in_sync: "In sync",
  changed: "Changed",
  drifted: "Drifted",
  unknown: "Unknown",
};

export function driftTone(d: ConfigDrift): Tone {
  switch (d) {
    case "in_sync": return "good";
    case "changed": return "warn";
    case "drifted": return "bad";
    default: return "";
  }
}

export const DRIFT_HELP: Record<ConfigDrift, string> = {
  in_sync: "This capture matches the golden baseline exactly.",
  changed: "This capture differs from the capture before it.",
  drifted: "This capture differs from the golden baseline.",
  unknown:
    "Not assessed — nothing has been captured, or no golden baseline is set. " +
    "That is an absence of assessment, not a clean result.",
};

export const NEVER_CAPTURED_HELP =
  "No configuration has been captured from this device yet, so drift cannot be assessed.";

export type Badge = { label: string; tone: Tone; help: string };

/**
 * The device-level state badge. Four honest states plus the two edges that
 * must never be dressed up as a pass: never captured, and capture failed.
 */
export function statusBadge(s: ConfigStatus | null | undefined): Badge {
  if (!s || !s.last_capture_at) {
    return { label: "Never captured", tone: "", help: NEVER_CAPTURED_HELP };
  }
  if (String(s.state) === "failed") {
    return {
      label: "Capture failed",
      tone: "bad",
      help: s.last_error || "The last capture attempt failed, so the state below is stale.",
    };
  }
  const d = driftOf(s.state);
  return { label: DRIFT_LABEL[d], tone: driftTone(d), help: DRIFT_HELP[d] };
}

/** Filter chips for the fleet drift list. "" = no state filter (all rows). */
export const DRIFT_FILTERS: ReadonlyArray<{ value: string; label: string }> = [
  { value: "", label: "All" },
  { value: "in_sync", label: "In sync" },
  { value: "changed", label: "Changed" },
  { value: "drifted", label: "Drifted" },
  { value: "unknown", label: "Unknown" },
];

// ── formatting ──────────────────────────────────────────────────────────────

/** Short, copy-safe version id. The full sha stays available as a title/tooltip. */
export function shortSha(sha: string | null | undefined, n = 12): string {
  const s = String(sha ?? "");
  return s.length > n ? s.slice(0, n) : s;
}

export function fmtBytes(n: number | undefined): string {
  const v = Number(n);
  if (!Number.isFinite(v) || v < 0) return "—";
  if (v < 1024) return `${v} B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`;
  return `${(v / (1024 * 1024)).toFixed(1)} MB`;
}

/** "+12 / −3", or an em dash when the backend reported no counts. */
export function fmtChurn(added?: number, removed?: number): string {
  const a = Number.isFinite(Number(added)) ? Number(added) : null;
  const r = Number.isFinite(Number(removed)) ? Number(removed) : null;
  if (a === null && r === null) return "—";
  return `+${a ?? 0} / −${r ?? 0}`;
}

// ── unified diff → renderable line records ──────────────────────────────────

export type DiffLineKind = "add" | "del" | "meta" | "hunk" | "ctx";
export type DiffLine = { kind: DiffLineKind; text: string };

/**
 * Split a unified diff into tagged lines so the renderer can colour +/- WITHOUT
 * parsing markup. The returned `text` is the raw line; the caller renders it as
 * an escaped text node. No HTML is produced here, by construction.
 */
export function diffLines(unified: string | null | undefined): DiffLine[] {
  const body = String(unified ?? "").replace(/\r\n?/g, "\n");
  if (body === "") return [];
  const raw = body.split("\n");
  if (raw.length > 0 && raw[raw.length - 1] === "") raw.pop();
  return raw.map((text): DiffLine => {
    if (text.startsWith("+++") || text.startsWith("---") || text.startsWith("diff ")) {
      return { kind: "meta", text };
    }
    if (text.startsWith("@@")) return { kind: "hunk", text };
    if (text.startsWith("+")) return { kind: "add", text };
    if (text.startsWith("-")) return { kind: "del", text };
    return { kind: "ctx", text };
  });
}

// ── failure classification ──────────────────────────────────────────────────

// The API client throws `Error("<status> <statusText>: <body>")`. These are the
// only four failures the configuration surfaces treat as PRODUCT states rather
// than as errors.
export type ApiFailure = "off" | "forbidden" | "busy" | "other";

export function classifyError(e: unknown): ApiFailure {
  const m = String((e as Error | undefined)?.message ?? e ?? "");
  // 404 (route absent) and 501 (not implemented) both mean the same thing to an
  // operator: the deployment does not run config backup.
  if (/^404\b/.test(m) || /^501\b/.test(m)) return "off";
  if (/^403\b/.test(m)) return "forbidden";
  if (/^429\b/.test(m)) return "busy";
  return "other";
}

export const FEATURE_OFF_MESSAGE = "Config backup is not enabled on this deployment";
export const FEATURE_OFF_HINT =
  "Turn on FEATURE_CONFIG_BACKUP to capture device configurations, compare them against a " +
  "golden baseline and track drift across the fleet.";
export const NO_PERMISSION_MESSAGE =
  "You do not have permission to do that — this action needs infrastructure write access.";
export const BACKUP_BUSY_MESSAGE = "A backup is already running for this device.";

/** The one place a caught error becomes operator-facing copy for an action. */
export function actionErrorMessage(e: unknown): string {
  switch (classifyError(e)) {
    case "off": return `${FEATURE_OFF_MESSAGE}.`;
    case "forbidden": return NO_PERMISSION_MESSAGE;
    case "busy": return BACKUP_BUSY_MESSAGE;
    default: return String((e as Error | undefined)?.message ?? e ?? "The request failed.");
  }
}
