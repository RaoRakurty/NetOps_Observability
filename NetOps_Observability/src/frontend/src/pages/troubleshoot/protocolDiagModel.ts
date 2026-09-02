// protocolDiagModel — the pure half of the Protocol diagnostics panel
// (Troubleshooting, item 7; backend internal/protocoldiag + the three
// /api/troubleshoot/protocol-diagnostics/* endpoints).
//
// Everything here is a pure function or a copy constant: request builders that
// emit the EXACT wire shape the server accepts, the one place a caught error
// becomes operator-facing copy, and the download name for the redacted TAC
// bundle. The component keeps no formatting or classification logic of its own,
// so both are testable without a DOM.
//
// SAFETY. The server rejects unknown JSON fields (DisallowUnknownFields) and
// bounds the analyze body (2 MiB, <=64 outputs, <=256 KiB each). The builders
// below mirror those bounds CLIENT-side so an oversized paste is refused with a
// readable reason instead of a 400 from the wire — the server still re-checks,
// because the client is never the authority.

import type {
  ProtocolDiagAnalyzeRequest,
  ProtocolDiagCollectRequest,
  ProtocolDiagIssue,
} from "../../services/api";

// ── the three tabs ──────────────────────────────────────────────────────────

/** Protocol tab ids, in the order the backend lists them. */
export const PROTOCOL_TABS: ReadonlyArray<{ id: string; label: string }> = [
  { id: "bgp", label: "BGP" },
  { id: "ospf", label: "OSPF" },
  { id: "isis", label: "IS-IS" },
];

/**
 * The device families the curated command bundles are bound for. The catalog
 * endpoint renders ONE dialect per response (?vendor=) and does not enumerate
 * the bound set, so the covered list is stated here to keep the operator's
 * "vendors covered" answer honest. Keep in sync with protocoldiag.Vendor.
 */
export const VENDORS_COVERED: ReadonlyArray<string> = ["Cisco IOS-XE", "Juniper Junos", "Nokia SR OS"];

// ── bounds (mirrors the server's own caps) ──────────────────────────────────

export const MAX_OUTPUTS = 64;
export const MAX_OUTPUT_CHARS = 256 * 1024;
export const MAX_TARGET_CHARS = 256;

// ── error classification + copy ─────────────────────────────────────────────

/**
 * What went wrong, in product terms:
 *  · "unwired"   — 503: this deployment has no command runner, so there is
 *                  nothing to collect WITH. Paste the output instead.
 *  · "missing"   — 404: the device is not visible to you (another tenant's, or
 *                  gone). The server never reveals which.
 *  · "forbidden" — 403: the caller lacks infrastructure write.
 *  · "rejected"  — 400: the server refused the request; show its own reason.
 */
export type ProtocolDiagFailure = "unwired" | "missing" | "forbidden" | "rejected" | "other";

export function classifyProtocolDiagError(e: unknown): ProtocolDiagFailure {
  const m = String((e as Error | undefined)?.message ?? e ?? "");
  if (/^503\b/.test(m)) return "unwired";
  if (/^404\b/.test(m)) return "missing";
  if (/^403\b/.test(m)) return "forbidden";
  if (/^400\b/.test(m)) return "rejected";
  return "other";
}

export const COLLECTOR_UNWIRED_MESSAGE =
  "Collection is not wired on this deployment yet — paste the command output below and analyze that instead.";
export const DEVICE_NOT_VISIBLE_MESSAGE =
  "That device is not visible to you — pick one from your own inventory.";
export const NO_PERMISSION_MESSAGE =
  "You do not have permission to do that — collecting from a device needs infrastructure write access.";
export const NOTHING_TO_ANALYZE_MESSAGE =
  "There is no output to analyze yet — collect it from the device, or paste at least one command's output.";
export const NO_ANALYSIS_FOR_TAC_MESSAGE =
  "Analyze the output first — the TAC bundle is built from the redacted capture plus the analysis.";

/** The server's own reason, when it sent one, from `"<code> <text>: <body>"`. */
export function serverReason(e: unknown): string | null {
  const m = String((e as Error | undefined)?.message ?? e ?? "");
  const i = m.indexOf(": ");
  if (i < 0) return null;
  const body = m.slice(i + 2).trim();
  if (body === "") return null;
  try {
    const parsed: unknown = JSON.parse(body);
    const err = (parsed as { error?: unknown } | null)?.error;
    if (typeof err === "string" && err.trim() !== "") return err.trim();
  } catch {
    /* not JSON — fall through to the raw body */
  }
  return body;
}

/** The one place a caught error becomes operator-facing copy. */
export function protocolDiagErrorMessage(e: unknown): string {
  switch (classifyProtocolDiagError(e)) {
    case "unwired": return COLLECTOR_UNWIRED_MESSAGE;
    case "missing": return DEVICE_NOT_VISIBLE_MESSAGE;
    case "forbidden": return NO_PERMISSION_MESSAGE;
    case "rejected": return serverReason(e) ?? "The server refused the request.";
    default: return serverReason(e) ?? String((e as Error | undefined)?.message ?? e ?? "The request failed.");
  }
}

// ── request builders ────────────────────────────────────────────────────────

/** The free-form platform string the server derives the command dialect from. */
export function platformOf(d: { vendor?: string; os?: string; model?: string } | null | undefined): string {
  return [d?.vendor, d?.os, d?.model].map((s) => String(s ?? "").trim()).filter(Boolean).join(" ");
}

function clamp(s: string, n: number): string {
  const v = String(s ?? "");
  return v.length <= n ? v : v.slice(0, n);
}

export type BuildResult<T> = { ok: true; request: T } | { ok: false; reason: string };

/**
 * Builds the collect body. Target fields are optional and clamped to the
 * server's own per-field cap; the object always carries all four keys because
 * the server rejects unknown fields but accepts empty ones (an empty field
 * renders the command in its unscoped form).
 */
export function buildCollectRequest(
  deviceId: string,
  issueId: string,
  target: { interface?: string; peer?: string; prefix?: string; vrf?: string } = {},
): BuildResult<ProtocolDiagCollectRequest> {
  const dev = String(deviceId ?? "").trim();
  const issue = String(issueId ?? "").trim();
  if (dev === "") return { ok: false, reason: "Pick a device first." };
  if (issue === "") return { ok: false, reason: "Pick the issue you are chasing first." };
  return {
    ok: true,
    request: {
      device_id: dev,
      issue_id: issue,
      target: {
        interface: clamp(String(target.interface ?? "").trim(), MAX_TARGET_CHARS),
        peer: clamp(String(target.peer ?? "").trim(), MAX_TARGET_CHARS),
        prefix: clamp(String(target.prefix ?? "").trim(), MAX_TARGET_CHARS),
        vrf: clamp(String(target.vrf ?? "").trim(), MAX_TARGET_CHARS),
      },
    },
  };
}

/**
 * Builds the analyze body from whatever output the operator has — collected,
 * pasted, or a mix. Commands with no output are DROPPED (an absent capture is
 * absent evidence, never an empty string that could read as "nothing wrong"),
 * spec ids are filtered against the issue's own bundle, and both server caps
 * are enforced here first.
 */
export function buildAnalyzeRequest(
  issue: ProtocolDiagIssue | null | undefined,
  device: { hostname?: string; platform?: string } | null | undefined,
  outputs: Record<string, string>,
): BuildResult<ProtocolDiagAnalyzeRequest> {
  if (!issue) return { ok: false, reason: "Pick the issue you are chasing first." };
  const known = new Set(issue.commands.map((c) => c.spec_id));
  const rows: { spec_id: string; output: string }[] = [];
  for (const c of issue.commands) {
    if (!known.has(c.spec_id)) continue;
    const out = String(outputs[c.spec_id] ?? "");
    if (out.trim() === "") continue;
    if (out.length > MAX_OUTPUT_CHARS) {
      return { ok: false, reason: `The output for \`${c.command}\` is larger than the ${Math.round(MAX_OUTPUT_CHARS / 1024)} KB the server accepts — trim it and try again.` };
    }
    rows.push({ spec_id: c.spec_id, output: out });
  }
  if (rows.length === 0) return { ok: false, reason: NOTHING_TO_ANALYZE_MESSAGE };
  if (rows.length > MAX_OUTPUTS) return { ok: false, reason: `At most ${MAX_OUTPUTS} command outputs can be analyzed at once.` };
  return {
    ok: true,
    request: {
      protocol: issue.protocol,
      issue_id: issue.id,
      device: {
        hostname: clamp(String(device?.hostname ?? "").trim(), MAX_TARGET_CHARS),
        platform: clamp(String(device?.platform ?? "").trim(), MAX_TARGET_CHARS),
      },
      outputs: rows,
    },
  };
}

// ── presentation helpers ────────────────────────────────────────────────────

/** A safe download name: every character outside [A-Za-z0-9._-] collapses to
 *  `_`, so an id or hostname from the wire can never steer a path. */
export function tacFileName(issueId: string, hostname: string): string {
  const safe = (s: string) => String(s ?? "").replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 64).replace(/^_+|_+$/g, "");
  const host = safe(hostname) || "device";
  const issue = safe(issueId) || "issue";
  return `tac-bundle-${host}-${issue}.txt`;
}

/** Confidence → a theme tone class. Honest: low is a triage hint, not a verdict. */
export function confidenceTone(c: string): "good" | "warn" | "muted" {
  switch (String(c ?? "").toLowerCase()) {
    case "high": return "good";
    case "medium": return "warn";
    default: return "muted";
  }
}

export function confidenceLabel(c: string): string {
  const v = String(c ?? "").trim();
  if (v === "") return "unrated";
  return v.toLowerCase();
}

/** Human label for a protocol id, falling back to the raw id upper-cased. */
export function protocolLabel(id: string): string {
  return PROTOCOL_TABS.find((t) => t.id === id)?.label ?? String(id ?? "").toUpperCase();
}
