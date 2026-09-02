// pcapModel.ts — the PURE adapters and guardrails behind the device
// "Packet capture" panel.
//
// A packet capture is the one operator action on this platform that points a
// packet engine at live traffic on a production device. Every judgement about
// whether a request is even allowed to leave the browser is computed here, in
// one place, so the safety rules are testable without a DOM:
//
//  · BOUNDED BY CONSTRUCTION. Duration is 1-60 s and the packet cap is
//    1-10 000. These mirror the backend's own guardrails; the client refuses
//    first so the operator gets an inline reason instead of a bare 400, but the
//    SERVER remains the authority (§3 — never trust the client) and its 400 is
//    rendered verbatim when it disagrees.
//  · THE FILTER IS HOSTILE INPUT. It is operator-authored text that reaches a
//    packet-filter compiler. It is validated against a closed grammar —
//    host / net / port / portrange / proto primitives, src|dst qualifiers,
//    and|or|not logic, protocol keywords — and shell metacharacters are
//    refused outright with the offending character named. Nothing here escapes
//    or "cleans" a filter: an invalid filter is REFUSED, never rewritten.
//  · NOTHING HERE PRODUCES MARKUP. Capture metadata (interface, filter, error)
//    is device- and operator-authored; these helpers return DATA only and every
//    consumer renders it as an escaped React text node.

import type { PcapCapture, PcapStartRequest, PcapStatus } from "../../services/api";
import { classifyError, fmtBytes } from "../config/configModel";
import type { Tone } from "../config/configModel";

export { fmtBytes };

// ── the guardrails (mirror the backend contract exactly) ────────────────────

export const MIN_DURATION_S = 1;
export const MAX_DURATION_S = 60;
export const DEFAULT_DURATION_S = 15;
export const MIN_PACKETS = 1;
export const MAX_PACKETS = 10000;
export const DEFAULT_PACKETS = 1000;
export const MAX_FILTER_LEN = 256;
export const MAX_INTERFACE_LEN = 64;

// ── status vocabulary ───────────────────────────────────────────────────────

const STATUS_VALUES: readonly string[] = ["running", "done", "failed", "expired"];

/** Coerce an untrusted wire value to one of the four lifecycle states. An
 *  unrecognised value collapses to "failed" — an unknown state is NEVER
 *  optimistically shown as a finished, downloadable capture. */
export function pcapStatusOf(v: unknown): PcapStatus {
  const s = String(v ?? "");
  return STATUS_VALUES.includes(s) ? (s as PcapStatus) : "failed";
}

export const STATUS_LABEL: Record<PcapStatus, string> = {
  running: "Running",
  done: "Done",
  failed: "Failed",
  expired: "Expired",
};

export function statusTone(s: PcapStatus): Tone {
  switch (s) {
    case "done": return "good";
    case "running": return "warn";
    case "failed": return "bad";
    default: return "";
  }
}

export const STATUS_HELP: Record<PcapStatus, string> = {
  running: "The capture is still collecting on the device.",
  done: "The capture finished and the file is available to download.",
  failed: "The capture did not complete — the reason is shown on the row.",
  expired:
    "The retention window closed and the file was deleted. The counts below are what " +
    "the capture recorded; the packets themselves are gone.",
};

/** A capture in a terminal state is never polled again. */
export function isTerminal(s: PcapStatus): boolean {
  return s !== "running";
}

/** Only a finished capture that still holds bytes can be downloaded. */
export function canDownload(c: Pick<PcapCapture, "status" | "bytes">): boolean {
  return pcapStatusOf(c.status) === "done" && Number(c.bytes) > 0;
}

// ── BPF filter grammar ──────────────────────────────────────────────────────

/**
 * Characters that must never reach a filter compiler or a command line.
 * Named individually in the refusal so the operator can see WHICH one.
 */
const METACHAR_RE = /[;&|`$<>\\'"(){}[\]*?!~#@,%^=+]/;

/** Control characters — a newline included — never belong in a one-line filter. */
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f]/;

/** Everything the grammar can legally contain outside those metacharacters. */
const ALLOWED_CHAR_RE = /^[A-Za-z0-9 ._:/-]*$/;

const LOGIC = new Set(["and", "or"]);
const DIRECTIONS = new Set(["src", "dst"]);
const PROTOCOLS = new Set(["ip", "ip6", "tcp", "udp", "icmp", "icmp6", "arp", "rarp", "sctp", "vlan"]);
const PRIMITIVES = new Set(["host", "net", "port", "portrange", "proto"]);

const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const IPV6_RE = /^[0-9A-Fa-f:]+$/;
const HOSTNAME_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$/;

function isIPv4(s: string): boolean {
  return IPV4_RE.test(s) && s.split(".").every((o) => Number(o) <= 255);
}

function isIPv6(s: string): boolean {
  return s.includes(":") && IPV6_RE.test(s);
}

/**
 * host <value> — an address or a resolvable name. A name whose LAST label is
 * all digits is refused: no real TLD is numeric, so "300.1.1.1" is a mistyped
 * address, not a hostname, and accepting it would let a typo silently capture
 * nothing at all.
 */
function isHostValue(s: string): boolean {
  if (isIPv4(s) || isIPv6(s)) return true;
  if (!HOSTNAME_RE.test(s)) return false;
  const last = s.slice(s.lastIndexOf(".") + 1);
  return !/^\d+$/.test(last);
}

/** net <value> — an address with an optional prefix length. */
function isNetValue(s: string): boolean {
  const slash = s.indexOf("/");
  if (slash < 0) return isIPv4(s) || isIPv6(s);
  const addr = s.slice(0, slash);
  const bits = s.slice(slash + 1);
  if (!/^\d{1,3}$/.test(bits)) return false;
  const n = Number(bits);
  if (isIPv4(addr)) return n <= 32;
  if (isIPv6(addr)) return n <= 128;
  return false;
}

function isPortNumber(s: string): boolean {
  return /^\d{1,5}$/.test(s) && Number(s) <= 65535;
}

/** portrange <a>-<b>, and a bare port for convenience. */
function isPortRangeValue(s: string): boolean {
  const dash = s.indexOf("-");
  if (dash < 0) return isPortNumber(s);
  const lo = s.slice(0, dash);
  const hi = s.slice(dash + 1);
  return isPortNumber(lo) && isPortNumber(hi) && Number(lo) <= Number(hi);
}

/** proto <value> — a known protocol keyword or an IP protocol number. */
function isProtoValue(s: string): boolean {
  if (PROTOCOLS.has(s)) return true;
  return /^\d{1,3}$/.test(s) && Number(s) <= 255;
}

export type FilterCheck = { ok: true } | { ok: false; reason: string };

export const FILTER_GRAMMAR_HINT =
  "Filters accept host, net, port, portrange and proto tokens with src/dst qualifiers " +
  "and and/or/not — for example: host 10.0.0.1 and port 179";

/**
 * Validate an operator-typed BPF filter against the closed grammar the backend
 * enforces. An empty filter is VALID and means "capture everything on the
 * interface". A refusal always says why, in the operator's own words.
 */
export function validateFilter(raw: string): FilterCheck {
  const s = String(raw ?? "").trim();
  if (s === "") return { ok: true };
  if (s.length > MAX_FILTER_LEN) {
    return { ok: false, reason: `The filter is longer than ${MAX_FILTER_LEN} characters.` };
  }
  if (CONTROL_RE.test(s)) {
    return {
      ok: false,
      reason:
        "Shell metacharacters are not allowed in a capture filter — remove the control character. " +
        FILTER_GRAMMAR_HINT,
    };
  }
  const meta = METACHAR_RE.exec(s);
  if (meta) {
    return {
      ok: false,
      reason:
        `Shell metacharacters are not allowed in a capture filter — remove "${meta[0]}". ` +
        FILTER_GRAMMAR_HINT,
    };
  }
  if (!ALLOWED_CHAR_RE.test(s)) {
    return { ok: false, reason: `The filter contains a character the grammar does not allow. ${FILTER_GRAMMAR_HINT}` };
  }

  const tok = s.split(/\s+/).filter((t) => t !== "");
  let i = 0;
  const bad = (reason: string): FilterCheck => ({ ok: false, reason });

  const parseTerm = (): FilterCheck => {
    while (i < tok.length && tok[i].toLowerCase() === "not") i++;
    if (i < tok.length && DIRECTIONS.has(tok[i].toLowerCase())) i++;
    let sawProtocol = false;
    if (i < tok.length && PROTOCOLS.has(tok[i].toLowerCase())) {
      sawProtocol = true;
      i++;
      if (i >= tok.length || LOGIC.has(tok[i].toLowerCase())) return { ok: true };
      if (DIRECTIONS.has(tok[i].toLowerCase())) i++;
    }
    if (i >= tok.length) {
      return sawProtocol ? { ok: true } : bad(`The filter ends after "${tok[tok.length - 1]}" — it is incomplete.`);
    }
    const kw = tok[i].toLowerCase();
    if (!PRIMITIVES.has(kw)) {
      return bad(`"${tok[i]}" is not a filter token this deployment accepts. ${FILTER_GRAMMAR_HINT}`);
    }
    i++;
    if (i >= tok.length) return bad(`"${kw}" needs a value after it.`);
    const val = tok[i];
    i++;
    const okValue =
      kw === "host" ? isHostValue(val)
        : kw === "net" ? isNetValue(val)
          : kw === "port" ? isPortNumber(val)
            : kw === "portrange" ? isPortRangeValue(val)
              : isProtoValue(val);
    if (!okValue) return bad(`"${val}" is not a valid value for "${kw}".`);
    return { ok: true };
  };

  for (;;) {
    const t = parseTerm();
    if (!t.ok) return t;
    if (i >= tok.length) return { ok: true };
    const next = tok[i].toLowerCase();
    if (!LOGIC.has(next)) {
      return bad(`Expected "and" or "or" before "${tok[i]}". ${FILTER_GRAMMAR_HINT}`);
    }
    i++;
    if (i >= tok.length) return bad(`The filter ends with "${next}" — it is incomplete.`);
  }
}

// ── the whole request ───────────────────────────────────────────────────────

const INTERFACE_RE = /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/;

export type CaptureField = "interface" | "duration_s" | "max_packets" | "filter";
export type FieldErrors = Partial<Record<CaptureField, string>>;

export type CaptureForm = {
  interface: string;
  duration_s: number | string;
  max_packets: number | string;
  filter: string;
};

export type CaptureCheck =
  | { ok: true; request: PcapStartRequest }
  | { ok: false; errors: FieldErrors };

export const DURATION_MESSAGE =
  `A capture may run for ${MIN_DURATION_S}-${MAX_DURATION_S} seconds. Longer captures are refused.`;
export const PACKETS_MESSAGE =
  `A capture may collect ${MIN_PACKETS}-${MAX_PACKETS.toLocaleString("en-US")} packets. Larger captures are refused.`;
export const INTERFACE_MESSAGE =
  "Choose the interface to capture on, exactly as the device names it.";
export const INTERFACE_CHARS_MESSAGE =
  "That is not a valid interface name — letters, digits and . _ : / - only.";

function whole(v: number | string): number | null {
  const s = String(v ?? "").trim();
  if (s === "" || !/^-?\d+$/.test(s)) return null;
  const n = Number(s);
  return Number.isSafeInteger(n) ? n : null;
}

/**
 * The single gate every "Start capture" click passes through. Returns either
 * the exact body to POST — with `filter` omitted when empty, matching the
 * optional field in the contract — or the per-field reasons to render inline.
 */
export function validateCapture(form: CaptureForm): CaptureCheck {
  const errors: FieldErrors = {};

  const iface = String(form.interface ?? "").trim();
  if (iface === "") errors.interface = INTERFACE_MESSAGE;
  else if (iface.length > MAX_INTERFACE_LEN) {
    errors.interface = `An interface name may not exceed ${MAX_INTERFACE_LEN} characters.`;
  } else if (!INTERFACE_RE.test(iface)) errors.interface = INTERFACE_CHARS_MESSAGE;

  const dur = whole(form.duration_s);
  if (dur === null || dur < MIN_DURATION_S || dur > MAX_DURATION_S) errors.duration_s = DURATION_MESSAGE;

  const pkts = whole(form.max_packets);
  if (pkts === null || pkts < MIN_PACKETS || pkts > MAX_PACKETS) errors.max_packets = PACKETS_MESSAGE;

  const filter = String(form.filter ?? "").trim();
  const f = validateFilter(filter);
  if (!f.ok) errors.filter = f.reason;

  if (Object.keys(errors).length > 0) return { ok: false, errors };

  const request: PcapStartRequest = {
    interface: iface,
    duration_s: dur as number,
    max_packets: pkts as number,
  };
  if (filter !== "") request.filter = filter;
  return { ok: true, request };
}

// ── formatting ──────────────────────────────────────────────────────────────

export function fmtPackets(n: number | undefined): string {
  const v = Number(n);
  if (!Number.isFinite(v) || v < 0) return "—";
  return Math.round(v).toLocaleString("en-US");
}

/** The filter a capture ran with, in words. "" is a real answer, not a gap. */
export function fmtFilter(f: string | undefined): string {
  const s = String(f ?? "").trim();
  return s === "" ? "no filter (all traffic)" : s;
}

// ── failure classification ──────────────────────────────────────────────────

export const FEATURE_OFF_MESSAGE = "Packet capture is not enabled on this deployment";
export const FEATURE_OFF_HINT =
  "Turn on FEATURE_PACKET_CAPTURE to run bounded, on-demand packet captures against a " +
  "device interface and download the resulting .pcap.";
export const NO_PERMISSION_MESSAGE =
  "You do not have permission to do that — this action needs infrastructure write access.";
export const RUNNING_MESSAGE =
  "A capture is already running on this device. Wait for it to finish, or delete it, before starting another.";
export const DOWNLOAD_BLOCKED_HINT =
  "If nothing arrived, this browser blocked the download — the file is still on the server.";

/**
 * The server's own reason, pulled out of the `"<status> <text>: <body>"` Error
 * the API client throws. Returned as PLAIN TEXT for an escaped React node; a
 * body that is not the contracted `{error}` object yields null rather than a
 * guess.
 */
export function serverReason(e: unknown): string | null {
  const m = String((e as Error | undefined)?.message ?? e ?? "");
  const at = m.indexOf("{");
  if (at < 0) return null;
  try {
    const body: unknown = JSON.parse(m.slice(at));
    const err = (body as { error?: unknown })?.error;
    const s = typeof err === "string" ? err.trim() : "";
    return s === "" ? null : s.slice(0, 400);
  } catch {
    return null;
  }
}

/** 409 is a product state of its own here (one capture per device at a time). */
export type PcapFailure = "off" | "forbidden" | "conflict" | "rejected" | "other";

export function classifyPcapError(e: unknown): PcapFailure {
  const m = String((e as Error | undefined)?.message ?? e ?? "");
  if (/^409\b/.test(m)) return "conflict";
  if (/^400\b/.test(m)) return "rejected";
  const base = classifyError(e);
  if (base === "off") return "off";
  if (base === "forbidden") return "forbidden";
  return "other";
}

/** The one place a caught error becomes operator-facing copy for an action. */
export function pcapErrorMessage(e: unknown): string {
  switch (classifyPcapError(e)) {
    case "off": return `${FEATURE_OFF_MESSAGE}.`;
    case "forbidden": return NO_PERMISSION_MESSAGE;
    case "conflict": return serverReason(e) ?? RUNNING_MESSAGE;
    case "rejected": return serverReason(e) ?? "The server refused the capture request.";
    default: return serverReason(e) ?? String((e as Error | undefined)?.message ?? e ?? "The request failed.");
  }
}

// ── polling ─────────────────────────────────────────────────────────────────

export const POLL_INTERVAL_MS = 2000;
/** Bounded by construction (§9): 2 s × 45 = 90 s, comfortably past the 60 s
 *  ceiling a capture can legally run for. A capture still "running" after that
 *  stops being polled and says so rather than spinning forever. */
export const MAX_POLLS = 45;
export const POLL_GAVE_UP_MESSAGE =
  "This capture is still running after 90 seconds. Refresh the list to check again.";
