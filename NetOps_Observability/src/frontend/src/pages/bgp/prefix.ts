// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// prefix.ts — the ONE place the BGP page turns what an operator typed into the
// resource it actually checks.
//
// Owner, 2026-09-08: searching `1.1.1.1/24` must be checked as `1.1.1.0/24` and
// SAY SO. A host address carrying a mask is not a mistake worth refusing — it is
// how an operator writes down "this address, in that block" — but the thing the
// internet routes is the NETWORK address, and a screen that silently answers
// about a different string than the one on screen is how an outage call goes
// wrong. So: normalise, then print what was checked.
//
// PARITY WITH THE SERVER IS THE POINT. `bgpNormalizeResource` (src/backend/
// bgp_ops.go) and `parsePrefix` (internal/bgpwatch/helpers.go) both mask the
// host bits off with `netip` and both accept a bare address as its host prefix.
// This module reproduces that behaviour byte for byte — including Go's
// canonical text form (RFC 5952 zero-run elision, lowercase hex, the 4-in-6
// `::ffff:a.b.c.d` spelling) — so the string the operator is told was checked is
// the string the API answers about. `prefix.test.ts` holds the parity cases.
//
// Deliberately strict, in the same places `netip` is strict: a leading zero in a
// dotted octet ("1.1.1.01") is REFUSED rather than guessed at, because it is
// ambiguous between decimal and octal. A zone id ("fe80::1%eth0") is refused on
// BOTH sides as of 2026-09-08: netip is lopsided about it (ParsePrefix rejects a
// zone, ParseAddr accepts one and then drops the zone AND anything after it), so
// the server used to turn "fe80::1%eth0/64" into "fe80::1/128" — an answer about
// a different thing than was typed. Both boundaries now refuse it.

/** The digits of an AS number, as the backend's `bgpASNRe` reads them. */
const ASN_RE = /^[Aa][Ss]([0-9]{1,10})$/;

/** The largest AS number (32-bit); AS0 is reserved by RFC 7607. */
const ASN_MAX = 4294967295;

/** What one typed entry turned out to be. */
export interface ResourceNorm {
  /** `prefix` and `asn` are checkable; `invalid` is refused, by name. */
  kind: "prefix" | "asn" | "invalid";
  /** The canonical resource to send to the API. Empty when `kind` is invalid. */
  resource: string;
  /** True when the canonical form is not what was typed — the page says so. */
  changed: boolean;
  /** An operator sentence naming the refused entry. Empty unless invalid. */
  error: string;
}

// ── IPv4 ────────────────────────────────────────────────────────────────────

/** Four dotted octets, or null. Leading zeros are refused (so is `netip`): an
 *  octet written "010" is ambiguous between decimal and octal. */
export function parseIPv4(s: string): number[] | null {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  const out: number[] = [];
  for (const p of parts) {
    if (!/^[0-9]{1,3}$/.test(p)) return null;
    if (p.length > 1 && p[0] === "0") return null;
    const n = Number(p);
    if (n > 255) return null;
    out.push(n);
  }
  return out;
}

function formatIPv4(b: readonly number[]): string {
  return b.join(".");
}

// ── IPv6 ────────────────────────────────────────────────────────────────────

/** Sixteen bytes, or null. Handles `::` elision and a trailing embedded IPv4;
 *  refuses a zone id, a second `::`, and an elision covering no group at all —
 *  each of those is an error in `netip` too. */
export function parseIPv6(s: string): number[] | null {
  if (!s.includes(":") || s.includes("%")) return null;

  const cut = s.indexOf("::");
  let headText = s, tailText = "";
  if (cut >= 0) {
    headText = s.slice(0, cut);
    tailText = s.slice(cut + 2);
    if (tailText.includes("::")) return null;
  }

  const groups = (text: string, out: number[]): boolean => {
    if (text === "") return true;
    const parts = text.split(":");
    for (let i = 0; i < parts.length; i++) {
      const p = parts[i];
      if (p.includes(".")) {
        // An embedded IPv4 is only legal as the LAST 32 bits.
        if (i !== parts.length - 1) return false;
        const v4 = parseIPv4(p);
        if (!v4) return false;
        out.push(...v4);
        continue;
      }
      if (!/^[0-9a-fA-F]{1,4}$/.test(p)) return false;
      const n = parseInt(p, 16);
      out.push((n >> 8) & 0xff, n & 0xff);
    }
    return true;
  };

  const head: number[] = [], tail: number[] = [];
  if (!groups(headText, head) || !groups(tailText, tail)) return null;

  if (cut < 0) return head.length === 16 ? head : null;
  const zeros = 16 - head.length - tail.length;
  if (zeros < 2) return null; // "::" must stand for at least one group of zeros
  return [...head, ...new Array<number>(zeros).fill(0), ...tail];
}

/** Go's canonical text form: lowercase hex, the longest run of zero groups
 *  elided (leftmost on a tie, never a single group), and an IPv4-mapped address
 *  printed the way `netip.Addr.String` prints it. */
function formatIPv6(b: readonly number[]): string {
  const mapped = b.slice(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff;
  if (mapped) return "::ffff:" + formatIPv4(b.slice(12));

  const g: number[] = [];
  for (let i = 0; i < 16; i += 2) g.push((b[i] << 8) | b[i + 1]);

  let bestAt = -1, bestLen = 0, runAt = -1, runLen = 0;
  for (let i = 0; i < 8; i++) {
    if (g[i] !== 0) { runAt = -1; runLen = 0; continue; }
    if (runAt < 0) { runAt = i; runLen = 1; } else runLen++;
    if (runLen > bestLen) { bestAt = runAt; bestLen = runLen; }
  }
  const hex = (n: number) => n.toString(16);
  if (bestLen < 2) return g.map(hex).join(":");
  return g.slice(0, bestAt).map(hex).join(":") + "::" + g.slice(bestAt + bestLen).map(hex).join(":");
}

// ── masking ─────────────────────────────────────────────────────────────────

/** The network address: every bit past `bits` cleared. */
export function maskBytes(b: readonly number[], bits: number): number[] {
  const out = b.slice();
  for (let i = 0; i < out.length; i++) {
    const keep = bits - i * 8;
    if (keep >= 8) continue;
    out[i] = keep <= 0 ? 0 : out[i] & ((0xff << (8 - keep)) & 0xff);
  }
  return out;
}

/** A prefix length, or -1. Leading zeros are refused, as in `netip`. */
function parseBits(s: string, max: number): number {
  if (!/^[0-9]{1,3}$/.test(s)) return -1;
  if (s.length > 1 && s[0] === "0") return -1;
  const n = Number(s);
  return n <= max ? n : -1;
}

// ── the boundary ────────────────────────────────────────────────────────────

/** The refused entry, quoted and bounded — an unbounded echo is not a message. */
function clip(s: string, max = 40): string {
  return s.length <= max ? s : s.slice(0, max) + "…";
}

/**
 * normalizeResource turns a typed entry into the resource the API is asked
 * about — the mirror of the backend's `bgpNormalizeResource`.
 *
 *   1.1.1.1/24     → 1.1.1.0/24   (host bits masked off; `changed`)
 *   2001:db8::1/32 → 2001:db8::/32
 *   1.1.1.1        → 1.1.1.1/32   (a bare address IS its host prefix)
 *   as64500        → AS64500
 *   3333           → invalid — a bare number is ambiguous between an AS and an
 *                    address, and guessing which is worse than asking.
 */
export function normalizeResource(raw: string): ResourceNorm {
  const input = raw.trim();
  const refuse = (): ResourceNorm => ({
    kind: "invalid", resource: "", changed: false,
    error: `“${clip(input)}” is not a prefix or an AS number.`,
  });
  if (input === "") {
    return { kind: "invalid", resource: "", changed: false, error: "Type a prefix or an AS number." };
  }

  const asn = ASN_RE.exec(input);
  if (asn) {
    const n = Number(asn[1]);
    if (!Number.isSafeInteger(n) || n === 0 || n > ASN_MAX) return refuse();
    const resource = `AS${n}`;
    return { kind: "asn", resource, changed: resource !== input, error: "" };
  }

  const slash = input.lastIndexOf("/");
  const addrText = slash < 0 ? input : input.slice(0, slash);
  const bitsText = slash < 0 ? "" : input.slice(slash + 1);

  const v4 = parseIPv4(addrText);
  const v6 = v4 ? null : parseIPv6(addrText);
  if (!v4 && !v6) return refuse();

  const bytes = (v4 ?? v6) as number[];
  const width = v4 ? 32 : 128;
  const bits = slash < 0 ? width : parseBits(bitsText, width);
  if (bits < 0) return refuse();

  const masked = maskBytes(bytes, bits);
  const resource = `${v4 ? formatIPv4(masked) : formatIPv6(masked)}/${bits}`;
  return { kind: "prefix", resource, changed: resource !== input, error: "" };
}
