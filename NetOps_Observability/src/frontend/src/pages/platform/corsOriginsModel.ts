// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// corsOriginsModel — the pure half of Platform → Configuration → Cross-origin
// access (tracker 439). The server (internal/corsallow) is the authority on
// what an origin is; this mirrors its rules only so the page can point at a bad
// line BEFORE a round trip. Anything this accepts, the server still checks.

import type { CorsOriginsView } from "../../services/api";

/** One line per web address; blank lines ignored. */
export function parseLines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l !== "");
}

const DEV_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Why a line is not an origin, in plain words; "" when it looks fine. */
export function lineProblem(line: string): string {
  if (line.includes("*")) return "no wildcards — list each app's address";
  if (/[\s?#\\]/.test(line)) return "only a scheme and a host, like https://app.example.com";
  let u: URL;
  try {
    u = new URL(line);
  } catch {
    return "write it like https://app.example.com";
  }
  if (u.username || u.password) return "no user name or password";
  if (u.pathname !== "/") return "no path — just the scheme and host";
  if (u.protocol === "http:") {
    if (!DEV_HOSTS.has(u.hostname)) return "use https; plain http is only for localhost";
  } else if (u.protocol !== "https:") {
    return "it must start with https://";
  }
  return "";
}

/** Every bad line with its reason; empty when all lines look fine. */
export function problems(lines: string[], max: number): string[] {
  const out = lines.flatMap((l) => {
    const p = lineProblem(l);
    return p ? [`${l} — ${p}`] : [];
  });
  if (lines.length > max) out.push(`${lines.length} addresses — at most ${max}`);
  return out;
}

/** Where the list in force comes from, in one plain sentence. */
export function sourceLine(v: CorsOriginsView): string {
  switch (v.source) {
    case "saved":
      return v.origins.length === 0
        ? "Saved here: no app may send data from a browser."
        : "Saved here. This list is in force.";
    case "env":
      return "From the installation. Saving here replaces it.";
    default:
      return "No app may send data from a browser yet.";
  }
}

/** The saved text for a view, one address per line. */
export function textFor(v: CorsOriginsView): string {
  return v.origins.join("\n");
}
