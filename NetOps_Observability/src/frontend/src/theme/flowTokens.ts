// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// flowTokens — the bridge from theme/flows-tokens.css to the places that cannot
// use var(): ECharts draws on a canvas, so it needs the resolved colour. Every
// colour the flow views use is a --flow-* token; this file only names them and
// reads the live value for the current theme (light or dark, chosen at login).
// It carries NO colour of its own: when a token is missing (a unit test with no
// stylesheet) it answers "" and the chart falls back to its library default.

import { cssVar } from "./tokens";

export type FlowToken =
  | "in" | "out" | "spark" | "src" | "dst"
  | "util-1" | "util-2" | "util-3" | "util-warn" | "util-crit" | "util-warn-fg" | "util-crit-fg"
  | "proto-tcp" | "proto-udp" | "proto-icmp" | "proto-other";

/** The resolved colour of one --flow-* token for the current theme. */
export function flowColor(name: FlowToken): string {
  return cssVar(`--flow-${name}`, "");
}

export const FLOW_CATEGORICAL = 8;

/** The i-th categorical colour (applications, talkers, protocols), cycling. */
export function flowCat(i: number): string {
  const n = ((Math.floor(i) % FLOW_CATEGORICAL) + FLOW_CATEGORICAL) % FLOW_CATEGORICAL;
  return cssVar(`--flow-cat-${n + 1}`, "");
}

/** A protocol's colour: TCP, UDP and ICMP have their own; the rest share one. */
export function flowProtoColor(proto: number | string): string {
  const p = String(proto).trim().toLowerCase();
  if (p === "6" || p === "tcp") return flowColor("proto-tcp");
  if (p === "17" || p === "udp") return flowColor("proto-udp");
  if (p === "1" || p === "58" || p === "icmp" || p === "icmpv6") return flowColor("proto-icmp");
  return flowColor("proto-other");
}

/** Charts animate only when the operator has not asked for reduced motion. */
export function chartAnimation(): boolean {
  try {
    return !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  } catch {
    return false;
  }
}
