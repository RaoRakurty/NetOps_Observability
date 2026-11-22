// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// dashboardModel.ts — the pure rules behind My dashboards: the saved body, the
// two starting templates, and the address of every dashboard
// (#/overview/dashboards[/new[?template=…] | /<id>]). No React, no IO.

/** One grid cell: a registry panel type and its width out of 12 columns. */
export type Cell = { type: string; span: number };
export type BoardBody = { v: 1; cells: Cell[] };

/** The only layout unit; reorder + resize covers composition. */
export const SPANS: number[] = [3, 4, 6, 8, 12];
/** Mirrors the server's bound on a saved object's size (one cell is small). */
export const MAX_CELLS = 40;

/** A stored body, defensively: unknown panel types are KEPT (a board saved by a
 *  newer version must survive an open-and-save here), bad spans fall back to 4,
 *  and anything past MAX_CELLS is dropped. */
export function parseBody(raw: unknown): BoardBody {
  const body = raw as Partial<BoardBody> | null;
  const cells: Cell[] = [];
  if (body && Array.isArray(body.cells)) {
    for (const c of body.cells.slice(0, MAX_CELLS)) {
      if (c && typeof c.type === "string" && c.type.length > 0 && c.type.length <= 64) {
        cells.push({ type: c.type, span: SPANS.includes(c.span) ? c.span : 4 });
      }
    }
  }
  return { v: 1, cells };
}

// ── templates ───────────────────────────────────────────────────────────────

export type TemplateId = "default" | "telemetry";

/** The default Overview as registry cells: "Make a copy of the default" starts
 *  here, so a NOC admin edits a copy and the default itself upgrades with the
 *  product. Keep in step with OverviewPage's order. */
const DEFAULT_CELLS: Cell[] = [
  { type: "overview-attention", span: 12 },
  { type: "overview-kpis", span: 12 },
  { type: "rca-top-issues", span: 6 }, { type: "rca-path", span: 6 },
  { type: "rca-impact", span: 6 }, { type: "rca-coverage", span: 6 },
  { type: "active-alerts", span: 6 }, { type: "rca-contributors", span: 6 },
  { type: "bgp-peers", span: 6 }, { type: "ospf-nbrs", span: 6 },
  { type: "hot-paths", span: 12 },
  { type: "site-health", span: 12 },
  { type: "what-changed", span: 6 }, { type: "capacity-outlook", span: 6 },
  { type: "telemetry-coverage", span: 6 }, { type: "site-availability", span: 6 },
  { type: "traffic", span: 8 }, { type: "tunnels-health", span: 4 },
  { type: "if-util-topn", span: 6 }, { type: "sat-cpu", span: 3 }, { type: "sat-mem", span: 3 },
];

/** The retired My Dashboard board, flattened: nothing an operator had on it
 *  disappears — it is one click away as a template. */
const TELEMETRY_CELLS: Cell[] = [
  { type: "kpis", span: 12 },
  { type: "sat-cpu", span: 3 }, { type: "sat-mem", span: 3 }, { type: "sat-storage", span: 3 }, { type: "sat-temp", span: 3 },
  { type: "traffic", span: 8 }, { type: "top-hosts", span: 4 }, { type: "flows-proto", span: 4 }, { type: "tunnels-health", span: 4 }, { type: "devices-vendor", span: 4 },
  { type: "wan-interfaces", span: 6 }, { type: "if-util-topn", span: 6 },
  { type: "if-errors-topn", span: 6 }, { type: "if-discards-topn", span: 6 },
  { type: "bgp-peers", span: 6 }, { type: "ospf-nbrs", span: 6 },
  { type: "probe-rtt", span: 4 }, { type: "probe-jitter", span: 4 }, { type: "probe-loss", span: 4 },
  { type: "alerts-severity", span: 12 }, { type: "active-alerts", span: 6 }, { type: "incidents", span: 6 },
  { type: "topology", span: 12 },
];

export const TEMPLATES: Record<TemplateId, { name: string; blurb: string; cells: Cell[] }> = {
  default: { name: "Copy of Overview", blurb: "Start from the default Overview and change what you need.", cells: DEFAULT_CELLS },
  telemetry: { name: "Network telemetry", blurb: "Resources, traffic, interfaces, routing, path quality, alerts and topology.", cells: TELEMETRY_CELLS },
};

export function isTemplateId(s: string | null | undefined): s is TemplateId {
  return s === "default" || s === "telemetry";
}

// ── addresses ───────────────────────────────────────────────────────────────

export type DashRoute =
  | { kind: "list" }
  | { kind: "new"; template?: TemplateId }
  | { kind: "open"; id: string };

const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/** The dashboard a hash names. Anything that is not a well-formed id is the
 *  list, never a request built from arbitrary text. */
export function dashRoute(hash: string): DashRoute {
  const raw = hash.replace(/^#\/?/, "");
  const qi = raw.indexOf("?");
  const path = (qi >= 0 ? raw.slice(0, qi) : raw).split("/");
  const query = new URLSearchParams(qi >= 0 ? raw.slice(qi + 1) : "");
  if (path[0] !== "overview" || path[1] !== "dashboards" || !path[2]) return { kind: "list" };
  if (path[2] === "new") {
    const t = query.get("template");
    return isTemplateId(t) ? { kind: "new", template: t } : { kind: "new" };
  }
  return ID_RE.test(path[2]) ? { kind: "open", id: path[2] } : { kind: "list" };
}

export function dashHref(r: DashRoute): string {
  switch (r.kind) {
    case "list": return "#/overview/dashboards";
    case "new": return r.template ? `#/overview/dashboards/new?template=${r.template}` : "#/overview/dashboards/new";
    case "open": return `#/overview/dashboards/${encodeURIComponent(r.id)}`;
  }
}
