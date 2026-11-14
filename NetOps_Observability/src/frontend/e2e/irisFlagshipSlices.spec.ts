// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Iris flagship slices, end to end in a real browser — tracker 337 N-E5: one
// spec per flagship vertical slice (plan §5 Phase S). Each test drives the real
// SPA through the slice's turns against the Iris API faked at the network
// boundary (./irisBackend.ts), turn by turn as the operator types them.
//
// The turns are the golden corpus's scripted conversations
// (src/backend/internal/nlquery/testdata/golden/*.json, context.script
// N-S1 / N-S2a / N-S2b / N-S3), so the questions here are the ones the
// compiler is pinned to answer. Each fake answer carries the AST the corpus
// expects and a ResultSet + PresentationPlan shaped exactly as the Go planner
// builds them (plan/lists.go changeRow / changesAroundIncidents, planner.go
// compare rows, present.Default's view per query type):
//
//   N-S1  incident → "What happened?" (the engine's RCA) → "Who changed it?"
//         → "Show exactly what he changed." → "What else did they change?"
//         → "Only WAN changes." → "Show the last 7 days."
//   N-S2a "Show Dallas WAN packet loss for the last two hours." → "Compare it
//         with yesterday." → "Only Comcast." → "Which interfaces changed most?"
//   N-S2b "Which Comcast circuits had unusual loss in the last hour?" → "Only
//         Dallas." → "Were there BGP flaps on those circuits?"
//   N-S3  "Show me what changed 30 minutes before every SD-WAN incident this
//         week." → "Only WAN changes." → "Show the last 30 days."
//
// Every slice also proves: one server conversation carries every turn, hostile
// values reach the screen as text, and the controls a screen reader needs are
// named. Steps a slice describes that the UI cannot do yet are NOT faked — they
// are asserted as the honest current behaviour and filed in tracker 337.

import { test, expect, type Page, type Route } from "@playwright/test";
import { bootIris, openIris, askIris, irisPanel, TENANT_CONFIG, type Json } from "./irisBackend";
import { RCA_DETAIL } from "../src/test/irisFixtures";

test.use({ timezoneId: "UTC", locale: "en-US" });

const answers = (page: Page) => irisPanel(page).locator(".op-row.assistant .op-bubble-grounded");
const lastAnswer = (page: Page) => answers(page).last();

/** Hostile cell text: if anything renders it as HTML, onerror sets the flag. */
const HOSTILE = '<img src=x onerror="window.__sliceXss=1">';

const NOW = "2026-09-24T15:00:00Z";
const INCIDENT_ID = "3f2a9c1e-7b4d-4e8a-9c01-5d6e7f8a9b0c";
const CHANGED_NOTE =
  "a change that happened before a problem is only CORRELATED with it; only the engine's causal chain can say it caused it";

let qseq = 0;
/** A data answer exactly as /api/ai/ask sends one (ai.Answer + nlqCompiled body). */
function dataAnswer(intent: string, text: string, ast: Json, result: Json, presentation: Json): Json {
  const id = `q-${(++qseq).toString(16).padStart(4, "0")}`;
  return {
    mode: "data_query", intent, modules: [], text,
    citations: [{ id: `query:${id}`, kind: "query", label: "Live network data", href: "" }],
    disclaimers: [],
    data: {
      intent, entities: null, clarify: null, decline: "", unparsed: false, not_understood: null,
      validation: { valid: true }, ast,
      result: {
        query_id: id, ast_hash: "a1b2c3d4", catalog_version: "1", truncated: false,
        provenance: { source: "change_ledger", executed_at: NOW, duration_ms: 12 },
        ...result,
      },
      presentation: { chosen_by: "server", ...presentation },
    },
  };
}

async function expectNoMarkupRan(page: Page) {
  await expect(page.locator('img[src="x"]')).toHaveCount(0);
  expect(await page.evaluate(() => (window as unknown as { __sliceXss?: number }).__sliceXss)).toBeUndefined();
}

/** Every button / field / link in the panel has an accessible name. */
async function expectEveryControlNamed(page: Page) {
  const unnamed = await irisPanel(page).evaluate((root) => {
    const out: string[] = [];
    for (const el of Array.from(root.querySelectorAll("button, textarea, input, select, a[href]"))) {
      const h = el as HTMLElement;
      const name = (h.getAttribute("aria-label") || h.getAttribute("title") || h.getAttribute("placeholder") || h.textContent || "").trim();
      const labelled = h.id && root.querySelector(`label[for="${h.id}"]`);
      if (!name && !labelled && !h.closest("label")) out.push(h.outerHTML.slice(0, 120));
    }
    return out;
  });
  expect(unnamed).toEqual([]);
}

// ---- N-S1: incident → change conversation ----------------------------------------

const incidentTime = { kind: "incident", anchor: { incident_id: INCIDENT_ID, before: "30m", after: "10m" } };
const byTime = [{ field: "event_at", dir: "desc" }];

function change(over: Json): Json {
  return {
    source: "ledger", object_kind: "device", site: "dfw-hq", app: "", ticket: "", has_diff: false,
    relation: "temporal", ...over,
  };
}

const CHG_1042 = change({
  change_id: "chg-1042", time: "2026-09-24T14:18:00Z", type: "NETWORK_CHANGE", actor: "jsmith",
  object: "dfw-edge-1", summary: `WAN policy wan-pref updated ${HOSTILE}`, has_diff: true,
});
const CHG_1043 = change({
  change_id: "chg-1043", time: "2026-09-24T14:05:00Z", type: "CONFIG_CHANGE", actor: "alice",
  object: "dfw-core-1", summary: "NTP server list updated",
});
const CHG_0990 = change({
  change_id: "chg-0990", time: "2026-09-24T09:40:00Z", type: "NETWORK_CHANGE", actor: "jsmith",
  object: "aus-edge-1", site: "aus-br", summary: "WAN transport preference set to mpls",
});
const CHG_0991 = change({
  change_id: "chg-0991", time: "2026-09-24T08:10:00Z", type: "CONFIG_CHANGE", actor: "jsmith",
  object: "dfw-core-1", summary: "SNMP location string updated",
});
const CHG_0870 = change({
  change_id: "chg-0870", time: "2026-09-19T16:30:00Z", type: "NETWORK_CHANGE", actor: "jsmith",
  object: "sjc-edge-1", site: "sjc-br", summary: "WAN QoS class map updated",
});

function s1Answer(question: string): Json {
  const q = question.toLowerCase();
  if (q.startsWith("explain") || q === "what happened?") {
    return dataAnswer(
      "explain_incident",
      "INC-42 · WAN loss at DFW — root cause: Carrier circuit CKT-9 dropped (confidence High).",
      { v: 1, query_type: "incident_explain", target: "incident", incident_id: INCIDENT_ID, time_range: {} },
      {
        query_type: "incident_explain",
        window: { from: "2026-09-24T14:00:00Z", to: NOW },
        rows: [{ incident_id: INCIDENT_ID, display_id: "INC-42", title: "WAN loss at DFW", state: "open", verdict_tier: "confirmed", created_at: "2026-09-24T14:30:00Z" }],
        detail: { ...RCA_DETAIL, IncidentID: INCIDENT_ID },
        provenance: { source: "rca_report", executed_at: NOW, duration_ms: 9 },
      },
      { primary_view: "INCIDENT_CARD", secondary_view: "EVIDENCE_LIST", title: "Why this incident happened" },
    );
  }
  if (q.startsWith("who changed")) {
    return dataAnswer(
      "list_changes", "2 changes in the 30 minutes before the incident (newest first).",
      { v: 1, query_type: "change_list", target: "change", entities: [{ type: "site", id: "site:dfw-hq" }], time_range: incidentTime, order_by: byTime },
      { query_type: "change_list", window: { from: "2026-09-24T14:00:00Z", to: "2026-09-24T14:40:00Z" }, rows: [CHG_1042, CHG_1043], notes: [CHANGED_NOTE] },
      { primary_view: "TIMELINE", secondary_view: "TABLE", title: "Changes in this window" },
    );
  }
  if (q.startsWith("show exactly")) {
    return dataAnswer(
      "change_diff", "1 change: jsmith — WAN policy wan-pref updated on dfw-edge-1.",
      { v: 1, query_type: "change_list", target: "change", entities: [{ type: "change", id: "change:chg-1042" }], time_range: incidentTime, order_by: byTime, limit: 1 },
      // The planner's change row carries has_diff but never before/after or a
      // unified diff, so present.Default cannot pick DIFF (one row WITH
      // before/after) — it draws the timeline + table. Filed in tracker 337.
      { query_type: "change_list", window: { from: "2026-09-24T14:00:00Z", to: "2026-09-24T14:40:00Z" }, rows: [CHG_1042], notes: [CHANGED_NOTE] },
      { primary_view: "TIMELINE", secondary_view: "TABLE", title: "Changes in this window" },
    );
  }
  const actor = { field: "actor", op: "eq", values: ["jsmith"] };
  const wan = { field: "class", op: "eq", values: ["wan"] };
  if (q.startsWith("what else")) {
    return dataAnswer(
      "list_changes", "3 changes by jsmith in the last 24 hours.",
      { v: 1, query_type: "change_list", target: "change", filters: [actor], time_range: { kind: "relative", last: "24h" }, order_by: byTime },
      { query_type: "change_list", window: { from: "2026-09-23T15:00:00Z", to: NOW }, rows: [CHG_1042, CHG_0990, CHG_0991], notes: [CHANGED_NOTE] },
      { primary_view: "TIMELINE", secondary_view: "TABLE", title: "Changes in this window" },
    );
  }
  if (q.startsWith("only wan")) {
    return dataAnswer(
      "list_changes", "2 WAN changes by jsmith in the last 24 hours.",
      { v: 1, query_type: "change_list", target: "change", filters: [actor, wan], time_range: { kind: "relative", last: "24h" }, order_by: byTime },
      { query_type: "change_list", window: { from: "2026-09-23T15:00:00Z", to: NOW }, rows: [CHG_1042, CHG_0990], notes: [CHANGED_NOTE] },
      { primary_view: "TIMELINE", secondary_view: "TABLE", title: "Changes in this window" },
    );
  }
  if (q.startsWith("show the last 7 days")) {
    return dataAnswer(
      "list_changes", "3 WAN changes by jsmith in the last 7 days.",
      { v: 1, query_type: "change_list", target: "change", filters: [actor, wan], time_range: { kind: "relative", last: "7d" }, order_by: byTime },
      { query_type: "change_list", window: { from: "2026-09-17T15:00:00Z", to: NOW }, rows: [CHG_1042, CHG_0990, CHG_0870], notes: [CHANGED_NOTE] },
      { primary_view: "TIMELINE", secondary_view: "TABLE", title: "Changes in this window" },
    );
  }
  return { mode: "unavailable", intent: "capability", modules: [], text: "unexpected question in the N-S1 script", citations: [], disclaimers: [] };
}

const INCIDENT = {
  id: INCIDENT_ID, tenant_id: "t_acme", title: "WAN loss at DFW", description: "Packet loss on the DFW WAN edge",
  severity: "critical", status: "open", source_type: "correlation", occurrences: 3,
  created_at: "2026-09-24T14:30:00Z", updated_at: "2026-09-24T14:45:00Z",
  first_seen_at: "2026-09-24T14:30:00Z", last_seen_at: "2026-09-24T14:45:00Z", sync_status: "none",
};

/** The incident list and its detail, on top of the Iris fake (later routes win). */
async function withIncident(page: Page) {
  await page.route(/^https?:\/\/[^/]+\/api\/incidents(\/|\?|$)/, async (route: Route) => {
    const p = new URL(route.request().url()).pathname;
    const json = (b: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(b) });
    if (p === "/api/incidents") return json([INCIDENT]);
    if (p === `/api/incidents/${INCIDENT_ID}/timeline`) return json({ incident: INCIDENT, timeline: [] });
    if (p === `/api/incidents/${INCIDENT_ID}`) return json({ incident: INCIDENT, events: [] });
    return route.fallback();
  });
}

test("N-S1: from an incident, what happened, who changed it, what else they changed — one conversation", async ({ page }) => {
  const fake = await bootIris(page, { answer: s1Answer, tenantConfig: TENANT_CONFIG });
  await withIncident(page);
  await page.goto("/#/operations/incidents");

  // The incident page is where the slice starts: open the incident and ask Iris
  // about it (N-E4 entry point — it names the incident by its own title).
  await page.getByText("WAN loss at DFW").first().click();
  await page.getByTestId("ask-iris-incident").click();
  await expect(irisPanel(page)).toBeVisible();

  // "What happened?" — the engine's existing RCA, as the incident card + evidence.
  let ans = lastAnswer(page);
  await expect(ans.getByRole("region", { name: "Why this incident happened" })).toBeVisible();
  const card = ans.getByTestId("op-data-answer");
  await expect(card.getByText("Carrier circuit CKT-9 dropped")).toBeVisible(); // the engine's identified cause
  await expect(card.getByText("Interface ge-0/0/1 went down at 10:31")).toBeVisible();
  await expect(card.getByText("Carrier ticket status").first()).toBeVisible(); // missing evidence is said, not hidden
  await expect(card.getByRole("link", { name: "INC-42 · WAN loss at DFW" })).toHaveAttribute(
    "href", `/#/investigate/rca?id=${INCIDENT_ID}`,
  );

  // "Who changed it?" — the incident-anchored change window: a timeline and a table.
  await askIris(page, "Who changed it?");
  await expect(answers(page)).toHaveCount(2);
  ans = lastAnswer(page);
  await expect(ans.getByRole("region", { name: "Changes in this window" })).toBeVisible();
  const grid = ans.getByRole("grid", { name: "Changes" });
  await expect(grid).toBeVisible();
  await expect(grid.getByText("jsmith").first()).toBeVisible();
  await expect(grid.getByText("alice")).toBeVisible();
  // A change before a problem is related IN TIME only — never shown as its cause.
  await expect(grid.getByText("Happened before — not proven cause").first()).toBeVisible();
  await expect(ans.getByText(CHANGED_NOTE)).toBeVisible();

  // "Show exactly what he changed." — the one change, opened from the table.
  await askIris(page, "Show exactly what he changed.");
  await expect(answers(page)).toHaveCount(3);
  ans = lastAnswer(page);
  await ans.getByRole("grid", { name: "Changes" }).getByRole("gridcell", { name: "Sep 24, 14:18:00 UTC" }).click();
  const drawer = page.getByRole("dialog");
  await expect(drawer).toBeVisible();
  await expect(drawer.getByText(`WAN policy wan-pref updated ${HOSTILE}`)).toBeVisible(); // hostile summary as text
  await expect(drawer.getByText("Happened before — not proven cause")).toBeVisible();
  // The before/after is not in the answer (tracker 337 gap): the drawer says so
  // and links to the change record, rather than drawing a diff it does not have.
  await expect(drawer.getByText("Before/after not included here — open the change record.")).toBeVisible();
  await expect(drawer.getByRole("link", { name: "Open the change record" })).toHaveAttribute(
    "href", "/#/operations/digital-experience/changes?id=chg-1042",
  );
  // Esc closes the drawer only — the conversation stays open.
  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();
  await expect(irisPanel(page)).toBeVisible();

  // "What else did they change?" → "Only WAN changes." → "Show the last 7 days."
  await askIris(page, "What else did they change?");
  await expect(answers(page)).toHaveCount(4);
  await expect(lastAnswer(page).getByRole("grid", { name: "Changes" }).getByRole("gridcell", { name: "dfw-core-1" })).toBeVisible();

  await askIris(page, "Only WAN changes.");
  await expect(answers(page)).toHaveCount(5);
  ans = lastAnswer(page);
  await expect(ans.locator(".op-text").first()).toContainText("2 WAN changes by jsmith");
  await expect(ans.getByRole("grid", { name: "Changes" }).getByRole("gridcell", { name: "dfw-core-1" })).toHaveCount(0);

  await askIris(page, "Show the last 7 days.");
  await expect(answers(page)).toHaveCount(6);
  await expect(lastAnswer(page).getByRole("grid", { name: "Changes" }).getByRole("gridcell", { name: "sjc-edge-1" })).toBeVisible();

  // One server conversation carried every turn, in the order the operator typed them.
  expect(fake.started).toEqual(["conv-1"]);
  expect(fake.asks.map((a) => a.question.split(":")[0])).toEqual([
    'Explain the critical incident "WAN loss at DFW"',
    "Who changed it?",
    "Show exactly what he changed.",
    "What else did they change?",
    "Only WAN changes.",
    "Show the last 7 days.",
  ]);
  expect(new Set(fake.asks.map((a) => a.conversation_id))).toEqual(new Set(["conv-1"]));

  await expectNoMarkupRan(page);
  await expectEveryControlNamed(page);
});

// ---- N-S2: NL analytics refinement -----------------------------------------------

const lossPct = { metric: "circuit_loss_pct", unit: "percent" };
const dallas = { type: "site", id: "site:dfw-hq" };
const comcast = { type: "provider", id: "provider:comcast" };
const last2h = { kind: "relative", last: "2h" };
const yesterday = { kind: "relative", last: "2h", offset: "1d" };

function series(circuit: string, base: number) {
  const t0 = Date.parse("2026-09-24T13:00:00Z") / 1000;
  return { entity: { circuit }, points: Array.from({ length: 8 }, (_, i) => ({ t: t0 + i * 900, v: base + (i % 3) * 0.2 })) };
}

function s2aAnswer(question: string): Json {
  const q = question.toLowerCase();
  const win = { from: "2026-09-24T13:00:00Z", to: NOW };
  const cmp = { from: "2026-09-23T13:00:00Z", to: "2026-09-23T15:00:00Z" };
  if (q.startsWith("show dallas")) {
    return dataAnswer(
      "show_metric", "Circuit loss for 2 Dallas circuits, highest peak first: dfw-comcast-1 peak 2.4%; dfw-att-1 peak 0.6%.",
      { v: 1, query_type: "metric_series", target: "circuit", ...{ metric: "circuit_loss_pct" }, aggregation: "avg", entities: [dallas], time_range: last2h },
      { query_type: "metric_series", ...lossPct, window: { ...win, step: 900_000_000_000 }, series: [series("dfw-comcast-1", 2.0), series("dfw-att-1", 0.2)], provenance: { source: "victoriametrics", executed_at: NOW, duration_ms: 31 } },
      { primary_view: "TIME_SERIES", secondary_view: "TABLE", title: "Circuit loss over time" },
    );
  }
  const cmpAst = { v: 1, query_type: "compare_windows", target: "circuit", metric: "circuit_loss_pct", aggregation: "avg", time_range: last2h, compare_to: yesterday };
  if (q.startsWith("compare")) {
    return dataAnswer(
      "compare", "Dallas circuit loss against the same 2 hours yesterday: dfw-comcast-1 2.2% (was 0.3%); dfw-att-1 0.3% (was 0.2%).",
      { ...cmpAst, entities: [dallas] },
      { query_type: "compare_windows", ...lossPct, window: win, compare: cmp, rows: [
        { circuit: "dfw-comcast-1", value: 2.2, previous: 0.3, delta: 1.9 },
        { circuit: "dfw-att-1", value: 0.3, previous: 0.2, delta: 0.1 },
      ], provenance: { source: "victoriametrics", executed_at: NOW, duration_ms: 44 } },
      { primary_view: "BAR", secondary_view: "TABLE", title: "Circuit loss: this window against the earlier one" },
    );
  }
  if (q.startsWith("only comcast")) {
    return dataAnswer(
      "compare", "Dallas Comcast circuit loss against yesterday: dfw-comcast-1 2.2% (was 0.3%).",
      { ...cmpAst, entities: [dallas, comcast] },
      { query_type: "compare_windows", ...lossPct, window: win, compare: cmp, rows: [
        { circuit: "dfw-comcast-1", value: 2.2, previous: 0.3, delta: 1.9 },
      ], provenance: { source: "victoriametrics", executed_at: NOW, duration_ms: 40 } },
      { primary_view: "BAR", secondary_view: "TABLE", title: "Circuit loss: this window against the earlier one" },
    );
  }
  if (q.startsWith("which interfaces")) {
    return dataAnswer(
      "compare", "Largest change first: dfw-comcast-1 +1.9 points; dfw-comcast-2 +0.4 points.",
      { ...cmpAst, entities: [dallas, comcast], order_by: [{ field: "delta", dir: "desc" }], limit: 10 },
      { query_type: "compare_windows", ...lossPct, window: win, compare: cmp, rows: [
        { circuit: "dfw-comcast-1", value: 2.2, previous: 0.3, delta: 1.9 },
        { circuit: "dfw-comcast-2", value: 0.9, previous: 0.5, delta: 0.4 },
      ], provenance: { source: "victoriametrics", executed_at: NOW, duration_ms: 46 } },
      { primary_view: "BAR", secondary_view: "TABLE", title: "Circuit loss: this window against the earlier one" },
    );
  }
  return { mode: "unavailable", intent: "capability", modules: [], text: "unexpected question in the N-S2a script", citations: [], disclaimers: [] };
}

test("N-S2a: Dallas WAN loss, compared with yesterday, only Comcast, which changed most", async ({ page }) => {
  const fake = await bootIris(page, { answer: s2aAnswer, tenantConfig: TENANT_CONFIG });
  await page.goto("/#/overview/home");
  await openIris(page);

  await askIris(page, "Show Dallas WAN packet loss for the last two hours.");
  let ans = lastAnswer(page);
  await expect(ans.getByRole("region", { name: "Circuit loss over time" })).toBeVisible();
  await expect(ans.locator("figure.iris-chart canvas").first()).toBeVisible();

  await askIris(page, "Compare it with yesterday.");
  await expect(answers(page)).toHaveCount(2);
  ans = lastAnswer(page);
  await expect(ans.getByRole("region", { name: "Circuit loss: this window against the earlier one" })).toBeVisible();
  let grid = ans.getByRole("grid", { name: "Answer rows" });
  await expect(grid.getByRole("gridcell", { name: "dfw-comcast-1" })).toBeVisible();
  await expect(grid.getByRole("gridcell", { name: "dfw-att-1" })).toBeVisible();

  await askIris(page, "Only Comcast.");
  await expect(answers(page)).toHaveCount(3);
  grid = lastAnswer(page).getByRole("grid", { name: "Answer rows" });
  await expect(grid.getByRole("gridcell", { name: "dfw-comcast-1" })).toBeVisible();
  await expect(grid.getByRole("gridcell", { name: "dfw-att-1" })).toHaveCount(0);

  await askIris(page, "Which interfaces changed most?");
  await expect(answers(page)).toHaveCount(4);
  grid = lastAnswer(page).getByRole("grid", { name: "Answer rows" });
  // Largest change first — the server's order, kept.
  const cells = await grid.getByRole("gridcell").allInnerTexts();
  const first = cells.findIndex((c) => c.includes("dfw-comcast-1"));
  const second = cells.findIndex((c) => c.includes("dfw-comcast-2"));
  expect(first).toBeGreaterThanOrEqual(0);
  expect(second).toBeGreaterThan(first);

  expect(fake.started).toEqual(["conv-1"]);
  expect(new Set(fake.asks.map((a) => a.conversation_id))).toEqual(new Set(["conv-1"]));
  await expectEveryControlNamed(page);
});

function s2bAnswer(question: string): Json {
  const q = question.toLowerCase();
  const win = { from: "2026-09-24T14:00:00Z", to: NOW };
  const filterAst = { v: 1, query_type: "metric_filter", target: "circuit", metric: "circuit_loss_pct", aggregation: "avg", predicate: { op: "above_baseline" }, time_range: { kind: "relative", last: "1h" } };
  if (q.startsWith("which comcast")) {
    return dataAnswer(
      "threshold", "2 Comcast circuits were above their usual loss in the last hour: dfw-comcast-1 2.2%; aus-comcast-1 1.1%.",
      { ...filterAst, entities: [comcast] },
      { query_type: "metric_filter", ...lossPct, window: win, rows: [
        { circuit: "dfw-comcast-1", value: 2.2 }, { circuit: "aus-comcast-1", value: 1.1 },
      ], provenance: { source: "victoriametrics", executed_at: NOW, duration_ms: 28 } },
      { primary_view: "TABLE", title: "Circuit loss matching the condition" },
    );
  }
  if (q.startsWith("only dallas")) {
    return dataAnswer(
      "threshold", "1 Dallas Comcast circuit was above its usual loss in the last hour: dfw-comcast-1 2.2%.",
      { ...filterAst, entities: [comcast, dallas] },
      { query_type: "metric_filter", ...lossPct, window: win, rows: [{ circuit: "dfw-comcast-1", value: 2.2 }], provenance: { source: "victoriametrics", executed_at: NOW, duration_ms: 25 } },
      { primary_view: "TABLE", title: "Circuit loss matching the condition" },
    );
  }
  if (q.startsWith("were there bgp flaps")) {
    return dataAnswer(
      "threshold", `BGP flaps on dfw-comcast-1 in the last hour: peer 198.51.100.1 flapped 3 times.`,
      { v: 1, query_type: "metric_filter", target: "bgp_peer", metric: "bgp_flaps", aggregation: "sum", entities: [{ type: "circuit", id: "circuit:dfw-comcast-1" }], predicate: { op: "gt", value: 0 }, time_range: { kind: "relative", last: "1h" } },
      { query_type: "metric_filter", metric: "bgp_flaps", unit: "count", window: win, rows: [{ bgp_peer: "198.51.100.1", device: HOSTILE, value: 3 }], provenance: { source: "victoriametrics", executed_at: NOW, duration_ms: 22 } },
      { primary_view: "TABLE", title: "BGP flaps matching the condition" },
    );
  }
  return { mode: "unavailable", intent: "capability", modules: [], text: "unexpected question in the N-S2b script", citations: [], disclaimers: [] };
}

test("N-S2b: Comcast circuits with unusual loss, only Dallas, then BGP flaps on those circuits", async ({ page }) => {
  const fake = await bootIris(page, { answer: s2bAnswer, tenantConfig: TENANT_CONFIG });
  await page.goto("/#/overview/home");
  await openIris(page);

  await askIris(page, "Which Comcast circuits had unusual loss in the last hour?");
  let grid = lastAnswer(page).getByRole("grid", { name: "Answer rows" });
  await expect(grid.getByRole("gridcell", { name: "dfw-comcast-1" })).toBeVisible();
  await expect(grid.getByRole("gridcell", { name: "aus-comcast-1" })).toBeVisible();

  await askIris(page, "Only Dallas.");
  await expect(answers(page)).toHaveCount(2);
  grid = lastAnswer(page).getByRole("grid", { name: "Answer rows" });
  await expect(grid.getByRole("gridcell", { name: "dfw-comcast-1" })).toBeVisible();
  await expect(grid.getByRole("gridcell", { name: "aus-comcast-1" })).toHaveCount(0);

  await askIris(page, "Were there BGP flaps on those circuits?");
  await expect(answers(page)).toHaveCount(3);
  const ans = lastAnswer(page);
  await expect(ans.getByRole("region", { name: "BGP flaps matching the condition" })).toBeVisible();
  grid = ans.getByRole("grid", { name: "Answer rows" });
  await expect(grid.getByRole("gridcell", { name: "198.51.100.1" })).toBeVisible();
  await expect(grid.getByText(HOSTILE, { exact: true })).toBeVisible(); // hostile cell as text

  expect(fake.started).toEqual(["conv-1"]);
  expect(fake.asks.map((a) => a.question)).toEqual([
    "Which Comcast circuits had unusual loss in the last hour?", "Only Dallas.", "Were there BGP flaps on those circuits?",
  ]);
  await expectNoMarkupRan(page);
  await expectEveryControlNamed(page);
});

// ---- N-S3: what changed before every SD-WAN incident ------------------------------

const sdwanSet = (time: Json) => ({ kind: "incidents", anchor: { incidents: { time_range: time, filters: [{ field: "seam_class", op: "eq", values: ["sdwan"] }] }, before: "30m", after: "1m" } });
const thisWeek = { kind: "absolute", from: "2026-09-21T05:00:00Z", to: NOW };
const aroundNote = (n: number) =>
  `changes shown are those within 30m0s before / 1m0s after each of ${n} incidents — correlated in time, not established as causes`;

const NEAR_A = change({
  change_id: "chg-2001", time: "2026-09-23T10:48:00Z", type: "NETWORK_CHANGE", actor: "jsmith", object: "dfw-edge-1",
  summary: "Overlay TLOC preference changed", incident_id: "inc-sdwan-a", minutes_before_incident: 12,
});
const NEAR_A2 = change({
  change_id: "chg-2002", time: "2026-09-23T10:41:00Z", type: "CONFIG_CHANGE", actor: "alice", object: "dfw-core-1",
  summary: "Syslog server list updated", incident_id: "inc-sdwan-a", minutes_before_incident: 19,
});
const NEAR_B = change({
  change_id: "chg-2003", time: "2026-09-22T07:55:00Z", type: "NETWORK_CHANGE", actor: "bob", object: "aus-edge-1", site: "aus-br",
  summary: "Control-plane policy pushed from the controller", incident_id: "inc-sdwan-b", minutes_before_incident: 5,
});
const NEAR_C = change({
  change_id: "chg-1801", time: "2026-09-02T18:20:00Z", type: "NETWORK_CHANGE", actor: "jsmith", object: "sjc-edge-1", site: "sjc-br",
  summary: "Transport color mapping edited", incident_id: "inc-sdwan-c", minutes_before_incident: 22,
});

function s3Answer(question: string): Json {
  const q = question.toLowerCase();
  const base = { v: 1, query_type: "change_list", target: "change", order_by: byTime };
  const wan = { field: "class", op: "eq", values: ["wan"] };
  const rs = (rows: Json[], n: number, from: string) => ({
    query_type: "change_list", window: { from, to: NOW }, rows, notes: [aroundNote(n)],
    provenance: { source: "change_ledger", executed_at: NOW, duration_ms: 37 },
  });
  const plan = { primary_view: "TIMELINE", secondary_view: "TABLE", title: "Changes in this window" };
  if (q.startsWith("show me what changed")) {
    return dataAnswer("list_changes", "3 changes within 30 minutes before 2 SD-WAN incidents this week.",
      { ...base, time_range: sdwanSet(thisWeek) }, rs([NEAR_A, NEAR_A2, NEAR_B], 2, "2026-09-21T05:00:00Z"), plan);
  }
  if (q.startsWith("only wan")) {
    return dataAnswer("list_changes", "2 WAN changes within 30 minutes before 2 SD-WAN incidents this week.",
      { ...base, filters: [wan], time_range: sdwanSet(thisWeek) }, rs([NEAR_A, NEAR_B], 2, "2026-09-21T05:00:00Z"), plan);
  }
  if (q.startsWith("show the last 30 days")) {
    return dataAnswer("list_changes", "3 WAN changes within 30 minutes before 3 SD-WAN incidents in the last 30 days.",
      { ...base, filters: [wan], time_range: sdwanSet({ kind: "relative", last: "30d" }) }, rs([NEAR_A, NEAR_B, NEAR_C], 3, "2026-08-25T15:00:00Z"), plan);
  }
  return { mode: "unavailable", intent: "capability", modules: [], text: "unexpected question in the N-S3 script", citations: [], disclaimers: [] };
}

test("N-S3: what changed 30 minutes before every SD-WAN incident — correlated in time, each row linked to its incident", async ({ page }) => {
  const fake = await bootIris(page, { answer: s3Answer, tenantConfig: TENANT_CONFIG });
  await page.goto("/#/overview/home");
  await openIris(page);

  await askIris(page, "Show me what changed 30 minutes before every SD-WAN incident this week.");
  let ans = lastAnswer(page);
  await expect(ans.getByRole("region", { name: "Changes in this window" })).toBeVisible();
  // The server's statement of what this list is — and is not — reaches the operator.
  await expect(ans.getByText(aroundNote(2))).toBeVisible();
  const grid = ans.getByRole("grid", { name: "Changes" });
  await expect(grid.getByRole("gridcell", { name: "aus-edge-1" })).toBeVisible();
  // Correlated, never causal: every row reads "Happened before — not proven cause".
  await expect(grid.getByText("Linked by the root-cause engine")).toHaveCount(0);

  // Each row names the incident it was found near, with how long before it started.
  // The row opens from its first cell (the time); wide cells overlap in a narrow panel.
  await grid.getByRole("gridcell", { name: "Sep 23, 10:48:00 UTC" }).click();
  const drawer = page.getByRole("dialog");
  await expect(drawer).toBeVisible();
  await expect(drawer.getByText(/Happened before — not proven cause/)).toBeVisible();
  await expect(drawer.getByText(/12 minutes before it started/)).toBeVisible();
  await expect(drawer.getByRole("link", { name: "inc-sdwan-a" })).toHaveAttribute("href", /inc-sdwan-a/);
  // Esc closes the drawer — and ONLY the drawer: the conversation stays open.
  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();
  await expect(irisPanel(page)).toBeVisible();

  await askIris(page, "Only WAN changes.");
  await expect(answers(page)).toHaveCount(2);
  ans = lastAnswer(page);
  await expect(ans.getByRole("grid", { name: "Changes" }).getByRole("gridcell", { name: "dfw-core-1" })).toHaveCount(0);

  await askIris(page, "Show the last 30 days.");
  await expect(answers(page)).toHaveCount(3);
  ans = lastAnswer(page);
  await expect(ans.getByText(aroundNote(3))).toBeVisible();
  await expect(ans.getByRole("grid", { name: "Changes" }).getByRole("gridcell", { name: "sjc-edge-1" })).toBeVisible();

  expect(fake.started).toEqual(["conv-1"]);
  expect(new Set(fake.asks.map((a) => a.conversation_id))).toEqual(new Set(["conv-1"]));
  await expectNoMarkupRan(page);
  await expectEveryControlNamed(page);
});
