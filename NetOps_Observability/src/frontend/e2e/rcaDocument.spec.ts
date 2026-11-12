// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// The NOC RCA document (owner 2026-11-11), end to end in a real browser against
// a mocked backend. The case is P-424934 from the Fable review: a standing
// security exposure finding and vManage's BGP reports, persisted CONFIRMED with
// the exposure story on top and a security + controller confirming pair. The
// RCA view must read "Possibly because of …", put the finding in the background
// band, claim no impact and never draw a definitive break — and lay the ten
// sections out in the order a NOC engineer reads them.
//
// RCA_SHOT_DIR (optional): a directory to save full-page screenshots into.

import { test, expect, type Page, type Route } from "@playwright/test";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import p3Detail from "../../backend/internal/rca/testdata/p3e0400/detail.json" with { type: "json" };
import p3Report from "../../backend/internal/rca/testdata/p3e0400/rca-report.json" with { type: "json" };
import p3Context from "../src/components/rca/testdata/p3e0400.topology_context.json" with { type: "json" };

// The harness compiles the whole RCA view on first load (cold Vite) — allow it.
test.describe.configure({ timeout: 90_000 });

const ID = "a4249340-0000-4000-8000-000000000000";
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString().replace("T", " ").slice(0, 19);

const HYPS = {
  ranking: {
    hypotheses: [
      {
        id: "sig.ent.security.exposure-story", confidence: 1, confidence_label: "confirmed",
        satisfied: ["security_exposure", "bgp_adjacency_change|link_state_change"], missing: [],
        operator_phrase: "This device carries a known exposure and is showing a network fault at the same time — the two are on one node, not yet proven to be one cause",
        verdict: { verdict_tier: "confirmed", owner: "netops", independent_pair: ["ctl-vmanage-bfa81d722501", "security:netrule"], trusted_modalities: ["control_plane", "security"],
          first_steps: ["Open the exposure evidence (advisory + affected version) on this device"] },
      },
      {
        id: "sig.ent.wan-edge.bgp-peer-flap", confidence: 1, confidence_label: "suspected",
        satisfied: ["bgp_adjacency_change"], missing: ["control_plane"],
        verdict: { verdict_tier: "suspected", owner: "netops", reasons: ["single modality class (control_plane); need >=2"],
          first_steps: ["Check the BGP session state and last reset reason on cEDGE-81"] },
      },
    ],
  },
};

const OBJ = {
  correlation_id: ID, version: 3, state: "open",
  window_start: iso(30 * 60_000), window_end: iso(22 * 60_000),
  trigger_signal: "s-1", top_hypothesis: "sig.ent.security.exposure-story", top_confidence: 1, verdict_tier: "confirmed",
  hypotheses: JSON.stringify(HYPS), evidence_missing: "[]",
  affected: JSON.stringify({ devices: ["cEDGE-81"], sites: ["RETAIL-WALMART"] }),
  signal_count: 8, node_count: 4, engine_version: "v1", catalog_version: "c1", created_at: iso(30 * 60_000),
  app_impact: "{}",
};

const sig = (i: number, over: Record<string, unknown>) => ({
  signal_id: `s-${i}`, ts: iso((29 - i) * 60_000), ingest_ts: iso((29 - i) * 60_000), source: "controller",
  kind: "bgp_adjacency_change", observer_type: "controller", observer_id: "ctl-vmanage-bfa81d722501",
  collection_path: "via_controller", modality_class: "control_plane", clock_quality: "ntp",
  entity_type: "device", entity_id: "cEDGE-81:192.168.200.34", severity: "high", value: 0, metric_name: "",
  attrs: JSON.stringify({ peer: "192.168.200.34", state: "idle", peer_router_id: "0.0.0.0" }),
  onset_uncertainty_s: 0, phase: "anomalous", clear_ts: "", attached: true, is_trigger: i === 1, evidence: null,
  link_status: "attached", link_role: "supporting", ...over,
});

const TIMELINE = {
  correlation_id: ID, version: 3, window_start: OBJ.window_start, window_end: OBJ.window_end,
  trigger_signal: "s-1", verdict_tier: "confirmed", top_hypothesis: OBJ.top_hypothesis, top_confidence: 1,
  evidence_missing: "[]",
  signals: [
    sig(1, {}), sig(2, {}),
    sig(3, { kind: "security_exposure", source: "security", modality_class: "security", observer_type: "platform",
      observer_id: "security:netrule", collection_path: "via_aggregator", entity_id: "cEDGE-81",
      attrs: JSON.stringify({ control_title: "Telnet permitted on management lines" }), is_trigger: false }),
    sig(4, { kind: "security_posture", source: "security", modality_class: "security", observer_type: "platform",
      observer_id: "security:netrule", collection_path: "via_aggregator", entity_id: "cEDGE-81",
      attrs: JSON.stringify({ control_title: "Telnet reachable from an untrusted seam" }), is_trigger: false }),
  ],
  evidence: [], edges: [],
  counts: { total: 4, attached: 4, unattached: 0, recovery: 0, unlinked: 0, attached_observers: 2,
    by_modality: {}, attached_by_modality: {}, by_role: {}, by_grounding: {}, by_status: {} },
};

const REPORT = {
  states: { incident: "active", impact_real_user: "not_observable", impact_synthetic: "not_observable" },
  times: {}, promotion: { promoted: false, basis: "not_promoted", reason: "", criteria: [] },
};

// The case renders through the dev-only RCA preview harness (rca-preview.html),
// which mounts the real CorrelationDetail → RcaWorkspace against a fetch mock;
// the spec injects P-424934 as the harness's case.
async function openCase(page: Page) {
  await page.addInitScript((fx) => { (window as unknown as { __RCA_PREVIEW__: unknown }).__RCA_PREVIEW__ = fx; },
    { object: OBJ, timeline: TIMELINE, report: REPORT });
  await page.route(/^https?:\/\/[^/]+\/api\//, (route: Route) => route.fulfill({ status: 200, contentType: "application/json", body: "{}" }));
  await page.goto("/rca-preview.html");
  await expect(page.locator(".rw-doc-title").first()).toBeVisible({ timeout: 30_000 });
}

// The RCA workspace that carries the document (other .rca-ws hosts exist).
const workspace = (page: Page) => page.locator(".rca-ws", { has: page.locator(".rw-doc-title") }).first();

async function shot(page: Page, name: string) {
  const dir = process.env.RCA_SHOT_DIR;
  if (dir) await workspace(page).screenshot({ path: `${dir}/${name}.png` });
}

// A focused screenshot of one part of the view (section 6, the Iris dock).
async function shotOf(loc: ReturnType<Page["locator"]>, name: string) {
  const dir = process.env.RCA_SHOT_DIR;
  if (dir) await loc.screenshot({ path: `${dir}/${name}.png` });
}

test("P-424934 reads as the NOC RCA document — background never confirms", async ({ page }) => {
  await page.setViewportSize({ width: 1400, height: 1000 });
  await openCase(page);
  const ws = workspace(page);

  // the ten sections, in reading order
  const titles = await ws.locator(".rw-doc-title").allInnerTexts();
  expect(titles).toEqual([
    "1 · What broke", "2 · Who is affected", "3 · When", "4 · Cause and how sure we are", "5 · How we know",
    "6 · Where the break is", "7 · Background on this device (not a cause)", "8 · Other explanations considered",
    "9 · Who owns the fix", "10 · What to do now · Watch for recurrence",
  ]);

  // section 1 — the object, symptom, site; never the raw template title
  await expect(ws.locator(".rw-whatbroke")).toHaveText("BGP peer flapping — WAN edge on cEDGE-81 · site RETAIL-WALMART");
  // section 4 — one of the four phrases, and it is not "Confirmed cause"
  await expect(ws.getByTestId("rca-phrase")).toHaveText(/^Possibly because of /);
  // section 5 — the source in plain words; one controller is one witness
  await expect(ws.getByText("vManage reported BGP neighbor change (2 observations).")).toBeVisible();
  await expect(ws.getByText("Every observation above came through vManage, so together they count as one witness.")).toBeVisible();
  // section 7 — the security finding is background
  const band = ws.getByRole("region", { name: "Background on this device (not a cause)" });
  await expect(band.getByText("Known security exposure on this device")).toBeVisible();
  await expect(band.getByText("Telnet permitted on management lines")).toBeVisible();

  const text = await ws.innerText();
  expect(text).not.toContain("Confirmed cause");
  expect(text).not.toContain("Exposed device is also failing");
  expect(text).not.toMatch(/customer impact is confirmed/i);
  expect(text).not.toContain("management_plane");

  // the reading guide opens
  await ws.getByText("How to read this RCA").click();
  await expect(ws.getByText(/Section 7 is background and may be unrelated/)).toBeVisible();
  await shot(page, "rca-view-p424934");
});

// ── P-3E0400 (RCA document v2 regression case) ─────────────────────────────────
// The captured lab case: six observations on cedge-60-07ae8615, no measured
// path, no neighbour data. Its eight-page PDF said "this correlation object is
// not path-shaped"; v2 must render the device_only diagnostic card in the
// SERVER's state words, and Iris must answer about THIS problem.

const P3_REPORT = { ...p3Report, topology_context: p3Context };
const P3_ID = p3Detail.object.correlation_id;
const p3Sig = (i: number, over: Record<string, unknown>) => ({
  signal_id: `p3-${i}`, ts: "2026-11-12 04:50:50", ingest_ts: "2026-11-12 04:50:51", source: "snmp",
  kind: "if_metric_anomaly", observer_type: "poller", observer_id: "cedge-60-07ae8615", collection_path: "direct",
  modality_class: "device_telemetry", clock_quality: "ntp", entity_type: "interface", entity_id: "cedge-60-07ae8615:Gi4",
  severity: "crit", value: 1, metric_name: "ifInErrors", attrs: "{}", onset_uncertainty_s: 0, phase: "anomalous",
  clear_ts: "", attached: true, is_trigger: i === 1, evidence: null, link_status: "attached", link_role: "supporting", ...over,
});
const P3_TIMELINE = {
  correlation_id: P3_ID, version: 3, window_start: p3Detail.object.window_start, window_end: p3Detail.object.window_end,
  trigger_signal: "p3-1", verdict_tier: "suspected", top_hypothesis: p3Detail.object.top_hypothesis, top_confidence: 0.5,
  evidence_missing: p3Detail.object.evidence_missing,
  signals: [
    p3Sig(1, {}),
    p3Sig(2, { entity_id: "cedge-60-07ae8615:Gi3", severity: "warn", ts: "2026-11-12 04:51:10" }),
    p3Sig(3, { entity_id: "cedge-60-07ae8615:Tu1", ts: "2026-11-12 04:51:30" }),
    p3Sig(4, { entity_id: "cedge-60-07ae8615:Tu2", severity: "warn", ts: "2026-11-12 04:52:00" }),
    p3Sig(5, { kind: "device_alarm", entity_type: "device", entity_id: "cedge-60-07ae8615", severity: "high", ts: "2026-11-12 04:53:00" }),
    p3Sig(6, { kind: "device_resource_anomaly", entity_type: "device", entity_id: "cedge-60-07ae8615", severity: "high", ts: "2026-11-12 04:54:21" }),
  ],
  evidence: [], edges: p3Detail.edges,
  counts: { total: 41, attached: 6, unattached: 0, recovery: 35, unlinked: 0, attached_observers: 1,
    by_modality: {}, attached_by_modality: {}, by_role: {}, by_grounding: {}, by_status: {} },
};
const IRIS_ANSWER = {
  mode: "problem_explanation", intent: "explain", modules: ["rca"],
  text: "Evidence concentrates on cedge-60-07ae8615; not independently localised. Four interfaces show counter changes.",
  citations: [
    { id: P3_ID, kind: "problem", label: "", href: `#/investigate/rca?id=${P3_ID}` },
    { id: "p3-1", kind: "evidence", label: "Gi4 interface counter change", href: "#/explore/metrics?q=Gi4" },
  ],
  disclaimers: [], provider: "anthropic", model: "claude-lab", conversation_id: "conv-p3", answer_id: "ans-p3",
};

// The server document's state words for device_only (rca_report_html_topology.go
// topoStateLabel + AssembleTopologyContext). When WS-A's golden is present in
// the tree, the UI is compared against the golden itself.
const SERVER_STATE = "device only — no neighbour or path data";
const SERVER_REASON = "cedge-60-07ae8615 is in the inventory, but no neighbour or path data was found for it.";
function serverGoldenState(): { state: string; reason: string } {
  const golden = fileURLToPath(new URL("../../backend/internal/rca/testdata/topoctx/device_only.golden.html", import.meta.url));
  if (!existsSync(golden)) return { state: SERVER_STATE, reason: SERVER_REASON };
  const m = readFileSync(golden, "utf8").match(/State: <b>([^<]+)<\/b> — ([^<]+)<\/div>/);
  return m ? { state: m[1].trim(), reason: m[2].trim() } : { state: SERVER_STATE, reason: SERVER_REASON };
}

async function openP3(page: Page, theme: "light" | "dark" = "light") {
  await page.addInitScript((fx) => { (window as unknown as { __RCA_PREVIEW__: unknown }).__RCA_PREVIEW__ = fx; }, {
    object: p3Detail.object, timeline: P3_TIMELINE, report: P3_REPORT,
    routes: {
      "/api/features": { ai_entitlements: ["ai.chat", "ai.nlquery"] },
      "/api/ai/conversations": { id: "conv-p3", created_at: "", updated_at: "", turns: [] },
      "/api/ai/ask": IRIS_ANSWER,
      "/api/ai/feedback": {},
    },
  });
  await page.route(/^https?:\/\/[^/]+\/api\//, (route: Route) => route.fulfill({ status: 200, contentType: "application/json", body: "{}" }));
  await page.goto(`/rca-preview.html?theme=${theme}`);
  await expect(page.locator(".rw-doc-title").first()).toBeVisible({ timeout: 30_000 });
}

test("P-3E0400 renders device_only in the server's words — never 'not path-shaped'", async ({ page }) => {
  await page.setViewportSize({ width: 1500, height: 1100 });
  await openP3(page);
  const ws = workspace(page);
  const want = serverGoldenState();
  const topo = ws.getByTestId("topo-context");
  await expect(topo).toHaveAttribute("data-state", "device_only");
  await expect(ws.getByTestId("topo-state")).toHaveText(want.state);
  await expect(ws.getByTestId("topo-reason")).toHaveText(want.reason);
  const card = ws.getByTestId("topo-device-card");
  await expect(card.getByText("Device diagnostic — cedge-60-07ae8615")).toBeVisible();
  await expect(card).toContainText("LLDP, CDP, BGP-LS, the persisted topology graph, the SD-WAN overlay, the SD-WAN controller");
  await expect(ws.getByTestId("topo-remediation")).toContainText("Enable LLDP or CDP on cedge-60-07ae8615");
  const text = await ws.innerText();
  expect(text).not.toMatch(/path-shaped/);
  expect(text).not.toMatch(/localizes to this routing adjacency/);
  await ws.getByTestId("topo-context").scrollIntoViewIfNeeded();
  await shot(page, "rca-p3e0400-light");
  await shotOf(ws.locator("section.rw-panel", { has: page.getByTestId("topo-context") }), "rca-p3e0400-section6-light");
});

test("P-3E0400 in the dark theme keeps the same content on dark surfaces", async ({ page }) => {
  await page.setViewportSize({ width: 1500, height: 1100 });
  await openP3(page, "dark");
  const ws = workspace(page);
  await expect(ws.getByTestId("topo-state")).toHaveText(serverGoldenState().state);
  // the sheet follows the theme through its tokens: a dark panel, light text
  const [bg, fg] = await ws.locator(".rw-panel").first().evaluate((el) => {
    const cs = getComputedStyle(el);
    return [cs.backgroundColor, cs.color];
  });
  const lum = (rgb: string) => {
    const [r, g, b] = (rgb.match(/\d+(\.\d+)?/g) ?? ["0", "0", "0"]).slice(0, 3).map(Number);
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  expect(lum(bg)).toBeLessThan(80);
  expect(lum(fg)).toBeGreaterThan(160);
  await shot(page, "rca-p3e0400-dark");
  await shotOf(ws.locator("section.rw-panel", { has: page.getByTestId("topo-context") }), "rca-p3e0400-section6-dark");
  const darkChat = page.getByTestId("rca-iris-chat");
  await darkChat.getByRole("button", { name: "Explain this problem" }).click();
  await expect(darkChat.getByText(/Evidence concentrates/)).toBeVisible();
  await shotOf(darkChat, "rca-p3e0400-iris-dark");
});

test("Iris docked in the RCA view answers about P-3E0400, with links and feedback", async ({ page }) => {
  await page.setViewportSize({ width: 1500, height: 1100 });
  await openP3(page);
  const chat = page.getByTestId("rca-iris-chat");
  await expect(chat).toBeVisible();
  await expect(chat.getByText("About P-3E0400", { exact: true })).toBeVisible();
  await chat.getByRole("button", { name: "Explain this problem" }).click();
  await expect(chat.getByText(/Evidence concentrates on cedge-60-07ae8615/)).toBeVisible();
  await expect(chat.getByRole("link", { name: "P-3E0400" })).toHaveAttribute("href", `#/investigate/rca?id=${P3_ID}`);
  await expect(chat.getByText("Grounded in this problem's evidence · claude-lab")).toBeVisible();

  await chat.getByRole("textbox").fill("why only suspected?");
  await chat.getByRole("button", { name: "Ask" }).click();
  await expect(chat.locator(".ric-turn")).toHaveCount(2);
  await chat.getByRole("button", { name: "Helpful" }).first().click();

  const calls = await page.evaluate(() => (window as unknown as { __RCA_PREVIEW_CALLS__?: { path: string; body: Record<string, unknown> }[] }).__RCA_PREVIEW_CALLS__ ?? []);
  const asks = calls.filter((c) => c.path === "/api/ai/ask");
  expect(asks).toHaveLength(2);
  for (const a of asks) expect(a.body.context).toEqual({ correlation_id: P3_ID });
  expect(asks[0].body.question).toBe("Explain this problem");
  expect(asks[1].body.conversation_id).toBe("conv-p3");
  expect(calls.some((c) => c.path === "/api/ai/feedback" && c.body.answer_id === "ans-p3")).toBe(true);
  await chat.scrollIntoViewIfNeeded();
  await shot(page, "rca-p3e0400-iris");
  await shotOf(chat, "rca-p3e0400-iris-light");
});

test("the RCA view holds at phone width with no horizontal page scroll", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 900 });
  await openCase(page);
  await expect(page.getByTestId("rca-phrase")).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
  await shot(page, "rca-view-p424934-phone");
});
