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
  await expect(ws.locator(".rw-whatbroke")).toHaveText("Routing adjacency change on cEDGE-81 · site RETAIL-WALMART");
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

test("the RCA view holds at phone width with no horizontal page scroll", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 900 });
  await openCase(page);
  await expect(page.getByTestId("rca-phrase")).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
  await shot(page, "rca-view-p424934-phone");
});
