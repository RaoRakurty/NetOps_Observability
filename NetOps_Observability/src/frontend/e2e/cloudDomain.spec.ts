// Cloud domain END-TO-END — "the Cloud page is not loading".
//
// The Cloud tab has now failed twice for reasons no unit test could see: first an
// optional callback nobody passed (the domain could never leave "lan", so the tab
// never mounted), then whatever this spec catches. Both were invisible to vitest
// because they live in the wiring between the nav, the canvas and the network.
//
// So this drives the REAL browser through the REAL user path — open the canvas the
// way the nav mounts it, pick Cloud from the domain dropdown — against the EXACT
// payload the deployed API served. `fixtures-cloud-topology.json` is not
// hand-written: it is `cloud.BuildTopologyView` run over the deployed
// `deployment/docker/cloud-fixtures` (15 nodes, 19 edges, 5 groups).
//
// It is kept BYTE-FOR-BYTE as captured, which means its region groups still carry
// `"children": null` — the nil Go slice that threw "children is not iterable" and
// unmounted the whole page. The producer now emits `[]`
// (TestBuildTopologyViewGroupChildrenNeverNull), but this fixture deliberately
// keeps the broken shape so the spec also proves the CLIENT survives it: two
// independent layers, either of which alone prevents the blank screen. Do not
// "refresh" this file from the fixed backend — that would silently retire half
// the regression.

import { test, expect, type Page, type Route } from "@playwright/test";
import cloudView from "./fixtures-cloud-topology.json" with { type: "json" };

// A single-tenant operator on purpose: a platform-wide principal is first shown
// the "choose a tenant" gate, which is a different screen and a different test.
const ME = { username: "alice", role: "operator", tenant_id: "t_acme", platform_admin: false, accessible_tenants: ["t_acme"], all_tenants: false };

// Ids straight out of the deployed fixture — a rename in the projection should
// break this spec loudly rather than let it assert against nothing.
const A_SUBNET = "subnet-0651f2da157e5b5d3";
const AN_IGW = "igw-0f9a0365a92d4b32f";

// Every /api/topology/cloud request the canvas makes, counted: the previous defect
// was that this route was NEVER CALLED, and an assertion on rendered pixels alone
// would not have said so.
async function openCanvas(page: Page): Promise<{ cloudCalls: () => number }> {
  let calls = 0;
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const url = new URL(route.request().url());
    const json = (b: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(b) });
    const p = url.pathname;
    if (p.includes("/api/auth/me")) return json(ME);
    if (p.includes("/api/scopes")) return json({ scopes: [{ tenant_id: "t_acme", tenant_name: "Acme", org_id: "o", org_name: "Acme", region: "us" }], all_tenants: false });
    if (p.includes("/api/topology/cloud")) { calls++; return json(cloudView); }
    if (p.includes("/api/topology/view") || p.includes("/api/topology/graph")) {
      return json({
        view_id: "v", mode: "explore", scope: { tenant_id: "t_acme" }, layout_type: "spine_leaf",
        generated_at: new Date().toISOString(), groups: [], overlays: ["health"],
        nodes: [{ id: "lan1", label: "lan1", kind: "router", health: "ok", confidence: 1, resolved: true, evidence: [] }],
        edges: [],
      });
    }
    return json({});
  });
  await page.goto("/#/infrastructure/topology-canvas");
  await expect(page.getByTestId("rf__node-lan1")).toBeVisible(); // LAN canvas up first
  return { cloudCalls: () => calls };
}

test("selecting Cloud mounts the cloud canvas and renders the real discovered network", async ({ page }) => {
  const { cloudCalls } = await openCanvas(page);

  await page.getByLabel("Network domain").selectOption("cloud");

  // 1. The selection actually reaches the network. (The first defect died here.)
  await expect.poll(cloudCalls, { message: "GET /api/topology/cloud was never requested" }).toBeGreaterThan(0);

  // 2. The honest non-live states must NOT be what the operator ends up looking at.
  await expect(page.getByText("No cloud network discovered yet")).toHaveCount(0);
  await expect(page.getByText("Unable to load the cloud network")).toHaveCount(0);
  await expect(page.getByText("Loading the cloud network…")).toHaveCount(0);

  // 3. Real nodes on the real canvas — a subnet and a gateway from the fixture.
  await expect(page.getByTestId(`rf__node-${A_SUBNET}`)).toBeVisible();
  await expect(page.getByTestId(`rf__node-${AN_IGW}`)).toBeVisible();

  await page.screenshot({ path: "test-results/cloud-domain.png", fullPage: false });
});

// "Is it intentional that connection between the blocks inside vpc is not shown?"
// It was not. The routes were all THERE — 19 edge elements, correct stroke, correct
// geometry — and every single one was painted UNDER its own VPC's shade box, because
// React Flow's edge layer is z-index:auto and loses a tree-order tie with the group
// node at z 0. The canvas said "we don't know how these connect" while holding the
// route table that says exactly how.
//
// Counting the edges is what MISSED it the first time, so this asserts what the
// operator actually gets: hit-test the midpoint of an edge and require the topmost
// element there to be the edge itself, not the box it lives in.
test("routes inside a VPC are visible, not buried under the group box", async ({ page }) => {
  await openCanvas(page);
  await page.getByLabel("Network domain").selectOption("cloud");
  await expect(page.getByTestId(`rf__node-${A_SUBNET}`)).toBeVisible();
  await page.waitForTimeout(700); // fit animation

  const probe = await page.evaluate(() => {
    const paths = Array.from(document.querySelectorAll(".react-flow__edge-path"));
    let occluded = 0, checked = 0;
    for (const p of paths) {
      const b = p.getBoundingClientRect();
      if (b.width < 2 && b.height < 2) continue; // degenerate; nothing to see
      checked++;
      const hit = document.elementFromPoint(b.x + b.width / 2, b.y + b.height / 2);
      // A hit on the group node means the shade box is on top of the line.
      if (hit?.closest(".react-flow__node-groupNode")) occluded++;
    }
    return { total: paths.length, checked, occluded };
  });

  expect(probe.total, "route edges rendered").toBeGreaterThan(10);
  expect(probe.checked, "edges with real geometry").toBeGreaterThan(0);
  expect(probe.occluded, "edges hidden under their own group box").toBe(0);
});

// "Topology canvas should be 100." Two different things have to be true for that,
// and only one of them is CSS — so both are measured here rather than eyeballed.
test("the canvas fills the window, and the network fills the canvas", async ({ page }) => {
  await openCanvas(page);
  await page.getByLabel("Network domain").selectOption("cloud");
  await expect(page.getByTestId(`rf__node-${A_SUBNET}`)).toBeVisible();
  await page.waitForTimeout(700); // let the fit animation settle

  const vp = page.viewportSize();
  const stage = await page.locator(".topo-stage").first().boundingBox();
  expect(vp).not.toBeNull();
  expect(stage).not.toBeNull();
  if (!vp || !stage) return;

  // 1. THE STAGE FILLS THE WINDOW. Only the shell chrome above it and a small
  //    gutter may be spent — no dead band underneath (the old
  //    `min-height: calc(100vh - 96px)` guess left 30px of nothing).
  expect(stage.width).toBeGreaterThan(vp.width * 0.9);
  const gapBelow = vp.height - (stage.y + stage.height);
  expect(gapBelow, "dead space under the canvas").toBeLessThanOrEqual(12);

  // 2. THE NETWORK FILLS THE STAGE. The real defect behind "the canvas is
  //    empty": independent cloud boxes were laid out in one long row, so
  //    fit-to-view shrank them into a thin horizontal strip with the top and
  //    bottom thirds blank. Measured as the union of the rendered node boxes
  //    against the stage, so a regression to a ribbon layout fails here.
  const content = await page.evaluate(() => {
    const nodes = Array.from(document.querySelectorAll(".react-flow__node"));
    if (!nodes.length) return null;
    let x1 = Infinity, y1 = Infinity, x2 = -Infinity, y2 = -Infinity;
    for (const n of nodes) {
      const b = n.getBoundingClientRect();
      if (!b.width || !b.height) continue;
      x1 = Math.min(x1, b.x); y1 = Math.min(y1, b.y);
      x2 = Math.max(x2, b.x + b.width); y2 = Math.max(y2, b.y + b.height);
    }
    return { w: x2 - x1, h: y2 - y1 };
  });
  expect(content).not.toBeNull();
  if (!content) return;
  expect(content.w / stage.width, "content width vs stage").toBeGreaterThan(0.7);
  expect(content.h / stage.height, "content height vs stage").toBeGreaterThan(0.6);
});
