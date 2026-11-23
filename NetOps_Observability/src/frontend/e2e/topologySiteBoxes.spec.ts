// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Site boxes on a real SD-WAN estate (owner, 2026-11-23):
//   "Topology is still not able to box the sites based on site-ids."
//   "I cannot drag a box separately from the devices — they are all glued together."
//
// The lab's shape: 8 branch edges at 7 controller-reported site ids and a full
// mesh of overlay tunnels. Shape: Auto used to call that a dense mesh and draw a
// name-sorted circle, so every site's members scattered and the boxes the api
// sent meant nothing. Now each site is its own box, and a box drags as a unit.

import { test, expect, type Page, type Route } from "@playwright/test";

const ME = { username: "alice", role: "operator", tenant_id: "t_acme", platform_admin: false, accessible_tenants: ["t_acme"], all_tenants: false };
const SCOPES = { scopes: [{ tenant_id: "t_acme", tenant_name: "Acme", org_id: "o", org_name: "Acme", region: "us" }], all_tenants: false };

const SITES: Record<string, string> = {
  "vEdge-20": "20", "cEDGE-40": "40", "vEdge-51": "50", "vEdge-52": "50",
  "cEDGE-60": "60", "cEDGE-80": "80", "cEDGE-81": "81", "vEdge-100": "100",
};
const key = (sid: string) => `discovered:t_acme:sdwan:${sid}`;

function topoView(mode: string) {
  const ids = Object.keys(SITES);
  const nodes = ids.map((id) => ({
    id, label: id, kind: "router", role: "wan_edge", health: "ok", confidence: 1, resolved: true,
    site: key(SITES[id]), site_label: `Site ${SITES[id]} · from vManage`, site_source: "discovered", site_origin: "vmanage",
    group_id: `site:${key(SITES[id])}`, evidence: [{ source: "inventory", confidence: 1 }],
  }));
  const edges: unknown[] = [];
  for (let i = 0; i < ids.length; i++) {
    for (let j = i + 1; j < ids.length; j++) {
      edges.push({ id: `t-${i}-${j}`, source: ids[i], target: ids[j], relationship: "overlay", status: "up", confidence: 1,
        evidence: [{ source: "vmanage", confidence: 1 }] });
    }
  }
  const bySite = new Map<string, string[]>();
  for (const id of ids) bySite.set(SITES[id], [...(bySite.get(SITES[id]) ?? []), id]);
  const groups = [...bySite.entries()].map(([sid, children]) => ({
    id: `site:${key(sid)}`, label: `Site ${sid} · from vManage`, group_type: "site", children,
    health: "ok", collapsed: false, source: "discovered", origin: "vmanage",
  }));
  return {
    view_id: "lab", mode, scope: { tenant_id: "t_acme" }, layout_type: "hierarchical", generated_at: new Date().toISOString(),
    nodes, edges, groups, overlays: ["health"],
  };
}

async function mockApi(page: Page) {
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const url = new URL(route.request().url());
    const json = (b: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(b) });
    const p = url.pathname;
    if (p.includes("/api/auth/me")) return json(ME);
    if (p.includes("/api/scopes")) return json(SCOPES);
    if (p.includes("/api/topology/view")) return json(topoView(url.searchParams.get("mode") || "explore"));
    if (p.includes("/api/topology/graph")) return json({ ...topoView("explore"), stale: false });
    if (p === "/api/sites") return json({ sites: [], active: "internal" });
    if (p.includes("/api/geomap")) return json({ sites: [], devices: [], enabled: true });
    return json({});
  });
}

type Box = { x: number; y: number; w: number; h: number };
async function box(page: Page, testId: string): Promise<Box> {
  const b = await page.getByTestId(testId).boundingBox();
  if (!b) throw new Error(`${testId} has no box`);
  return { x: b.x, y: b.y, w: b.width, h: b.height };
}
/** Wait for fit-to-view to land and stop: measuring (or grabbing) mid-animation
 *  reads the box and its devices at different zoom frames. */
async function settled(page: Page, testId: string): Promise<void> {
  let last = "";
  await expect.poll(async () => {
    const b = await box(page, testId);
    const onStage = b.y > 0 && b.y + b.h < 950 && b.x > 0 && b.x + b.w < 1600;
    const now = JSON.stringify(b);
    const still = now === last;
    last = now;
    return onStage && still;
  }, { timeout: 8000, intervals: [250] }).toBe(true);
}
const inside = (inner: Box, outer: Box) =>
  inner.x >= outer.x - 1 && inner.y >= outer.y - 1 && inner.x + inner.w <= outer.x + outer.w + 1 && inner.y + inner.h <= outer.y + outer.h + 1;

test("each reported site is its own box — Auto does not draw the mesh as a circle", async ({ page }) => {
  await page.setViewportSize({ width: 1600, height: 950 });
  await mockApi(page);
  await page.goto("/#/investigate/topology");
  await expect(page.getByTestId("rf__node-vEdge-51")).toBeVisible();
  await settled(page, `rf__node-site:${key("50")}`);
  // Auto names no shape on a grouped view.
  await expect(page.getByLabel("Arrange by topology shape").locator("option[value=auto]")).toHaveText("Auto");
  // Site 50's two edges sit inside Site 50's box, and nobody else does.
  const site50 = await box(page, `rf__node-site:${key("50")}`);
  expect(inside(await box(page, "rf__node-vEdge-51"), site50)).toBe(true);
  expect(inside(await box(page, "rf__node-vEdge-52"), site50)).toBe(true);
  for (const other of ["vEdge-20", "cEDGE-40", "cEDGE-60", "cEDGE-80", "cEDGE-81", "vEdge-100"]) {
    expect(inside(await box(page, `rf__node-${other}`), site50), `${other} drawn inside Site 50`).toBe(false);
  }
  // Seven separate sites read as seven separate boxes: no two boxes overlap.
  // (The circle Auto used to draw packed single-device sites so tightly that
  // their boxes ran into one another.)
  const sites = ["20", "40", "50", "60", "80", "81", "100"];
  const boxes = await Promise.all(sites.map((s) => box(page, `rf__node-site:${key(s)}`)));
  for (let i = 0; i < boxes.length; i++) {
    for (let j = i + 1; j < boxes.length; j++) {
      const a = boxes[i], b = boxes[j];
      const overlap = a.x < b.x + b.w - 1 && b.x < a.x + a.w - 1 && a.y < b.y + b.h - 1 && b.y < a.y + a.h - 1;
      expect(overlap, `Site ${sites[i]} and Site ${sites[j]} boxes overlap`).toBe(false);
    }
  }
});

test("dragging a site box moves its devices with it, and only its devices", async ({ page }) => {
  await page.setViewportSize({ width: 1600, height: 950 });
  await mockApi(page);
  await page.goto("/#/investigate/topology");
  await expect(page.getByTestId("rf__node-vEdge-51")).toBeVisible();
  const boxId = `rf__node-site:${key("50")}`;
  await settled(page, boxId);
  const b0 = await box(page, boxId);
  const e51 = await box(page, "rf__node-vEdge-51");
  const other = await box(page, "rf__node-cEDGE-80");
  // Grab the box by its label chip — drawn above the tunnel lines, so it is
  // reachable even where every tunnel crosses the box (the full-mesh lab).
  const chip = await page.getByTestId(`rf__node-group-label:site:${key("50")}`).getByText("Site 50 · from vManage").boundingBox();
  if (!chip) throw new Error("site label not drawn");
  const gx = chip.x + chip.width / 2;
  const gy = chip.y + chip.height / 2;
  // The point really is the chip, not a line over it.
  expect(await page.evaluate(([x, y]) => document.elementFromPoint(x, y)?.closest(".react-flow__node")?.getAttribute("data-id"), [gx, gy]))
    .toBe(`group-label:site:${key("50")}`);
  await page.mouse.move(gx, gy);
  await page.mouse.down();
  await page.mouse.move(gx + 60, gy + 90, { steps: 12 });
  await page.mouse.up();
  const e51After = await box(page, "rf__node-vEdge-51");
  const b1 = await box(page, boxId);
  expect(e51After.x - e51.x).toBeGreaterThan(30);
  expect(e51After.y - e51.y).toBeGreaterThan(45);
  expect(inside(e51After, b1)).toBe(true);
  expect(inside(await box(page, "rf__node-vEdge-52"), b1)).toBe(true);
  // A device in another site did not move.
  const otherAfter = await box(page, "rf__node-cEDGE-80");
  expect(Math.abs(otherAfter.x - other.x)).toBeLessThan(2);
  expect(Math.abs(otherAfter.y - other.y)).toBeLessThan(2);
});
