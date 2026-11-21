// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Discovered sites (owner report 2026-11-20: "Topology couldn't create or
// logically group sites for its branches"). With no declared sites, the canvas
// groups devices by the site id their controller reports and MARKS those groups
// as discovered — reading "Site 50 · from vManage", never the raw grouping key.
// Infrastructure → Sites → Manage Sites then adopts them: a preview first,
// already-placed devices left alone, one explicit Adopt.

import { test, expect, type Page, type Route } from "@playwright/test";

const ME = { username: "alice", role: "operator", tenant_id: "t_acme", platform_admin: false, accessible_tenants: ["t_acme"], all_tenants: false };
const SCOPES = { scopes: [{ tenant_id: "t_acme", tenant_name: "Acme", org_id: "o", org_name: "Acme", region: "us" }], all_tenants: false };

const KEY50 = "discovered:t_acme:sdwan:50";
const KEY250 = "discovered:t_acme:sdwan:250";

function node(id: string, site: string, label: string) {
  return {
    id, label: id, kind: "router", health: "ok", confidence: 1, resolved: true,
    site, site_label: label, site_source: "discovered", site_origin: "vmanage", group_id: `site:${site}`,
    evidence: [{ source: "inventory", confidence: 1 }],
  };
}

function topoView(mode: string) {
  return {
    view_id: "v", mode, scope: { tenant_id: "t_acme" }, layout_type: "spine_leaf", generated_at: new Date().toISOString(),
    nodes: [node("vEdge-51", KEY50, "Site 50 · from vManage"), node("vEdge-52", KEY50, "Site 50 · from vManage"), node("vSmart", KEY250, "Site 250 · from vManage")],
    edges: [],
    groups: [
      { id: `site:${KEY250}`, label: "Site 250 · from vManage", group_type: "site", children: ["vSmart"], health: "ok", collapsed: false, source: "discovered", origin: "vmanage" },
      { id: `site:${KEY50}`, label: "Site 50 · from vManage", group_type: "site", children: ["vEdge-51", "vEdge-52"], health: "ok", collapsed: false, source: "discovered", origin: "vmanage" },
    ],
    overlays: ["health"],
  };
}

const PLAN = {
  sites: [
    { key: KEY50, site_id: "50", origin: "vmanage", label: "Site 50 · from vManage", slug: "site-50", name: "Site 50", action: "create",
      devices: [
        { device_id: "vEdge-51", name: "vEdge-51", action: "bind" },
        { device_id: "vEdge-53", name: "vEdge-53", action: "skip", detail: "already placed at Boston by an operator" },
      ] },
  ],
  summary: { create: 1, reuse: 0, bind: 1, skip: 1, refused: 0, error: 0 },
};

async function mockApi(page: Page, adoptCalls: unknown[]) {
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const url = new URL(route.request().url());
    const json = (b: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(b) });
    const p = url.pathname;
    if (p.includes("/api/auth/me")) return json(ME);
    if (p.includes("/api/scopes")) return json(SCOPES);
    if (p.includes("/api/topology/view")) return json(topoView(url.searchParams.get("mode") || "explore"));
    if (p.includes("/api/topology/graph")) return json({ ...topoView("explore"), stale: false });
    if (p === "/api/discovered-sites/adopt") {
      adoptCalls.push(route.request().postDataJSON());
      return json({ dry_run: false, plan: PLAN });
    }
    if (p === "/api/discovered-sites") return json({ adoptable: true, plan: adoptCalls.length ? { sites: [], summary: {} } : PLAN });
    if (p === "/api/sites") return json({ sites: [], active: "internal" });
    if (p.includes("/api/geomap")) return json({ sites: [], devices: [], enabled: true });
    return json({});
  });
}

test("the canvas groups devices by their reported site and marks the group as discovered", async ({ page }) => {
  await mockApi(page, []);
  await page.goto("/#/investigate/topology");
  await expect(page.getByTestId("rf__node-vSmart")).toBeVisible();
  await expect(page.getByText("Site 50 · from vManage").first()).toBeVisible();
  await expect(page.getByText("Discovered site").first()).toBeVisible();
  // The tenant-qualified grouping key is never what a person reads.
  await expect(page.getByText(KEY50)).toHaveCount(0);
});

test("Sites adopts discovered sites after a preview, leaving placed devices alone", async ({ page }) => {
  const adoptCalls: unknown[] = [];
  await mockApi(page, adoptCalls);
  await page.goto("/#/infrastructure/sites/sites");
  await page.getByRole("button", { name: "Adopt discovered sites…" }).click();
  const panel = page.getByRole("region", { name: "Adopt discovered sites" });
  await expect(panel.getByText("Site 50 · from vManage")).toBeVisible();
  await expect(panel.getByText(/already placed at Boston by an operator/)).toBeVisible();
  expect(adoptCalls).toHaveLength(0); // the preview wrote nothing
  await panel.getByRole("button", { name: "Adopt 1 site" }).click();
  await expect(panel.getByText(/Created 1 site, placed 1 device/)).toBeVisible();
  expect(adoptCalls).toEqual([{ dry_run: false, keys: [KEY50] }]);
});
