// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Overview smoke (2026-11-22): Operations Overview and My Dashboard merged into
// ONE default page. Drives the REAL SPA with the backend mocked at the network
// boundary and checks: the page renders its groups in order, a tenant user never
// sees the platform's own panels, the old addresses land on it, the collapsed
// Traffic group stays closed, and nothing scrolls sideways at phone width.

import { test, expect, type Page, type Route } from "@playwright/test";

// First paint after a navigation compiles the lazy page chunk on the cold dev
// server: the repo-wide 30 s first-paint wait. Only the FIRST assertion after
// each goto/reload takes it; every later assertion keeps the default, tight wait.
const FIRST_PAINT = 30_000;

const ME = { username: "alice", role: "operator", tenant_id: "t_acme", platform_admin: false, accessible_tenants: ["t_acme"], all_tenants: false };
const HEALTH = { scope: "global", score: 96, band: "healthy", confidence: "high", coverage_status: "OK", signal_classes_live: ["availability", "device_health"], contributions: [], stale_inputs: [] };

async function mockApi(page: Page, me = ME) {
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const url = new URL(route.request().url());
    const json = (b: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(b) });
    const p = url.pathname;
    if (p.includes("/api/auth/me")) return json(me);
    if (p.includes("/api/scopes")) return json({ scopes: [{ tenant_id: "t_acme", tenant_name: "Acme", org_id: "o", org_name: "Acme", region: "us" }], all_tenants: false });
    if (p.endsWith("/api/correlations")) return json({ data: [] });
    if (p.endsWith("/api/correlations/stats")) return json({ open: 0, open_confirmed: 0, open_suspected: 0, signatures_matched: 0 });
    if (p.endsWith("/api/health/score")) return json(HEALTH);
    if (p.endsWith("/api/geomap")) return json({ geo_enabled: true, sites: [
      { name: "HQ", slug: "hq", lat: 0, lng: 0, has_coords: true, devices: 4, up: 4, down: 0 },
      { name: "Branch 7", slug: "b7", lat: 0, lng: 0, has_coords: true, devices: 2, up: 0, down: 2 },
    ] });
    if (p.endsWith("/api/events/feed")) return json({ items: [] });
    if (p.endsWith("/api/metrics/forecast")) return json({ interfaces: [], min_days: 14 });
    if (p.endsWith("/api/paths/health")) return json({ paths: [] });
    if (p.endsWith("/api/alerts")) return json([]);
    if (p.includes("/api/metrics/query")) return json({ status: "success", data: { resultType: "vector", result: [] } });
    return json({});
  });
}

test("the Operations Overview is the default Overview again", async ({ page }) => {
  await mockApi(page);
  await page.goto("/#/overview/operations");
  await expect(page.getByTestId("operations-overview")).toBeVisible({ timeout: FIRST_PAINT });
  await expect(page.getByRole("heading", { level: 1, name: "Operations Overview" })).toBeVisible();
  await expect(page.getByTestId("overview-page")).toHaveCount(0);
});

test("the standard layout renders its groups in order, with Traffic closed", async ({ page }) => {
  await mockApi(page);
  await page.goto("/#/overview/operations/standard");
  const root = page.getByTestId("overview-page");
  // First paint compiles the lazy page chunk on the cold dev server: the repo-wide 30 s first-paint wait.
  await expect(root.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible({ timeout: FIRST_PAINT });
  await expect(page.getByTestId("overview-attention")).toHaveText("Nothing needs attention right now.");
  await expect(root.locator(".dm-group-head")).toHaveText([
    "Open problems", "What is broken now", "Health by site", "What changed", "Is data arriving", "Traffic and resources",
  ]);
  const traffic = root.locator("details.dm-group").last();
  await expect(traffic).not.toHaveAttribute("open", "");
  // Health by site: worst first.
  await expect(page.getByTestId("overview-site-health").locator("tbody tr").first()).toContainText("Branch 7");
  // A tenant user never sees the platform's own health.
  await expect(page.getByText("Platform health (internal)")).toHaveCount(0);
});

for (const old of ["#/overview/board", "#/dashboards/board", "#/dashboards/operations"]) {
  test(`${old} lands on the Overview`, async ({ page }) => {
    await mockApi(page);
    await page.goto(`/${old}`);
    await expect(page.getByTestId("operations-overview")).toBeVisible({ timeout: FIRST_PAINT });
    await expect(page).toHaveURL(/#\/overview\/operations$/);
  });
}

test("Overview has no sideways scroll at phone width", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockApi(page);
  for (const addr of ["/#/overview/operations", "/#/overview/operations/standard"]) {
    await page.goto(addr);
    await expect(page.locator(".fp.dm-board").first()).toBeVisible({ timeout: FIRST_PAINT });
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, addr).toBeLessThanOrEqual(1);
  }
});

for (const theme of ["light", "indigo"] as const) {
  test(`Overview headings and body meet the type floor (${theme === "light" ? "light" : "dark"})`, async ({ page }) => {
    await page.addInitScript((t) => localStorage.setItem("netops.theme", t), theme);
    await mockApi(page);
    await page.goto("/#/overview/operations/standard");
    const head = page.locator(".overview-page .dm-group-head").first();
    await expect(head).toBeVisible({ timeout: FIRST_PAINT });
    expect(await head.evaluate((el) => parseFloat(getComputedStyle(el).fontSize))).toBeGreaterThanOrEqual(16);
    const body = page.getByTestId("overview-attention").locator(".fp-spot-text");
    expect(await body.evaluate((el) => parseFloat(getComputedStyle(el).fontSize))).toBeGreaterThanOrEqual(14);
  });
}

test("a team default opens for the tenant, and the Operations Overview keeps its own address", async ({ page }) => {
  await mockApi(page);
  const board = {
    id: "0f1e2d3c4b5a69788796a5b4c3d2e1f0", type: "dashboard", name: "NOC wall", owner: "adm", tenant_id: "t_acme",
    body: { v: 1, cells: [{ type: "rca-top-issues", span: 12 }] }, created_at: "2026-11-22T10:00:00Z", updated_at: "2026-11-22T10:00:00Z",
  };
  // Registered after mockApi, so Playwright matches it first.
  await page.route(/\/api\/settings\/overview-default$/, (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ tenant_id: "t_acme", dashboard_id: board.id, dashboard: board, unavailable: false }) }));
  await page.goto("/#/overview/operations");
  // First paint compiles the lazy page chunk on the cold dev server (CI): the repo-wide 30 s first-paint wait.
  await expect(page.getByText("Your team's default: NOC wall")).toBeVisible({ timeout: FIRST_PAINT });
  await expect(page.getByTestId("team-default-board")).toBeVisible();
  await page.getByTestId("dashboard-picker").selectOption({ label: "Operations Overview" });
  await expect(page).toHaveURL(/#\/overview\/operations\/builtin$/);
  await expect(page.getByRole("heading", { level: 1, name: "Operations Overview" })).toBeVisible();
});
