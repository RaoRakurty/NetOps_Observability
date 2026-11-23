// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// My dashboards (2026-11-22): the builder under Overview. Drives the REAL SPA
// with the saved-object API mocked statefully at the network boundary: make a
// copy of the default, save it, reload it by its address, delete it — and an id
// the server refuses (another tenant's) reads "does not exist", never a blank.

import { test, expect, type Page, type Route } from "@playwright/test";

// First paint after a navigation compiles the lazy page chunk on the cold dev
// server: the repo-wide 30 s first-paint wait. Only the FIRST assertion after
// each goto/reload takes it; every later assertion keeps the default, tight wait.
const FIRST_PAINT = 30_000;

const ME = { username: "alice", role: "operator", tenant_id: "t_acme", platform_admin: false, accessible_tenants: ["t_acme"], all_tenants: false };
const HEALTH = { scope: "global", score: 96, band: "healthy", confidence: "high", coverage_status: "OK", signal_classes_live: ["availability"], contributions: [], stale_inputs: [] };

type Saved = { id: string; type: string; name: string; owner: string; tenant_id: string; body: unknown; created_at: string; updated_at: string };

async function mockApi(page: Page, store: Saved[]) {
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const req = route.request();
    const url = new URL(req.url());
    const p = url.pathname;
    const json = (b: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(b) });
    if (p.includes("/api/auth/me")) return json(ME);
    if (p.includes("/api/scopes")) return json({ scopes: [{ tenant_id: "t_acme", tenant_name: "Acme", org_id: "o", org_name: "Acme", region: "us" }], all_tenants: false });
    if (p === "/api/saved" && req.method() === "GET") return json(store.filter((s) => s.type === (url.searchParams.get("type") ?? s.type)));
    if (p === "/api/saved" && req.method() === "POST") {
      const b = req.postDataJSON() as { type: string; name: string; body: unknown };
      const now = new Date().toISOString();
      const obj: Saved = { id: `d${store.length + 1}aaaa`, type: b.type, name: b.name, owner: "alice", tenant_id: "t_acme", body: b.body, created_at: now, updated_at: now };
      store.push(obj);
      return json(obj, 201);
    }
    const m = p.match(/^\/api\/saved\/([^/]+)$/);
    if (m) {
      const i = store.findIndex((s) => s.id === m[1]);
      // Another tenant's id, or a deleted one: the server's answer is 404 either way.
      if (i < 0) return route.fulfill({ status: 404, contentType: "text/plain", body: "not found" });
      if (req.method() === "DELETE") { store.splice(i, 1); return route.fulfill({ status: 204, body: "" }); }
      return json(store[i]);
    }
    if (p.endsWith("/api/correlations")) return json({ data: [] });
    if (p.endsWith("/api/correlations/stats")) return json({ open: 0, open_confirmed: 0, open_suspected: 0, signatures_matched: 0 });
    if (p.endsWith("/api/health/score")) return json(HEALTH);
    if (p.endsWith("/api/geomap")) return json({ geo_enabled: true, sites: [] });
    if (p.endsWith("/api/events/feed")) return json({ items: [] });
    if (p.endsWith("/api/metrics/forecast")) return json({ interfaces: [], min_days: 14 });
    if (p.endsWith("/api/paths/health")) return json({ paths: [] });
    if (p.includes("/api/metrics/query")) return json({ status: "success", data: { resultType: "vector", result: [] } });
    return json({});
  });
}

test("make a copy of the default, save it, open it by its address, delete it", async ({ page }) => {
  const store: Saved[] = [];
  await mockApi(page, store);
  await page.goto("/#/overview/dashboards");
  await expect(page.getByTestId("dashboard-list")).toBeVisible({ timeout: FIRST_PAINT });
  await page.getByRole("button", { name: /Make a copy of the default/ }).click();
  await expect(page.getByLabel("Dashboard name")).toHaveValue("Copy of Overview");
  await page.getByLabel("Dashboard name").fill("NOC wall");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page).toHaveURL(/#\/overview\/dashboards\/d1aaaa$/);
  await expect(page.getByRole("heading", { level: 1, name: "NOC wall" })).toBeVisible();
  // The copy carries the Overview's own answer-first panel.
  await expect(page.getByText("Nothing needs attention right now.")).toBeVisible();

  // A reload by address opens the same dashboard.
  await page.reload();
  await expect(page.getByRole("heading", { level: 1, name: "NOC wall" })).toBeVisible({ timeout: FIRST_PAINT });

  // The picker on Overview lists it.
  await page.goto("/#/overview/operations");
  await expect(page.getByTestId("dashboard-picker").locator("option", { hasText: "NOC wall" })).toHaveCount(1, { timeout: FIRST_PAINT });

  await page.goto("/#/overview/dashboards");
  await expect(page.getByTestId("dashboard-list")).toBeVisible({ timeout: FIRST_PAINT });
  await page.getByRole("button", { name: "Delete NOC wall" }).click();
  await page.getByRole("button", { name: 'Delete "NOC wall"' }).click();
  await expect(page.getByText("No dashboards yet. Start from one of the three above.")).toBeVisible();
  expect(store).toHaveLength(0);
});

test("another tenant's dashboard address reads 'does not exist', never a blank page", async ({ page }) => {
  await mockApi(page, []);
  await page.goto("/#/overview/dashboards/0f1e2d3c4b5a69788796a5b4c3d2e1f0");
  await expect(page.getByTestId("dashboard-missing")).toBeVisible({ timeout: FIRST_PAINT });
  await expect(page.getByText("This dashboard does not exist")).toBeVisible();
  await expect(page.getByText("It was deleted, or it belongs to another tenant.")).toBeVisible();
});
