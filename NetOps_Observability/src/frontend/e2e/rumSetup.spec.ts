// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Real-user setup (Digital Experience › Data Health, 2026-11-22). Drives the
// REAL SPA with the backend mocked at the network boundary: the four numbered
// steps render, generating a key puts it into the tag and the proxy rules, the
// rule switches per layer, the feed list says which apps send and which went
// quiet, body text is ≥ 14 px, and a phone width has no sideways scroll.

import { test, expect, type Page, type Route } from "@playwright/test";

const ME = { username: "alice", role: "admin", tenant_id: "t_acme", platform_admin: false, accessible_tenants: ["t_acme"], all_tenants: false };

const DATA_HEALTH = {
  window: "24h", enabled: true, policy_version: 1,
  data_health: { can_confirm: false, explanation: "One kind of instrument is reporting.", anchor_sources_flowing: 1, sources: [] },
};

const SOURCES = {
  status: "ok", window_s: 86400, lookback_s: 604800, reporting: 1, quiet: 1, truncated: false,
  sources: [
    { app: "hr.example.com", app_source: "hostname", state: "quiet", events_24h: 0, page_views_24h: 0, errors_24h: 0, last_seen: "2026-11-20T10:00:00Z" },
    { app: "checkout", app_source: "attribute", state: "reporting", events_24h: 120, page_views_24h: 40, errors_24h: 3, last_seen: new Date().toISOString() },
  ],
};

async function mockApi(page: Page, keys: unknown[]) {
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const url = new URL(route.request().url());
    const json = (b: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(b) });
    const p = url.pathname;
    if (p.includes("/api/auth/me")) return json(ME);
    if (p.includes("/api/scopes")) return json({ scopes: [{ tenant_id: "t_acme", tenant_name: "Acme", org_id: "o", org_name: "Acme", region: "us" }], all_tenants: false });
    if (p.endsWith("/api/dem/data-health")) return json(DATA_HEALTH);
    if (p.endsWith("/api/dem/rum/sources")) return json(SOURCES);
    if (p.endsWith("/api/apikeys") && route.request().method() === "POST") {
      keys.push(route.request().postDataJSON());
      return json({ key: { id: "k1" }, secret: "cx_e2e_secret" }, 201);
    }
    if (p.endsWith("/api/correlations") || p.endsWith("/api/incidents")) return json([]);
    return json({});
  });
}

test("the setup walks four steps, puts a generated key into the tag and the rules, and lists the feeds", async ({ page }) => {
  const keys: unknown[] = [];
  await mockApi(page, keys);
  await page.goto("/#/operations/digital-experience/data-health");
  const setup = page.getByTestId("rum-setup");
  await expect(setup).toBeVisible();
  for (const h of ["Get a key", "The tag", "Add it once", "Is it working?"]) {
    await expect(setup.getByRole("heading", { name: h })).toBeVisible();
  }

  await setup.getByRole("button", { name: "Generate a key" }).click();
  await expect(setup.getByLabel("Ingest key")).toContainText("cx_e2e_secret");
  expect(keys).toEqual([{ label: "Real-user monitoring", scopes: ["ingest:experience"] }]);
  await expect(setup.getByLabel("Real-user tag")).toContainText("data-key='cx_e2e_secret'");
  await expect(setup.getByLabel("Real-user tag")).not.toContainText("data-app");

  await setup.getByRole("tab", { name: "F5 BIG-IP (iRule)" }).click();
  await expect(setup.getByLabel("F5 BIG-IP (iRule) rule")).toContainText("STREAM::expression");
  await expect(setup.getByLabel("F5 BIG-IP (iRule) rule")).toContainText("cx_e2e_secret");

  await expect(setup.getByTestId("rum-summary")).toHaveText("1 app is sending real-user data; 1 went quiet (nothing in the last 24 hours).");
  const table = setup.getByRole("table", { name: "Apps sending real-user data" });
  await expect(table.getByText("Went quiet")).toBeVisible();
  await expect(table.getByText("Named by its web address")).toBeVisible();
  await expect(setup).not.toContainText("CORS_ALLOWED_ORIGINS");
});

test("body text is at least 14px and a phone width does not scroll sideways", async ({ page }) => {
  await mockApi(page, []);
  await page.setViewportSize({ width: 390, height: 900 });
  await page.goto("/#/operations/digital-experience/data-health");
  const setup = page.getByTestId("rum-setup");
  await expect(setup.getByTestId("rum-summary")).toBeVisible();
  const sizes = await setup.locator("p, li h4, pre").evaluateAll((els) =>
    els.map((el) => parseFloat(getComputedStyle(el).fontSize)));
  expect(sizes.length).toBeGreaterThan(4);
  for (const px of sizes) expect(px).toBeGreaterThanOrEqual(14);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});
