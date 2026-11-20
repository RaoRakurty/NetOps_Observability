// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Paths section smoke (Paths redesign P0, 2026-11-20). Drives the REAL SPA with
// the backend mocked at the network boundary and checks the section's shape:
// the three measurement pages under the PATHS header with their new names,
// Troubleshooting beside RCA (not under PATHS), every old address still opening
// its page, and the Measured paths empty state saying what is true.

import { test, expect, type Page, type Route } from "@playwright/test";

const ME = { username: "alice", role: "operator", tenant_id: "t_acme", platform_admin: false, accessible_tenants: ["t_acme"], all_tenants: false };

async function mockApi(page: Page) {
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const url = new URL(route.request().url());
    const json = (b: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(b) });
    const p = url.pathname;
    if (p.includes("/api/auth/me")) return json(ME);
    if (p.includes("/api/scopes")) return json({ scopes: [{ tenant_id: "t_acme", tenant_name: "Acme", org_id: "o", org_name: "Acme", region: "us" }], all_tenants: false });
    if (p.endsWith("/api/probe/paths")) return json([]);
    if (p.endsWith("/api/paths/health")) return json({ paths: [] });
    if (p.endsWith("/api/tunnels")) return json({ data: [] });
    if (p.endsWith("/api/correlations") || p.endsWith("/api/incidents")) return json([]);
    return json({});
  });
}

test("Paths groups the three measurement pages; Troubleshooting sits beside RCA", async ({ page }) => {
  await mockApi(page);
  await page.goto("/#/investigate/flowtrace");
  const nav = page.getByRole("navigation", { name: "Investigate views" });
  await expect(nav).toBeVisible();
  const labels = (await nav.locator(".subnav-cell").allInnerTexts()).map((t) => t.replace(/\s+/g, " ").trim());
  const rca = labels.findIndex((t) => t === "RCA");
  expect(labels[rca + 1]).toBe("Troubleshooting");
  // The group header is CSS-uppercased in some themes; compare case-blind.
  const pathsAt = labels.findIndex((t) => /^paths\b/i.test(t));
  expect(pathsAt).toBeGreaterThan(rca + 1);
  expect(labels.slice(pathsAt).map((t) => t.replace(/^paths\s*/i, ""))).toEqual(["Measured paths", "Tunnels", "WAN circuits"]);
  // Exactly one header in the section, and it is the Paths one.
  await expect(nav.locator(".subnav-group")).toHaveCount(1);
});

test("Measured paths says path discovery is not switched on — no env names, no phantom setting", async ({ page }) => {
  await mockApi(page);
  await page.goto("/#/investigate/flowtrace");
  await expect(page.getByTestId("paths-empty-hint")).toHaveText("Path discovery is not switched on for this installation yet.");
  await expect(page.getByText(/API settings/)).toHaveCount(0);
  await expect(page.locator("code", { hasText: /FEATURE_|_TARGETS/ })).toHaveCount(0);
  await expect(page.getByTestId("paths-synthetics-link").getByRole("link")).toHaveAttribute("href", "#/operations/digital-experience/synthetics");
});

for (const [hash, check] of [
  ["#/investigate/tunnels", "Tunnels"],
  ["#/investigate/wan-paths", "WAN circuits"],
  ["#/infrastructure/wan-circuits", "WAN circuits"],
] as const) {
  test(`${hash} opens ${check}`, async ({ page }) => {
    await mockApi(page);
    await page.goto(`/${hash}`);
    await expect(page.getByRole("heading", { name: check, exact: true })).toBeVisible();
  });
}

test("the old Flow Trace address still opens Measured paths", async ({ page }) => {
  await mockApi(page);
  await page.goto("/#/infrastructure/flowtrace");
  await expect(page.getByTestId("paths-empty-hint")).toBeVisible();
});

test("Troubleshooting opens its case picker", async ({ page }) => {
  await mockApi(page);
  await page.goto("/#/investigate/troubleshooting");
  await expect(page.getByTestId("ts-pick")).toBeVisible();
});
