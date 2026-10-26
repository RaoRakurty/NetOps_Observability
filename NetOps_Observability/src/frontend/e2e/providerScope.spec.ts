// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Provider scope vs All tenants (tracker 365), end to end against a faked API
// that isolates the way the real one now does: X-Acting-Tenant "global"
// (Provider) answers ONLY the platform's own integrations; no header is the
// All-tenants view and answers every tenant's, each carrying its tenantId.
//
// The incident it guards (2026-10-25): under "Provider" the owner saw every
// tenant's NMS integrations unlabelled and deleted another tenant's vManage
// integration. So the spec proves, in a browser:
//   1. "All tenants" opens NMS Integrations with a Tenant column naming each row;
//   2. picking Provider sends X-Acting-Tenant: global and shows only Provider rows;
//   3. deleting another tenant's integration names that tenant in the dialog,
//      and dismissing it sends no DELETE.

import { test, expect, type Page, type Route } from "@playwright/test";

const INTEGRATIONS = [
  { id: "nmsi-retail", tenantId: "t_retail", vendor: "vmanage", displayName: "SDWAN", enabled: true, baseUrl: "https://vmanage.retail.example", pollIntervalS: 300 },
  { id: "nmsi-prov", tenantId: "global", vendor: "vmanage", displayName: "Provider vManage", enabled: true, baseUrl: "https://vmanage.prov.example", pollIntervalS: 300 },
];

async function boot(page: Page) {
  const seen = { actingOnList: [] as string[], deletes: 0 };
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    const acting = req.headers()["x-acting-tenant"] || "";
    const json = (b: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(b) });
    if (p === "/api/auth/me") {
      return json({ username: "root", role: "super-admin", tenant_id: "global", platform_admin: true, all_tenants: true, accessible_tenants: [], org_id: "global" });
    }
    if (p === "/api/scopes") {
      return json({
        scopes: [
          { tenant_id: "global", tenant_name: "Provider", org_id: "global", org_name: "Global", region: "" },
          { tenant_id: "t_retail", tenant_name: "RETAIL", org_id: "global", org_name: "Global", region: "us-east" },
        ],
        all_tenants: true,
      });
    }
    if (p === "/api/nms/connectors") return json({ connectors: [] });
    if (p === "/api/nms/integrations" && req.method() === "GET") {
      seen.actingOnList.push(acting);
      // The backend's rule: Provider is the platform's own rows only.
      const rows = acting === "global" ? INTEGRATIONS.filter((i) => i.tenantId === "global") : INTEGRATIONS;
      return json({ integrations: rows });
    }
    if (p.startsWith("/api/nms/integrations/") && req.method() === "DELETE") {
      seen.deletes++;
      return route.fulfill({ status: 204, body: "" });
    }
    if (p.endsWith("/states")) return json({ states: [] });
    if (p.endsWith("/health")) return json({ error: "no health" }, 404);
    return json({});
  });
  return seen;
}

test("All tenants: NMS Integrations opens with a Tenant column naming each row", async ({ page }) => {
  await boot(page);
  await page.goto("/#/infrastructure/nms");
  await expect(page.getByRole("columnheader", { name: "Tenant" })).toBeVisible();
  const retail = page.getByRole("row").filter({ has: page.getByRole("button", { name: "SDWAN" }) });
  await expect(retail.getByTestId("nms-tenant")).toHaveText("RETAIL");
  const prov = page.getByRole("row").filter({ has: page.getByRole("button", { name: "Provider vManage" }) });
  await expect(prov.getByTestId("nms-tenant")).toHaveText("Provider");
  // The top bar says which view this is.
  await expect(page.locator(".scope-btn")).toContainText("All tenants");
});

test("picking Provider narrows to the platform's own integrations", async ({ page }) => {
  const seen = await boot(page);
  await page.goto("/#/infrastructure/nms");
  await expect(page.getByRole("button", { name: "SDWAN" })).toBeVisible();
  await page.locator(".scope-btn").click();
  await expect(page.getByText("Every tenant, each row labelled with its tenant")).toBeVisible();
  await page.locator(".scope-opt").filter({ hasText: "Provider" }).click(); // reloads the app under the new scope
  await expect(page.getByRole("button", { name: "Provider vManage" })).toBeVisible();
  await expect(page.getByRole("button", { name: "SDWAN" })).toHaveCount(0);
  await expect(page.getByRole("columnheader", { name: "Tenant" })).toHaveCount(0);
  await expect(page.locator(".scope-btn")).toContainText("Provider");
  expect(seen.actingOnList).toContain("global");
});

test("deleting another tenant's integration names that tenant, and dismissing deletes nothing", async ({ page }) => {
  const seen = await boot(page);
  await page.goto("/#/infrastructure/nms");
  await page.getByRole("button", { name: "SDWAN" }).click();
  await expect(page.getByTestId("nms-owner-note")).toContainText('belongs to the tenant "RETAIL", not Provider');
  let message = "";
  page.once("dialog", async (d) => {
    message = d.message();
    await d.dismiss();
  });
  await page.getByRole("button", { name: "Delete" }).click();
  await expect.poll(() => message).toContain('Delete "SDWAN"?');
  expect(message).toContain('belongs to the tenant "RETAIL"');
  expect(seen.deletes).toBe(0);
});
