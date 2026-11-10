// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Network Scan → "Scans for a customer" (tenant-owned discovery scopes,
// 2026-11-10), end to end against a faked API that answers the way the real one
// does: the platform administrator adds a scan for RETAIL with RETAIL's own SNMP
// profile and sees its devices, the duplicate of the platform scan flagged; a
// customer administrator sees only its own scan, read-only, and never fetches
// the tenant list or sends a write.

import { test, expect, type Page, type Route } from "@playwright/test";

type Scope = Record<string, unknown> & { id: string; tenant_id: string; name: string };

function newServer() {
  return { scopes: [] as Scope[], posts: [] as Record<string, unknown>[], writes: 0, tenantReads: 0 };
}

const FOUND = [
  { id: "cedge-81-aa", name: "cEDGE-81", address: "10.70.0.81", vendor: "cisco", credential_ref: "p-retail", also_found_by_platform: true },
  { id: "cedge-82-bb", name: "cEDGE-82", address: "10.70.0.82", vendor: "cisco", credential_ref: "p-retail", also_found_by_platform: false },
];

async function boot(page: Page, platform: boolean, srv: ReturnType<typeof newServer>) {
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    const m = req.method();
    const json = (b: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(b) });
    if (p === "/api/auth/me") {
      return json(platform
        ? { username: "root", role: "super-admin", tenant_id: "global", platform_admin: true, all_tenants: true, accessible_tenants: [], org_id: "global" }
        : { username: "ops", role: "super-admin", tenant_id: "t_retail", platform_admin: false, accessible_tenants: ["t_retail"], all_tenants: false, org_id: "org-retail" });
    }
    if (p === "/api/scopes") return json({ scopes: [{ tenant_id: "t_retail", tenant_name: "RETAIL-WALMART", org_id: "org-retail", org_name: "Retail", region: "us" }], all_tenants: platform });
    if (p === "/api/discovery/config") {
      if (!platform) return json({ error: "platform administrator required" }, 403);
      return json({ config: { enabled: true, ranges: ["10.70.0.80/29"], allow_non_private: false, interval_sec: 300 }, limits: { max_hosts: 4096, max_ranges: 32 }, stats: {}, scan_profiles: { total: 1, v2c: 1, v3: 0 }, found: [] });
    }
    if (p === "/api/tenants") {
      srv.tenantReads++;
      if (!platform) return json({ error: "platform administrator required" }, 403);
      return json([{ id: "global", name: "Provider", slug: "global" }, { id: "t_retail", name: "RETAIL-WALMART", slug: "retail" }, { id: "t_acme", name: "Acme", slug: "acme" }]);
    }
    if (p === "/api/snmp/credentials") {
      const all = [
        { id: "p-retail", name: "RETAIL edges ro", version: "v2c", tenant_id: "t_retail" },
        { id: "p-acme", name: "Acme ro", version: "v2c", tenant_id: "t_acme" },
        { id: "p-plat", name: "Platform ro", version: "v2c" },
      ];
      return json(platform ? all : all.filter((c) => c.tenant_id === "t_retail"));
    }
    if (p === "/api/discovery/scopes" && m === "GET") {
      const visible = platform ? srv.scopes : srv.scopes.filter((s) => s.tenant_id === "t_retail");
      return json({ scopes: visible, limits: { max_hosts: 4096, per_customer: 16, max_credential_refs: 16 } });
    }
    if (p.startsWith("/api/discovery/scopes") && m !== "GET") {
      srv.writes++;
      if (!platform) return json({ error: "platform administrator required" }, 403);
      const body = req.postDataJSON() as Record<string, unknown>;
      srv.posts.push(body);
      const sc: Scope = {
        ...body, id: "ds-0000000000000001", tenant_id: String(body.tenant_id), tenant_name: "RETAIL-WALMART", name: String(body.name),
        status: { last_sweep: new Date().toISOString(), answering: 2, stale: 0 }, found: FOUND, found_total: 2,
      };
      srv.scopes.push(sc);
      return json(sc, 201);
    }
    return json([]);
  });
}

test("the platform administrator adds a scan for a customer with the customer's own profile", async ({ page }) => {
  const srv = newServer();
  await boot(page, true, srv);
  await page.goto("/#/admin/discovery/scan");
  await expect(page.getByRole("heading", { name: "Scans for a customer" })).toBeVisible();
  await expect(page.getByText("No customer has its own scan yet.")).toBeVisible();
  await page.getByRole("button", { name: "New scan for a customer" }).click();

  const steps = page.getByRole("list", { name: "Set up a scan for a customer" });
  await steps.getByLabel("Customer").selectOption("t_retail");
  const profiles = steps.getByRole("group", { name: "The customer's SNMP profiles" });
  await expect(profiles.getByRole("checkbox")).toHaveCount(1); // RETAIL's only — never Acme's or the platform's
  await expect(profiles).toContainText("RETAIL edges ro");
  await profiles.getByRole("checkbox").check();
  await steps.getByLabel("Name of this scan").fill("RETAIL edges");
  await steps.getByLabel("Addresses to scan, comma-separated").fill("10.70.0.80/30");
  await expect(steps.getByText("4 / 4,096 addresses")).toBeVisible();
  await steps.getByRole("button", { name: "Add scan" }).click();

  await expect(page.getByText("Scan added. It runs within a few minutes.")).toBeVisible();
  expect(srv.posts).toEqual([{ tenant_id: "t_retail", name: "RETAIL edges", ranges: ["10.70.0.80/30"], allow_non_private: false, credential_refs: ["p-retail"], enabled: true }]);
  const scan = page.getByRole("region", { name: "Scan RETAIL edges" });
  await expect(scan).toContainText("RETAIL-WALMART");
  await expect(scan.getByRole("table")).toContainText("cEDGE-81");
  await expect(scan.getByRole("row", { name: /cEDGE-81/ })).toContainText("Also found by the platform scan");
  await expect(scan.getByRole("row", { name: /cEDGE-82/ })).not.toContainText("Also found by the platform scan");
  await expect(scan.getByRole("note")).toContainText("not attributed to anyone until one copy is removed");
});

test("a customer administrator sees its own scan read-only and sends no write", async ({ page }) => {
  const srv = newServer();
  srv.scopes.push({
    id: "ds-0000000000000001", tenant_id: "t_retail", tenant_name: "RETAIL-WALMART", name: "RETAIL edges",
    ranges: ["10.70.0.80/30"], allow_non_private: false, credential_refs: ["p-retail"], enabled: true,
    status: { last_sweep: new Date().toISOString(), answering: 2, stale: 0 }, found: FOUND, found_total: 2,
  });
  srv.scopes.push({ id: "ds-0000000000000002", tenant_id: "t_acme", name: "Acme scan", ranges: ["10.9.0.0/30"], found: [], found_total: 0 });
  await boot(page, false, srv);
  await page.goto("/#/admin/discovery/scan");
  await expect(page.getByText("Your platform operator runs the network scan.")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Your scans" })).toBeVisible();
  const scan = page.getByRole("region", { name: "Scan RETAIL edges" });
  await expect(scan.getByRole("row", { name: /cEDGE-81/ })).toContainText("Also found by the platform scan");
  await expect(page.getByRole("region", { name: "Scan Acme scan" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "New scan for a customer" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Change scan|Remove scan/ })).toHaveCount(0);
  await page.waitForTimeout(500);
  expect(srv.tenantReads).toBe(0);
  expect(srv.writes).toBe(0);
});
