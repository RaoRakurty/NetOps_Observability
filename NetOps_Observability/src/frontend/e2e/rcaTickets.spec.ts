// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Administration → RCA Tickets (owner 2026-10-18), end to end against a faked
// API: the steps unlock in order as destinations and rules come in; a FAILED
// delivery is visible even while the steps before it are locked; the old
// Ticket Delivery address lands on its step.

import { test, expect, type Page, type Route } from "@playwright/test";

type World = { pagerduty: boolean; policies: unknown[]; running: boolean; outbox: unknown[] };

async function boot(page: Page, w: World) {
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const p = new URL(route.request().url()).pathname;
    const json = (b: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(b) });
    if (p === "/api/auth/me") return json({ username: "ops", role: "admin", tenant_id: "t_acme", platform_admin: false, accessible_tenants: ["t_acme"], all_tenants: false, org_id: "org-acme" });
    if (p === "/api/scopes") return json({ scopes: [{ tenant_id: "t_acme", tenant_name: "Acme", org_id: "org-acme", org_name: "Acme", region: "us" }], all_tenants: false });
    if (p === "/api/notify/itsm") {
      return json({
        servicenow: { enabled: false, configured: false, instance_url: "", user: "" },
        jira: { enabled: false, configured: false, base_url: "", email: "" },
        pagerduty: { enabled: w.pagerduty, has_routing_key: w.pagerduty },
        slack: { enabled: false, has_webhook: false },
      });
    }
    if (p === "/api/tac/connectors") return json({ connectors: [] });
    if (p === "/api/incident-policies") return json({ policies: w.policies, ticketing_running: w.running });
    if (p === "/api/auth/permissions") return json({ permissions: { administration: 3, infrastructure: 3 } });
    if (p === "/api/tickets/outbox") return json({ outbox: w.outbox, total: w.outbox.length });
    if (p === "/api/tickets/audit") return json({ audit: [], total: 0 });
    return json({});
  });
}

const step = (page: Page, id: string) => page.locator(`[data-step="${id}"]`);

test("steps unlock in order: destinations → rules → deliveries", async ({ page }) => {
  const w: World = { pagerduty: false, policies: [], running: true, outbox: [] };
  await boot(page, w);
  await page.goto("/#/admin/ticketing");
  await expect(page.getByRole("heading", { name: "RCA Tickets" })).toBeVisible();
  await expect(step(page, "rules")).toContainText("Finish step 1 first.");
  await expect(step(page, "deliveries")).toContainText("Finish step 2 first.");
  // Vendor case routing serves TAC escalation on its own — never locked.
  await expect(step(page, "cases")).not.toContainText("Finish step");

  w.pagerduty = true;
  await page.reload();
  await expect(step(page, "destinations").locator('[data-testid="dest-pagerduty"]')).toContainText("Connected");
  await expect(step(page, "rules")).not.toContainText("Finish step");
  await expect(step(page, "deliveries")).not.toContainText("Finish step");
});

test("a failed delivery is visible while the steps before it are locked", async ({ page }) => {
  await boot(page, {
    pagerduty: false, policies: [], running: false,
    outbox: [{ id: "ob-1", corr_object_id: "11111111-1111-1111-1111-111111111111", system: "servicenow", status: "dead", attempts: 5, last_error: "401 Unauthorized from the provider", created_at: new Date().toISOString(), updated_at: new Date().toISOString() }],
  });
  await page.goto("/#/admin/ticketing");
  await expect(step(page, "deliveries")).not.toContainText("Finish step");
  await expect(step(page, "deliveries")).toContainText("1 in the outbox");
  await expect(step(page, "rules")).toContainText("Finish step 1 first.");
});

test("the old Ticket Delivery address lands on the Deliveries step", async ({ page }) => {
  await boot(page, { pagerduty: true, policies: [], running: true, outbox: [] });
  await page.goto("/#/admin/ticket-delivery");
  await expect(page).toHaveURL(/#\/admin\/ticketing\/deliveries$/);
  await expect(step(page, "deliveries")).toBeVisible();
});
