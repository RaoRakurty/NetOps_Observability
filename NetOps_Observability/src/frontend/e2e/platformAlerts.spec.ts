// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Platform → Platform alerts (owner 2026-11-11: platform self-health alerts are
// set up in the GUI, not env), end to end against a faked API: the platform
// administrator sees that alerts reach nobody, sets up ntfy, saves, and sends a
// test; a tenant administrator never sees — or fetches — the page.

import { test, expect, type Page, type Route } from "@playwright/test";

type Srv = { route: Record<string, unknown>; reads: number; puts: unknown[]; tests: string[] };

function newServer(): Srv {
  return {
    route: {
      ntfy: { enabled: false, server: "https://ntfy.sh", topic: "", token_set: false, tiers: { page: true, warning: true } },
      sms: { enabled: false, account_sid: "", auth_token_set: false, from: "", to: [], tiers: { page: true, warning: false }, max_per_hour: 10 },
      page_routed: false,
      warning_routed: false,
      store_status: "ok",
      ignored_env: [],
      sms_budget_remaining: -1,
    },
    reads: 0,
    puts: [],
    tests: [],
  };
}

async function boot(page: Page, platform: boolean, srv: Srv) {
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    const json = (b: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(b) });
    if (p === "/api/auth/me") {
      return json(platform
        ? { username: "root", role: "admin", tenant_id: "", platform_admin: true, all_tenants: true, accessible_tenants: [], org_id: "global" }
        : { username: "ops", role: "admin", tenant_id: "t_acme", platform_admin: false, accessible_tenants: ["t_acme"], all_tenants: false, org_id: "org-acme" });
    }
    if (p === "/api/scopes") return json({ scopes: [{ tenant_id: "t_acme", tenant_name: "Acme", org_id: "org-acme", org_name: "Acme", region: "us" }], all_tenants: platform });
    if (p === "/api/platform/alerting/host-route") {
      srv.reads++;
      if (!platform) return json({ error: "platform administrator only" }, 403);
      if (req.method() === "PUT") {
        const b = req.postDataJSON() as { ntfy: { enabled: boolean; server: string; topic: string; token: string; tiers: unknown } };
        srv.puts.push(b);
        srv.route = {
          ...srv.route,
          ntfy: { enabled: b.ntfy.enabled, server: b.ntfy.server, topic: b.ntfy.topic, token_set: b.ntfy.token !== "", tiers: b.ntfy.tiers },
          page_routed: b.ntfy.enabled,
          warning_routed: b.ntfy.enabled,
          updated_by: "root",
          updated_at: "2026-11-11T09:00:00Z",
        };
      }
      return json(srv.route);
    }
    if (p === "/api/platform/alerting/host-route/test") {
      const b = req.postDataJSON() as { channel: string };
      srv.tests.push(b.channel);
      return json({ channel: b.channel, verdict: "ok", message: "Sent. Check the phone or app subscribed to this topic." });
    }
    return json([]);
  });
}

test("platform administrator sets up ntfy, saves, and sends a test", async ({ page }) => {
  const srv = newServer();
  await boot(page, true, srv);
  await page.goto("/#/platform/platform-alerts");
  await expect(page.getByRole("heading", { name: "Platform alerts" })).toBeVisible();
  await expect(page.getByTestId("platform-alerts-banner")).toContainText("reach nobody");
  await page.getByRole("switch", { name: "Use ntfy" }).check();
  await page.getByLabel(/^Topic/).fill("corr-e2e-topic");
  await page.getByLabel(/^Access token/).fill("placeholder-e2e-token-value");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText("Saved. The new settings are in use now.")).toBeVisible();
  await expect(page.getByTestId("platform-alerts-banner")).toHaveCount(0);
  // The secret went up once and never comes back into the page.
  expect((srv.puts[0] as { ntfy: { token: string } }).ntfy.token).toBe("placeholder-e2e-token-value");
  await expect(page.getByLabel(/^Access token/)).toHaveValue("");
  await expect(page.getByLabel(/^Access token/)).toHaveAttribute("placeholder", /Saved/);
  await page.getByRole("button", { name: "Send test push" }).click();
  await expect(page.getByTestId("verdict-ntfy")).toContainText("Sent.");
  expect(srv.tests).toEqual(["ntfy"]);
});

test("a tenant administrator never sees or fetches Platform alerts — not even through its deep link", async ({ page }) => {
  const srv = newServer();
  await boot(page, false, srv);
  await page.goto("/#/platform/platform-alerts");
  await page.waitForTimeout(500);
  await expect(page.getByRole("heading", { name: "Platform alerts" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Platform alerts" })).toHaveCount(0);
  expect(srv.reads).toBe(0);
});
