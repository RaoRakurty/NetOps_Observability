// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Administration → Discovery (owner 2026-10-18), end to end against a faked
// API: the platform administrator turns a collector on from the Sensors
// section and restarts to apply it; a tenant administrator never sees — or
// fetches — Sensors; every old Data sources address lands on its section.

import { test, expect, type Page, type Route } from "@playwright/test";

type Feature = { env: string; label: string; group: string; help: string; apply: "restart"; risky: boolean; running: boolean; desired: boolean; restart_pending: boolean; source: string; install_value: null };

function newServer() {
  const features: Feature[] = [
    { env: "ENABLE_SNMP_COLLECTION", label: "SNMP polling", group: "Collection", help: "", apply: "restart", risky: false, running: true, desired: true, restart_pending: false, source: "install", install_value: null },
    { env: "ENABLE_GNMI_COLLECTION", label: "gNMI streaming telemetry", group: "Collection", help: "", apply: "restart", risky: false, running: false, desired: false, restart_pending: false, source: "default", install_value: null },
  ];
  return { features, featureReads: 0, collectorReads: 0, restarts: 0 };
}

async function boot(page: Page, platform: boolean, srv: ReturnType<typeof newServer>) {
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
    if (p === "/api/collectors") {
      srv.collectorReads++;
      if (!platform) return json({ error: "platform administrator only" }, 403);
      return json([{ name: "snmpv2c", kind: "protocol", enabled: true, healthy: true, targets: 8, reachable: 8 }]);
    }
    if (p === "/api/platform/features" && req.method() === "GET") {
      srv.featureReads++;
      if (!platform) return json({ error: "platform administrator only" }, 403);
      return json({ features: srv.features, restart_pending: srv.features.some((f) => f.restart_pending), can_restart: true, store_load_error: "" });
    }
    if (p === "/api/platform/features" && req.method() === "PUT") {
      const b = req.postDataJSON() as { env: string; value: boolean };
      const f = srv.features.find((x) => x.env === b.env)!;
      f.desired = b.value;
      f.restart_pending = f.desired !== f.running;
      return json({});
    }
    if (p === "/api/platform/restart") {
      srv.restarts++;
      for (const f of srv.features) { f.running = f.desired; f.restart_pending = false; }
      return json({ status: "restarting" });
    }
    if (p === "/api/discovery/config") {
      if (!platform) return json({ error: "platform administrator only" }, 403);
      return json({ config: { enabled: false, ranges: [], allow_non_private: false, interval_sec: 300 }, limits: { max_hosts: 4096, max_ranges: 32 }, stats: {}, scan_profiles: { total: 1, v2c: 1, v3: 0 }, found: [] });
    }
    return json([]);
  });
}

test("platform administrator turns gNMI on from Sensors and restarts to apply it", async ({ page }) => {
  const srv = newServer();
  await boot(page, true, srv);
  await page.goto("/#/admin/discovery/sensors");
  await expect(page.getByRole("button", { name: /3\. Sensors/ })).toHaveAttribute("aria-expanded", "true");
  await page.getByRole("button", { name: "Turn on gNMI streaming telemetry" }).click();
  await expect(page.getByText("On after restart")).toBeVisible();
  await page.getByTestId("sensor-restart-banner").getByRole("button", { name: "Restart now" }).click();
  await expect.poll(() => srv.restarts).toBe(1);
  await expect(page.getByText("Correlix restarted. The new settings are running.")).toBeVisible({ timeout: 15_000 });
});

test("a tenant administrator never sees or fetches Sensors — not even through its deep link", async ({ page }) => {
  const srv = newServer();
  await boot(page, false, srv);
  await page.goto("/#/admin/discovery/sensors");
  await expect(page.getByRole("heading", { name: "Discovery" })).toBeVisible();
  await expect(page.getByRole("button", { name: /Sensors/ })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /2\. Network Scan/ })).toHaveAttribute("aria-expanded", "true");
  await page.waitForTimeout(500);
  expect(srv.collectorReads).toBe(0);
  expect(srv.featureReads).toBe(0);
});

for (const [from, section] of [
  ["#/admin/datasources", "coverage"],
  ["#/admin/snmp", "snmp"],
  ["#/admin/sensors", "sensors"],
  ["#/admin/telemetry-coverage", "telemetry"],
  ["#/infrastructure/discovery", "scan"],
] as const) {
  test(`old address ${from} opens the ${section} section`, async ({ page }) => {
    await boot(page, true, newServer());
    await page.goto(`/${from}`);
    await expect(page.locator(`.adm-section[data-section="${section}"]`)).toHaveClass(/open/);
    await expect(page.locator(".adm-section.open")).toHaveCount(1);
  });
}
