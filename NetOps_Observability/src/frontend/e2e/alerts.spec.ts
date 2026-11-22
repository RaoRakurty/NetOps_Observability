// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Active Alerts E2E (owner, 2026-11-22: "modify Incidents and Active Alerts the
// way we did the Logs section"). The backend is mocked at the network boundary.
// Pins: the device by NAME, tabs that ask the API for their status, a side panel
// that opens from the keyboard and closes on Esc, and the Logs layout rules — no
// sideways page scroll and nothing under the type floor at three widths.

import { test, expect, type Page } from "@playwright/test";

const TENANT = "t_acme";
const ME = { username: "alice", role: "operator", tenant_id: TENANT, platform_admin: true, accessible_tenants: [TENANT], all_tenants: false };

const now = Date.now();
const at = (ago: number) => new Date(now - ago).toISOString();
const EPISODES = [
  { id: "ep-1", resource: "vedge-20-02efdcad", signal: "HighCPU", state: "critical", summary: "CPU 97% for 10 minutes",
    status: "active", first_seen: at(3_600_000), last_seen: at(60_000), count: 7, flapping: true, flip_count: 6 },
  { id: "ep-2", resource: "cedge-81-dde8d64d", signal: "InterfaceDown", state: "warning", summary: "GigabitEthernet2 down",
    status: "active", first_seen: at(7_200_000), last_seen: at(300_000), count: 2, muted: true, muted_by: "noc-lee" },
];

async function boot(page: Page): Promise<string[]> {
  const statuses: string[] = [];
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route) => {
    const url = new URL(route.request().url());
    const json = (body: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
    if (url.pathname === "/api/auth/me") return json(ME);
    if (url.pathname === "/api/scopes") return json({ scopes: [{ tenant_id: TENANT, tenant_name: "Acme", region: "us" }], all_tenants: false });
    if (url.pathname === "/api/alerts/episodes") {
      const st = url.searchParams.get("status") ?? "";
      statuses.push(st);
      const eps = st === "active" || st === "all" ? EPISODES : [];
      return json({ episodes: eps, total: eps.length, truncated: false });
    }
    if (url.pathname === "/api/alerts") return json([{ id: "a1" }, { id: "a2" }]);
    if (url.pathname === "/api/devices") {
      return json([
        { id: "vedge-20-02efdcad", name: "vEdge-20", address: "192.168.222.103" },
        { id: "cedge-81-dde8d64d", name: "cEDGE-81", address: "192.168.222.107" },
      ]);
    }
    return json({});
  });
  await page.goto("about:blank");
  await page.goto("/#/operations/alerts");
  await expect(page.getByRole("grid", { name: "Alert episodes" })).toBeVisible({ timeout: 30_000 });
  return statuses;
}

const rows = (page: Page) => page.getByRole("grid", { name: "Alert episodes" }).locator(".dtv-row");
const panel = (page: Page) => page.getByTestId("alert-panel");

test("rows name the device, not its inventory id", async ({ page }) => {
  await boot(page);
  await expect(rows(page).first()).toContainText("on vEdge-20");
  await expect(page.getByText("HighCPU on vEdge-20")).toBeVisible();
});

test("each tab asks the API for its own status", async ({ page }) => {
  const statuses = await boot(page);
  expect(statuses).toContain("active");
  await page.getByRole("button", { name: /^Cleared/ }).click();
  await expect(page.getByText("Nothing cleared recently.")).toBeVisible();
  expect(statuses).toContain("cleared");
});

test("a row opens the side panel from the keyboard; Esc closes it", async ({ page }) => {
  await boot(page);
  const grid = page.getByRole("grid", { name: "Alert episodes" });
  await grid.focus();
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Enter");
  await expect(panel(page)).toBeVisible();
  await expect(panel(page).getByRole("button", { name: /Acknowledge/ })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(panel(page)).toHaveCount(0);
});

for (const [name, width, height] of [["desktop-1366", 1366, 768], ["desktop-1920", 1920, 1080], ["phone", 390, 844]] as const) {
  test(`no sideways page scroll and nothing under the type floor at ${name}`, async ({ page }) => {
    await page.setViewportSize({ width, height });
    await boot(page);
    await rows(page).first().click();
    await expect(panel(page)).toBeVisible();
    await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== "running"));
    const audit = await page.evaluate(() => {
      const tooSmall: string[] = [];
      for (const root of document.querySelectorAll(".cc-panel, .evd-panel")) {
        for (const el of [root, ...root.querySelectorAll("*")]) {
          const hasText = [...el.childNodes].some((n) => n.nodeType === Node.TEXT_NODE && (n.textContent ?? "").trim());
          if (!hasText) continue;
          const fs = parseFloat(getComputedStyle(el).fontSize);
          if (fs < 12.5) tooSmall.push(`${(el as HTMLElement).className} ${fs}px "${(el.textContent ?? "").slice(0, 30)}"`);
        }
      }
      return { tooSmall, overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth };
    });
    expect(audit.tooSmall).toEqual([]);
    expect(audit.overflow).toBeLessThanOrEqual(0);
  });
}
