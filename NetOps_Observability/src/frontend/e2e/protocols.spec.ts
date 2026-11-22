// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Analytics › Protocol Monitoring (2026-11-22): one leaf, three tabs. Drives the
// REAL SPA with the backend mocked at the network boundary: each tab deep-links,
// the old BGP Operations address opens the BGP tab, the OSPF tab leads with what
// needs attention (device name, site, open problem), and the page meets the type
// floor in both themes.

import { test, expect, type Page, type Route } from "@playwright/test";

const ME = { username: "alice", role: "operator", tenant_id: "t_acme", platform_admin: false, accessible_tenants: ["t_acme"], all_tenants: false };
const COV = { events: true, live_series: true, lsdb: false, areas: false, spf_runs: false, timers: false };
const DEPTH = {
  lsdb: { lsp_count: null, note: "not collected" }, areas: { areas: null, note: "not collected" },
  spf_runs: { runs: null, note: "not collected" }, timers: { rows: null, note: "not collected" },
};
const adj = (o: Record<string, unknown>) => ({
  device: "r1", peer: "10.0.0.2", ifname: "Gi1", current_state: "full", state_source: "live_series", up: true,
  flaps: 0, changes: 0, up_events: 0, down_events: 0, hold_seconds: null, timeline: [], ...o,
});
const ADJ = (proto: string) => ({
  protocol: proto, device: "", window_seconds: 86400, since: "s", now: "n", source: "both", limit: 2000, truncated: false,
  coverage: COV, notes: [], event_count: 2, ...DEPTH,
  adjacencies: [adj({ up: false, current_state: "down", flaps: 2, last_change: "2026-11-22T01:00:00Z" }), adj({ peer: "10.0.0.3" })],
});
const SUM = (proto: string) => ({ protocol: proto, window_seconds: 86400, since: "s", now: "n", coverage: COV, devices: [], notes: [], truncated: false });

async function mockApi(page: Page) {
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const url = new URL(route.request().url());
    const json = (b: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(b) });
    const p = url.pathname;
    if (p.includes("/api/auth/me")) return json(ME);
    if (p.includes("/api/scopes")) return json({ scopes: [{ tenant_id: "t_acme", tenant_name: "Acme", org_id: "o", org_name: "Acme", region: "us" }], all_tenants: false });
    if (p.endsWith("/api/devices")) return json([{ id: "r1", name: "core-1", address: "10.1.1.1", source: "snmp", last_seen: "", labels: { site: "DC East" } }]);
    if (p.endsWith("/api/correlations")) return json({ data: [{
      correlation_id: "5564d1aa-0000-4000-8000-000000000001", version: 1, state: "open", window_start: "", verdict_tier: "suspected",
      signal_count: 3, affected: JSON.stringify({ interfaces: ["10.1.1.1:if3"] }), top_hypothesis: "sig.ent.access.ospf-adjacency-flap",
    }] });
    const m = p.match(/\/api\/protocols\/(ospf|isis)\/(adjacencies|summary|health)$/);
    if (m) return json(m[2] === "adjacencies" ? ADJ(m[1]) : m[2] === "summary" ? SUM(m[1]) : {});
    if (p.includes("/api/bgp/watchlist")) return json({ watchlist: [], incidents: {} });
    if (p.includes("/api/bgp/alerts")) return json({ alerts: [], incidents: [], classes: [], status: {} });
    if (p.includes("/api/bgp/bmp/sessions")) return json({ sessions: [], count: 0, coverage: {} });
    if (p.includes("/api/metrics/query") || p.includes("/api/query")) return json({ status: "success", data: { resultType: "vector", result: [] } });
    if (p.includes("/api/bgp/")) return json({});
    return json({});
  });
}

test("each tab deep-links, and the tab is written to the address bar", async ({ page }) => {
  await mockApi(page);
  await page.goto("/#/analytics/protocols/isis");
  // First paint compiles the lazy page chunk on the cold dev server (CI): the repo-wide 30 s first-paint wait.
  await expect(page.getByTestId("protocols-page")).toBeVisible({ timeout: 30_000 });
  await expect(page.getByTestId("protocols-tab-isis")).toHaveAttribute("aria-selected", "true");
  await page.getByTestId("protocols-tab-ospf").click();
  await expect(page).toHaveURL(/#\/analytics\/protocols\/ospf$/);
});

test("the old BGP Operations address opens the BGP tab", async ({ page }) => {
  await mockApi(page);
  await page.goto("/#/analytics/bgp-ops");
  // First paint compiles the lazy page chunk on the cold dev server (CI): the repo-wide 30 s first-paint wait.
  await expect(page.getByTestId("protocols-page")).toBeVisible({ timeout: 30_000 });
  await expect(page.getByTestId("protocols-tab-bgp")).toHaveAttribute("aria-selected", "true");
  // No second page title inside the tab.
  await expect(page.getByRole("heading", { name: "BGP Operations" })).toHaveCount(0);
});

test("OSPF leads with what needs attention: device by name, site, why, and the open problem", async ({ page }) => {
  await mockApi(page);
  await page.goto("/#/analytics/protocols/ospf");
  await expect(page.getByRole("heading", { name: "Needs attention" })).toBeVisible({ timeout: 30_000 });
  const panel = page.locator("table.igp-attention");
  await expect(panel.getByText("core-1")).toBeVisible();
  await expect(panel.getByText("DC East")).toBeVisible();
  await expect(panel.getByText("Down now")).toBeVisible();
  await expect(panel.getByRole("link")).toHaveAttribute("href", /#\/investigate\/rca\?id=5564d1aa/);
  // The steady adjacency is behind "All adjacencies", not in the answer.
  await expect(panel.getByText(/10\.0\.0\.3/)).toHaveCount(0);
});

/** Every visible text run under `root` below the floor: 14px, or 12.5px for a chip. */
async function textBelowFloor(page: Page, root: string): Promise<string[]> {
  return page.locator(root).first().evaluate((el) => {
    const out: string[] = [];
    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const text = (n.textContent ?? "").trim();
      const host = n.parentElement;
      if (!text || !host || host.closest("[hidden], svg, canvas, .ask-iris, details:not([open]) > :not(summary)")) continue;
      const cs = getComputedStyle(host);
      if (cs.display === "none" || cs.visibility === "hidden") continue;
      const px = parseFloat(cs.fontSize);
      const chip = Boolean(host.closest(".badge, .chip, .chip-link, .igp-cov-chip, .igp-state"));
      if (px < (chip ? 12.5 : 14)) out.push(`${px}px "${text.slice(0, 40)}" <${host.tagName.toLowerCase()} class="${host.className}">`);
    }
    return out;
  });
}

for (const theme of ["light", "indigo"] as const) {
  test(`the OSPF tab meets the type floor in the ${theme === "light" ? "light" : "dark"} theme`, async ({ page }) => {
    await page.addInitScript((t) => localStorage.setItem("netops.theme", t), theme);
    await mockApi(page);
    await page.goto("/#/analytics/protocols/ospf");
    await expect(page.locator("table.igp-attention").getByText("core-1")).toBeVisible({ timeout: 30_000 });
    expect(await textBelowFloor(page, "[data-testid=protocols-page]")).toEqual([]);
  });
}
