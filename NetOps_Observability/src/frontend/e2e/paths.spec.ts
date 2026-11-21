// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Paths section smoke (Paths redesign P0, 2026-11-20). Drives the REAL SPA with
// the backend mocked at the network boundary and checks the section's shape:
// the three measurement pages under the PATHS header with their new names,
// Troubleshooting beside RCA (not under PATHS), every old address still opening
// its page, and the Measured paths empty state saying what is true.

import { test, expect, type Page, type Route } from "@playwright/test";

const ME = { username: "alice", role: "operator", tenant_id: "t_acme", platform_admin: false, accessible_tenants: ["t_acme"], all_tenants: false };

const SUGGESTED = {
  path_discovery: false, active_probe: false, tracing: 0,
  suggestions: [
    { device_id: "cedge-40", name: "cedge-40", address: "192.168.222.105", site: "Branch 40" },
    { device_id: "cedge-50", name: "cedge-50", address: "192.168.222.106", site: "Branch 50" },
  ],
};

async function mockApi(page: Page, created: unknown[] = []) {
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const url = new URL(route.request().url());
    const json = (b: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(b) });
    const p = url.pathname;
    if (p.includes("/api/auth/me")) return json(ME);
    if (p.includes("/api/scopes")) return json({ scopes: [{ tenant_id: "t_acme", tenant_name: "Acme", org_id: "o", org_name: "Acme", region: "us" }], all_tenants: false });
    if (p.endsWith("/api/probe/paths")) return json([]);
    if (p.endsWith("/api/probe/targets/suggested")) return json(SUGGESTED);
    if (p.endsWith("/api/dem/targets") && route.request().method() === "POST") {
      created.push(route.request().postDataJSON());
      return route.fulfill({ status: 201, contentType: "application/json", body: "{}" });
    }
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

test("Measured paths shows numbered setup steps — the real switch, no env names, no phantom setting", async ({ page }) => {
  await mockApi(page);
  await page.goto("/#/investigate/flowtrace");
  await expect(page.getByRole("link", { name: "Platform › Configuration › Features" })).toHaveAttribute("href", "#/platform/features");
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
  await expect(page.getByText("No active path measurements.")).toBeVisible();
});

test("Troubleshooting opens its case picker", async ({ page }) => {
  await mockApi(page);
  await page.goto("/#/investigate/troubleshooting");
  await expect(page.getByTestId("ts-pick")).toBeVisible();
});

/** Every visible text run under `root` below the floor: 14px, or 12.5px for a chip. */
async function textBelowFloor(page: Page, root: string): Promise<string[]> {
  return page.locator(root).first().evaluate((el) => {
    const out: string[] = [];
    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const text = (n.textContent ?? "").trim();
      const host = n.parentElement;
      // .rca-ws is the RCA workspace's own component, embedded verbatim (case
      // header, case path): its scale belongs to the RCA workspace, not here.
      if (!text || !host || host.closest("[hidden], svg, canvas, .ask-iris, .rca-ws")) continue;
      const cs = getComputedStyle(host);
      if (cs.display === "none" || cs.visibility === "hidden") continue;
      const px = parseFloat(cs.fontSize);
      const chip = Boolean(host.closest(".badge, .ph-badge, .tsl-state"));
      if (px < (chip ? 12.5 : 14)) out.push(`${px}px "${text.slice(0, 40)}" <${host.tagName.toLowerCase()} class="${host.className}">`);
    }
    return out;
  });
}

// ── Troubleshooting with a case open (the answer block + lanes) ─────────────
const CASE = {
  correlation_id: "corr-1", version: 3, state: "open",
  window_start: new Date(Date.now() - 15 * 60_000).toISOString(), window_end: new Date().toISOString(),
  top_hypothesis: "undetermined", top_confidence: 0.4, verdict_tier: "suspected",
  hypotheses: "{}", evidence_missing: "[]", affected: JSON.stringify({ devices: ["edge1"], sites: ["dc1"] }),
  signal_count: 4, node_count: 2, owner: "wan_provider", title: "Link state change on edge1",
  engine_version: "v1", catalog_version: "c1", created_at: new Date().toISOString(),
};
const CASE_TIMELINE = {
  correlation_id: "corr-1", version: 3, window_start: CASE.window_start, window_end: CASE.window_end,
  trigger_signal: "sig-1", verdict_tier: "suspected", top_hypothesis: "undetermined", top_confidence: 0.4,
  evidence_missing: "[]", signals: [], evidence: [], edges: [],
  counts: { total: 0, attached: 0, unattached: 0, recovery: 0, unlinked: 0, attached_observers: 0, by_modality: {}, attached_by_modality: {}, by_role: {}, by_grounding: {}, by_status: {} },
};

async function mockCase(page: Page) {
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const url = new URL(route.request().url());
    const json = (b: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(b) });
    const p = url.pathname;
    if (p.includes("/api/auth/me")) return json(ME);
    if (p.includes("/api/scopes")) return json({ scopes: [{ tenant_id: "t_acme", tenant_name: "Acme", org_id: "o", org_name: "Acme", region: "us" }], all_tenants: false });
    if (p.endsWith("/api/correlations")) return json({ data: [CASE] });
    if (p.endsWith("/api/correlations/corr-1")) return json({ object: CASE, edges: [] });
    if (p.endsWith("/api/correlations/corr-1/timeline")) return json(CASE_TIMELINE);
    if (p.endsWith("/api/paths/health")) return json({ paths: [] });
    if (p.endsWith("/api/probe/paths")) return json([]);
    if (p.endsWith("/api/incidents")) return json([]);
    if (p.endsWith("/api/events/feed")) return json({ items: [{ signal_id: "s1", ts: new Date().toISOString(), kind: "link_down", title: "Link down", entity_id: "edge1", severity: "critical" }] });
    return json({});
  });
}

for (const theme of ["light", "indigo"] as const) {
  test(`Troubleshooting with a case reads as board groups (${theme === "light" ? "light" : "dark"})`, async ({ page }) => {
    await page.addInitScript((t) => localStorage.setItem("netops.theme", t), theme);
    await mockCase(page);
    await page.goto("/#/investigate/troubleshooting?case=corr-1");
    await expect(page.getByTestId("ts-facts")).toBeVisible();
    await expect(page.locator(".ts-group-head")).toHaveText(["What's wrong?", "The answer", "The evidence"]);
    await page.getByRole("button", { name: "Show the evidence" }).click();
    await expect(page.getByTestId("lane-open-events")).toHaveAttribute("href", "#/explore/logs");
    const dd = await page.locator(".ts-fact dd").first().evaluate((el) => parseFloat(getComputedStyle(el).fontSize));
    expect(dd).toBeGreaterThanOrEqual(16);
    const small = await textBelowFloor(page, ".ts-inv");
    expect(small, `text below the floor:\n${small.join("\n")}`).toEqual([]);
    await page.screenshot({ path: `test-results/ts-case-${theme}.png`, fullPage: true });
  });
}

// ── P1 type floor, both themes ──────────────────────────────────────────────
// The Paths pages and Troubleshooting share one type scale: every piece of
// readable text ≥ 14px, headings ≥ 16px, and only chips (badges) at 12.5px.
// Checked on the COMPUTED style in the light and the dark theme, so a theme
// rule cannot quietly shrink copy.
const PAGES = [
  ["#/investigate/flowtrace", ".paths-page"],
  ["#/investigate/tunnels", ".paths-page"],
  ["#/investigate/wan-paths", ".paths-page"],
  ["#/investigate/troubleshooting", ".ts-inv"],
] as const;

for (const theme of ["light", "indigo"] as const) {
  for (const [hash, root] of PAGES) {
    test(`${hash} meets the type floor in the ${theme === "light" ? "light" : "dark"} theme`, async ({ page }) => {
      await page.addInitScript((t) => localStorage.setItem("netops.theme", t), theme);
      await mockApi(page);
      await page.goto(`/${hash}`);
      await expect(page.locator(root).first()).toBeVisible();
      const small = await textBelowFloor(page, root);
      expect(small, `text below the floor:\n${small.join("\n")}`).toEqual([]);
      await page.screenshot({ path: `test-results/paths-${theme}-${hash.split("/").pop()}.png`, fullPage: true });
    });
  }
}

// Paths P3: step 2 offers the workspace's own branch edges pre-ticked, and
// adding them creates traced catalogue targets with no tenant in the body.
test("Measured paths setup adds the ticked branch edges as traced targets", async ({ page }) => {
  const created: Record<string, unknown>[] = [];
  await mockApi(page, created);
  await page.goto("/#/investigate/flowtrace");
  const list = page.getByTestId("paths-suggestions");
  await expect(list.locator("input[type=checkbox]")).toHaveCount(2);
  await list.locator("input[type=checkbox]").nth(1).uncheck();
  await page.getByTestId("paths-trace-selected").click();
  await expect(page.getByTestId("paths-added")).toContainText("1 added");
  expect(created).toEqual([{ name: "Path to cedge-40", kind: "icmp", host: "192.168.222.105", site: "Branch 40", interval_sec: 60, trace_path: true }]);
});
