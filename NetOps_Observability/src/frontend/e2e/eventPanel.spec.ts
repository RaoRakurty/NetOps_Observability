// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Event Intelligence panel E2E (tracker 387). The backend is mocked at the network
// boundary with the shared fixtures (src/lib/eventFixtures.ts): the real vedge-51 CPU
// trap as the golden record, plus one record per lane. It proves in a real browser what
// jsdom cannot: the panel's layout at the owner's screenshot sizes, the keyboard path
// (focus moves in, stays in, Esc gives it back), contrast in dark and light, and no
// sideways scroll on a phone.
//
// Screenshots go to EVENT_SHOTS_DIR when it is set. Nothing is written otherwise.

import { test, expect, type Page } from "@playwright/test";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import {
  APP_LOG, BGP_TRANSITION, CPU_GOLDEN, CPU_INFO, CPU_RECOVERED, CPU_WARNING, FIXTURE_SECRET, FLOW_RECORD, SYSLOG_AUDIT,
  SYSLOG_FAULT, SYSLOG_UNPARSED,
} from "../src/lib/eventFixtures";

const TENANT = "global";
const ME = { username: "alice", role: "operator", tenant_id: "t_acme", platform_admin: true, accessible_tenants: ["t_acme"], all_tenants: false };
const SHOTS = process.env.EVENT_SHOTS_DIR ?? "";

const HITS = [CPU_GOLDEN, BGP_TRANSITION, SYSLOG_FAULT, SYSLOG_AUDIT, SYSLOG_UNPARSED, FLOW_RECORD, CPU_WARNING, CPU_INFO, CPU_RECOVERED, APP_LOG];
type SearchBody = { query?: string; signal?: string };

// The owner's screenshots show the local line in US Central; the browser is put on
// that clock so the Timing card's second line ("(Nov 09, 2026 22:07:27.500 CST)") shows.
test.use({ timezoneId: "America/Chicago" });

const SEVERITY_COUNTS = {
  signal: "", total: 7547, unrated: 0, other: 0,
  counts: [
    { field: "severity", value: "critical", count: 128 }, { field: "severity", value: "warning", count: 412 },
    { field: "severity", value: "info", count: 1026 }, { field: "severity", value: "cleared", count: 5981 },
  ],
};

// A cold dev server on a busy host can take a while to serve the first page: the
// first load makes vite pre-bundle and reload. Each worker loads the app once before
// its first test, so no test spends its own budget on the warm-up.
test.beforeAll(async ({ browser }, testInfo) => {
  testInfo.setTimeout(300_000);
  const page = await browser.newPage();
  await page.goto(`${testInfo.project.use.baseURL ?? ""}/`, { waitUntil: "load", timeout: 280_000 });
  await page.waitForLoadState("networkidle", { timeout: 120_000 }).catch(() => undefined);
  await page.close();
});
test.beforeEach(({}, testInfo) => testInfo.setTimeout(Math.max(testInfo.timeout, 120_000)));

async function boot(page: Page, opts: { theme?: string; hash?: string } = {}): Promise<SearchBody[]> {
  const searches: SearchBody[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("netops_token", "e2e-fake-token");
  });
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route) => {
    const url = route.request().url();
    const json = (body: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
    if (url.includes("/api/auth/me")) return json(ME);
    if (url.includes("/api/scopes")) return json({ scopes: [{ tenant_id: TENANT, tenant_name: "Provider", region: "us" }], all_tenants: false });
    if (url.includes("/api/logs/retention")) return json({ signal: "", total: 7547, oldest: "2026-10-28T00:00:00Z", days: 13 });
    if (url.includes("/api/logs/severity-counts")) return json(SEVERITY_COUNTS);
    if (url.includes("/api/metrics/query_range")) return json({ status: "success", data: { resultType: "matrix", result: [] } });
    if (url.includes("/api/logs/search")) {
      const body = route.request().postDataJSON() as SearchBody;
      searches.push(body);
      const q = body.query ?? "";
      const id = /^_id:"(.+)"$/.exec(q)?.[1];
      if (id) return json({ hits: { total: { value: 1 }, hits: HITS.filter((h) => h._id === id) } });
      // The related-records search: the golden trap has no other record yet.
      if (q.startsWith("device_id:")) return json({ hits: { total: { value: 0 }, hits: [] } });
      return json({ hits: { total: { value: 7547 }, hits: HITS } });
    }
    return json({});
  });
  await page.goto("about:blank");
  await page.goto(opts.hash ?? "/#/explore/logs");
  if (!opts.hash) await expect(page.getByRole("grid", { name: "Log results" })).toBeVisible({ timeout: 90_000 });
  if (opts.theme) {
    await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), opts.theme);
    await expect(page.locator("html")).toHaveAttribute("data-theme", opts.theme);
  }
  return searches;
}

const panel = (page: Page) => page.getByTestId("event-panel");
const detail = (page: Page) => page.getByTestId("event-detail");
const row = (page: Page, text: string) => page.getByRole("grid", { name: "Log results" }).locator(".dtv-row", { hasText: text }).first();

async function openRow(page: Page, text: string) {
  if (await panel(page).count()) {
    await page.keyboard.press("Escape");
    await expect(panel(page)).toHaveCount(0);
  }
  await row(page, text).click();
  await expect(panel(page)).toBeVisible();
  // The panel slides in; measure and capture where it lands, not mid-flight.
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== "running"));
}

async function shot(page: Page, name: string) {
  if (!SHOTS) return;
  mkdirSync(SHOTS, { recursive: true });
  // Let fonts settle so the comparison is against the real faces.
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({ path: join(SHOTS, `${name}.png`) });
}

// WCAG contrast of an element's text against what is painted behind it.
async function contrasts(page: Page, selector: string) {
  return page.evaluate((sel) => {
    const canvas = document.createElement("canvas").getContext("2d", { willReadFrequently: true })!;
    const rgba = (c: string): [number, number, number, number] => {
      canvas.clearRect(0, 0, 1, 1);
      canvas.fillStyle = c;
      canvas.fillRect(0, 0, 1, 1);
      const d = canvas.getImageData(0, 0, 1, 1).data;
      return [d[0], d[1], d[2], d[3] / 255];
    };
    const over = (top: number[], under: number[]) => [0, 1, 2].map((i) => top[i] * top[3] + under[i] * (1 - top[3])).concat(1);
    const lum = (c: number[]) => {
      const f = (v: number) => { const s = v / 255; return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4; };
      return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]);
    };
    return [...document.querySelectorAll(sel)].filter((el) => (el.textContent ?? "").trim()).map((el) => {
      const layers: number[][] = [];
      for (let e: Element | null = el; e; e = e.parentElement) {
        const bg = rgba(getComputedStyle(e).backgroundColor);
        if (bg[3] > 0) layers.push(bg);
        if (bg[3] === 1) break;
      }
      let under = [255, 255, 255, 1];
      for (const layer of layers.reverse()) under = over(layer, under);
      const fg = over(rgba(getComputedStyle(el).color), under);
      const [a, b] = [lum(fg), lum(under)].sort((x, y) => y - x);
      return { what: `${(el as HTMLElement).className}: ${(el.textContent ?? "").slice(0, 24)}`, ratio: (a + 0.05) / (b + 0.05) };
    });
  }, selector);
}

const TEXT_SELECTORS = [
  ".evd-title", ".evd-subtitle", ".evd-sev-pill", ".evd-chip", ".evd-tab", ".evd-card-title", ".evd-vis-title",
  ".evd-kv-label", ".evd-kv-val", ".evd-kv-sec", ".evd-pill", ".evd-legend-k", ".evd-legend-v", ".evd-stat dt", ".evd-stat dd",
  ".evd-thr-pill", ".evd-thr-val", ".evd-seg-label", ".evd-ring-value", ".evd-ring-label", ".evd-table td", ".evd-table th",
  ".evd-bullets li", ".evd-guidance", ".evd-btn",
].map((s) => `.evd ${s}`).join(", ");

test("the critical CPU trap: headline, ring, reported threshold and the decoded varbinds", async ({ page }) => {
  await page.setViewportSize({ width: 1672, height: 941 });
  await boot(page);
  await openRow(page, "CPU utilization reached 100%");
  const d = detail(page);
  await expect(d.getByTestId("event-title")).toHaveText("CPU utilization reached 100% on vEdge-51 — system CPU 95.85%");
  await expect(d.getByTestId("event-severity")).toHaveText("Critical");
  await expect(d.getByTestId("event-ring-value")).toHaveText("100%");
  await expect(d.getByTestId("event-threshold")).toContainText("Threshold (reported)");
  await expect(d.getByTestId("event-threshold")).toContainText("90%");
  await expect(d.getByTestId("event-stats")).toContainText("Total CPU (derived)100.00%");
  const varbinds = d.getByTestId("event-varbinds").locator("tbody tr");
  await expect(varbinds).toHaveCount(7);
  for (const name of ["sysUpTime", "eventTime", "netconfNotificationSeverity", "viptelaSystemWarning", "viptelaSystemCpuUserPercentage", "viptelaSystemCpuSystemPercentage", "viptelaSystemCpuIdlePercentage"]) {
    await expect(varbinds.filter({ hasText: name })).toHaveCount(1);
  }
  await expect(d.getByTestId("event-varbinds")).toContainText("1.3.6.1.4.1.41916.100.1.191.0");
  await expect(d.getByTestId("event-timing")).toContainText("24.413 seconds");
  await expect(d.getByTestId("event-timing")).toContainText("(Nov 09, 2026 22:07:27.500 CST)");
  await expect(d.getByTestId("event-classification")).toContainText("Yes (hidden)");
  await expect(d.getByTestId("event-identity")).toContainText("cpu:vedge-51-0a0b4db5:device");
  // Nothing the record does not back: no incident status, no acknowledge.
  await expect(d).not.toContainText("Incident Status");
  await expect(d.getByRole("button", { name: /Acknowledge/ })).toHaveCount(0);
  expect(await page.content()).not.toContain(FIXTURE_SECRET);
});

test("the keyboard path: focus moves in, stays in, Esc closes and gives it back", async ({ page }) => {
  await boot(page);
  const grid = page.getByRole("grid", { name: "Log results" });
  await grid.focus();
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Enter");
  await expect(panel(page)).toBeVisible();
  await expect(panel(page)).toBeFocused();
  for (let i = 0; i < 40; i++) {
    await page.keyboard.press("Tab");
    expect(await panel(page).evaluate((el) => el.contains(document.activeElement))).toBe(true);
  }
  for (let i = 0; i < 5; i++) {
    await page.keyboard.press("Shift+Tab");
    expect(await panel(page).evaluate((el) => el.contains(document.activeElement))).toBe(true);
  }
  // The tabs answer the arrows.
  await detail(page).getByRole("tab", { name: "Overview" }).focus();
  await page.keyboard.press("End");
  await expect(detail(page).getByRole("tab", { name: "Raw Event" })).toHaveAttribute("aria-selected", "true");
  await page.keyboard.press("Escape");
  await expect(panel(page)).toHaveCount(0);
  expect(await grid.evaluate((el) => el.contains(document.activeElement) || el === document.activeElement)).toBe(true);
});

test("the full page opens from its deep link, with the timeline and no invented recovery", async ({ page }) => {
  await page.setViewportSize({ width: 1536, height: 1024 });
  const t = encodeURIComponent(String(CPU_GOLDEN._source!.timestamp));
  await boot(page, { hash: `/#/explore/logs/event/snmptrap/golden-cpu-1?t=${t}` });
  const d = detail(page);
  await expect(d).toBeVisible({ timeout: 90_000 });
  await expect(d.getByRole("navigation", { name: "Breadcrumb" })).toContainText("Event Detail");
  await expect(d.getByTestId("event-title")).toHaveText("CPU utilization reached 100% on vEdge-51 — system CPU 95.85%");
  await expect(d.getByTestId("event-timeline")).toContainText("Raise (Critical)");
  await expect(d.getByTestId("event-timeline")).toContainText("Event Received");
  await expect(d.getByTestId("event-no-recovery")).toBeVisible();
  await expect(d.getByTestId("event-identity")).toContainText("0 (no related records yet)");
});

test("BGP, syslog fault, audit, unparsed and flow records use the same panel", async ({ page }) => {
  await boot(page);
  await openRow(page, "never established");
  await expect(detail(page).getByTestId("event-bgp")).toContainText("10.10.20.2");
  await expect(detail(page).getByTestId("event-bgp")).toContainText("OpenSent");
  await expect(detail(page).getByTestId("event-bgp")).toContainText("6 notifications grouped");
  await openRow(page, "could not reach 8.8.8.8");
  await expect(detail(page).getByTestId("event-syslog")).toContainText("could not reach 8.8.8.8");
  await expect(detail(page).getByTestId("event-syslog")).toContainText("Original frame");
  await openRow(page, "audit user");
  await expect(detail(page).getByTestId("event-audit")).toContainText("ciscosdwan");
  await openRow(page, "FP_QFULL");
  await expect(detail(page).getByTestId("event-syslog")).toContainText("Not parsed yet");
  await openRow(page, "192.168.222.105");
  await expect(detail(page).getByTestId("flow-strip")).toContainText("ge0/0 (1)");
});

for (const theme of ["dark", "light", "oled", "indigo", "graphite", "white"]) {
  test(`panel text holds AA contrast on the ${theme} theme`, async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.setViewportSize({ width: 1672, height: 941 });
    await boot(page, { theme });
    for (const text of ["CPU utilization reached 100%", "never established", "could not reach 8.8.8.8", "CPU recovered"]) {
      await openRow(page, text);
      const results = await contrasts(page, TEXT_SELECTORS);
      expect(results.length).toBeGreaterThan(20);
      const failing = results.filter((r) => r.ratio < 4.5).map((r) => `${r.what} ${r.ratio.toFixed(2)}`);
      expect(failing, text).toEqual([]);
    }
  });
}

test("a phone gets the panel full screen, cards stacked, nothing sideways", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await boot(page);
  await openRow(page, "CPU utilization reached 100%");
  const box = await panel(page).boundingBox();
  expect(box?.width).toBeLessThanOrEqual(390);
  expect(box?.width).toBeGreaterThanOrEqual(389);
  const overflow = await panel(page).evaluate((el) => el.scrollWidth - el.clientWidth);
  expect(overflow).toBeLessThanOrEqual(0);
  const outside = await page.evaluate(() => [...document.querySelectorAll(".evd-card, .evd-head, .evd-tabs")].filter((el) => el.getBoundingClientRect().right > window.innerWidth + 0.5).map((el) => el.className));
  expect(outside).toEqual([]);
  // Device and Timing cards stack rather than sit side by side.
  const [dev, timing] = await Promise.all([detail(page).getByTestId("event-device").boundingBox(), detail(page).getByTestId("event-timing").boundingBox()]);
  expect(timing!.y).toBeGreaterThan(dev!.y + dev!.height - 1);
  const small = await page.evaluate(() => [...document.querySelectorAll(".evd *")].filter((el) => [...el.childNodes].some((n) => n.nodeType === 3 && (n.textContent ?? "").trim()) && parseFloat(getComputedStyle(el).fontSize) < 12.5).map((el) => `${el.className}`));
  expect(small).toEqual([]);
});

test("screenshots", async ({ page }) => {
  test.skip(!SHOTS, "set EVENT_SHOTS_DIR to capture");
  test.slow();
  await page.emulateMedia({ reducedMotion: "reduce" });
  for (const theme of ["dark", "light"]) {
    await page.setViewportSize({ width: 1672, height: 941 });
    await boot(page, { theme });
    await shot(page, `list-${theme}-1672x941`);
    for (const [text, name] of [
      ["CPU utilization reached 100%", "cpu-critical"],
      ["CPU utilization reached 80.1%", "cpu-warning"],
      ["CPU utilization at 34.5%", "cpu-info"],
      ["CPU recovered", "cpu-recovered"],
      ["never established", "bgp-transition"],
      ["could not reach 8.8.8.8", "syslog-fault"],
      ["audit user", "syslog-audit"],
      ["FP_QFULL", "syslog-unparsed"],
      ["192.168.222.105", "flow"],
    ] as const) {
      await openRow(page, text);
      await shot(page, `panel-${name}-${theme}-1672x941`);
    }
    await page.setViewportSize({ width: 1536, height: 1024 });
    const t = encodeURIComponent(String(CPU_GOLDEN._source!.timestamp));
    await boot(page, { theme, hash: `/#/explore/logs/event/snmptrap/golden-cpu-1?t=${t}` });
    await expect(detail(page)).toBeVisible({ timeout: 90_000 });
    await shot(page, `page-cpu-critical-${theme}-1536x1024`);
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await boot(page, { theme: "dark" });
  await openRow(page, "CPU utilization reached 100%");
  await shot(page, "panel-cpu-critical-dark-phone");
});

test("the list: store-counted severity tiles, sub-tabs, filters and numbered pages", async ({ page }) => {
  await page.setViewportSize({ width: 1672, height: 941 });
  const searches = await boot(page);
  const tiles = page.getByTestId("logs-severity-tiles");
  await expect(tiles.getByRole("button", { name: /^Critical: 128 matching/ })).toBeVisible();
  await expect(tiles.getByRole("button", { name: /^Healthy: 5,981 matching/ })).toBeVisible();
  await expect(page.getByRole("group", { name: "Log type" }).getByRole("button", { name: "Events" })).toContainText("Events (7,547)");
  await expect(page.getByTestId("logs-pager-text")).toContainText("of 7,547 events");
  await tiles.getByRole("button", { name: /^Critical:/ }).click();
  await expect.poll(() => searches[searches.length - 1].query ?? "").toContain('"critical"');
  await page.getByRole("navigation", { name: "Result pages" }).getByRole("button", { name: "Page 2" }).click();
  await expect(page.getByRole("navigation", { name: "Result pages" }).getByRole("button", { name: "Page 2" })).toHaveAttribute("aria-current", "page");
});
