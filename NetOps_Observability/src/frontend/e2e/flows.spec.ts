// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Explore → Flows E2E (P1 2026-11-12, P2 tracker 400). The backend is mocked at
// the network boundary with the shapes the flow and metrics APIs return — the
// link-level APIs (links, series, movers, capacity) included. It proves in a real
// browser what jsdom cannot: the default view's layout and type floor (every
// text ≥ 14 px, owner's NOC-admin standard), a link's drill-down, the empty
// state, the RCA deep link with its parameters, and that the legacy #/flows
// address still lands on the page.
//
// Screenshots go to FLOWS_SHOTS_DIR when it is set. Nothing is written otherwise.

import { test, expect, type Page, type Route } from "@playwright/test";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

const TENANT = "t_acme";
const ME = { username: "alice", role: "operator", tenant_id: TENANT, platform_admin: true, accessible_tenants: [TENANT], all_tenants: false };
const SHOTS = process.env.FLOWS_SHOTS_DIR ?? "";
const NOW = Date.now();

const DEVICES = [
  { id: "edge-1-ab12", name: "dallas-edge-1", address: "10.20.0.1", source: "snmp", last_seen: new Date(NOW).toISOString() },
  { id: "core-1-cd34", name: "dc-core-1", address: "10.20.0.2", source: "snmp", last_seen: new Date(NOW).toISOString() },
];
const IN_ROWS = [
  { k: "3", exporter: "10.20.0.1", in_if_name: "GigabitEthernet0/0/3", in_if_name_basis: "resolved", bytes_total: "8800000000", packets_total: "9000000", flows: "41000" },
  { k: "1", exporter: "10.20.0.2", in_if_name: "Ethernet1", in_if_name_basis: "resolved", bytes_total: "2100000000", packets_total: "2000000", flows: "9000" },
  { k: "4294967295", exporter: "10.20.0.2", in_if_name: "", in_if_name_basis: "sentinel", bytes_total: "5000", packets_total: "5", flows: "5" },
];
const OUT_ROWS = [
  { k: "3", exporter: "10.20.0.1", out_if_name: "GigabitEthernet0/0/3", out_if_name_basis: "resolved", bytes_total: "3100000000", packets_total: "3000000", flows: "20000" },
];

const WINDOW = { from: "", to: "", seconds: 3600, explicit: false, prev_from: "", retention_days: 7, starts_before_retention: false, prev_before_retention: false };
const BASIS = { flows: 51000, flows_rate_reported: 0, sampling: "not_reported", bucket_time: "received" };
const LINKS = [
  {
    exporter: "10.20.0.1", ifindex: 3, if_name: "GigabitEthernet0/0/3", if_name_basis: "resolved", device_id: "edge-1-ab12", device_name: "dallas-edge-1", site: "Dallas",
    in_bytes: 8800000000, out_bytes: 3100000000, prev_in_bytes: 6000000000, prev_out_bytes: 3000000000, in_packets: 9000000, out_packets: 3000000, flows: 61000,
    in_basis: "measured", out_basis: "measured", sampling: "not_reported",
  },
  {
    exporter: "10.20.0.2", ifindex: 1, if_name: "Ethernet1", if_name_basis: "resolved", device_id: "core-1-cd34", device_name: "dc-core-1",
    in_bytes: 2100000000, out_bytes: null, prev_in_bytes: 2000000000, prev_out_bytes: null, in_packets: 2000000, out_packets: 0, flows: 9000,
    in_basis: "partly_exported", in_unnamed_pct: 15, out_basis: "not_exported", sampling: "not_reported",
  },
];
const CAPACITY = {
  window: WINDOW, count: 3, total: 3, forecast: { days: 28, min_days: 14, min_r2: 0.5, threshold_pct: 90 },
  interfaces: [
    {
      device_id: "edge-1-ab12", device_name: "dallas-edge-1", site: "Dallas", ifindex: "3", if_name: "GigabitEthernet0/0/3", exporter: "10.20.0.1",
      speed_bps: 1e9, speed_basis: "reported", p95_in_bps: 610e6, p95_out_bps: 250e6, p95_bps: 610e6, peak_bps: 930e6,
      p95_in_pct: 61, p95_out_pct: 25, p95_pct: 61, peak_pct: 93, headroom_bps: 390e6, headroom_pct: 39,
      forecast: { status: "rising", days_to_90: 23, slope_pct_per_day: 1.2, fitted_pct: 62, r2: 0.82, history_days: 28, min_days: 14 },
    },
    {
      device_id: "core-1-cd34", device_name: "dc-core-1", ifindex: "1", if_name: "Ethernet1", exporter: "10.20.0.2",
      speed_bps: 10e9, speed_basis: "reported", p95_in_bps: 1.2e9, p95_out_bps: 0.4e9, p95_bps: 1.2e9, peak_bps: 3.8e9,
      p95_in_pct: 12, p95_out_pct: 4, p95_pct: 12, peak_pct: 38, headroom_bps: 8.8e9, headroom_pct: 88,
      forecast: { status: "not_enough_history", days_to_90: null, slope_pct_per_day: null, fitted_pct: null, r2: null, history_days: 6, min_days: 14 },
    },
    {
      device_id: "core-1-cd34", device_name: "dc-core-1", ifindex: "", if_name: "ge0/1", speed_bps: null, speed_basis: "unknown",
      p95_in_bps: 5e6, p95_out_bps: null, p95_bps: 5e6, peak_bps: 9e6, p95_in_pct: null, p95_out_pct: null, p95_pct: null, peak_pct: null,
      headroom_bps: null, headroom_pct: null,
      forecast: { status: "speed_unknown", days_to_90: null, slope_pct_per_day: null, fitted_pct: null, r2: null, history_days: 0, min_days: 14 },
    },
  ],
};

type Opts = { empty?: boolean };

function series(device: string, index: string, ifName: string, base: number) {
  return { metric: { device, index, ifName }, values: Array.from({ length: 30 }, (_, i) => [Math.floor(NOW / 1000) - (30 - i) * 120, String(base * (1 + Math.sin(i / 4) * 0.3))]) };
}

async function boot(page: Page, hash: string, opts: Opts = {}) {
  const seen: string[] = [];
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const url = new URL(route.request().url());
    const p = url.pathname;
    seen.push(`${p}?${url.searchParams.toString()}`);
    const json = (body: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
    if (p === "/api/auth/me") return json(ME);
    if (p === "/api/scopes") return json({ scopes: [{ tenant_id: TENANT, tenant_name: "Acme", region: "us" }], all_tenants: false });
    if (p === "/api/devices/locations") return json({ devices: [{ id: "edge-1-ab12", name: "dallas-edge-1", site: "Dallas", source: "manual" }] });
    if (p === "/api/devices") return json(DEVICES);
    if (p === "/api/flows/links") {
      return json({ window: WINDOW, links: opts.empty ? [] : LINKS, count: opts.empty ? 0 : LINKS.length, basis: BASIS });
    }
    if (p === "/api/flows/links/series") {
      const t0 = Math.floor(NOW / 1000 / 60) * 60 - 40 * 60;
      const t = Array.from({ length: 40 }, (_, i) => t0 + i * 60);
      const inb = t.map((_, i) => (opts.empty ? 0 : Math.round(50_000_000 + i * 900_000 + Math.sin(i / 3) * 9_000_000)));
      return json({
        window: WINDOW, served: { from: "", to: "" }, step_seconds: 60, exporter: url.searchParams.get("device"), ifindex: Number(url.searchParams.get("if")),
        t, in_bytes: inb, out_bytes: inb.map((v) => Math.round(v * 0.4)), in_packets: inb.map(() => 1), out_packets: inb.map(() => 1),
        last_bucket_complete: false, in_basis: "measured", out_basis: "measured", basis: BASIS,
      });
    }
    if (p === "/api/flows/links/movers") {
      const by = url.searchParams.get("by");
      const key = by === "port" ? "6/443" : by === "app" ? "AWS S3" : "52.94.236.248";
      return json({
        window: WINDOW, exporter: url.searchParams.get("device"), ifindex: Number(url.searchParams.get("if")), by, dir: "both", basis: BASIS,
        totals: { bytes: 11900000000, prev_bytes: 9000000000 },
        movers: opts.empty ? [] : [{ key, bytes: 1900000000, prev_bytes: 400000000, delta: 1500000000, change: 3.75, status: "up" }],
      });
    }
    if (p === "/api/flows/capacity") return json(opts.empty ? { ...CAPACITY, interfaces: [], count: 0, total: 0 } : CAPACITY);
    if (p === "/api/flows/topn") {
      if (opts.empty) return json({ data: [], rows: 0 });
      const by = url.searchParams.get("by");
      if (by === "in_if") return json({ data: IN_ROWS, rows: IN_ROWS.length });
      if (by === "out_if") return json({ data: OUT_ROWS, rows: OUT_ROWS.length });
      if (by === "device") return json({ data: [{ k: "10.20.0.1", bytes_total: 1, packets_total: 1, flows: 1 }] });
      if (by === "service_port") return json({ data: [{ k: "6/443", bytes_total: "4000000", packets_total: 10, flows: 9, label: "https", label_basis: "iana" }] });
      return json({ data: [] });
    }
    if (p === "/api/flows/timeseries") {
      if (opts.empty) return json({ data: [] });
      const rows = Array.from({ length: 40 }, (_, i) => {
        const d = new Date(NOW - (40 - i) * 90_000);
        const scale = url.searchParams.has("out_if") ? 0.4 : 1;
        return { bucket: d.toISOString().slice(0, 19).replace("T", " "), bytes_total: Math.round((50_000_000 + i * 900_000 + Math.sin(i / 3) * 9_000_000) * scale), packets_total: 1 };
      });
      return json({ data: rows });
    }
    if (p === "/api/flows/top") {
      return json({ data: opts.empty ? [] : [{ src: "10.30.1.15", dst: "52.94.236.248", bytes_total: "1900000000", packets_total: "1300000", flows: "300" }] });
    }
    if (p === "/api/correlations") {
      return json({
        data: [{
          correlation_id: "7b0e8c4e-1111-4222-8333-444455556666", state: "open",
          window_start: new Date(NOW - 50 * 60_000).toISOString(), window_end: new Date(NOW - 35 * 60_000).toISOString(),
          top_hypothesis: "undetermined", affected: JSON.stringify({ devices: ["dallas-edge-1"] }),
        }],
      });
    }
    if (p === "/api/metrics/query_range") {
      const q = url.searchParams.get("query") ?? "";
      const dir = q.includes("_in_") ? 1 : 0.4;
      return json({ status: "success", data: { resultType: "matrix", result: [series("edge-1-ab12", "3", "GigabitEthernet0/0/3", 720e6 * dir), series("core-1-cd34", "1", "Ethernet1", 120e6 * dir)] } });
    }
    if (p === "/api/metrics/query") {
      const q = url.searchParams.get("query") ?? "";
      if (q.startsWith("sum(")) return json({ status: "success", data: { result: [{ metric: {}, value: [0, q.includes("_in_") ? "1840000000" : "760000000"] }] } });
      if (q.includes("_over_time")) {
        const peak = q.startsWith("max");
        return json({ status: "success", data: { result: [
          { metric: { device: "edge-1-ab12", index: "3", ifName: "GigabitEthernet0/0/3" }, value: [0, peak ? "93" : "61"] },
          { metric: { device: "core-1-cd34", index: "1", ifName: "Ethernet1" }, value: [0, peak ? "38" : "12"] },
        ] } });
      }
      return json({ status: "success", data: { result: [
        { metric: { device: "edge-1-ab12", index: "3" }, value: [0, "1000000000"] },
        { metric: { device: "core-1-cd34", index: "1" }, value: [0, "10000000000"] },
      ] } });
    }
    if (p === "/api/flows/coverage") return json({ data: [{ flows: opts.empty ? 0 : "51000", exporters: "2", flows_sampling_reported: "0", platform_addresses_configured: 1, platform_monitoring_flows: "1200" }] });
    if (p === "/api/flows/by-type") return json({ data: opts.empty ? [] : [{ flow_type: "netflow", flows: "51000", exporters: "2" }] });
    if (p === "/api/flows/geo") return json({ data: [], geo_enabled: false });
    if (p === "/api/flows/apps") return json({ apps: [], count: 0 });
    if (p === "/api/flows/services") return json({ services: [], count: 0 });
    if (p === "/api/flows/by-proto") return json({ data: [] });
    if (p === "/api/appid/resolve/batch") return json({});
    return json({});
  });
  await page.goto("about:blank");
  await page.goto(`/${hash}`);
  // The first page load on a cold dev server compiles the whole app; allow for it.
  await expect(page.getByTestId("flows-page")).toBeVisible({ timeout: 60_000 });
  return seen;
}

async function shot(page: Page, name: string) {
  if (!SHOTS) return;
  mkdirSync(SHOTS, { recursive: true });
  await page.screenshot({ path: join(SHOTS, `${name}.png`), fullPage: true });
}

// Every text-bearing element on the page and in the drawer is at least 14 px,
// and nothing pushes the page sideways.
async function typeAudit(page: Page) {
  return page.evaluate(() => {
    const tooSmall: string[] = [];
    for (const root of document.querySelectorAll(".flows-page, .tr-about.open")) {
      for (const el of [root, ...root.querySelectorAll("*")]) {
        const hasText = [...el.childNodes].some((n) => n.nodeType === Node.TEXT_NODE && (n.textContent ?? "").trim());
        if (!hasText) continue;
        const r = (el as HTMLElement).getBoundingClientRect();
        if (r.width === 0 && r.height === 0) continue; // not rendered
        const fs = parseFloat(getComputedStyle(el).fontSize);
        if (fs < 14) tooSmall.push(`${el.tagName}.${(el as HTMLElement).className} ${fs}px "${(el.textContent ?? "").trim().slice(0, 30)}"`);
      }
    }
    return { tooSmall, overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth };
  });
}

test("Right now: busiest links by name, utilisation, change and trend — with the type floor", async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 900 });
  const seen = await boot(page, "#/explore/flows");
  await expect(page.getByRole("heading", { name: "Flows" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Right now" })).toHaveAttribute("aria-pressed", "true");
  const table = page.getByRole("grid", { name: "Busiest links" });
  await expect(table.getByText("dallas-edge-1 · GigabitEthernet0/0/3")).toBeVisible();
  await expect(table.getByText("dc-core-1 · Ethernet1")).toBeVisible();
  // The IPFIX "no interface" bucket is not a link.
  await expect(table.getByText(/4294967295/)).toHaveCount(0);
  await expect(table.locator(".tr-spark").first()).toBeVisible();
  await expect(table.locator(".tr-util.warn, .tr-util.bad").first()).toBeVisible();
  await expect(page.getByTestId("flow-sampling-note")).toContainText("shown as received");
  // One links call over the window (P2), the change from the same scan, and a
  // direction the router does not export said in words.
  expect(seen.some((s) => s.startsWith("/api/flows/links?since=3600s"))).toBe(true);
  expect(seen.some((s) => s.startsWith("/api/flows/topn?by=in_if"))).toBe(false);
  await expect(table.getByText("+32%")).toBeVisible();
  await expect(table.getByText("Not exported")).toBeVisible();
  // The old page's Device Health and Flags sections are gone from the page itself.
  await expect(page.getByText("TCP flag combinations")).toHaveCount(0);
  await expect(page.getByText("Avg CPU (%)")).toHaveCount(0);

  const audit = await typeAudit(page);
  expect(audit.tooSmall, audit.tooSmall.join("\n")).toEqual([]);
  expect(audit.overflow).toBeLessThanOrEqual(0);
  await shot(page, "flows-right-now");
});

test("a link drills down to in/out over time, its talkers, services and the problems that name its device", async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 1000 });
  const seen = await boot(page, "#/explore/flows");
  await page.getByRole("grid", { name: "Busiest links" }).getByText("dallas-edge-1 · GigabitEthernet0/0/3").click();
  const detail = page.getByTestId("link-detail");
  await expect(detail.getByRole("heading", { name: "dallas-edge-1 · GigabitEthernet0/0/3" })).toBeVisible();
  await expect(detail.getByText("10.30.1.15")).toBeVisible();
  await expect(detail.getByRole("link", { name: /Possible|undetermined|cause/i })).toHaveAttribute("href", "#/investigate/rca?id=7b0e8c4e-1111-4222-8333-444455556666");
  await expect(page).toHaveURL(/#\/explore\/flows\?device=10\.20\.0\.1&if=3$/);
  expect(seen.some((s) => s.startsWith("/api/flows/links/series") && s.includes("device=10.20.0.1") && s.includes("if=3"))).toBe(true);
  // What changed on the link against the window before.
  const changed = detail.getByTestId("what-changed");
  await expect(changed.getByText("52.94.236.248")).toBeVisible();
  await expect(changed.getByText("+375%")).toBeVisible();
  await changed.getByRole("button", { name: "Ports" }).click();
  await expect(changed.getByText(/443/)).toBeVisible();
  const audit = await typeAudit(page);
  expect(audit.tooSmall, audit.tooSmall.join("\n")).toEqual([]);
  await shot(page, "flows-link-detail");
});

test("an empty window says so instead of drawing an empty table", async ({ page }) => {
  await boot(page, "#/explore/flows", { empty: true });
  await expect(page.getByText("No flow records in this window.")).toBeVisible();
  await expect(page.getByRole("grid", { name: "Busiest links" })).toHaveCount(0);
  await shot(page, "flows-empty");
});

test("the RCA deep link opens the link with the problem window marked", async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 1000 });
  const from = new Date(NOW - 50 * 60_000).toISOString();
  const to = new Date(NOW - 35 * 60_000).toISOString();
  const seen = await boot(page, `#/explore/flows?device=10.20.0.1&if=3&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`);
  await expect(page.getByTestId("problem-banner")).toBeVisible();
  await expect(page.getByTestId("link-detail")).toBeVisible();
  await expect(page.getByTestId("problem-window")).toBeVisible();
  // The link APIs get an EXACT window around the problem, whatever the shell range.
  const series = seen.find((s) => s.startsWith("/api/flows/links/series"));
  expect(series).toBeTruthy();
  const sq = new URLSearchParams((series ?? "").split("?")[1]);
  expect(Number(sq.get("from")) * 1000).toBeLessThanOrEqual(Date.parse(from) - 300_000);
  expect(Number(sq.get("to")) * 1000).toBeGreaterThanOrEqual(Date.parse(to));
  await page.getByRole("button", { name: "Show the usual window" }).click();
  await expect(page.getByTestId("problem-banner")).toHaveCount(0);
  await expect(page.getByTestId("link-detail")).toBeVisible();
  await shot(page, "flows-rca-deep-link");
});

test("a deep link with a selected link, and the legacy #/flows address, both land on the page", async ({ page }) => {
  await boot(page, "#/explore/flows?device=10.20.0.1&if=3");
  await expect(page).toHaveURL(/#\/explore\/flows\?device=10\.20\.0\.1&if=3$/);
  await expect(page.getByTestId("link-detail")).toBeVisible();
  await page.goto("about:blank");
  await page.goto("/#/flows");
  await expect(page.getByTestId("flows-page")).toBeVisible({ timeout: 30_000 });
  await expect(page).toHaveURL(/#\/explore\/flows$/);
});

test("Who is talking and Capacity read the same way, and About this data holds the rest", async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 1000 });
  await boot(page, "#/explore/flows/talking");
  await expect(page.getByRole("search", { name: "Filter flows" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Services and ports" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Countries" })).toHaveCount(0); // no dataset loaded
  await page.getByRole("search", { name: "Filter flows" }).getByRole("combobox", { name: "Device", exact: true }).selectOption("10.20.0.1");
  await page.getByRole("button", { name: "Add" }).click();
  await expect(page.getByText("Device: dallas-edge-1 (10.20.0.1)")).toBeVisible();
  let audit = await typeAudit(page);
  expect(audit.tooSmall, audit.tooSmall.join("\n")).toEqual([]);
  await shot(page, "flows-who-is-talking");

  await page.getByRole("button", { name: "Capacity" }).click();
  await expect(page).toHaveURL(/#\/explore\/flows\/capacity/);
  const cap = page.getByRole("table", { name: "Link capacity" });
  await expect(cap.getByRole("rowheader", { name: "Dallas" })).toBeVisible();
  await expect(cap.getByText("390 Mbps free")).toBeVisible();
  await expect(cap.getByText("In about 23 days")).toBeVisible();
  await expect(cap.getByText("Collecting history — 6 of 14 days")).toBeVisible();
  await expect(page.getByTestId("capacity-next")).toHaveCount(0);
  await page.getByRole("button", { name: "Speed not reported (1)" }).click();
  await expect(page.getByRole("table", { name: "Speed not reported" })).toBeVisible();
  audit = await typeAudit(page);
  expect(audit.tooSmall, audit.tooSmall.join("\n")).toEqual([]);
  await shot(page, "flows-capacity");

  await page.getByRole("button", { name: "About this data" }).click();
  const drawer = page.getByRole("dialog", { name: "About this data" });
  await expect(drawer.getByText(/flows from 2 devices/)).toBeVisible();
  await expect(drawer.getByTestId("about-sampling")).toContainText("shown as received");
  await expect(drawer.getByRole("link", { name: /Device Monitoring/ })).toBeVisible();
  audit = await typeAudit(page);
  expect(audit.tooSmall, audit.tooSmall.join("\n")).toEqual([]);
  await shot(page, "flows-about");
});

test("phone width: no sideways scroll", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await boot(page, "#/explore/flows");
  await expect(page.getByRole("grid", { name: "Busiest links" })).toBeVisible();
  const audit = await typeAudit(page);
  expect(audit.overflow).toBeLessThanOrEqual(0);
});

// Both login themes, for the PR and for review: the default view and Capacity.
for (const theme of ["light", "dark"] as const) {
  test(`${theme} theme: default view and Capacity read cleanly`, async ({ page }) => {
    await page.setViewportSize({ width: 1366, height: 900 });
    // Reduced motion: the page drops its hover/colour transitions, so a theme
    // switch lands at once (and the screenshot is not mid-transition).
    await page.emulateMedia({ reducedMotion: "reduce" });
    await boot(page, "#/explore/flows");
    await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
    const transition = await page.evaluate(() => getComputedStyle(document.querySelector(".flows-page .btn-ghost")!).transitionDuration);
    expect(transition.split(",").every((d) => parseFloat(d) === 0)).toBe(true);
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
    const table = page.getByRole("grid", { name: "Busiest links" });
    await expect(table.getByText("dallas-edge-1 · GigabitEthernet0/0/3")).toBeVisible();
    // The utilisation meter takes its band from the token scale.
    await expect(table.locator('[data-band="crit"], [data-band="warn"]').first()).toBeVisible();
    // Tokens resolve in this theme (a missing token would read as an empty string).
    const inColor = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--flow-in").trim());
    expect(inColor).toMatch(/^#[0-9a-f]{6}$/i);
    await shot(page, `flows-right-now-${theme}`);
    await page.getByRole("button", { name: "Capacity" }).click();
    await expect(page.getByRole("table", { name: "Link capacity" }).getByRole("rowheader", { name: "Dallas" })).toBeVisible();
    const audit = await typeAudit(page);
    expect(audit.tooSmall, audit.tooSmall.join("\n")).toEqual([]);
    await shot(page, `flows-capacity-${theme}`);
  });
}
