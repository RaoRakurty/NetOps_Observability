// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Paths section smoke (Paths redesign P0, 2026-11-20; one page with tabs since
// P5, 2026-11-21; the Measured paths tab retired 2026-11-22). Drives the REAL
// SPA with the backend mocked at the network boundary and checks the section's
// shape: one Paths leaf whose tabs are Tunnels and WAN circuits, Troubleshooting
// beside RCA, every old address opening a tab, the shared site filter and "Path
// data" drawer (with the steps that choose what is traced), and each measured
// path on the row it measures, opened hop by hop as the ribbon.

import { test, expect, type Page, type Route } from "@playwright/test";

// First paint after a navigation compiles the lazy page chunk on the cold dev
// server: the repo-wide 30 s first-paint wait. Only the FIRST assertion after
// each goto/reload takes it (a click right after goto already waits for its
// element); every later assertion keeps the default, tight wait.
const FIRST_PAINT = 30_000;

const ME = { username: "alice", role: "operator", tenant_id: "t_acme", platform_admin: false, accessible_tenants: ["t_acme"], all_tenants: false };

const SUGGESTED = {
  path_discovery: false, active_probe: false, tracing: 0,
  suggestions: [
    { device_id: "cedge-40", name: "cedge-40", address: "192.168.222.105", site: "Branch 40" },
    { device_id: "cedge-50", name: "cedge-50", address: "192.168.222.106", site: "Branch 50" },
  ],
};

// Paths P4: one row per SD-WAN tunnel (both ends folded), controller quality
// with its own time, an open case on one tunnel, and the site matrix.
const asOf = new Date(Date.now() - 40 * 60_000).toISOString();
const end = (device: string, ip: string, site: string, state = "up") => ({
  device_id: device, device, system_ip: ip, color: "mpls", state, sessions: 1, up: state === "up" ? 1 : 0,
  site: { label: site, source: "manual" },
});
const TUNNEL_ROW = (id: string, a: ReturnType<typeof end>, b: ReturnType<typeof end>, state: string, kase: string | null) => ({
  id, type: "sdwan", tunnel_id: id, status: state === "up" ? "up" : "down", state, ends_reported: 2, a, b,
  local_device: a.device, local_addr: "mpls", remote_device: b.device, remote_addr: "mpls",
  latency_ms: 18.4, jitter_ms: 2.1, loss_pct: state === "up" ? 0.2 : 4.5, qoe: 8.6, uptime_s: 0, measured: true, ts: new Date().toISOString(),
  quality: { latency_ms: 18.4, jitter_ms: 2.1, loss_pct: state === "up" ? 0.2 : 4.5, qoe: 8.6, as_of: asOf, ends: 2, source: "controller_statistics" },
  case: kase ? { id: kase, tier: "suspected", entity_id: id } : null, sources: ["controller"],
});
const TUNNELS = {
  data: [
    TUNNEL_ROW("10.255.255.40/mpls|10.255.255.100/mpls", end("cedge-40", "10.255.255.40", "Branch 40"), end("vedge-100", "10.255.255.100", "DC East"), "up", null),
    TUNNEL_ROW("10.255.255.50/mpls|10.255.255.100/mpls", end("cedge-50", "10.255.255.50", "Branch 50", "down"), end("vedge-100", "10.255.255.100", "DC East"), "disagree", "case-uuid-1"),
  ],
  rows: 2, total: 2, truncated: false,
  quality: { status: "ok", window_s: 10800 }, cases: { status: "ok" },
  matrix: {
    sites: [
      { key: "s1", label: "Branch 40", source: "manual", devices: 1 },
      { key: "s2", label: "Branch 50", source: "manual", devices: 1 },
      { key: "s3", label: "DC East", source: "manual", devices: 1 },
    ],
    cells: [
      { a: "s1", b: "s3", state: "up", tunnels: 1, up: 1, down: 0, disagree: 0, transports: [{ color: "mpls", state: "up", tunnels: 1 }], measured: 1, worst_loss_pct: 0.2, worst_latency_ms: 18.4, quality_as_of: asOf, cases: [] },
      { a: "s2", b: "s3", state: "disagree", tunnels: 1, up: 0, down: 0, disagree: 1, transports: [{ color: "mpls", state: "disagree", tunnels: 1 }], measured: 1, worst_loss_pct: 4.5, worst_latency_ms: 18.4, quality_as_of: asOf, cases: ["case-uuid-1"] },
    ],
    sites_total: 3, unplaced_tunnels: 0, truncated: false,
  },
};

// The workspace's inventory: the measured path's target is cedge-50, an end of
// the second tunnel, so that tunnel row carries the path.
const DEVICES = [
  { id: "cedge-40", name: "cedge-40", address: "192.168.222.105", source: "snmp", last_seen: "" },
  { id: "cedge-50", name: "cedge-50", address: "10.9.9.9", source: "snmp", last_seen: "" },
];

// A measured path whose loss starts at hop 2 and lasts to the target (P5 ribbon).
const PROBE_PATH = {
  dst: "10.9.9.9", method: "icmp", vantage_id: "v1", site: "Branch 50", reached: true, changed: false,
  ts: new Date().toISOString(),
  hops: [
    { ttl: 1, ip: "10.0.0.1", rtt_ms: 1.2, loss_pct: 0 },
    { ttl: 2, ip: "10.0.0.2", rtt_ms: 9.8, loss_pct: 20 },
    { ttl: 3, ip: "", rtt_ms: undefined, loss_pct: undefined },
    { ttl: 4, ip: "10.9.9.9", rtt_ms: 12.4, loss_pct: 25 },
  ],
};

async function mockApi(page: Page, created: unknown[] = [], paths: unknown[] = []) {
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const url = new URL(route.request().url());
    const json = (b: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(b) });
    const p = url.pathname;
    if (p.includes("/api/auth/me")) return json(ME);
    if (p.includes("/api/scopes")) return json({ scopes: [{ tenant_id: "t_acme", tenant_name: "Acme", org_id: "o", org_name: "Acme", region: "us" }], all_tenants: false });
    if (p.endsWith("/api/probe/paths")) return json(paths);
    if (p.endsWith("/api/probe/targets/suggested")) return json(SUGGESTED);
    if (p.endsWith("/api/dem/targets") && route.request().method() === "POST") {
      created.push(route.request().postDataJSON());
      return route.fulfill({ status: 201, contentType: "application/json", body: "{}" });
    }
    if (p.endsWith("/api/paths/health")) return json({ paths: [] });
    if (p.endsWith("/api/tunnels")) return json(TUNNELS);
    if (p.endsWith("/api/devices")) return json(DEVICES);
    if (p.endsWith("/api/correlations") || p.endsWith("/api/incidents")) return json([]);
    return json({});
  });
}

test("Tunnels draws one row per tunnel and a site matrix that filters the table", async ({ page }) => {
  await mockApi(page);
  await page.goto("/#/investigate/paths/tunnels");
  const matrix = page.getByTestId("tunnels-matrix");
  await expect(matrix).toBeVisible({ timeout: FIRST_PAINT });
  // Two site pairs, each drawn on both sides of the diagonal.
  await expect(page.getByTestId("tunnels-matrix-cell")).toHaveCount(4);
  await expect(page.locator('[data-testid="tunnels-matrix-cell"][data-state="disagree"]').first()).toHaveClass(/t-warn/);
  await expect(page.getByText("2 of 2 tunnels")).toBeVisible();
  await expect(page.getByTestId("tunnel-state").filter({ hasText: "ends disagree" })).toHaveCount(1);
  await expect(page.getByTestId("tunnel-asof").first()).toHaveText(/^as of \d\d:\d\d \(40 min ago\)$/);

  await page.locator('[data-testid="tunnels-matrix-cell"][data-state="disagree"]').first().click();
  await expect(page.getByText("1 of 2 tunnels")).toBeVisible();
  await expect(page.getByTestId("tunnels-cell-filter")).toContainText("Branch 50");
  await page.getByTestId("tunnels-cell-filter").click();
  await expect(page.getByText("2 of 2 tunnels")).toBeVisible();
});

test("a Tunnels case chip opens the case in RCA", async ({ page }) => {
  await mockApi(page);
  await page.goto("/#/investigate/paths/tunnels");
  const chip = page.getByTestId("tunnel-case");
  await expect(chip).toHaveAttribute("href", "#/investigate/rca?id=case-uuid-1", { timeout: FIRST_PAINT });
  await chip.click();
  await expect(page).toHaveURL(/#\/investigate\/rca\?id=case-uuid-1$/);
});

test("Paths is one leaf after Topology; Troubleshooting sits beside RCA", async ({ page }) => {
  await mockApi(page);
  await page.goto("/#/investigate/paths/tunnels");
  const nav = page.getByRole("navigation", { name: "Investigate views" });
  await expect(nav).toBeVisible({ timeout: FIRST_PAINT });
  const labels = (await nav.locator(".subnav-cell").allInnerTexts()).map((t) => t.replace(/\s+/g, " ").trim());
  const rca = labels.findIndex((t) => t === "RCA");
  expect(labels[rca + 1]).toBe("Troubleshooting");
  expect(labels).toContain("Paths");
  for (const old of ["Measured paths", "Tunnels", "WAN circuits"]) expect(labels).not.toContain(old);
  // No group header any more: the three pages are tabs of one leaf.
  await expect(nav.locator(".subnav-group")).toHaveCount(0);
  await expect(page.getByRole("tab")).toHaveText(["Tunnels", "WAN circuits"]);
});

test("Path data holds the numbered steps that choose what is traced — the real switch, no env names", async ({ page }) => {
  await mockApi(page);
  await page.goto("/#/investigate/paths/wan-circuits");
  await page.getByTestId("paths-data-open").click();
  const setup = page.getByTestId("paths-data-setup");
  await expect(setup).toBeVisible();
  await expect(setup.getByRole("link", { name: "Platform › Configuration › Features" }).first()).toHaveAttribute("href", "#/platform/features");
  await expect(page.getByText(/API settings/)).toHaveCount(0);
  await expect(setup.locator("code", { hasText: /FEATURE_|_TARGETS/ })).toHaveCount(0);
});

// Every address a bookmark can hold opens Paths on the right tab, and the URL
// is rewritten to the canonical tab address.
for (const [hash, tab, label] of [
  ["#/investigate/paths/measured", "wan-circuits", "WAN circuits"],
  ["#/investigate/paths/tunnels", "tunnels", "Tunnels"],
  ["#/investigate/paths/wan-circuits", "wan-circuits", "WAN circuits"],
  ["#/investigate/paths", "tunnels", "Tunnels"],
  ["#/investigate/flowtrace", "wan-circuits", "WAN circuits"],
  ["#/investigate/tunnels", "tunnels", "Tunnels"],
  ["#/investigate/wan-paths", "wan-circuits", "WAN circuits"],
  ["#/infrastructure/flowtrace", "wan-circuits", "WAN circuits"],
  ["#/infrastructure/tunnels", "tunnels", "Tunnels"],
  ["#/infrastructure/wan-circuits", "wan-circuits", "WAN circuits"],
  ["#/topology/tunnels", "tunnels", "Tunnels"],
] as const) {
  test(`${hash} opens the ${label} tab`, async ({ page }) => {
    await mockApi(page);
    await page.goto(`/${hash}`);
    await expect(page.getByRole("tab", { name: label })).toHaveAttribute("aria-selected", "true", { timeout: FIRST_PAINT });
    if (hash !== "#/investigate/paths") await expect(page).toHaveURL(new RegExp(`#/investigate/paths/${tab}$`));
  });
}

test("the tabs switch in place and are linkable", async ({ page }) => {
  await mockApi(page);
  await page.goto("/#/investigate/paths/wan-circuits");
  await page.getByRole("tab", { name: "Tunnels" }).click();
  await expect(page).toHaveURL(/#\/investigate\/paths\/tunnels$/);
  await expect(page.getByTestId("tunnels-matrix")).toBeVisible();
  await page.getByRole("tab", { name: "WAN circuits" }).click();
  await expect(page).toHaveURL(/#\/investigate\/paths\/wan-circuits$/);
  await expect(page.getByRole("heading", { name: "WAN circuits", exact: true })).toBeVisible();
  await page.goBack();
  await expect(page.getByRole("tab", { name: "Tunnels" })).toHaveAttribute("aria-selected", "true");
});

test("the site filter narrows the open tab and is remembered across tabs and reloads", async ({ page }) => {
  await mockApi(page);
  await page.goto("/#/investigate/paths/tunnels");
  const site = page.getByTestId("paths-site");
  await expect(site.locator("option")).toHaveText(["All sites", "Branch 40", "Branch 50", "DC East"], { timeout: FIRST_PAINT });
  await expect(page.getByText("2 of 2 tunnels")).toBeVisible();
  await site.selectOption({ label: "Branch 50" });
  await expect(page.getByText("1 of 1 tunnels")).toBeVisible();
  // A site the next tab has no rows for stays chosen and says so.
  await page.getByRole("tab", { name: "WAN circuits" }).click();
  await expect(site).toHaveValue("branch-50");
  await expect(site.locator("option:checked")).toHaveText("branch-50 (no rows here)");
  await page.reload();
  await expect(page.getByTestId("paths-site")).toHaveValue("branch-50", { timeout: FIRST_PAINT });
  await page.getByRole("tab", { name: "Tunnels" }).click();
  await expect(page.getByText("1 of 1 tunnels")).toBeVisible();
  await page.getByTestId("paths-site").selectOption({ label: "All sites" });
  await expect(page.getByText("2 of 2 tunnels")).toBeVisible();
});

test("Path data says what is on and where to turn the rest on", async ({ page }) => {
  await mockApi(page);
  await page.goto("/#/investigate/paths/tunnels");
  await page.getByTestId("paths-data-open").click();
  const drawer = page.getByTestId("paths-data");
  await expect(drawer).toBeVisible();
  await expect(page.getByTestId("paths-data-discovery")).toHaveAttribute("data-state", "off");
  await expect(page.getByTestId("paths-data-tunnels")).toHaveAttribute("data-state", "on");
  await expect(page.getByTestId("paths-data-tunnels")).toContainText("2 tunnels");
  await expect(page.getByTestId("paths-data-discovery").getByRole("link")).toHaveAttribute("href", "#/platform/features");
  await expect(drawer.locator("code", { hasText: /FEATURE_|\/api\// })).toHaveCount(0);
  await expect(drawer).not.toContainText("/api/");
  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();
});

test("a tunnel row carries its measured path and opens it hop by hop, ribbon above the hop table", async ({ page }) => {
  await mockApi(page, [], [PROBE_PATH]);
  await page.goto("/#/investigate/paths/tunnels");
  // cedge-50's tunnel carries the path to cedge-50; the other row has none.
  const cells = page.getByTestId("path-cell");
  await expect(cells).toHaveCount(2, { timeout: FIRST_PAINT });
  await expect(page.getByTestId("path-verdict")).toHaveText("Loss from hop 2");
  await page.getByTestId("path-verdict").click();
  const panel = page.getByTestId("path-panel");
  await expect(panel).toBeVisible();
  await expect(panel.getByRole("heading", { name: "To End A (cedge-50)" })).toBeVisible();
  const ribbon = panel.getByTestId("paths-ribbon");
  await expect(ribbon).toBeVisible();
  await expect(ribbon.locator(".netpath-prov")).toHaveText("Measured");
  // The prober plus four hops, the silent one drawn as "No reply". (The list
  // also holds a "Link to …" item per connector; only hop nodes are counted.)
  const hops = ribbon.locator('[role="listitem"][aria-label^="Hop "]');
  await expect(hops).toHaveCount(5);
  await expect(hops.nth(3)).toHaveAttribute("aria-label", /No reply/);
  await expect(panel.getByLabel("Path hops")).toBeVisible();
  // The panel keeps the Paths type floor.
  const small = await textBelowFloor(page, ".mpath-panel");
  expect(small, `text below the floor:\n${small.join("\n")}`).toEqual([]);
  await page.keyboard.press("Escape");
  await expect(panel).toBeHidden();
});

test("a measured path no row claims is listed apart and opens the same way", async ({ page }) => {
  await mockApi(page, [], [{ ...PROBE_PATH, dst: "8.8.8.8", site: "" }]);
  await page.goto("/#/investigate/paths/tunnels");
  const other = page.getByTestId("paths-other");
  await expect(other).toContainText("Measured paths to other targets (1)", { timeout: FIRST_PAINT });
  await other.locator("summary").click();
  await other.getByTestId("paths-other-open").click();
  await expect(page.getByTestId("path-panel").getByRole("heading", { name: "To 8.8.8.8" })).toBeVisible();
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
    await expect(page.locator(".ts-group-head")).toHaveText(["Start troubleshooting", "The answer", "The evidence"]);
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
  ["#/investigate/paths/tunnels", ".paths-shell"],
  ["#/investigate/paths/wan-circuits", ".paths-shell"],
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
// adding them creates traced catalogue targets with no tenant in the body. In
// the Path data drawer since the Measured paths tab was retired (2026-11-22).
test("Path data's setup adds the ticked branch edges as traced targets", async ({ page }) => {
  const created: Record<string, unknown>[] = [];
  await mockApi(page, created);
  await page.goto("/#/investigate/paths/wan-circuits");
  await page.getByTestId("paths-data-open").click();
  const list = page.getByTestId("paths-suggestions");
  await expect(list.locator("input[type=checkbox]")).toHaveCount(2);
  await list.locator("input[type=checkbox]").nth(1).uncheck();
  await page.getByTestId("paths-trace-selected").click();
  await expect(page.getByTestId("paths-added")).toContainText("1 added");
  expect(created).toEqual([{ name: "Path to cedge-40", kind: "icmp", host: "192.168.222.105", site: "Branch 40", interval_sec: 60, trace_path: true }]);
});

for (const theme of ["light", "indigo"] as const) {
  test(`Path data meets the type floor in the ${theme === "light" ? "light" : "dark"} theme`, async ({ page }) => {
    await page.addInitScript((t) => localStorage.setItem("netops.theme", t), theme);
    await mockApi(page);
    await page.goto("/#/investigate/paths/wan-circuits");
    await page.getByTestId("paths-data-open").click();
    await expect(page.getByTestId("paths-data-discovery")).toBeVisible();
    const small = await textBelowFloor(page, ".paths-data-body");
    expect(small, `text below the floor:\n${small.join("\n")}`).toEqual([]);
  });
}
