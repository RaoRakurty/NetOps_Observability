// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Logs page E2E. The backend is mocked at the network boundary with the record shapes
// measured on the lab: a trap nobody can name yet, an unparsed syslog line and a flow
// with two sampling values. It proves in a real browser what jsdom cannot: the layout
// at each width, the type floor, severity contrast on every theme, and that a secret
// in a record never reaches the page.
//
// Screenshots go to LOGS_SHOTS_DIR when it is set. Nothing is written otherwise.

import { test, expect, type Page } from "@playwright/test";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

const TENANT = "t_acme";
const ME = { username: "alice", role: "operator", tenant_id: TENANT, platform_admin: true, accessible_tenants: [TENANT], all_tenants: false };
const SECRET = "s3cr3t-community";
const SHOTS = process.env.LOGS_SHOTS_DIR ?? "";

const NOW = Date.now();
const at = (msAgo: number) => new Date(NOW - msAgo).toISOString();

const TRAP = {
  _index: `netops-snmptrap-${TENANT}-2026.11.09`,
  _id: "t1",
  _source: {
    timestamp: at(60_000), signal: "snmptrap", host: "192.168.222.102", hostname: "192.168.222.102", device: "",
    snmp_version: "v2c", snmp_community: SECRET, authenticated: false,
    trap_oid: "1.3.6.1.4.1.41916.100.2.27", trap_name: "enterpriseSpecific", event_type: "enterprise_specific",
    severity: "notice", sys_uptime_human: "3d 4h", parser_status: "partially_decoded",
    message: `enterpriseSpecific 1.3.6.1.4.1.41916.100.2.27 snmp_community=${SECRET}`,
    varbinds: [
      { name: "sysUpTime", oid: "1.3.6.1.2.1.1.3.0", value: "27300000" },
      { oid: "1.3.6.1.4.1.41916.100.1.54.0", value: "System cpu usage back to normal level" },
      { oid: "1.3.6.1.4.1.41916.100.1.190.0", value: "12.23" },
      { oid: "1.3.6.1.4.1.41916.100.1.191.0", value: "7.98" },
    ],
    tenant_attribution: "unmatched", tenant_seg: "global", tenant_registry: "miss", topic: "netops.snmptrap",
    partition: 3, offset: 991823, source_type: "kafka", message_key: "abc123", ts_source: "event",
  },
};
const SYSLOG = {
  _index: `netops-syslog-${TENANT}-2026.11.09`,
  _id: "s1",
  _source: {
    timestamp: at(90_000), signal: "syslog", hostname: "vEdge-52", source_ip: "192.168.222.102", appname: "confd",
    facility: "user", severity: "notice", vendor: "unknown", parser_status: "unparsed",
    message: "4220 - - audit user: ciscosdwan/980840 created new session via snmp from 127.0.0.1:54511 with udp",
    tenant_attribution: "unmatched", topic: "netops.syslog", partition: 2,
  },
};
const SYSLOG_ERR = {
  _index: `netops-syslog-${TENANT}-2026.11.09`,
  _id: "s2",
  _source: {
    timestamp: at(120_000), hostname: "core-sw-01.dallas.example.net", source_ip: "10.20.30.40", appname: "ifmgr",
    facility: "local7", procid: "812", severity: "err", vendor: "arista", parser_status: "parsed",
    message: "%LINK-3-UPDOWN: Interface Ethernet12, changed state to down after a very long explanation that has to be cut off at the end of the row rather than widening the table or the page behind it",
    tenant_attribution: "unmatched",
  },
};
const CRIT = {
  _index: `netops-syslog-${TENANT}-2026.11.09`,
  _id: "s3",
  _source: { timestamp: at(150_000), hostname: "edge-9", source_ip: "10.20.30.9", appname: "kernel", severity: "crit", message: "BGP neighbor 10.0.0.2 down: hold timer expired" },
};
const WARN = {
  _index: `netops-syslog-${TENANT}-2026.11.09`,
  _id: "s4",
  _source: { timestamp: at(180_000), hostname: "edge-9", source_ip: "10.20.30.9", appname: "ospfd", severity: "warning", message: "OSPF neighbor 10.0.0.3 established" },
};
const FLOW = {
  _index: `netops-flows-${TENANT}-2026.11.09`,
  _id: "f1",
  _source: {
    timestamp: at(210_000), signal: "netflow", src_addr: "192.168.222.105", dst_addr: "192.168.172.1", src_port: 161, dst_port: 38204,
    proto: 17, sampler_address: "192.168.222.104", in_if: 1, out_if: 4, bytes: 1003, packets: 13, sample_rate: 50, sampling_rate: 0,
    tenant_attribution: "unmatched", partition: 1,
  },
};
const APP = {
  _index: "netops-applogs-2026.11.09",
  _id: "a1",
  _source: { timestamp: at(240_000), level: "debug", compose_service: "api", container_name: "cx-api-1", message: "request served" },
};
const HITS = [TRAP, SYSLOG, SYSLOG_ERR, CRIT, WARN, FLOW, APP];

type SearchBody = { query?: string; signal?: string };

async function boot(page: Page, theme?: string): Promise<SearchBody[]> {
  const searches: SearchBody[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("netops_token", "e2e-fake-token");
  });
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route) => {
    const url = route.request().url();
    const json = (body: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
    if (url.includes("/api/auth/me")) return json(ME);
    if (url.includes("/api/scopes")) return json({ scopes: [{ tenant_id: TENANT, tenant_name: "Acme", region: "us" }], all_tenants: false });
    if (url.includes("/api/logs/retention")) return json({ signal: "", total: 48211, oldest: at(13 * 86_400_000), days: 13 });
    if (url.includes("/api/logs/search")) {
      const body = route.request().postDataJSON() as SearchBody;
      searches.push(body);
      const hits = body.signal === "flows" ? [FLOW] : body.signal === "snmptrap" ? [TRAP] : HITS;
      return json({ hits: { total: { value: hits.length * 700 }, hits } });
    }
    return json({});
  });
  // A hash-only goto would not reload, and a screenshot would keep the last theme.
  await page.goto("about:blank");
  await page.goto("/#/explore/logs");
  await expect(page.getByRole("grid", { name: "Log results" })).toBeVisible({ timeout: 30_000 });
  // Set directly: the preference loader folds dark, oled and graphite into one knob
  // position, and each of them has to be looked at on its own.
  if (theme) {
    await page.evaluate((t) => document.documentElement.setAttribute("data-theme", t), theme);
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
  }
  return searches;
}

const rows = (page: Page) => page.getByRole("grid", { name: "Log results" }).locator(".dtv-row");
const detail = (page: Page) => page.getByTestId("log-detail");

async function shot(page: Page, name: string) {
  if (!SHOTS) return;
  mkdirSync(SHOTS, { recursive: true });
  await page.screenshot({ path: join(SHOTS, `${name}.png`) });
}

// No text below the owner's floor, and only the three approved faces.
async function typeAudit(page: Page) {
  return page.evaluate(() => {
    const out: { tooSmall: string[]; outsideFaces: string[]; overflow: number; outside: string[] } = { tooSmall: [], outsideFaces: [], overflow: 0, outside: [] };
    const roots = [...document.querySelectorAll(".lv, .lv-det")];
    for (const root of roots) {
      for (const el of [root, ...root.querySelectorAll("*")]) {
        const hasText = [...el.childNodes].some((n) => n.nodeType === Node.TEXT_NODE && (n.textContent ?? "").trim());
        if (!hasText) continue;
        const cs = getComputedStyle(el);
        if (parseFloat(cs.fontSize) < 12.5) out.tooSmall.push(`${el.className} ${cs.fontSize} "${(el.textContent ?? "").slice(0, 30)}"`);
        const face = cs.fontFamily.split(",")[0].replace(/"/g, "");
        if (!["Inter", "JetBrains Mono", "Space Grotesk"].includes(face)) out.outsideFaces.push(`${el.tagName}.${el.className}: ${face}`);
      }
    }
    out.overflow = document.documentElement.scrollWidth - document.documentElement.clientWidth;
    for (const el of document.querySelectorAll(".lv, .lv .card, .lv-filters, .xpl-bar, .lv-results-head, .lv-stream, .lv .dtv, .lv-det, .lv-card")) {
      if (el.getBoundingClientRect().right > window.innerWidth + 0.5) out.outside.push(el.className);
    }
    return out;
  });
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
    return [...document.querySelectorAll(sel)].map((el) => {
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

test("rows read as device, severity, type and a plain event, with no secret or pipeline noise", async ({ page }) => {
  await boot(page);
  await expect(rows(page)).toHaveCount(HITS.length);
  const first = rows(page).nth(0);
  await expect(first.getByText("enterpriseSpecific")).toBeVisible();
  await expect(first.getByText("Not decoded yet")).toBeVisible();
  await expect(first.getByText("Notice")).toBeVisible();
  await expect(first.getByText("Trap", { exact: true })).toBeVisible();

  const syslog = rows(page).nth(1);
  await expect(syslog.getByText("vEdge-52")).toBeVisible();
  await expect(syslog.getByText("192.168.222.102")).toBeVisible();

  const flow = rows(page).nth(5);
  await expect(flow.getByText("192.168.222.105 → 192.168.172.1")).toBeVisible();
  await expect(flow.getByText("UDP 161 → 38204 · 1,003 bytes · 13 packets")).toBeVisible();

  const text = (await page.locator(".lv").textContent()) ?? "";
  expect(text).not.toContain(SECRET);
  expect(text).not.toContain("unmatched");
  expect(text.toLowerCase()).not.toContain("unknown");

  await expect(first).toHaveCSS("height", "44px");
});

test("details open on a summary; pipeline fields stay closed; the raw view has no secret", async ({ page }) => {
  await boot(page);
  await rows(page).nth(0).click();
  await expect(detail(page)).toBeVisible();
  await expect(detail(page).getByRole("tab", { name: "Summary" })).toHaveAttribute("aria-selected", "true");
  await expect(detail(page).getByText("System cpu usage back to normal level")).toBeVisible();
  await expect(detail(page).locator(".lf-json")).toHaveCount(0);

  await detail(page).getByRole("tab", { name: "Fields" }).click();
  await expect(detail(page).getByText("trap_oid")).toBeVisible();
  await expect(detail(page).getByText("partition", { exact: true })).toBeHidden();
  await detail(page).getByText("Pipeline details").click();
  await expect(detail(page).getByText("partition", { exact: true })).toBeVisible();

  await detail(page).getByRole("tab", { name: "Raw" }).click();
  await expect(detail(page).locator(".lf-json")).toContainText('"snmp_community": "hidden"');
  expect(await page.content()).not.toContain(SECRET);
});

test("a quick filter adds a real clause and runs it", async ({ page }) => {
  const searches = await boot(page);
  await page.getByRole("button", { name: /Filter by device vEdge-52/ }).click();
  await expect(page.getByRole("textbox", { name: "Search query" })).toHaveValue('hostname:"vEdge-52"');
  await expect.poll(() => searches[searches.length - 1].query).toBe('hostname:"vEdge-52"');
  await page.getByRole("button", { name: /Filter by severity Critical/ }).click();
  await expect.poll(() => searches[searches.length - 1].query).toBe('hostname:"vEdge-52" AND severity:"crit"');
  await page.getByRole("button", { name: /Show only Flow/ }).click();
  await expect.poll(() => searches[searches.length - 1].signal).toBe("flows");
  await expect(page.getByTestId("flows-sampling-note")).toContainText("totals are estimates");
});

test("the page works from the keyboard", async ({ page }) => {
  await boot(page);
  const help = page.getByRole("button", { name: "Search examples" });
  await help.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("logs-search-help")).toBeVisible();
  const outline = await help.evaluate((el) => getComputedStyle(el).outlineStyle);
  expect(outline).toBe("solid");

  const grid = page.getByRole("grid", { name: "Log results" });
  await grid.focus();
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Enter");
  await expect(detail(page)).toBeVisible();
  await detail(page).getByRole("tab", { name: "Summary" }).focus();
  await page.keyboard.press("ArrowRight");
  await expect(detail(page).getByRole("tab", { name: "Fields" })).toHaveAttribute("aria-selected", "true");
});

for (const [name, width, height] of [["desktop-1366", 1366, 768], ["desktop-1920", 1920, 1080], ["phone", 390, 844]] as const) {
  test(`no sideways page scroll and nothing under the type floor at ${name}`, async ({ page }) => {
    await page.setViewportSize({ width, height });
    await boot(page);
    await rows(page).nth(1).click();
    await expect(detail(page)).toBeVisible();
    const audit = await typeAudit(page);
    expect(audit.tooSmall).toEqual([]);
    expect(audit.outsideFaces).toEqual([]);
    expect(audit.outside).toEqual([]);
    expect(audit.overflow).toBeLessThanOrEqual(0);
    // A table on a phone must fit, not scroll inside its own box either.
    const inner = await page.getByRole("grid", { name: "Log results" }).evaluate((el) => el.scrollWidth - el.clientWidth);
    expect(inner).toBeLessThanOrEqual(0);
    // The time is never the thing a narrow row cuts off.
    const clipped = await page.locator(".lv .dtv-row .lf-time").first().evaluate((el) => {
      const cell = el.closest(".dtv-cell")!.getBoundingClientRect();
      return el.getBoundingClientRect().right - cell.right;
    });
    expect(clipped).toBeLessThanOrEqual(0);
  });
}

for (const theme of ["light", "dark", "oled", "indigo", "graphite", "white"]) {
  test(`stream text holds contrast on the ${theme} theme`, async ({ page }) => {
    // Reduced motion also proves that path: a colour transition would be measured mid-flight.
    await page.emulateMedia({ reducedMotion: "reduce" });
    await boot(page, theme);
    const results = await contrasts(page, ".lv .lf-level, .lv .lv-device, .lv .lv-signal, .lv .lv-detail-line .lf-msg, .lv .lv-title-line .lf-msg, .lv .lv-addr, .lv .lf-time-clock, .lv .lf-time-date, .lv .lf-state, .lv .lf-ip, .lv .lv-quiet-chip, .lv .lv-facet, .lv .ds-seg button.active, .lv .btn-primary");
    expect(results.length).toBeGreaterThan(20);
    const failing = results.filter((r) => r.ratio < 4.5).map((r) => `${r.what} ${r.ratio.toFixed(2)}`);
    expect(failing).toEqual([]);
  });
}

test("screenshots", async ({ page }) => {
  test.skip(!SHOTS, "set LOGS_SHOTS_DIR to capture");
  test.slow();
  for (const [theme, label] of [["dark", "dark"], ["light", "light"]] as const) {
    await page.setViewportSize({ width: 1366, height: 768 });
    await boot(page, theme);
    await shot(page, `${label}-1366-stream`);
    await rows(page).nth(0).click();
    await expect(detail(page)).toBeVisible();
    await shot(page, `${label}-1366-trap-summary`);
    await rows(page).nth(5).click();
    await expect(detail(page).getByTestId("flow-strip")).toBeVisible();
    await shot(page, `${label}-1366-flow-summary`);
    await rows(page).nth(1).click();
    await shot(page, `${label}-1366-syslog-summary`);
    await detail(page).getByRole("tab", { name: "Fields" }).click();
    await detail(page).getByText("Pipeline details").click();
    await shot(page, `${label}-1366-fields`);
    await detail(page).getByRole("tab", { name: "Raw" }).click();
    await shot(page, `${label}-1366-raw`);
  }
  await page.setViewportSize({ width: 1920, height: 1080 });
  await boot(page, "indigo");
  await shot(page, "indigo-1920-stream");
  await page.setViewportSize({ width: 390, height: 844 });
  await boot(page, "dark");
  await page.getByRole("grid", { name: "Log results" }).scrollIntoViewIfNeeded();
  await shot(page, "phone-dark-stream");
  await rows(page).nth(5).click();
  await expect(detail(page)).toBeVisible();
  await shot(page, "phone-dark-flow");
  await boot(page, "light");
  await page.getByRole("grid", { name: "Log results" }).scrollIntoViewIfNeeded();
  await shot(page, "phone-light-stream");
});
