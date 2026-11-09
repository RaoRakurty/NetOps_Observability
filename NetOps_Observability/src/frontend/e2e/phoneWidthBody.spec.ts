// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Page body at phone width (styles.css, "Phone width: page body"). The header
// has its own spec (headerPhoneWidth.spec.ts). A wide plain table used to widen
// the whole page because a `1fr` grid track grows to its content; on a phone it
// must scroll in its own box. Geometry is read from the laid-out page in
// Chromium with the API faked at the network boundary (./irisBackend.ts).

import { test, expect, type Page } from "@playwright/test";
import { bootIris, irisLauncher, TENANT_CONFIG, topCpuAnswer } from "./irisBackend";

test.use({ timezoneId: "UTC", locale: "en-US" });

async function boot(page: Page, width: number) {
  await bootIris(page, { answer: () => topCpuAnswer(), tenantConfig: TENANT_CONFIG });
  await page.setViewportSize({ width, height: 800 });
  await page.goto("/#/overview/home");
  await expect(irisLauncher(page)).toBeVisible();
}

// A panel in a grid track holding a plain table wider than any phone, with an
// sr-only label inside it: the shapes the 2026-10-19 crawl found on real pages.
async function addWideTable(page: Page) {
  return page.evaluate(() => {
    const host = document.createElement("div");
    host.className = "ov-grid";
    host.style.display = "grid";
    host.style.gridTemplateColumns = "1fr";
    host.innerHTML = `
      <div class="panel" data-testid="wide-panel">
        <table data-testid="wide-table">
          <thead><tr><th style="white-space:nowrap;min-width:1400px">
            A column far wider than a phone
            <span style="position:absolute;width:1px;height:1px;left:1390px">label</span>
          </th></tr></thead>
        </table>
      </div>`;
    const main = document.querySelector(".main");
    if (!main) throw new Error("no .main in the shell");
    main.appendChild(host);
  });
}

const pageOverflow = (page: Page) =>
  page.evaluate(() => {
    const se = document.scrollingElement!;
    return { sw: se.scrollWidth, cw: se.clientWidth };
  });

for (const width of [360, 390, 640]) {
  test(`${width} px: a wide table scrolls in its own box, not the page`, async ({ page }) => {
    await boot(page, width);
    await addWideTable(page);

    const { sw, cw } = await pageOverflow(page);
    expect(sw, `scrollWidth ${sw} <= clientWidth ${cw}`).toBeLessThanOrEqual(cw);

    const table = page.getByTestId("wide-table");
    const inner = await table.evaluate((t) => ({
      scroll: t.scrollWidth, client: t.clientWidth, overflow: getComputedStyle(t).overflowX,
    }));
    expect(inner.overflow).toBe("auto");
    expect(inner.scroll, "the table still holds its full width").toBeGreaterThan(inner.client);
    const panel = await page.getByTestId("wide-panel").boundingBox();
    expect(panel!.width, "the panel stayed within the screen").toBeLessThanOrEqual(width);
  });
}

test("above phone width a plain table stays a table", async ({ page }) => {
  await boot(page, 1280);
  await addWideTable(page);
  await expect(page.getByTestId("wide-table")).toHaveCSS("display", "table");
});

test("phone: KPI rows are two columns", async ({ page }) => {
  await boot(page, 390);
  const cols = await page.evaluate(() => {
    const el = document.createElement("div");
    el.className = "cc-kpis cc-kpis-4";
    document.querySelector(".main")!.appendChild(el);
    return getComputedStyle(el).gridTemplateColumns.split(" ").length;
  });
  expect(cols).toBe(2);
});
