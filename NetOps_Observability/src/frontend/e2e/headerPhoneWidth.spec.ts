// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Global header at phone and tablet widths (components/TopBar.tsx +
// components/topBarTier.ts). Before this, at ~390 px the BLOGO5 wordmark alone
// took ~320 px and search, help, health and ✦ Iris ran off-screen, so the whole
// page scrolled sideways. Geometry is read from the laid-out page in Chromium
// with the API faked at the network boundary (./irisBackend.ts).
//
// Owner rules carried here: ✦ Iris stays visible and reachable (design of
// record docs/design/IRIS_PANEL_DESIGN_2026-10-05.md §1, §16); one overflow
// control, keyboard-reachable, Esc returns focus; tap targets ≥ 44 px; the
// desktop header (> 1000 px) is untouched.
//
// Screenshots for the owner's visual review are written only when
// HEADER_SCREENSHOT_DIR is set (review material, not a gate).

import { test, expect, type Locator, type Page } from "@playwright/test";
import { bootIris, irisLauncher, TENANT_CONFIG, topCpuAnswer } from "./irisBackend";

test.use({ timezoneId: "UTC", locale: "en-US" });

const PHONES = [360, 390, 414, 480];
const TABLET = 768;

const topbar = (page: Page) => page.locator("header.topbar");
const moreBtn = (page: Page) => topbar(page).getByRole("button", { name: /^More/ });
const morePanel = (page: Page) => page.locator("#topbar-more-panel");
const search = (page: Page) => page.getByRole("combobox", { name: "Search devices, resources, and logs" });
const brand = (page: Page) => topbar(page).locator("img.cx-brand-img:visible");
// The account menu: in the default shell it lives in the rail's foot.
const account = (page: Page) => page.locator(".rail-account-btn");

async function box(loc: Locator) {
  const b = await loc.boundingBox();
  if (!b) throw new Error("element has no box (not rendered)");
  return b;
}

async function boot(page: Page, width: number, height = 800) {
  await bootIris(page, { answer: () => topCpuAnswer(), tenantConfig: TENANT_CONFIG });
  await page.setViewportSize({ width, height });
  await page.goto("/#/overview/home");
  await expect(irisLauncher(page)).toBeVisible();
}

/** The page itself never scrolls sideways. */
async function expectNoHorizontalScroll(page: Page, what: string) {
  const { sw, cw } = await page.evaluate(() => {
    const se = document.scrollingElement!;
    return { sw: se.scrollWidth, cw: se.clientWidth };
  });
  expect(sw, `${what}: scrollWidth ${sw} <= clientWidth ${cw}`).toBeLessThanOrEqual(cw);
}

async function expectTapTarget(loc: Locator, what: string) {
  const b = await box(loc);
  expect(b.width, `${what} width`).toBeGreaterThanOrEqual(44);
  expect(b.height, `${what} height`).toBeGreaterThanOrEqual(44);
}

for (const width of [...PHONES, TABLET]) {
  test(`${width} px: no sideways scroll; ✦ Iris, More and the account menu stay on screen`, async ({ page }) => {
    await boot(page, width);
    await expectNoHorizontalScroll(page, `${width} px`);

    await expect(irisLauncher(page)).toBeInViewport({ ratio: 1 });
    await expectTapTarget(irisLauncher(page), "✦ Iris");
    await expect(moreBtn(page)).toBeInViewport({ ratio: 1 });
    await expectTapTarget(moreBtn(page), "More");
    await expect(moreBtn(page)).toHaveAttribute("aria-expanded", "false");
    await expect(moreBtn(page)).toHaveAttribute("aria-controls", "topbar-more-panel");
    await expect(account(page)).toBeInViewport({ ratio: 1 });

    // Exactly one brand image is shown, and it is the BLOGO5 artwork.
    await expect(brand(page)).toHaveCount(1);
    await expect(brand(page)).toHaveAttribute("src", /\/brand\/blogo5(-dark)?\.png$/);
    const b = await box(brand(page));
    if (width <= 480) {
      // Phone: the whole wordmark scaled down (18 px tall ≈ 153 px wide), never
      // the eye cropped out of it — the owner rejected a standalone eye.
      expect(b.height, "wordmark height").toBeLessThanOrEqual(20);
      expect(b.width / b.height, "uncropped aspect (1356:160)").toBeGreaterThan(8);
      expect(b.width, "wordmark width").toBeLessThanOrEqual(170);
      await expect(search(page), "search folds into More on a phone").toBeHidden();
    } else {
      // Tablet: the wordmark stays and search stays inline.
      expect(b.width, "wordmark width").toBeGreaterThan(280);
      await expect(search(page)).toBeInViewport({ ratio: 1 });
    }
    // Folded away until More opens.
    await expect(page.getByRole("button", { name: "Open documentation" })).toBeHidden();
    await expect(page.getByRole("combobox", { name: "Time range" })).toBeHidden();

    // Open, the panel is fully on screen, and the page still does not scroll.
    await moreBtn(page).click();
    await expect(morePanel(page)).toBeInViewport({ ratio: 1 });
    await expectNoHorizontalScroll(page, `${width} px, More open`);
    for (const row of [
      page.getByRole("button", { name: "Open documentation" }),
      page.getByRole("combobox", { name: "Time range" }),
    ]) {
      await expect(row).toBeInViewport({ ratio: 1 });
      expect((await box(row)).height).toBeGreaterThanOrEqual(44);
    }
    await expect(morePanel(page).getByRole("status")).toBeVisible();
    if (width <= 480) await expect(morePanel(page).getByRole("combobox", { name: /Search devices/ })).toBeVisible();

    const dir = process.env.HEADER_SCREENSHOT_DIR;
    if (dir) await page.screenshot({ path: `${dir}/header-${width}-open.png` });
  });
}

test("the More panel opens and closes with the mouse; a click outside closes it", async ({ page }) => {
  await boot(page, 390);
  await moreBtn(page).click();
  await expect(moreBtn(page)).toHaveAttribute("aria-expanded", "true");
  await expect(morePanel(page)).toBeVisible();
  // Clicking the button again closes it.
  await moreBtn(page).click();
  await expect(moreBtn(page)).toHaveAttribute("aria-expanded", "false");
  await expect(morePanel(page)).toBeHidden();
  // Clicking anywhere outside closes it.
  await moreBtn(page).click();
  await expect(morePanel(page)).toBeVisible();
  await page.locator("#main-content").click({ position: { x: 20, y: 300 } });
  await expect(morePanel(page)).toBeHidden();
  await expect(moreBtn(page)).toHaveAttribute("aria-expanded", "false");
});

test("the More panel works from the keyboard: Enter opens, Tab walks in, Esc closes and returns focus", async ({ page }) => {
  await boot(page, 390);
  await moreBtn(page).focus();
  await page.keyboard.press("Enter");
  await expect(moreBtn(page)).toHaveAttribute("aria-expanded", "true");
  await expect(moreBtn(page), "focus stays on the button when it opens").toBeFocused();
  // The panel follows the button in the tab order: search first on a phone.
  await page.keyboard.press("Tab");
  await expect(search(page)).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("combobox", { name: "Time range" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(morePanel(page)).toBeHidden();
  await expect(moreBtn(page)).toHaveAttribute("aria-expanded", "false");
  await expect(moreBtn(page), "Esc returns focus to More").toBeFocused();
  // Space toggles it too (native button).
  await page.keyboard.press("Space");
  await expect(morePanel(page)).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(moreBtn(page)).toBeFocused();
});

test("Esc in the More panel does not also close an open Iris sheet", async ({ page }) => {
  await boot(page, 390);
  await irisLauncher(page).click();
  await expect(irisLauncher(page)).toHaveAttribute("aria-expanded", "true");
  await moreBtn(page).click();
  await expect(morePanel(page)).toBeVisible();
  await moreBtn(page).focus();
  await page.keyboard.press("Escape");
  await expect(morePanel(page)).toBeHidden();
  await expect(irisLauncher(page), "Iris is still open").toHaveAttribute("aria-expanded", "true");
});

test("Documentation from the More panel opens the help drawer and closes the panel", async ({ page }) => {
  await boot(page, 390);
  await moreBtn(page).click();
  await morePanel(page).getByRole("button", { name: "Open documentation" }).click();
  await expect(morePanel(page)).toBeHidden();
  await expect(page.locator(".help-scrim")).toBeVisible();
});

test("crossing to desktop width closes the panel and restores the desktop header", async ({ page }) => {
  await boot(page, 390);
  await moreBtn(page).click();
  await expect(morePanel(page)).toBeVisible();
  await page.setViewportSize({ width: 1280, height: 800 });
  await expect(moreBtn(page)).toHaveCount(0);
  await expect(search(page)).toBeVisible();
  await page.setViewportSize({ width: 390, height: 800 });
  await expect(moreBtn(page)).toHaveAttribute("aria-expanded", "false");
  await expect(morePanel(page)).toBeHidden();
});

test("desktop 1280 px: unchanged — no More button, the wordmark, every control inline", async ({ page }) => {
  await boot(page, 1280);
  await expect(topbar(page)).not.toHaveAttribute("data-tier", /.*/);
  await expect(moreBtn(page)).toHaveCount(0);
  await expect(page.locator("#topbar-more-panel")).toHaveCount(0);
  const b = await box(brand(page));
  expect(b.width, "the full wordmark").toBeGreaterThan(280);
  expect(b.height).toBe(38);
  await expectNoHorizontalScroll(page, "1280 px");
  // The desktop cluster, in its desktop order, all inline in the bar.
  const order = await topbar(page).locator(".topbar-right > *").evaluateAll((els) => els.map((e) => e.className));
  expect(order[0]).toContain("omni");
  for (const name of ["Open documentation", "Iris"]) {
    await expect(topbar(page).getByRole("button", { name, exact: true })).toBeInViewport({ ratio: 1 });
  }
  await expect(topbar(page).getByRole("combobox", { name: "Time range" })).toBeInViewport({ ratio: 1 });
  await expect(topbar(page).getByRole("status")).toBeInViewport({ ratio: 1 });
  // ✦ Iris keeps its desktop size (the 44 px tap target is narrow-only).
  expect((await box(irisLauncher(page))).height).toBe(30);
});
