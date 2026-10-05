// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// The floating Iris window E2E (owner decision 2026-10-05). The answers inside
// are covered by irisDrawer.spec.ts; this drives the CONTAINER in a real browser:
//   1. a round "Ask Iris" launcher sits at the bottom right of the page;
//   2. it pops a window up above itself, over the page, about 420 × 640;
//   3. the window goes full screen and comes back with the same conversation;
//   4. Close, Esc and Ctrl+I close it, and focus returns to the launcher;
//   5. it stays open, with its conversation, while the operator changes page;
//   6. on a phone-width screen it is a full-width sheet;
//   7. accessibility smoke: every control is named, and text is 14 px or more.

import { test, expect, type Page } from "@playwright/test";
import { bootIris, openIris, askIris, irisWindow, topCpuAnswer, TENANT_CONFIG } from "./irisBackend";

test.use({ timezoneId: "UTC", locale: "en-US" });

// exact: every page's `(i)` buttons are named "Ask Iris about …".
const launcher = (page: Page) => page.getByRole("button", { name: "Ask Iris", exact: true });

/** The window's box once its pop-up animation has finished. */
async function settledBox(page: Page) {
  await irisWindow(page).evaluate((el) => Promise.all(el.getAnimations().map((a) => a.finished)));
  return (await irisWindow(page).boundingBox())!;
}

async function boot(page: Page) {
  const fake = await bootIris(page, { answer: () => topCpuAnswer(), tenantConfig: TENANT_CONFIG });
  await page.goto("/#/overview/home");
  await expect(launcher(page)).toBeVisible();
  return fake;
}

test("launcher → pop-up → full screen → back → close", async ({ page }) => {
  await boot(page);
  const vp = page.viewportSize()!;

  // 1. Round, bottom-right, and nothing open yet.
  const lb = (await launcher(page).boundingBox())!;
  expect(Math.round(lb.width)).toBe(Math.round(lb.height));
  expect(vp.width - (lb.x + lb.width)).toBeLessThanOrEqual(32);
  expect(vp.height - (lb.y + lb.height)).toBeLessThanOrEqual(32);
  expect(await launcher(page).evaluate((el) => getComputedStyle(el).borderRadius)).toBe("50%");
  await expect(launcher(page)).toHaveAttribute("aria-expanded", "false");
  await expect(irisWindow(page)).toHaveCount(0);

  // 2. The window pops up above the launcher, over the page, focus in the box.
  await launcher(page).click();
  const win = irisWindow(page);
  await expect(win).toBeVisible();
  await expect(page.getByPlaceholder(/Ask Iris AI/)).toBeFocused();
  await expect(win.locator(".op-hd-title")).toHaveText("Iris");
  const wb = await settledBox(page);
  expect(wb.width).toBeGreaterThan(400);
  expect(wb.width).toBeLessThanOrEqual(421);
  expect(wb.height).toBeLessThanOrEqual(641);
  expect(wb.y + wb.height).toBeLessThan(lb.y); // above the launcher
  expect(Math.abs((wb.x + wb.width) - (lb.x + lb.width))).toBeLessThanOrEqual(1); // right edges line up
  await expect(page.locator("#main-content")).toBeVisible(); // the page is still there beside it

  await askIris(page, "top 3 devices by cpu in the last hour");
  await expect(win.locator(".op-bubble-grounded")).toHaveCount(1);

  // 3. Full screen: the whole viewport, the same conversation.
  await win.getByRole("button", { name: "Full screen" }).click();
  await expect(win).toHaveClass(/expanded/);
  const fb = await settledBox(page);
  expect(fb.x).toBe(0);
  expect(fb.y).toBe(0);
  expect(Math.round(fb.width)).toBe(vp.width);
  expect(Math.round(fb.height)).toBe(vp.height);
  await expect(win.locator(".op-bubble-grounded")).toHaveCount(1);

  // … and back to the window.
  await win.getByRole("button", { name: "Exit full screen" }).click();
  await expect(win).not.toHaveClass(/expanded/);
  expect((await settledBox(page)).width).toBeLessThanOrEqual(421);
  await expect(win.locator(".op-bubble-grounded")).toHaveCount(1);

  // 4. Close: the window goes, focus comes back to the launcher.
  await win.getByRole("button", { name: "Close Iris" }).click();
  await expect(irisWindow(page)).toHaveCount(0);
  await expect(launcher(page)).toBeFocused();
  await expect(launcher(page)).toHaveAttribute("aria-expanded", "false");
});

test("Esc closes it, Ctrl+I toggles it, and focus returns to the launcher", async ({ page }) => {
  await boot(page);
  await openIris(page);
  await page.keyboard.press("Escape");
  await expect(irisWindow(page)).toHaveCount(0);
  await expect(launcher(page)).toBeFocused();

  await page.keyboard.press("Control+i");
  await expect(irisWindow(page)).toBeVisible();
  await expect(page.getByPlaceholder(/Ask Iris AI/)).toBeFocused();
  await page.keyboard.press("Control+i");
  await expect(irisWindow(page)).toHaveCount(0);
});

test("Tab stays inside the window", async ({ page }) => {
  await boot(page);
  await openIris(page);
  const win = irisWindow(page);
  for (let i = 0; i < 25; i++) {
    await page.keyboard.press("Tab");
    expect(await win.evaluate((el) => el.contains(document.activeElement))).toBe(true);
  }
  for (let i = 0; i < 25; i++) {
    await page.keyboard.press("Shift+Tab");
    expect(await win.evaluate((el) => el.contains(document.activeElement))).toBe(true);
  }
});

test("the window stays open with its conversation while the operator changes page", async ({ page }) => {
  const fake = await boot(page);
  await openIris(page);
  await askIris(page, "top 3 devices by cpu in the last hour");
  await expect(irisWindow(page).locator(".op-bubble-grounded")).toHaveCount(1);

  await page.evaluate(() => { window.location.hash = "#/investigate/rca"; });
  await expect(page).toHaveURL(/#\/investigate\/rca/);
  await expect(irisWindow(page)).toBeVisible();
  await expect(irisWindow(page).locator(".op-bubble-grounded")).toHaveCount(1);
  expect(fake.started).toEqual(["conv-1"]);
});

test("the old left-docked drawer is gone, and the rail's Iris item opens the same window", async ({ page }) => {
  await boot(page);
  await expect(page.locator(".op-panel, .op-scrim")).toHaveCount(0);
  await page.locator('button.rail-item[title="Iris AI"]').click();
  await expect(irisWindow(page)).toBeVisible();
  await expect(page.getByRole("dialog", { name: "Iris" })).toHaveCount(1);
  await expect(page.getByPlaceholder(/Ask Iris AI/)).toHaveCount(1);
});

test("on a phone-width screen the window is a full-width sheet", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 800 });
  await boot(page);
  await openIris(page);
  const wb = await settledBox(page);
  expect(wb.x).toBe(0);
  expect(Math.round(wb.width)).toBe(390);
  expect(Math.round(wb.y + wb.height)).toBe(800);
});

test("accessibility smoke: every control is named and text is 14 px or more", async ({ page }) => {
  await boot(page);
  const lfs = await launcher(page).evaluate((el) => ({ name: el.getAttribute("aria-label"), keys: el.getAttribute("aria-keyshortcuts") }));
  expect(lfs).toEqual({ name: "Ask Iris", keys: "Control+I Meta+I" });

  await openIris(page);
  await askIris(page, "top 3 devices by cpu in the last hour");
  const win = irisWindow(page);
  await expect(win.locator(".op-bubble-grounded")).toHaveCount(1);

  for (const mode of ["window", "full screen"]) {
    if (mode === "full screen") await win.getByRole("button", { name: "Full screen" }).click();
    const unnamed = await win.evaluate((root) => {
      const out: string[] = [];
      for (const el of Array.from(root.querySelectorAll("button, textarea, input, select, a[href]"))) {
        const h = el as HTMLElement;
        const name = (h.getAttribute("aria-label") || h.getAttribute("title") || h.getAttribute("placeholder") || h.textContent || "").trim();
        if (!name && !h.closest("label")) out.push(h.outerHTML.slice(0, 120));
      }
      return out;
    });
    expect(unnamed, mode).toEqual([]);

    // Every piece of visible text in the window is on the 14/16 px scale. A
    // lone symbol (the table's sort glyph) is an icon, not text to read.
    const small = await win.evaluate((root) => {
      const out: string[] = [];
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
      for (let n = walker.nextNode(); n; n = walker.nextNode()) {
        const el = n.parentElement;
        if (!el || !/[\p{L}\p{N}]/u.test(n.textContent ?? "")) continue;
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) continue;
        const fs = parseFloat(getComputedStyle(el).fontSize);
        if (fs < 14) out.push(`${el.tagName}.${el.className} ${fs}px "${(n.textContent ?? "").trim().slice(0, 40)}"`);
      }
      return out;
    });
    expect(small, mode).toEqual([]);
  }
});
