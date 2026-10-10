// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Iris panel E2E — tracker 342: one test per acceptance criterion of the
// design of record, docs/design/IRIS_PANEL_DESIGN_2026-10-05.md ("Acceptance
// criteria"), in the order the design lists them, plus the narrow-viewport and
// entry-point rules (§1, §16). Drives the real SPA in Chromium with the API
// faked at the network boundary (./irisBackend.ts); geometry is read from the
// laid-out page, so "does not resize the workspace" and "reflows" are pixels,
// not class names.
//
// Screenshots for the owner's visual/motion review are taken by the last test,
// only when IRIS_SCREENSHOT_DIR is set (they are review material, not a gate).

import { test, expect, type Locator, type Page } from "@playwright/test";
import { bootIris, openIris, askIris, irisPanel, irisLauncher, topCpuAnswer, TENANT_CONFIG } from "./irisBackend";

test.use({ timezoneId: "UTC", locale: "en-US", viewport: { width: 1600, height: 900 } });

const GAP = 12; // --sp-3: the floating gap (design: 12–16 px)
const FLOAT_W = 448; // design: 440–460 px
const DOCK_W = 480; // design: default dock width
const SPARKLE = "m12 4 1.9 5.8L20 12l-6.1 2.2L12 20l-1.9-5.8L4 12l6.1-2.2z"; // Icon "copilot"

type Rect = { left: number; top: number; right: number; bottom: number; width: number; height: number };

async function rect(loc: Locator): Promise<Rect> {
  return loc.evaluate((el) => {
    const r = el.getBoundingClientRect();
    return { left: r.left, top: r.top, right: r.right, bottom: r.bottom, width: r.width, height: r.height };
  });
}

// The panel element itself, whether or not it is open (a closed panel is
// aria-hidden, so it has no role to find it by).
const panelEl = (page: Page) => page.locator("#iris-panel");
const workspace = (page: Page) => page.locator("#main-content");
const topbar = (page: Page) => page.locator("header.topbar");
const ctl = (page: Page, name: string) => irisPanel(page).getByRole("button", { name, exact: true });

/** Wait until every animation and transition on the panel has finished. */
async function settle(page: Page) {
  await panelEl(page).evaluate((el) => Promise.all(el.getAnimations().map((a) => a.finished)));
}

async function boot(page: Page) {
  const fake = await bootIris(page, { answer: () => topCpuAnswer(), tenantConfig: TENANT_CONFIG });
  await page.goto("/#/overview/home");
  await expect(irisLauncher(page)).toBeVisible();
  return fake;
}

async function open(page: Page) {
  await openIris(page);
  await settle(page);
}

async function mode(page: Page) {
  return panelEl(page).getAttribute("data-mode");
}

function near(actual: number, expected: number, what: string, tol = 1) {
  expect(Math.abs(actual - expected), `${what}: ${actual} ≈ ${expected}`).toBeLessThanOrEqual(tol);
}

// ── 1 ─────────────────────────────────────────────────────────────────────
test("clicking ✦ Iris in the header opens a right-side floating panel", async ({ page }) => {
  await boot(page);
  const launcher = irisLauncher(page);
  const bar = await rect(topbar(page));
  const l = await rect(launcher);
  // Upper right of the global header, with the sparkle — never the eye.
  expect(l.left).toBeGreaterThan(1600 * 0.75);
  expect(l.top).toBeGreaterThanOrEqual(bar.top);
  expect(l.bottom).toBeLessThanOrEqual(bar.bottom);
  await expect(launcher).toHaveText("Iris");
  expect(await launcher.locator("svg path").getAttribute("d")).toBe(SPARKLE);
  await expect(launcher).toHaveAttribute("aria-expanded", "false");

  await launcher.click();
  await settle(page);
  await expect(irisPanel(page)).toBeVisible();
  expect(await mode(page)).toBe("floating");
  await expect(launcher).toHaveAttribute("aria-expanded", "true");

  const p = await rect(panelEl(page));
  near(p.width, FLOAT_W, "floating width");
  near(1600 - p.right, GAP, "right gap");
  near(p.top - bar.bottom, GAP, "top gap below the header");
  near(900 - p.bottom, GAP, "bottom gap");
  const look = await panelEl(page).evaluate((el) => {
    const cs = getComputedStyle(el);
    return { radius: cs.borderTopLeftRadius, shadow: cs.boxShadow, border: cs.borderTopWidth };
  });
  expect(look.radius).toBe("12px");
  expect(look.shadow).not.toBe("none");
  expect(look.border).toBe("1px");
});

// ── 2 ─────────────────────────────────────────────────────────────────────
test("the floating panel overlays the workspace without resizing it", async ({ page }) => {
  await boot(page);
  const before = await rect(workspace(page));
  await open(page);
  const after = await rect(workspace(page));
  expect(after).toEqual(before);
  const p = await rect(panelEl(page));
  expect(p.left, "it sits over the workspace, not beside it").toBeLessThan(after.right);
});

// ── 3 + 4 ─────────────────────────────────────────────────────────────────
test("Dock snaps Iris to the right edge and the workspace reflows beside it", async ({ page }) => {
  await boot(page);
  const before = await rect(workspace(page));
  await open(page);
  const bar = await rect(topbar(page));

  await ctl(page, "Dock").click();
  await settle(page);
  expect(await mode(page)).toBe("docked");
  const p = await rect(panelEl(page));
  near(p.right, 1600, "flush with the right edge");
  near(p.top, bar.bottom, "directly under the header");
  near(p.bottom, 900, "down to the bottom edge");
  near(p.width, DOCK_W, "default dock width");
  const look = await panelEl(page).evaluate((el) => {
    const cs = getComputedStyle(el);
    return { radius: cs.borderTopLeftRadius, shadow: cs.boxShadow };
  });
  expect(look.radius, "corners flatten against the shell").toBe("0px");
  expect(look.shadow, "the floating shadow is gone").toBe("none");

  const after = await rect(workspace(page));
  near(after.width, before.width - DOCK_W, "workspace gave up exactly the dock width");
  expect(after.right, "no overlap").toBeLessThanOrEqual(p.left + 0.5);
  near(after.left, before.left, "the left navigation is untouched");
});

// ── 5 ─────────────────────────────────────────────────────────────────────
test("the dock width is resizable by pointer and keyboard, and remembered", async ({ page }) => {
  await boot(page);
  await open(page);
  await ctl(page, "Dock").click();
  await settle(page);
  const before = await rect(workspace(page));
  const sep = irisPanel(page).getByRole("separator", { name: "Resize Iris" });
  await expect(sep).toHaveAttribute("aria-orientation", "vertical");
  expect(await sep.evaluate((el) => getComputedStyle(el).cursor)).toBe("ew-resize");

  // Pointer: drag the splitter 100 px to the left.
  const s = await rect(sep);
  await page.mouse.move(s.left + s.width / 2, s.top + 200);
  await page.mouse.down();
  await page.mouse.move(s.left + s.width / 2 - 100, s.top + 200, { steps: 6 });
  expect(await page.evaluate(() => document.documentElement.classList.contains("iris-resizing"))).toBe(true);
  await page.mouse.up();
  await expect(sep).toHaveAttribute("aria-valuenow", String(DOCK_W + 100));
  near((await rect(panelEl(page))).width, DOCK_W + 100, "dragged width");
  near((await rect(workspace(page))).width, before.width - 100, "workspace follows in real time");
  expect(await page.evaluate(() => document.documentElement.classList.contains("iris-resizing"))).toBe(false);

  // Dragging past the limits stops at them.
  const s2 = await rect(sep);
  await page.mouse.move(s2.left + 2, s2.top + 200);
  await page.mouse.down();
  await page.mouse.move(100, s2.top + 200, { steps: 4 });
  await page.mouse.up();
  await expect(sep).toHaveAttribute("aria-valuenow", "650");

  // Keyboard: Home / End / arrows.
  await sep.focus();
  await page.keyboard.press("Home");
  await expect(sep).toHaveAttribute("aria-valuenow", "380");
  await page.keyboard.press("ArrowRight");
  await expect(sep).toHaveAttribute("aria-valuenow", "380"); // the minimum holds
  await page.keyboard.press("ArrowLeft");
  await page.keyboard.press("ArrowLeft");
  await expect(sep).toHaveAttribute("aria-valuenow", "412");
  near((await rect(panelEl(page))).width, 412, "keyboard width");

  // Remembered: a reload restores Docked at 412 px (closed until asked).
  await page.reload();
  await expect(irisLauncher(page)).toHaveAttribute("aria-expanded", "false");
  await open(page);
  expect(await mode(page)).toBe("docked");
  near((await rect(panelEl(page))).width, 412, "remembered width");
  expect(await page.evaluate(() => localStorage.getItem("iris.panel.width"))).toBe("412");
});

// ── 6 ─────────────────────────────────────────────────────────────────────
test("Undock restores the floating panel and the full-width workspace", async ({ page }) => {
  await boot(page);
  const before = await rect(workspace(page));
  await open(page);
  const floating = await rect(panelEl(page));
  await ctl(page, "Dock").click();
  await settle(page);
  await ctl(page, "Undock").click();
  await settle(page);
  expect(await mode(page)).toBe("floating");
  expect(await rect(panelEl(page))).toEqual(floating);
  expect(await rect(workspace(page))).toEqual(before);
  expect(await panelEl(page).evaluate((el) => getComputedStyle(el).borderTopLeftRadius)).toBe("12px");
});

// ── 7 ─────────────────────────────────────────────────────────────────────
test("Expand returns to the mode it was entered from", async ({ page }) => {
  await boot(page);
  await open(page);
  const floating = await rect(panelEl(page));
  const rail = await rect(page.locator(".shell > .rail"));

  await ctl(page, "Expand").click();
  await settle(page);
  expect(await mode(page)).toBe("expanded");
  const big = await rect(panelEl(page));
  near(big.left, rail.right + GAP, "expanded starts beside the navigation");
  near(1600 - big.right, GAP, "expanded right gap");
  await ctl(page, "Collapse").click();
  await settle(page);
  expect(await mode(page)).toBe("floating");
  expect(await rect(panelEl(page))).toEqual(floating);

  await ctl(page, "Dock").click();
  await settle(page);
  const docked = await rect(panelEl(page));
  const dockedWorkspace = await rect(workspace(page));
  await ctl(page, "Expand").click();
  await settle(page);
  expect(await mode(page)).toBe("expanded");
  await page.keyboard.press("Escape"); // focus is on the Collapse control, inside Iris
  await settle(page);
  expect(await mode(page)).toBe("docked");
  expect(await rect(panelEl(page))).toEqual(docked);
  expect(await rect(workspace(page))).toEqual(dockedWorkspace);
});

// ── 8 ─────────────────────────────────────────────────────────────────────
test("close and reopen restore the preferred mode, from every entry point, in ONE panel", async ({ page }) => {
  await boot(page);
  await open(page);
  await ctl(page, "Dock").click();
  await settle(page);

  const reopenings: [string, () => Promise<void>][] = [
    ["the ✦ Iris header control", () => irisLauncher(page).click()],
    ["the rail's Iris AI item", () => page.locator('button.rail-item[title="Iris AI"]').click()],
    ["the command palette", async () => {
      await page.keyboard.press("Control+k");
      const box = page.getByRole("combobox", { name: /Jump to a section/ });
      await box.fill("Open Copilot");
      await box.press("Enter");
    }],
    // An `(i)` raises this exact event (components/AskIris.tsx); the Overview
    // page may carry none, so the test raises it the way the button does.
    ["an (i) AskIris", async () => {
      await page.evaluate(() => window.dispatchEvent(new CustomEvent("iris:ask", {
        detail: { topic: "kpi.critical", question: "What does \"Critical\" mean here?" },
      })));
    }],
  ];
  for (const [via, reopen] of reopenings) {
    await ctl(page, "Close Iris").click();
    await settle(page);
    expect(await mode(page), `closed before reopening via ${via}`).toBe("closed");
    await expect(irisLauncher(page)).toHaveAttribute("aria-expanded", "false");
    await reopen();
    await settle(page);
    expect(await mode(page), `reopened via ${via}`).toBe("docked");
    await expect(page.locator("#iris-panel")).toHaveCount(1);
    await expect(page.locator(".op-chat")).toHaveCount(1);
  }

  // And Floating is remembered the same way.
  await ctl(page, "Undock").click();
  await ctl(page, "Close Iris").click();
  await irisLauncher(page).click();
  await settle(page);
  expect(await mode(page)).toBe("floating");
});

// ── 9 ─────────────────────────────────────────────────────────────────────
test("the conversation and component state survive every transition", async ({ page }) => {
  const fake = await boot(page);
  await open(page);
  await askIris(page, "top 3 devices by cpu in the last hour");
  // By element, not role: a closed panel is aria-hidden, and what is being
  // proven is that its content is still there, untouched, while closed.
  const answers = panelEl(page).locator(".op-row.assistant .op-bubble-grounded");
  await expect(answers).toHaveCount(1);
  const box = panelEl(page).locator("textarea.op-input");
  await box.fill("a draft I have not sent");
  // Tag the live DOM nodes: a remount would replace them and lose the tag.
  await box.evaluate((el) => { (el as HTMLElement & { __irisTag?: string }).__irisTag = "same-node"; });
  const tagged = () => box.evaluate((el) => (el as HTMLElement & { __irisTag?: string }).__irisTag);

  const steps: [string, () => Promise<void>][] = [
    ["dock", () => ctl(page, "Dock").click()],
    ["expand", () => ctl(page, "Expand").click()],
    ["Esc back to docked", () => page.keyboard.press("Escape")],
    ["undock", () => ctl(page, "Undock").click()],
    ["expand from floating", () => ctl(page, "Expand").click()],
    ["collapse", () => ctl(page, "Collapse").click()],
    ["close", () => ctl(page, "Close Iris").click()],
    ["reopen", () => irisLauncher(page).click()],
    ["Esc to closed", async () => { await box.focus(); await page.keyboard.press("Escape"); }],
    ["reopen again", () => irisLauncher(page).click()],
  ];
  for (const [what, step] of steps) {
    await step();
    await settle(page);
    expect(await tagged(), `not remounted after: ${what}`).toBe("same-node");
    await expect(box, `draft kept after: ${what}`).toHaveValue("a draft I have not sent");
    await expect(answers, `answer kept after: ${what}`).toHaveCount(1);
    expect(await page.evaluate(() => sessionStorage.getItem("iris.conversation")), what).toBe("conv-1");
  }

  // The same server conversation carries on.
  await askIris(page, "and memory?");
  await expect(answers).toHaveCount(2);
  expect(fake.started).toEqual(["conv-1"]);
  expect(fake.asks.map((a) => a.conversation_id)).toEqual(["conv-1", "conv-1"]);
});

// ── 10 ────────────────────────────────────────────────────────────────────
test("motion is restrained: 200 ms, transform and opacity only, nothing looping", async ({ page }) => {
  await boot(page);
  const cs = await panelEl(page).evaluate((el) => {
    const s = getComputedStyle(el);
    return { props: s.transitionProperty, durs: s.transitionDuration };
  });
  const props = cs.props.split(",").map((p) => p.trim());
  // Geometry is never transitioned (no width/left/top/right animation → no layout per frame).
  for (const forbidden of ["width", "left", "right", "top", "bottom", "all", "height"]) {
    expect(props, `does not transition ${forbidden}`).not.toContain(forbidden);
  }
  expect(props).toEqual(expect.arrayContaining(["transform", "opacity"]));
  const durs = cs.durs.split(",").map((d) => parseFloat(d) * 1000);
  props.forEach((p, i) => {
    if (p !== "visibility") expect(durs[i], `${p} duration`).toBe(200);
  });

  // Opening slides + fades in 200 ms.
  await irisLauncher(page).click();
  const opening = await panelEl(page).evaluate((el) =>
    el.getAnimations().map((a) => ({ prop: (a as CSSTransition).transitionProperty, ms: Number((a.effect as KeyframeEffect).getTiming().duration) })));
  expect(opening.map((a) => a.prop).sort()).toEqual(expect.arrayContaining(["opacity", "transform"]));
  for (const a of opening) if (a.prop === "transform" || a.prop === "opacity") expect(a.ms).toBe(200);
  await settle(page);

  // Docking is one 200 ms transform from where the panel was (FLIP), no bounce.
  const docking = await page.evaluate(async () => {
    (document.querySelector('#iris-panel button[aria-label="Dock"]') as HTMLButtonElement).click();
    await new Promise((r) => requestAnimationFrame(() => r(null)));
    return document.getElementById("iris-panel")!.getAnimations()
      .filter((a) => !(a instanceof CSSTransition))
      .map((a) => {
        const effect = a.effect as KeyframeEffect;
        return {
          ms: Number(effect.getTiming().duration),
          easing: effect.getTiming().easing,
          keys: [...new Set(effect.getKeyframes().flatMap((k) => Object.keys(k)))].sort(),
        };
      });
  });
  expect(docking).toHaveLength(1);
  expect(docking[0].ms).toBe(200);
  expect(docking[0].easing).toBe("cubic-bezier(0.2, 0, 0, 1)");
  expect(docking[0].keys.filter((k) => !["composite", "computedOffset", "easing", "offset", "transformOrigin"].includes(k))).toEqual(["transform"]);
  await settle(page);

  // Idle: neither the panel nor the header control animates on its own.
  const looping = await page.evaluate(() =>
    document.getAnimations().filter((a) => {
      const t = (a.effect as KeyframeEffect | null)?.target as Element | null;
      if (!t) return false;
      return (t.id === "iris-panel" || t.id === "iris-launcher" || !!t.closest("#iris-launcher"));
    }).length);
  expect(looping).toBe(0);
});

// ── 11 ────────────────────────────────────────────────────────────────────
test("keyboard and focus: Enter/Space open, Esc steps back, focus returns to ✦ Iris", async ({ page }) => {
  await boot(page);
  const launcher = irisLauncher(page);
  await expect(launcher).toHaveAttribute("aria-controls", "iris-panel");
  await launcher.focus();
  await page.keyboard.press("Enter");
  await settle(page);
  await expect(page.getByPlaceholder(/Ask Iris AI/), "focus moves into Iris").toBeFocused();
  await expect(panelEl(page)).toHaveAttribute("role", "complementary");

  // Tab reaches the window controls; each is labelled, has a tooltip and a
  // visible keyboard focus ring.
  for (const name of ["Dock", "Expand", "Close Iris"]) {
    const b = ctl(page, name);
    await expect(b).toHaveAttribute("title", /.+/);
  }
  let reached = "";
  for (let i = 0; i < 12 && reached !== "Dock"; i++) {
    await page.keyboard.press("Shift+Tab");
    reached = await page.evaluate(() => document.activeElement?.getAttribute("aria-label") ?? "");
  }
  expect(reached, "Shift+Tab from the question box reaches Dock").toBe("Dock");
  const ring = await page.evaluate(() => getComputedStyle(document.activeElement!).outlineStyle);
  expect(ring).not.toBe("none");

  // Space on Dock docks; Enter on Expand expands; Esc steps back one level.
  await page.keyboard.press("Space");
  await settle(page);
  expect(await mode(page)).toBe("docked");
  await ctl(page, "Expand").focus();
  await page.keyboard.press("Enter");
  await settle(page);
  expect(await mode(page)).toBe("expanded");
  await page.keyboard.press("Escape");
  await settle(page);
  expect(await mode(page)).toBe("docked");
  await page.keyboard.press("Escape");
  await settle(page);
  expect(await mode(page)).toBe("closed");
  await expect(launcher, "focus returns to the header control").toBeFocused();

  // Space on the header control reopens in the remembered mode.
  await page.keyboard.press("Space");
  await settle(page);
  expect(await mode(page)).toBe("docked");
  // A closed panel is out of the tab order entirely.
  await ctl(page, "Close Iris").click();
  await settle(page);
  expect(await panelEl(page).evaluate((el) => el.hasAttribute("inert"))).toBe(true);
});

// ── 12 ────────────────────────────────────────────────────────────────────
test("reduced-motion users get no motion", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await boot(page);
  await irisLauncher(page).click();
  const longest = () => page.evaluate(() => Math.max(0, ...document.getElementById("iris-panel")!.getAnimations()
    .map((a) => Number((a.effect as KeyframeEffect).getTiming().duration))));
  expect(await longest(), "opening").toBeLessThanOrEqual(1);
  await settle(page);
  await ctl(page, "Dock").click();
  expect(await longest(), "docking").toBeLessThanOrEqual(1);
  await settle(page);
  await ctl(page, "Expand").click();
  expect(await longest(), "expanding").toBeLessThanOrEqual(1);
  expect(await mode(page)).toBe("expanded");
});

// ── 13 ────────────────────────────────────────────────────────────────────
test("no bottom-right chatbot bubble exists — closed or open", async ({ page }) => {
  await boot(page);
  const corner = () => page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>("body *"))) {
      const cs = getComputedStyle(el);
      if (cs.position !== "fixed" || cs.visibility === "hidden" || cs.display === "none" || Number(cs.opacity) === 0) continue;
      const r = el.getBoundingClientRect();
      if (!r.width || !r.height) continue;
      // Anything fixed whose box lives in the bottom-right 200×200 corner.
      if (r.left > window.innerWidth - 200 && r.top > window.innerHeight - 200) out.push(el.className || el.tagName);
    }
    return out;
  });
  expect(await corner()).toEqual([]);
  await expect(page.locator(".iris-launcher, [data-testid='iris-launcher']")).toHaveCount(0);
  await open(page);
  expect(await corner()).toEqual([]);
  // The way in stays in the header.
  expect(await irisLauncher(page).evaluate((el) => !!el.closest("header.topbar"))).toBe(true);
});

// ── 14 ────────────────────────────────────────────────────────────────────
test("Iris only docks on the right — there is no left or bottom dock", async ({ page }) => {
  await boot(page);
  await open(page);
  const labels = await irisPanel(page).locator(".op-hd button").evaluateAll((bs) =>
    bs.map((b) => `${b.getAttribute("aria-label") ?? ""} ${b.getAttribute("title") ?? ""}`));
  expect(labels.filter((l) => /\b(left|bottom)\b/i.test(l))).toEqual([]);
  await ctl(page, "Dock").click();
  await settle(page);
  const p = await rect(panelEl(page));
  expect(p.left).toBeGreaterThan(1600 / 2);
  near(p.right, 1600, "right edge");
  expect(await page.locator('[role="separator"][aria-orientation="horizontal"]').count(), "no bottom splitter").toBe(0);
});

// ── §16 ───────────────────────────────────────────────────────────────────
test("narrow viewports overlay instead of squeezing the workspace", async ({ page }) => {
  await boot(page);
  await open(page);
  await ctl(page, "Dock").click();
  await settle(page);

  // 1000 px: no room for a 380 px dock beside a 640 px workspace → overlay.
  await page.setViewportSize({ width: 1000, height: 800 });
  await expect.poll(() => panelEl(page).getAttribute("class")).toContain("is-floating");
  const ws = await rect(workspace(page));
  const rail = await rect(page.locator(".shell > .rail"));
  near(ws.width, 1000 - rail.right, "the workspace keeps its full width");
  expect(await mode(page), "the docked preference is kept").toBe("docked");
  await expect(ctl(page, "Dock"), "no dock offered without room for one").toBeDisabled();
  await expect(ctl(page, "Dock")).toHaveAttribute("title", /wider window/);
  await expect(irisLauncher(page), "the header control stays on screen").toBeInViewport({ ratio: 1 });

  // 600 px: a near-full-screen sheet.
  await page.setViewportSize({ width: 600, height: 800 });
  await expect.poll(() => panelEl(page).getAttribute("class")).toContain("is-sheet");
  await settle(page);
  const sheet = await rect(panelEl(page));
  near(sheet.left, 0, "sheet left");
  near(sheet.right, 600, "sheet right");
  near((await rect(workspace(page))).width, 600 - (await rect(page.locator(".shell > .rail"))).right, "workspace untouched");

  // Wide again: docked returns, with its reflow.
  await page.setViewportSize({ width: 1600, height: 900 });
  await expect.poll(() => panelEl(page).getAttribute("class")).toContain("is-docked");
  await settle(page);
  near((await rect(panelEl(page))).width, DOCK_W, "docked again");
});

test("with Iris closed, the shell is exactly as before: no reserved column, header controls intact", async ({ page }) => {
  await boot(page);
  const rail = await rect(page.locator(".shell > .rail"));
  near((await rect(workspace(page))).width, 1600 - rail.right, "workspace spans to the right edge");
  await expect(topbar(page).getByRole("combobox", { name: /Search devices/ })).toBeVisible();
  await expect(topbar(page).getByRole("combobox", { name: "Time range" })).toBeVisible();
  await expect(topbar(page).getByRole("button", { name: "Open documentation" })).toBeVisible();
  await expect(page.locator('button.rail-item[title="Iris AI"]')).toBeVisible();
  expect(await panelEl(page).evaluate((el) => getComputedStyle(el).visibility)).toBe("hidden");
});

// ── review material ───────────────────────────────────────────────────────
test("screenshots for the owner's review (IRIS_SCREENSHOT_DIR only)", async ({ page }) => {
  const dir = process.env.IRIS_SCREENSHOT_DIR;
  test.skip(!dir, "set IRIS_SCREENSHOT_DIR to write review screenshots");
  await boot(page);
  await open(page);
  await askIris(page, "top 3 devices by cpu in the last hour");
  await expect(irisPanel(page).locator(".op-row.assistant .op-bubble-grounded")).toHaveCount(1);
  await page.waitForTimeout(400); // chart paint
  await page.screenshot({ path: `${dir}/iris-floating.png` });
  await ctl(page, "Dock").click();
  await settle(page);
  await page.screenshot({ path: `${dir}/iris-docked.png` });
  await ctl(page, "Expand").click();
  await settle(page);
  await page.screenshot({ path: `${dir}/iris-expanded.png` });
  await page.keyboard.press("Escape");
  await settle(page);
  await page.setViewportSize({ width: 1000, height: 760 });
  await expect.poll(() => panelEl(page).getAttribute("class")).toContain("is-floating");
  await settle(page);
  await page.screenshot({ path: `${dir}/iris-narrow-1000-overlay.png` });
  await page.setViewportSize({ width: 600, height: 860 });
  await expect.poll(() => panelEl(page).getAttribute("class")).toContain("is-sheet");
  await settle(page);
  await page.screenshot({ path: `${dir}/iris-narrow-600-sheet.png` });
  await page.setViewportSize({ width: 1600, height: 900 });
  await ctl(page, "Close Iris").click();
  await settle(page);
  await page.screenshot({ path: `${dir}/iris-closed-header.png`, clip: { x: 1000, y: 0, width: 600, height: 80 } });
});
