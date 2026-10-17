// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Iris answer progress (tracker 337 N-E2), end to end against the faked API:
//   1. the panel asks for a stream, and the streamed answer renders exactly as
//      the JSON answer does — with ONE ask;
//   2. a server that answers JSON to a stream request is read as JSON;
//   3. a stream a proxy cut short falls back to the plain ask once (two asks)
//      and the answer still renders;
//   4. hostile event and tool names never reach the screen.

import { test, expect, type Page } from "@playwright/test";
import { bootIris, openIris, askIris, irisPanel, topCpuAnswer, TENANT_CONFIG, XSS_IMG, type IrisBackendOptions } from "./irisBackend";

test.use({ timezoneId: "UTC", locale: "en-US" });

// The one Iris panel (#21); its window is e2e/irisPanel.spec.ts's subject.
const drawer = irisPanel;
const answers = (page: Page) => drawer(page).locator(".op-row.assistant .op-bubble-grounded");

async function boot(page: Page, stream: IrisBackendOptions["stream"]) {
  const fake = await bootIris(page, { answer: () => topCpuAnswer(), tenantConfig: TENANT_CONFIG, stream });
  await page.goto("/#/overview/home");
  await openIris(page);
  return fake;
}

test("a streamed answer renders like the JSON answer, with one ask", async ({ page }) => {
  const fake = await boot(page, () => ({
    events: [{ type: "planning" }, { type: "tool_started", tool: "nl_query" }, { type: "tool_finished", tool: "nl_query", outcome: "ok" }, { type: "grounding" }],
  }));
  await askIris(page, "top 3 devices by cpu in the last hour");
  const ans = answers(page).last();
  await expect(ans.locator(".op-text").first()).toContainText("Cpu — 3 results: core-rtr-1 91.5%");
  expect(fake.asks).toHaveLength(1);
  expect(fake.accepts[0]).toContain("text/event-stream");
});

test("a server that answers JSON to a stream request is read as JSON", async ({ page }) => {
  const fake = await boot(page, () => null);
  await askIris(page, "top 3 devices by cpu in the last hour");
  await expect(answers(page).last().locator(".op-text").first()).toContainText("Cpu — 3 results");
  expect(fake.asks).toHaveLength(1);
});

test("a broken stream falls back to the plain ask once and still answers", async ({ page }) => {
  const fake = await boot(page, () => "break");
  await askIris(page, "top 3 devices by cpu in the last hour");
  await expect(answers(page).last().locator(".op-text").first()).toContainText("Cpu — 3 results");
  expect(fake.asks).toHaveLength(2);
});

test("hostile event and tool names never reach the screen", async ({ page }) => {
  await boot(page, () => ({ events: [{ type: XSS_IMG }, { type: "tool_started", tool: XSS_IMG }, { type: "tool_started", tool: "<b>owned</b>" }] }));
  await askIris(page, "top 3 devices by cpu in the last hour");
  await expect(answers(page).last()).toBeVisible();
  await expect(drawer(page).getByText("owned")).toHaveCount(0);
  await expect(page.locator('img[src="x"]')).toHaveCount(0);
  expect(await page.evaluate(() => (window as unknown as { __irisXss?: number }).__irisXss)).toBeUndefined();
});
