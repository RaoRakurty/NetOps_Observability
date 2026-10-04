// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Iris box (the AI drawer) E2E — tracker 337 N-E5. Drives the real SPA against
// the Iris API faked at the network boundary (./irisBackend.ts) and proves:
//   1. a data question is answered as DATA: the summary, the chart and the
//      table all render, the query citation is shown, and hostile markup in a
//      result cell or the summary is text — never HTML;
//   2. follow-ups ride ONE server conversation: started once, its id sent with
//      every ask, kept across closing/reopening the drawer (sessionStorage), a
//      conversation the server no longer has is dropped and the question still
//      answered, and clearing the chat starts a new one;
//   3. an unbound reference or an unplaceable question gets the honest "not
//      understood" answer (no fabricated result), and an ambiguous name is
//      asked back rather than guessed;
//   4. accessibility smoke: the drawer is a named landmark, the answer is a
//      named region with a named grid, and every control has an accessible name.

import { test, expect, type Page } from "@playwright/test";
import {
  bootIris, openIris, askIris, topCpuAnswer, memorySeriesAnswer, capabilityAnswer, clarifyAnswer,
  XSS_IMG, TENANT_CONFIG, SUGGESTION_IGNORED,
} from "./irisBackend";

test.use({ timezoneId: "UTC", locale: "en-US" });

const drawer = (page: Page) => page.getByRole("complementary", { name: "Iris AI assistant" });
const answers = (page: Page) => drawer(page).locator(".op-row.assistant .op-bubble-grounded");

async function boot(page: Page, answer: (q: string) => Record<string, unknown>) {
  const fake = await bootIris(page, { answer, tenantConfig: TENANT_CONFIG });
  await page.goto("/#/overview/home");
  await openIris(page);
  return fake;
}

test("a data question renders the summary, the chart, the table and the citation — hostile values as text", async ({ page }) => {
  await boot(page, () => topCpuAnswer());
  await askIris(page, "top 3 devices by cpu in the last hour");

  const ans = answers(page).last();
  await expect(ans).toBeVisible();
  // The summary is the engine's sentence, escaped — the markup is visible text.
  await expect(ans.locator(".op-text").first()).toContainText(`Cpu — 3 results: core-rtr-1 91.5%; ${XSS_IMG} 72%`);

  // The result is drawn as data: a titled answer region, the bar chart, the table.
  const data = ans.getByTestId("op-data-answer");
  await expect(data.getByRole("region", { name: "Highest CPU util pct" })).toBeVisible();
  await expect(data.locator("figure.iris-chart canvas").first()).toBeVisible();
  const grid = data.getByRole("grid", { name: "Answer rows" });
  await expect(grid).toBeVisible();
  await expect(grid.getByRole("gridcell", { name: "core-rtr-1" })).toBeVisible();
  await expect(grid.getByText("91.5 percent")).toBeVisible();
  await expect(grid.getByText(XSS_IMG, { exact: true })).toBeVisible();

  // The query citation is shown — as text: a query has no page, and an empty
  // href would be a full reload of the app.
  const cite = ans.locator(".op-cite", { hasText: "Query 5d41a8c0" });
  await expect(cite).toBeVisible();
  expect(await cite.evaluate((el) => el.tagName)).toBe("SPAN");
  await expect(ans.getByTestId("iris-grounded-chip")).toHaveText("Grounded · tenant-scoped · cited");

  // Nothing was ever parsed as HTML: no <img src=x> anywhere, the handler never ran.
  await expect(page.locator('img[src="x"]')).toHaveCount(0);
  expect(await page.evaluate(() => (window as unknown as { __irisXss?: number }).__irisXss)).toBeUndefined();
});

test("follow-ups ride one server conversation, kept across closing and reopening the drawer", async ({ page }) => {
  const fake = await boot(page, (q) => (q.includes("memory") ? memorySeriesAnswer() : topCpuAnswer()));

  await askIris(page, "top 3 devices by cpu in the last hour");
  await expect(answers(page)).toHaveCount(1);
  expect(fake.started).toEqual(["conv-1"]);
  expect(await page.evaluate(() => sessionStorage.getItem("iris.conversation"))).toBe("conv-1");

  // Close the drawer (Opsis unmounts) and reopen it: the conversation survives.
  await drawer(page).getByTitle("Close (Esc)").click();
  await expect(page.getByPlaceholder(/Ask Iris AI/)).toHaveCount(0);
  await openIris(page);
  await askIris(page, "memory on that device");

  const ans = answers(page).last();
  await expect(ans.locator(".op-text").first()).toContainText("core-rtr-1 peak 66%");
  // A series answer draws its chart and does not also claim "Nothing found".
  await expect(ans.locator("figure.iris-chart canvas").first()).toBeVisible();
  await expect(ans.getByText(/Nothing found/)).toHaveCount(0);
  // The SERVER's plan is what is drawn (N-E1): its title, not the client's
  // default ("Mem util pct over time"), and its disclosure about the ignored
  // model suggestion, as text.
  await expect(ans.getByRole("region", { name: "Memory over time" })).toBeVisible();
  await expect(ans.getByTestId("iris-plan-disclosure")).toHaveText(SUGGESTION_IGNORED);

  expect(fake.started).toEqual(["conv-1"]); // one conversation, not two
  expect(fake.asks.map((a) => a.conversation_id)).toEqual(["conv-1", "conv-1"]);
  expect(fake.asks.map((a) => a.question)).toEqual(["top 3 devices by cpu in the last hour", "memory on that device"]);
});

test("a conversation the server no longer holds is dropped, the question still answered, and the next one starts afresh", async ({ page }) => {
  const fake = await boot(page, () => topCpuAnswer());
  await askIris(page, "top 3 devices by cpu in the last hour");
  await expect(answers(page)).toHaveCount(1);

  fake.live.delete("conv-1"); // the server restarted / the conversation expired
  await askIris(page, "top 3 devices by cpu in the last hour");
  await expect(answers(page)).toHaveCount(2);
  await expect(drawer(page).locator(".op-error")).toHaveCount(0); // answered, not an error
  expect(await page.evaluate(() => sessionStorage.getItem("iris.conversation"))).toBeNull();

  await askIris(page, "top 3 devices by cpu in the last hour");
  await expect(answers(page)).toHaveCount(3);
  // 404 on the stale id → the same question asked without one → a new conversation next time.
  expect(fake.asks.map((a) => a.conversation_id)).toEqual(["conv-1", "conv-1", undefined, "conv-2"]);
  expect(fake.started).toEqual(["conv-1", "conv-2"]);
});

test("clearing the chat forgets the conversation; the next question starts a new one", async ({ page }) => {
  const fake = await boot(page, () => topCpuAnswer());
  await askIris(page, "top 3 devices by cpu in the last hour");
  await expect(answers(page)).toHaveCount(1);

  await drawer(page).getByTitle("New conversation").click();
  await expect(answers(page)).toHaveCount(0);
  await expect(drawer(page).getByText("How can I help?")).toBeVisible();
  expect(await page.evaluate(() => sessionStorage.getItem("iris.conversation"))).toBeNull();

  await askIris(page, "top 3 devices by cpu in the last hour");
  await expect(answers(page)).toHaveCount(1);
  expect(fake.started).toEqual(["conv-1", "conv-2"]);
  expect(fake.asks.map((a) => a.conversation_id)).toEqual(["conv-1", "conv-2"]);
});

test("an unbound reference gets the honest 'not understood' answer — no fabricated result", async ({ page }) => {
  await boot(page, () => capabilityAnswer());
  await askIris(page, "memory on that device");

  const ans = answers(page).last();
  await expect(ans.locator(".op-ans-kind")).toHaveText("Notice");
  await expect(ans.locator(".op-text").first()).toContainText("I didn't quite catch that.");
  await expect(ans.getByText("Recommended next actions")).toBeVisible();
  // No data was invented: no answer region, no chart, no table, no citation.
  await expect(ans.getByTestId("op-data-answer")).toHaveCount(0);
  await expect(ans.getByRole("grid")).toHaveCount(0);
  await expect(ans.locator("canvas")).toHaveCount(0);
  await expect(ans.locator(".op-cite")).toHaveCount(0);
  await expect(ans.getByTestId("iris-grounded-chip")).toHaveText("Grounded · tenant-scoped"); // never "cited"
  await expect(ans.getByText("Was this helpful?")).toHaveCount(0); // nothing to rate
});

test("an ambiguous name is asked back, never guessed", async ({ page }) => {
  await boot(page, () => clarifyAnswer());
  await askIris(page, "cpu on the hq firewall");

  const ans = answers(page).last();
  await expect(ans.locator(".op-text").first()).toHaveText(
    "More than one thing matches that name — which did you mean: device:fw-hq-01, device:fw-hq-02?",
  );
  await expect(ans.getByTestId("op-data-answer")).toHaveCount(0); // no result to draw
  await expect(ans.getByRole("grid")).toHaveCount(0);
});

test("a failed ask shows the server's sentence, not the raw HTTP envelope", async ({ page }) => {
  await boot(page, () => ({ status: 502, body: { error: "the metrics store did not answer in time" } }));
  await askIris(page, "top 3 devices by cpu in the last hour");
  const err = drawer(page).locator(".op-error");
  await expect(err).toHaveText("The metrics store did not answer in time.");
  await expect(err).not.toContainText("502");
});

test("accessibility smoke: named landmark, named answer region and grid, every control named", async ({ page }) => {
  await boot(page, () => topCpuAnswer());
  await askIris(page, "top 3 devices by cpu in the last hour");
  const ans = answers(page).last();
  await expect(ans.getByRole("grid", { name: "Answer rows" })).toBeVisible();

  await expect(drawer(page)).toBeVisible();
  await expect(ans.getByRole("region", { name: "Highest CPU util pct" })).toBeVisible();
  await expect(drawer(page).getByRole("columnheader", { name: "Device" })).toBeVisible();

  // Every button and text field in the drawer has an accessible name (text,
  // aria-label, title or placeholder) — the minimum a screen reader needs.
  const unnamed = await drawer(page).evaluate((root) => {
    const out: string[] = [];
    for (const el of Array.from(root.querySelectorAll("button, textarea, input, select, a[href]"))) {
      const h = el as HTMLElement;
      const name = (h.getAttribute("aria-label") || h.getAttribute("title") || h.getAttribute("placeholder") || h.textContent || "").trim();
      const labelled = h.id && root.querySelector(`label[for="${h.id}"]`);
      if (!name && !labelled && !h.closest("label")) out.push(h.outerHTML.slice(0, 120));
    }
    return out;
  });
  expect(unnamed).toEqual([]);

  // Keyboard: the composer takes focus.
  const box = page.getByPlaceholder(/Ask Iris AI/);
  await box.focus();
  await expect(box).toBeFocused();
});
