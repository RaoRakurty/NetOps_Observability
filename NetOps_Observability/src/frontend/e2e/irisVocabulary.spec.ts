// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Iris vocabulary panel E2E (workspace AI settings) — tracker 337 N-E5.
// Drives the real panel inside the Iris drawer against the faked Iris API
// (./irisBackend.ts) and proves:
//   · adding a name whose target is ambiguous OFFERS a choice and saves nothing
//     until the operator picks one — never an automatic guess;
//   · "Check a name" shows how Iris resolves a phrase and how sure it is;
//   · "Try a question" runs inside one server conversation, a follow-up rides
//     the same conversation, and "New conversation" starts a fresh one;
//   · a question Iris cannot place says so and runs nothing;
//   · a conversation the server no longer has is replaced once, and said;
//   · hostile values in a result are text, and every control is named.

import { test, expect, type Page } from "@playwright/test";
import { bootIris, openIris, topCpuAnswer, memorySeriesAnswer, XSS_IMG, TENANT_CONFIG, type Json } from "./irisBackend";

test.use({ timezoneId: "UTC", locale: "en-US" });

const panel = (page: Page) => page.getByTestId("iris-vocabulary");

const FW = (n: string, extra: Json = {}) => ({
  input_text: "fw-hq", entity_id: `device:fw-hq-${n}`, entity_type: "device",
  confidence: 0.7, resolution_method: "partial_name", needs_confirmation: true, ...extra,
});

/** The conversation answers the panel gets: a table, a series, or "not understood". */
function converse(question: string): Json {
  if (question.includes("memory")) return memorySeriesAnswer().data as Json;
  if (question.includes("top 3")) return topCpuAnswer().data as Json;
  return { intent: "", entities: null, clarify: null, decline: "", unparsed: true, not_understood: ["frobnicate", "widgets"] };
}

function resolve(text: string, types: string[]): Json {
  if (text === "fw-hq" && types.join() === "device") return { refs: [FW("01"), FW("02")], ambiguous: true };
  if (text.toLowerCase() === "hq firewall") {
    return { refs: [{ input_text: text, entity_id: "device:fw-hq-02", entity_type: "device", confidence: 0.99, resolution_method: "tenant_alias" }], ambiguous: false };
  }
  return { refs: null, ambiguous: false };
}

async function openPanel(page: Page) {
  const fake = await bootIris(page, { tenantConfig: TENANT_CONFIG, converse, resolve });
  await page.goto("/#/overview/home");
  await openIris(page);
  await page.getByTitle("Assistant settings").click();
  await expect(panel(page)).toBeVisible();
  await expect(panel(page).getByText("No names yet.")).toBeVisible();
  return fake;
}

async function ask(page: Page, q: string) {
  await panel(page).getByLabel("Question").fill(q);
  await panel(page).getByRole("button", { name: "Ask", exact: true }).click();
}

test("adding a name with an ambiguous target offers a choice and never auto-saves", async ({ page }) => {
  const fake = await openPanel(page);
  const p = panel(page);
  await p.getByLabel("Name your team uses").fill("HQ firewall");
  await expect(p.getByLabel("Kind")).toHaveValue("device");
  await p.getByLabel("What it refers to").fill("fw-hq");
  await p.getByRole("button", { name: "Add", exact: true }).click();

  const choice = p.getByTestId("iris-alias-candidates");
  await expect(choice.getByText("Which one did you mean?")).toBeVisible();
  await expect(choice.getByRole("button")).toHaveText(["device:fw-hq-01", "device:fw-hq-02"]);
  expect(fake.resolves).toEqual([{ text: "fw-hq", types: ["device"] }]);
  expect(fake.aliasPuts).toEqual([]); // offered, not saved
  await expect(p.getByText("No names yet.")).toBeVisible();

  await choice.getByRole("button", { name: "device:fw-hq-02" }).click();
  const list = p.getByTestId("iris-alias-list");
  await expect(list).toContainText("HQ firewall → Device device:fw-hq-02");
  await expect(p.getByText("1 of 2000 used.")).toBeVisible();
  await expect(choice).toHaveCount(0);
  // The body carries exactly the three fields — never a tenant.
  expect(fake.aliasPuts).toEqual([{ entity_type: "device", entity_id: "device:fw-hq-02", alias: "HQ firewall" }]);

  // Removing it goes back to empty.
  await list.getByRole("button", { name: "Remove HQ firewall" }).click();
  await expect(p.getByText("No names yet.")).toBeVisible();
});

test("checking a name shows how Iris resolves it and how sure it is", async ({ page }) => {
  await openPanel(page);
  const p = panel(page);
  await p.getByLabel("Name to check").fill("HQ firewall");
  await p.getByRole("button", { name: "Check", exact: true }).click();
  const ref = p.getByTestId("iris-check").getByTestId("iris-ref");
  await expect(ref).toContainText("HQ firewall → Device device:fw-hq-02");
  await expect(ref).toContainText("(your team's name, 99% sure)");

  await p.getByLabel("Name to check").fill("nothing-like-it");
  await p.getByRole("button", { name: "Check", exact: true }).click();
  await expect(p.getByTestId("iris-check-none")).toHaveText("Iris does not recognise that name.");
  // N-C2: an unrecognised name offers the opt-in model suggestion — offered, never run unasked.
  await expect(p.getByTestId("iris-check").getByRole("button", { name: "Ask the AI model what I meant" })).toBeVisible();
});

test("a question and its follow-up share one conversation; 'New conversation' starts another", async ({ page }) => {
  const fake = await openPanel(page);
  const p = panel(page);

  await ask(page, "top 3 devices by cpu in the last hour");
  const result = p.getByTestId("iris-result");
  await expect(result).toContainText("3 rows · from victoriametrics in 42 ms");
  await expect(result.getByRole("cell", { name: "core-rtr-1" })).toBeVisible();
  await expect(result.getByRole("cell", { name: XSS_IMG })).toBeVisible(); // text, not an element
  await expect(page.locator('img[src="x"]')).toHaveCount(0);
  expect(await page.evaluate(() => (window as unknown as { __irisXss?: number }).__irisXss)).toBeUndefined();
  await expect(p.getByTestId("iris-understood")).toContainText("Understood as: query metric");
  await expect(p.getByLabel("Question")).toHaveValue(""); // cleared for the follow-up

  await ask(page, "memory on that device");
  await expect(result).toContainText("1 series · from victoriametrics in 18 ms");
  await expect(p.getByTestId("iris-understood").getByTestId("iris-ref")).toContainText("that device → Device device:core-rtr-1");
  await expect(p.getByTestId("iris-history").getByRole("listitem")).toHaveText([
    "top 3 devices by cpu in the last hour — answered",
    "memory on that device — answered",
  ]);
  expect(fake.started).toEqual(["conv-1"]);
  expect(fake.messages.map((m) => [m.id, m.question])).toEqual([
    ["conv-1", "top 3 devices by cpu in the last hour"],
    ["conv-1", "memory on that device"],
  ]);
  expect(fake.messages.every((m) => m.tz === "UTC")).toBe(true);

  await p.getByRole("button", { name: "New conversation" }).click();
  await expect(p.getByTestId("iris-history")).toHaveCount(0);
  await expect(result).toHaveCount(0);
  await expect(p.getByRole("button", { name: "New conversation" })).toHaveCount(0);

  await ask(page, "top 3 devices by cpu in the last hour");
  await expect(result).toContainText("3 rows");
  expect(fake.started).toEqual(["conv-1", "conv-2"]);
  expect(fake.messages.at(-1)?.id).toBe("conv-2");
});

test("a question Iris cannot place says so and runs nothing", async ({ page }) => {
  await openPanel(page);
  const p = panel(page);
  await ask(page, "frobnicate the widgets");
  await expect(p.getByTestId("iris-understood")).toContainText(
    "Iris did not fully understand this question — it could not place: frobnicate, widgets. Nothing will be run.",
  );
  await expect(p.getByTestId("iris-result")).toHaveCount(0);
  await expect(p.getByRole("button", { name: "Run it" })).toHaveCount(0);
  await expect(p.getByTestId("iris-history").getByRole("listitem")).toHaveText(["frobnicate the widgets — not understood"]);
});

test("a conversation the server no longer has is replaced once, and the restart is said", async ({ page }) => {
  const fake = await openPanel(page);
  const p = panel(page);
  await ask(page, "top 3 devices by cpu in the last hour");
  await expect(p.getByTestId("iris-result")).toContainText("3 rows");

  fake.live.delete("conv-1");
  await ask(page, "memory on that device");
  await expect(p.getByRole("alert")).toHaveText("That conversation had ended — started a new one.");
  await expect(p.getByTestId("iris-result")).toContainText("1 series");
  expect(fake.started).toEqual(["conv-1", "conv-2"]);
  expect(fake.messages.map((m) => m.id)).toEqual(["conv-1", "conv-1", "conv-2"]);
  // The old conversation's turns are not shown as if they were the new one's.
  await expect(p.getByTestId("iris-history").getByRole("listitem")).toHaveText(["memory on that device — answered"]);
});

test("accessibility smoke: every control in the panel has an accessible name", async ({ page }) => {
  await openPanel(page);
  await ask(page, "top 3 devices by cpu in the last hour");
  await expect(panel(page).getByTestId("iris-result")).toBeVisible();
  const unnamed = await panel(page).evaluate((root) => {
    const out: string[] = [];
    for (const el of Array.from(root.querySelectorAll("button, textarea, input, select, a[href]"))) {
      const h = el as HTMLElement;
      const name = (h.getAttribute("aria-label") || h.getAttribute("title") || h.textContent || "").trim();
      if (!name && !h.closest("label")) out.push(h.outerHTML.slice(0, 120));
    }
    return out;
  });
  expect(unnamed).toEqual([]);
  // Step headings are on the 16 px scale, body text on 14 px (NOC-admin UI standard).
  const small = await panel(page).evaluate((root) =>
    Array.from(root.querySelectorAll<HTMLElement>("input, button, select, li, td, th"))
      .filter((el) => parseFloat(getComputedStyle(el).fontSize) < 14)
      .map((el) => `${el.tagName} ${getComputedStyle(el).fontSize} ${el.outerHTML.slice(0, 80)}`));
  expect(small).toEqual([]);
});
