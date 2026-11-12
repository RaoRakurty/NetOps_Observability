// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Connect a model — tracker 337 plan C3–C6, owner D4–D6 (2026-11-09), in the
// real SPA with the API faked at the network boundary (./irisBackend.ts):
//   · the admin banner shows for a platform admin with no key, and never for
//     an operator (the config call is 403 for them);
//   · the banner opens the settings, where Gemini carries the free-tier
//     warning and Test connection sends the draft key and shows a verdict;
//   · every answer carries the footnote naming who answered;
//   · a platform admin's FRESH login with no key lands on the Features page,
//     where the Connect-a-model step is.

import { test, expect } from "@playwright/test";
import { bootIris, openIris, askIris, irisPanel, topCpuAnswer, TENANT_CONFIG, type Json } from "./irisBackend";

test.use({ timezoneId: "UTC", locale: "en-US", viewport: { width: 1600, height: 900 } });

const PLATFORM_ME = {
  username: "root", role: "superadmin", tenant_id: "global", platform_admin: true,
  accessible_tenants: ["t_acme"], all_tenants: true, org_id: "",
};

const RECOMMENDED = {
  gemini: { default: "gemini-flash-latest", fast: "gemini-flash-lite-latest", strong: "gemini-flash-latest" },
  anthropic: { default: "claude-sonnet-4-6", fast: "claude-haiku-4-5", strong: "claude-opus-4-8" },
  openai: { default: "gpt-4o-mini", fast: "gpt-4o-mini", strong: "gpt-4.1" },
};

const KEYLESS: Json = {
  provider: "gemini", model: "", model_fast: "", model_strong: "", feature_enabled: true,
  key_present: false, key_source: "none", providers: ["gemini", "anthropic", "openai"],
  model_suggestions: { gemini: ["gemini-flash-latest"], anthropic: ["claude-sonnet-4-6"], openai: ["gpt-4o-mini"] },
  recommended: RECOMMENDED, last_test: null, budget: { daily_tokens_default: 1000000, workspaces_exhausted: 0 },
};

test("a platform admin with no key sees the banner; it opens the settings and Test connection reports a verdict", async ({ page }) => {
  const fake = await bootIris(page, { me: PLATFORM_ME, copilotConfig: KEYLESS, answer: () => topCpuAnswer() });
  await page.goto("/#/overview/home");
  await openIris(page);
  const panel = irisPanel(page);
  const banner = panel.getByTestId("connect-model-banner");
  await expect(banner).toHaveText(/Connect a model to unlock full language understanding\./);
  await banner.getByRole("button", { name: "Connect a model" }).click();
  await expect(panel.getByRole("note")).toContainText("Free-tier Gemini keys");
  await panel.getByPlaceholder("Paste API key").fill("AIza-e2e-draft");
  await panel.getByRole("button", { name: "Test connection" }).click();
  await expect(panel.getByTestId("connection-test")).toContainText("Connected to gemini-flash-lite-latest in 0.4 s.");
  // Every tier field of the form is sent (2026-11-12); blanks test as the recommended models.
  expect(fake.connTests).toEqual([{ provider: "gemini", key: "AIza-e2e-draft", model: "", model_fast: "", model_strong: "" }]);
  // The key never shows on the page.
  await expect(page.locator("body")).not.toContainText("AIza-e2e-draft");
});

test("an operator never sees the banner, and each answer carries the footnote", async ({ page }) => {
  await bootIris(page, {
    tenantConfig: null,
    answer: () => ({ ...topCpuAnswer(), mode: "current_state_summary", data: undefined, provider: "gemini", model: "gemini-flash-latest" }),
  });
  await page.goto("/#/overview/home");
  await openIris(page);
  const panel = irisPanel(page);
  await expect(panel.getByTestId("connect-model-banner")).toHaveCount(0);
  await askIris(page, "what is going on right now");
  await expect(panel.locator(".op-provnote")).toHaveText("Answered with Gemini gemini-flash-latest · based on your Correlix data");
});

test("a workspace admin whose budget is spent is told so", async ({ page }) => {
  await bootIris(page, { tenantConfig: { ...TENANT_CONFIG, budget: { daily_tokens: 1000000, used_today: 1000000, exhausted: true } } });
  await page.goto("/#/overview/home");
  await openIris(page);
  await expect(irisPanel(page).getByTestId("connect-model-banner")).toContainText("Today's AI budget for this workspace is spent.");
});

test("a platform admin's fresh login with no key lands on Features, where the Connect-a-model step is", async ({ page }) => {
  await bootIris(page, { me: PLATFORM_ME, copilotConfig: KEYLESS });
  await page.route(/\/api\/platform\/features$/, (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ features: [], restart_pending: false, can_restart: false, store_load_error: "" }) }));
  await page.addInitScript(() => sessionStorage.setItem("netops_landing_pending", "1"));
  await page.goto("/#/overview/home");
  await expect(page).toHaveURL(/#\/platform\/features$/);
  const step = page.getByTestId("connect-model-step");
  await expect(step).toBeVisible();
  await expect(step.getByRole("radio", { name: "Gemini" })).toHaveAttribute("aria-checked", "true");
  await expect(step.getByRole("note")).toContainText("Google may use what is sent");
});
