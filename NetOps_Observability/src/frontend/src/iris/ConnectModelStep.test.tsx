// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ConnectModelStep — the first-login "Connect a model" step (tracker 337 C4,
// owner D5/D6): Gemini pre-selected with the free-tier warning, recommended
// models filled, Test sends the draft key and shows a plain verdict, Save
// sends the recommended models; nothing for a non-admin (403) and nothing but
// the budget notice once a key exists.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup, act } from "@testing-library/react";
import ConnectModelStep from "./ConnectModelStep";

const copilotConfig = vi.fn();
const setCopilotConfig = vi.fn();
const testCopilotConfig = vi.fn();
vi.mock("../services/api", () => ({
  api: {
    copilotConfig: (...a: unknown[]) => copilotConfig(...a),
    setCopilotConfig: (...a: unknown[]) => setCopilotConfig(...a),
    testCopilotConfig: (...a: unknown[]) => testCopilotConfig(...a),
  },
}));

const recommended = {
  gemini: { default: "gemini-flash-latest", fast: "gemini-flash-lite-latest", strong: "gemini-flash-latest" },
  anthropic: { default: "claude-sonnet-4-6", fast: "claude-haiku-4-5", strong: "claude-opus-4-8" },
  openai: { default: "gpt-4o-mini", fast: "gpt-4o-mini", strong: "gpt-4.1" },
};
const keyless = { provider: "gemini", model: "", feature_enabled: true, key_present: false, key_source: "none", recommended };

async function mount() {
  const u = render(<ConnectModelStep />);
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  return u;
}

beforeEach(() => {
  [copilotConfig, setCopilotConfig, testCopilotConfig].forEach((m) => m.mockReset());
  try { localStorage.clear(); } catch { /* none */ }
});
afterEach(() => cleanup());

describe("ConnectModelStep", () => {
  it("renders nothing for a caller who is not the platform admin (403)", async () => {
    copilotConfig.mockRejectedValue(new Error("403"));
    await mount();
    expect(screen.queryByTestId("connect-model-step")).toBeNull();
  });

  it("pre-selects Gemini, warns about free-tier data use and fills the recommended models", async () => {
    copilotConfig.mockResolvedValue(keyless);
    await mount();
    expect(screen.getByRole("radio", { name: "Gemini" }).getAttribute("aria-checked")).toBe("true");
    expect(screen.getByRole("note").textContent).toMatch(/Google may use what is sent/);
    expect((screen.getByLabelText("Default model") as HTMLInputElement).value).toBe("gemini-flash-latest");
    expect((screen.getByLabelText("Quick answers model") as HTMLInputElement).value).toBe("gemini-flash-lite-latest");
    fireEvent.click(screen.getByRole("radio", { name: "Claude" }));
    expect((screen.getByLabelText("Detailed answers model") as HTMLInputElement).value).toBe("claude-opus-4-8");
    expect(screen.queryByRole("note")).toBeNull();
  });

  it("tests the draft key and saves it with the recommended models", async () => {
    copilotConfig.mockResolvedValue(keyless);
    testCopilotConfig.mockResolvedValue({ ok: true, provider: "gemini", model: "gemini-flash-lite-latest", latency_ms: 640 });
    setCopilotConfig.mockResolvedValue({ ...keyless, key_present: true, key_source: "stored" });
    await mount();
    const test = screen.getByRole("button", { name: "Test connection" }) as HTMLButtonElement;
    expect(test.disabled).toBe(true); // nothing to test yet
    fireEvent.change(screen.getByLabelText("API key"), { target: { value: "AIza-draft" } });
    await act(async () => { fireEvent.click(test); });
    expect(testCopilotConfig).toHaveBeenCalledWith({ provider: "gemini", key: "AIza-draft", model: "gemini-flash-lite-latest" });
    expect(screen.getByText("Connected to gemini-flash-lite-latest in 0.6 s.")).toBeTruthy();
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Save" })); });
    expect(setCopilotConfig).toHaveBeenCalledWith({ provider: "gemini", model: "gemini-flash-latest", model_fast: "gemini-flash-lite-latest", model_strong: "gemini-flash-latest", key: "AIza-draft" });
  });

  it("is replaced by the budget notice once a key exists", async () => {
    copilotConfig.mockResolvedValue({ ...keyless, key_present: true, key_source: "stored", budget: { workspaces_exhausted: 1 } });
    await mount();
    expect(screen.queryByTestId("connect-model-step")).toBeNull();
    expect(screen.getByTestId("connect-model-banner").textContent).toBe("One workspace has spent today's AI budget.");
  });

  it("'Not now' hides the step and remembers it", async () => {
    copilotConfig.mockResolvedValue(keyless);
    await mount();
    fireEvent.click(screen.getByRole("button", { name: "Not now" }));
    expect(screen.queryByTestId("connect-model-step")).toBeNull();
    expect(localStorage.getItem("correlix.connectModel.dismissed")).toBe("1");
  });
});
