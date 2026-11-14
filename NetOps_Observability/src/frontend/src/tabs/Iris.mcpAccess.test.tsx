// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Iris settings → Workspace access: the read-only MCP opt-in (tracker 337
// N-I5). The platform owner turns MCP on per workspace; the box is disabled
// until the platform switch (IRIS_MCP, Features page) is on, and an edit that
// does not touch MCP never sends it — so a row from an older server can never
// switch MCP off by omission.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup, act } from "@testing-library/react";
import Iris from "./Iris";
import { ShellContext, TIME_RANGES, type ShellState } from "../context/shell";

const aiTenants = vi.fn();
const setAITenantAccess = vi.fn();

vi.mock("../services/api", () => ({
  StreamBrokenError: class StreamBrokenError extends Error {},
  api: {
    aiAsk: () => Promise.reject(new Error("unused")),
    aiAskStream: () => Promise.reject(new Error("unused")),
    copilotChat: () => Promise.reject(new Error("unused")),
    copilotConfig: () => Promise.resolve({ provider: "gemini", model: "m", feature_enabled: true, key_present: true }),
    aiTenantConfig: () => Promise.reject(new Error("403")),
    aiTenants: (...a: unknown[]) => aiTenants(...a),
    setAITenantAccess: (...a: unknown[]) => setAITenantAccess(...a),
    aiCommands: () => Promise.resolve({ commands: [] }),
    features: () => Promise.resolve({ copilot: true }),
    aiFeedback: () => Promise.resolve(),
    startIrisConversation: () => Promise.reject(new Error("503")),
    correctIrisQuery: () => Promise.reject(new Error("unused")),
    testCopilotConfig: () => Promise.reject(new Error("unused")),
  },
}));
vi.mock("../components/EChart", () => ({ default: () => <div data-testid="chart" /> }));

const shell: ShellState = {
  range: TIME_RANGES[1], setRange: () => {},
  query: "", setQuery: () => {},
  copilotOpen: true, setCopilotOpen: () => {},
  helpOpen: false, setHelpOpen: () => {}, helpPath: "", openHelp: () => {},
  navigate: () => {},
};

const row = {
  tenant_id: "t-a", name: "Acme", assistant_enabled: true, investigations_enabled: false,
  mcp_enabled: false, key_present: false, no_platform_key: false, max_calls: 0, daily_tokens: 0,
};

async function openSettings() {
  render(<ShellContext.Provider value={shell}><Iris /></ShellContext.Provider>);
  await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); });
  await act(async () => { fireEvent.click(screen.getByLabelText("AI models")); });
}

beforeEach(() => {
  aiTenants.mockReset();
  setAITenantAccess.mockReset();
  setAITenantAccess.mockResolvedValue({});
});
afterEach(() => cleanup());

describe("Iris settings — read-only MCP per workspace", () => {
  it("is disabled until the platform switch is on", async () => {
    aiTenants.mockResolvedValue({ tenants: [row], tools_feature: false, mcp_feature: false });
    await openSettings();
    const box = await screen.findByTestId("iris-mcp-toggle");
    expect((box as HTMLInputElement).disabled).toBe(true);
  });

  it("turns MCP on for one workspace and sends only that change", async () => {
    aiTenants.mockResolvedValue({ tenants: [row], tools_feature: false, mcp_feature: true });
    await openSettings();
    const box = await screen.findByTestId("iris-mcp-toggle");
    expect((box as HTMLInputElement).disabled).toBe(false);
    await act(async () => { fireEvent.click(box); });
    expect(setAITenantAccess).toHaveBeenCalledWith("t-a", expect.objectContaining({ mcp_enabled: true }));
  });

  it("never sends mcp_enabled for an edit that did not touch it", async () => {
    aiTenants.mockResolvedValue({ tenants: [{ ...row, mcp_enabled: true }], tools_feature: false, mcp_feature: true });
    await openSettings();
    const assistant = await screen.findByLabelText("Assistant");
    await act(async () => { fireEvent.click(assistant); });
    expect(setAITenantAccess).toHaveBeenCalledTimes(1);
    expect(setAITenantAccess.mock.calls[0][1]).not.toHaveProperty("mcp_enabled");
  });
});
