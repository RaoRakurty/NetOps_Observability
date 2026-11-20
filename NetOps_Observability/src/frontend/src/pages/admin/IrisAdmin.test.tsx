// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisAdmin.test.tsx — Administration → Iris, ONE page with four tabs (owner
// decision 2026-11-19, "consolidate"). Asserted here:
//   · tab routing: #/admin/iris/<tab> opens that tab, a click writes the hash,
//     a hash change switches the tab, an unknown tab is the first one;
//   · the AI models form moved here from the Iris drawer UNCHANGED in
//     behaviour: the same calls, the same probe confirmation, MCP sent only
//     when touched (these tests moved from tabs/Iris.routing.test.tsx and
//     tabs/Iris.mcpAccess.test.tsx with the form);
//   · permissions: an operator gets an honest note, a platform owner the
//     platform form, a workspace administrator the workspace form; the
//     workspace-scoped Iris tools keep the drawer's condition (workspace
//     administrator, assistant on, query tools licensed) and say why otherwise.
// The three pages that became tabs keep their own tests (NetworkContext,
// TenantRunbooks, IrisLearning); here they are stubs that prove placement.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup, act, within } from "@testing-library/react";
import IrisAdmin, { irisAdminTab, irisAdminHref } from "./IrisAdmin";

const copilotConfig = vi.fn();
const aiTenants = vi.fn();
const aiTenantConfig = vi.fn();
const features = vi.fn();
const testCopilotConfig = vi.fn();
const setCopilotConfig = vi.fn();
const setAITenantAccess = vi.fn();
const setAITenantConfig = vi.fn();
const testAITenantConfig = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    copilotConfig: (...a: unknown[]) => copilotConfig(...a),
    aiTenants: (...a: unknown[]) => aiTenants(...a),
    aiTenantConfig: (...a: unknown[]) => aiTenantConfig(...a),
    features: (...a: unknown[]) => features(...a),
    testCopilotConfig: (...a: unknown[]) => testCopilotConfig(...a),
    setCopilotConfig: (...a: unknown[]) => setCopilotConfig(...a),
    setAITenantAccess: (...a: unknown[]) => setAITenantAccess(...a),
    setAITenantConfig: (...a: unknown[]) => setAITenantConfig(...a),
    testAITenantConfig: (...a: unknown[]) => testAITenantConfig(...a),
  },
}));
vi.mock("./NetworkContext", () => ({ default: () => <div data-testid="stub-network-context" /> }));
vi.mock("./TenantRunbooks", () => ({ default: () => <div data-testid="stub-runbooks" /> }));
vi.mock("./IrisLearning", () => ({ default: () => <div data-testid="stub-learning" /> }));
vi.mock("../../components/IrisVocabulary", () => ({
  default: ({ part }: { part?: string }) => <div data-testid={`stub-vocab-${part ?? "all"}`} />,
}));
vi.mock("../../components/admin/AdminPageHeader", () => ({
  default: ({ title }: { title: string }) => <h1>{title}</h1>,
}));

const recommended = {
  gemini: { default: "gemini-flash-latest", fast: "gemini-flash-lite-latest", strong: "gemini-flash-latest" },
  anthropic: { default: "claude-sonnet-4-6", fast: "claude-haiku-4-5", strong: "claude-opus-4-8" },
  openai: { default: "gpt-4o-mini", fast: "gpt-4o-mini", strong: "gpt-4.1" },
};
const row = {
  tenant_id: "t-a", name: "Acme", assistant_enabled: true, investigations_enabled: true,
  mcp_enabled: false, probes_enabled: false, key_present: false, no_platform_key: false, max_calls: 0, daily_tokens: 0,
};

function operator() {
  copilotConfig.mockRejectedValue(new Error("403"));
  aiTenants.mockRejectedValue(new Error("403"));
  aiTenantConfig.mockRejectedValue(new Error("403"));
}
function keyedOwner(tenants = [row], extra: Record<string, unknown> = {}) {
  copilotConfig.mockResolvedValue({ provider: "anthropic", model: "claude-sonnet-4-6", feature_enabled: true, key_present: true,
    key_source: "stored", providers: ["gemini", "anthropic", "openai"], recommended });
  aiTenants.mockResolvedValue({ tenants, tools_feature: true, mcp_feature: false, probes_feature: false, ...extra });
  aiTenantConfig.mockRejectedValue(new Error("400 platform owners configure the assistant in platform settings"));
}
function keylessOwner() {
  copilotConfig.mockResolvedValue({ provider: "gemini", model: "", feature_enabled: true, key_present: false, key_source: "none",
    providers: ["gemini", "anthropic", "openai"], recommended, budget: { daily_tokens_default: 1000000, workspaces_exhausted: 0 } });
  aiTenants.mockResolvedValue({ tenants: [] });
  aiTenantConfig.mockRejectedValue(new Error("400"));
}
function workspaceAdmin(assistant = true) {
  copilotConfig.mockRejectedValue(new Error("403"));
  aiTenants.mockRejectedValue(new Error("403"));
  aiTenantConfig.mockResolvedValue({ assistant_enabled: assistant, provider: "anthropic", model: "", key_present: false,
    platform_key_available: true, no_platform_key: false, providers: ["gemini", "anthropic", "openai"], recommended });
}

async function renderAt(hash: string) {
  window.location.hash = hash;
  render(<IrisAdmin />);
  await act(async () => { for (let i = 0; i < 6; i++) await Promise.resolve(); });
}

beforeEach(() => {
  for (const f of [copilotConfig, aiTenants, aiTenantConfig, features, testCopilotConfig, setCopilotConfig,
    setAITenantAccess, setAITenantConfig, testAITenantConfig]) f.mockReset();
  features.mockResolvedValue({ copilot: true, ai_entitlements: ["ai.chat", "ai.nlquery"] });
  setAITenantAccess.mockResolvedValue({});
});
afterEach(() => { cleanup(); window.location.hash = ""; });

describe("Administration → Iris — tab routing (#/admin/iris/<tab>)", () => {
  it.each([
    ["#/admin/iris", "ai-models"],
    ["#/admin/iris/ai-models", "ai-models"],
    ["#/admin/iris/knowledge", "knowledge"],
    ["#/admin/iris/review?x=1", "review"],
    ["#/admin/iris/investigations", "investigations"],
    ["#/admin/iris/no-such-tab", "ai-models"],
  ])("%s opens %s", (hash, tab) => {
    expect(irisAdminTab(hash)).toBe(tab);
  });

  it("has the four tabs, in order, as an ARIA tab list", async () => {
    operator();
    await renderAt("#/admin/iris");
    const tabs = within(screen.getByRole("tablist")).getAllByRole("tab");
    expect(tabs.map((t) => t.textContent)).toEqual(["AI models", "Knowledge", "Learning & review", "Investigations"]);
    expect(tabs[0].getAttribute("aria-selected")).toBe("true");
    expect(screen.getByRole("tabpanel").getAttribute("data-tab")).toBe("ai-models");
  });

  it("a deep link opens its tab, a click writes the hash, a hash change switches the tab", async () => {
    operator();
    await renderAt("#/admin/iris/knowledge");
    expect(screen.getByTestId("stub-network-context")).toBeTruthy();
    expect(screen.getByTestId("stub-runbooks")).toBeTruthy();

    fireEvent.click(screen.getByRole("tab", { name: "Learning & review" }));
    expect(window.location.hash).toBe(irisAdminHref("review"));
    expect(screen.getByTestId("stub-learning")).toBeTruthy();
    expect(screen.queryByTestId("stub-network-context")).toBeNull();

    await act(async () => {
      window.location.hash = "#/admin/iris/investigations";
      window.dispatchEvent(new HashChangeEvent("hashchange"));
    });
    expect(screen.getByRole("tab", { name: "Investigations" }).getAttribute("aria-selected")).toBe("true");
  });
});

describe("Administration → Iris — who sees what", () => {
  it("an operator gets an honest note on every tab, never a form", async () => {
    operator();
    await renderAt("#/admin/iris/ai-models");
    expect(screen.getByTestId("iris-models-none").textContent).toMatch(/Only an administrator/);
    expect(screen.queryByText("Test connection")).toBeNull();
    expect(screen.getByText("These are per workspace. Open a workspace to see them.")).toBeTruthy();
    fireEvent.click(screen.getByRole("tab", { name: "Investigations" }));
    expect(screen.queryByTestId("stub-vocab-investigations")).toBeNull();
    expect(screen.getByText("These are per workspace. Open a workspace to see them.")).toBeTruthy();
  });

  it("the platform owner gets the platform form and the workspace access list, not the workspace tools", async () => {
    keyedOwner();
    await renderAt("#/admin/iris/ai-models");
    expect(screen.getByText("Test connection")).toBeTruthy();
    expect(screen.getByText("Workspace access")).toBeTruthy();
    expect(screen.queryByTestId("stub-vocab-chat")).toBeNull();
  });

  it("a workspace administrator with the assistant on gets the workspace form and every workspace tool on its tab", async () => {
    workspaceAdmin(true);
    await renderAt("#/admin/iris/ai-models");
    expect(screen.getByText("Your workspace's AI. Keys are encrypted and never shown again.")).toBeTruthy();
    expect(screen.getByTestId("stub-vocab-chat")).toBeTruthy();
    fireEvent.click(screen.getByRole("tab", { name: "Knowledge" }));
    expect(screen.getByTestId("stub-vocab-knowledge")).toBeTruthy();
    fireEvent.click(screen.getByRole("tab", { name: "Learning & review" }));
    expect(screen.getByTestId("stub-vocab-review")).toBeTruthy();
    fireEvent.click(screen.getByRole("tab", { name: "Investigations" }));
    expect(screen.getByTestId("stub-vocab-investigations")).toBeTruthy();
  });

  it("with the assistant off, the workspace tools say so instead of disappearing", async () => {
    workspaceAdmin(false);
    await renderAt("#/admin/iris/knowledge");
    expect(screen.queryByTestId("stub-vocab-knowledge")).toBeNull();
    expect(screen.getByText("Iris is turned off for this workspace.")).toBeTruthy();
  });

  it("without the query-tools licence, the workspace tools say so", async () => {
    workspaceAdmin(true);
    features.mockResolvedValue({ copilot: true, ai_entitlements: ["ai.chat"] });
    await renderAt("#/admin/iris/review");
    expect(screen.queryByTestId("stub-vocab-review")).toBeNull();
    expect(screen.getByText("Iris's query tools are not in this licence.")).toBeTruthy();
  });
});

describe("Administration → Iris → AI models — connect a model (tracker 337 C2/C3/C5)", () => {
  it("with no key, the guided step stands in for the form; \"Not now\" shows the full form", async () => {
    keylessOwner();
    await renderAt("#/admin/iris/ai-models");
    expect(await screen.findByTestId("connect-model-step")).toBeTruthy();
    expect(document.querySelector(".op-modelinput")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Not now" }));
    expect(screen.queryByTestId("connect-model-step")).toBeNull();
    expect(document.querySelector(".op-modelinput")).toBeTruthy();
  });

  it("picking a provider fills the recommended models (C2)", async () => {
    keyedOwner([]);
    await renderAt("#/admin/iris/ai-models");
    fireEvent.click(screen.getByText("Google"));
    expect(screen.getByRole("note").textContent).toMatch(/Free-tier Gemini keys/);
    fireEvent.click(screen.getByText("Anthropic"));
    const model = document.querySelector(".op-modelinput") as HTMLInputElement;
    expect(model.value).toBe("claude-sonnet-4-6");
    expect(screen.queryByRole("note")).toBeNull(); // the free-tier warning is Gemini's
  });

  it("Test connection sends the draft key and shows a plain verdict, never the provider's text", async () => {
    keyedOwner([]);
    copilotConfig.mockResolvedValue({ provider: "gemini", model: "", feature_enabled: true, key_present: true, key_source: "stored",
      providers: ["gemini", "anthropic", "openai"], recommended });
    testCopilotConfig.mockResolvedValue({ ok: false, provider: "gemini", model: "gemini-flash-lite-latest", latency_ms: 210, error_class: "auth" });
    await renderAt("#/admin/iris/ai-models");
    fireEvent.change(screen.getByPlaceholderText("Saved — leave blank to keep"), { target: { value: "AIza-draft" } });
    await act(async () => { fireEvent.click(screen.getByText("Test connection")); });
    // Every tier field of the form is sent (2026-11-12): blanks are tested as
    // the provider's recommended models, each with its own verdict.
    expect(testCopilotConfig).toHaveBeenCalledWith({ provider: "gemini", key: "AIza-draft", model: "", model_fast: "", model_strong: "" });
    expect((await screen.findByTestId("connection-test")).textContent).toContain("The provider rejected this key.");
  });

  it("Save writes the platform settings and says so on the page (the drawer used to close)", async () => {
    keyedOwner([]);
    setCopilotConfig.mockResolvedValue({ provider: "anthropic", model: "claude-sonnet-4-6", feature_enabled: true, key_present: true });
    await renderAt("#/admin/iris/ai-models");
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Save" })); });
    expect(setCopilotConfig).toHaveBeenCalledTimes(1);
    expect(screen.getByText("Saved.")).toBeTruthy();
  });
});

// Iris settings → Workspace access: the read-only MCP opt-in (tracker 337
// N-I5). Moved from tabs/Iris.mcpAccess.test.tsx with the form. The box is
// disabled until the platform switch (IRIS_MCP, Features page) is on, and an
// edit that does not touch MCP never sends it — so a row from an older server
// can never switch MCP off by omission.
describe("AI models → Workspace access — read-only MCP per workspace", () => {
  it("is disabled until the platform switch is on", async () => {
    keyedOwner([row], { mcp_feature: false });
    await renderAt("#/admin/iris/ai-models");
    expect((screen.getByTestId("iris-mcp-toggle") as HTMLInputElement).disabled).toBe(true);
  });

  it("turns MCP on for one workspace and sends only that change", async () => {
    keyedOwner([row], { mcp_feature: true });
    await renderAt("#/admin/iris/ai-models");
    const box = screen.getByTestId("iris-mcp-toggle") as HTMLInputElement;
    expect(box.disabled).toBe(false);
    await act(async () => { fireEvent.click(box); });
    expect(setAITenantAccess).toHaveBeenCalledWith("t-a", expect.objectContaining({ mcp_enabled: true }));
  });

  it("never sends mcp_enabled for an edit that did not touch it", async () => {
    keyedOwner([{ ...row, mcp_enabled: true }], { mcp_feature: true });
    await renderAt("#/admin/iris/ai-models");
    await act(async () => { fireEvent.click(screen.getByLabelText("Assistant")); });
    expect(setAITenantAccess).toHaveBeenCalledTimes(1);
    expect(setAITenantAccess.mock.calls[0][1]).not.toHaveProperty("mcp_enabled");
  });
});

// N-I3: the workspace's active-probe opt-in. Moved from tabs/Iris.routing.test.tsx.
describe("AI models → Workspace access — active probes opt-in", () => {
  it("is disabled, and says why, until the installation turns active probes on", async () => {
    keyedOwner([row], { probes_feature: false });
    await renderAt("#/admin/iris/ai-models");
    expect((screen.getByTestId("iris-probes-toggle") as HTMLInputElement).disabled).toBe(true);
    expect(screen.getByTestId("iris-probes-risk").textContent).toMatch(/Features page/);
    expect(screen.getByTestId("iris-probes-risk").textContent).toMatch(/Nothing is sent from a customer device/);
  });

  it("states the risk and asks before turning on, then sends the acknowledgement", async () => {
    keyedOwner([row], { probes_feature: true });
    setAITenantAccess.mockResolvedValue({ ...row, probes_enabled: true });
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    await renderAt("#/admin/iris/ai-models");
    const toggle = screen.getByTestId("iris-probes-toggle") as HTMLInputElement;
    expect(toggle.disabled).toBe(false);
    await act(async () => { fireEvent.click(toggle); });
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(String(confirm.mock.calls[0][0])).toMatch(/3 pings, one traceroute/);
    expect(setAITenantAccess).toHaveBeenCalledWith("t-a", expect.objectContaining({ probes_enabled: true, probes_acknowledged: true }));
    confirm.mockRestore();
  });

  it("sends nothing when the administrator declines", async () => {
    keyedOwner([row], { probes_feature: true });
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    await renderAt("#/admin/iris/ai-models");
    await act(async () => { fireEvent.click(screen.getByTestId("iris-probes-toggle")); });
    expect(setAITenantAccess).not.toHaveBeenCalled();
    confirm.mockRestore();
  });

  it("an error from the server is shown, never hidden", async () => {
    keyedOwner([row], { mcp_feature: true });
    setAITenantAccess.mockRejectedValue(new Error("500"));
    await renderAt("#/admin/iris/ai-models");
    await act(async () => { fireEvent.click(screen.getByTestId("iris-mcp-toggle")); });
    expect(screen.getByRole("alert").textContent).toBeTruthy();
  });
});
