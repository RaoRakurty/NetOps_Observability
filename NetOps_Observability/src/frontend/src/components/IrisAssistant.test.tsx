// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisAssistant.test.tsx — the floating Iris window (owner decision 2026-10-05).
//
// The container is new; the answer inside it is not. These pin the container:
//   · a round "Ask Iris" launcher opens a named dialog over the page;
//   · the header's Close, Esc and the launcher close it, and focus goes back to
//     what opened it; focus moves into the window on open and Tab stays inside;
//   · Full screen / Exit full screen toggle the same conversation, and the
//     choice is kept for the tab;
//   · Ctrl+I / ⌘I toggles it, Ctrl+Shift+I (browser dev tools) does not;
//   · moving between pages leaves it open with its conversation on screen;
//   · the server conversation id survives closing and reopening;
//   · model text with markup is still text (OWASP LLM02);
//   · the `(i)` AskIris event opens it and asks.

import { useState, type ReactNode } from "react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup, waitFor, act } from "@testing-library/react";
import IrisAssistant, { IRIS_EXPANDED_KEY, isIrisShortcut } from "./IrisAssistant";
import { askIris } from "./AskIris";
import { ShellContext, TIME_RANGES, type ShellState } from "../context/shell";
import type { AiAnswer } from "../services/api";

const aiAsk = vi.fn();
const startIrisConversation = vi.fn();
const features = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    aiAsk: (...a: unknown[]) => aiAsk(...a),
    copilotChat: () => Promise.reject(new Error("not used")),
    copilotConfig: () => Promise.reject(new Error("403")),
    aiTenantConfig: () => Promise.reject(new Error("403")),
    aiTenants: () => Promise.resolve({ tenants: [] }),
    aiCommands: () => Promise.resolve({ commands: [] }),
    features: (...a: unknown[]) => features(...a),
    aiFeedback: () => Promise.resolve(),
    startIrisConversation: (...a: unknown[]) => startIrisConversation(...a),
    correctIrisQuery: () => Promise.reject(new Error("not used")),
  },
}));
vi.mock("./EChart", () => ({ default: () => <div data-testid="chart" /> }));

const XSS = `<img src=x onerror="window.__irisXss=1">`;

function answer(over: Partial<AiAnswer> = {}): AiAnswer {
  return {
    mode: "current_state_summary",
    intent: "current_state",
    modules: ["command_center"],
    text: "Three suspected incidents; start with the DIA egress seam.",
    citations: [{ id: "problem:abc", kind: "finding", label: "dia-egress", href: "#/monitoring/correlations?id=abc" }],
    disclaimers: [],
    ...over,
  } as AiAnswer;
}

// A real, stateful shell: the window reads and writes `copilotOpen` exactly as
// it does under App, and `page` stands in for the routed view beside it.
function Harness({ page }: { page: string }) {
  const [open, setOpen] = useState(false);
  const shell: ShellState = {
    range: TIME_RANGES[1], setRange: () => {},
    query: "", setQuery: () => {},
    copilotOpen: open, setCopilotOpen: setOpen,
    helpOpen: false, setHelpOpen: () => {}, helpPath: "", openHelp: () => {},
    navigate: () => {},
  };
  const view: ReactNode = page === "a"
    ? <section aria-label="Page A"><button type="button">Page A action</button></section>
    : <section aria-label="Page B"><button type="button">Page B action</button></section>;
  return (
    <ShellContext.Provider value={shell}>
      {view}
      <IrisAssistant />
    </ShellContext.Provider>
  );
}

async function settle() {
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
}

async function mount(page = "a") {
  const utils = render(<Harness page={page} />);
  await settle();
  return utils;
}

const launcher = () => screen.getByRole("button", { name: "Ask Iris" });
const win = () => screen.queryByRole("dialog", { name: "Iris" });

async function openByLauncher() {
  await act(async () => { fireEvent.click(launcher()); });
  await settle();
  expect(win()).not.toBeNull();
}

async function ask(text: string) {
  const box = await screen.findByPlaceholderText(/Ask Iris AI/);
  fireEvent.change(box, { target: { value: text } });
  await act(async () => { fireEvent.click(screen.getByTitle("Send (⏎)")); });
  await settle();
}

beforeEach(() => {
  aiAsk.mockReset();
  startIrisConversation.mockReset().mockRejectedValue(new Error("503"));
  features.mockReset().mockResolvedValue({ copilot: true });
  try { sessionStorage.clear(); } catch { /* no storage here */ }
  delete (window as unknown as { __irisXss?: number }).__irisXss;
});
afterEach(() => cleanup());

describe("the launcher", () => {
  it("is a named round button that opens the Iris window", async () => {
    await mount();
    expect(launcher()).toHaveAttribute("aria-expanded", "false");
    expect(launcher().className).toContain("iris-launcher");
    expect(win()).toBeNull();

    await openByLauncher();
    expect(launcher()).toHaveAttribute("aria-expanded", "true");
    expect(launcher()).toHaveAttribute("aria-controls", "iris-window");
    expect(win()).toHaveAttribute("id", "iris-window");
    expect(screen.getByText("Iris", { selector: ".op-hd-title" })).toBeTruthy();
  });

  it("clicking it again closes the window", async () => {
    await mount();
    await openByLauncher();
    await act(async () => { fireEvent.click(launcher()); });
    expect(win()).toBeNull();
  });
});

describe("closing and focus", () => {
  it("moves focus into the window (the question box) on open", async () => {
    await mount();
    launcher().focus();
    await openByLauncher();
    expect(document.activeElement).toBe(screen.getByPlaceholderText(/Ask Iris AI/));
  });

  it("the header's Close button closes it and focus returns to the launcher", async () => {
    await mount();
    launcher().focus();
    await openByLauncher();
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Close Iris" })); });
    expect(win()).toBeNull();
    expect(document.activeElement).toBe(launcher());
  });

  it("Esc closes it and focus returns to the launcher", async () => {
    await mount();
    launcher().focus();
    await openByLauncher();
    await act(async () => { fireEvent.keyDown(screen.getByPlaceholderText(/Ask Iris AI/), { key: "Escape" }); });
    expect(win()).toBeNull();
    expect(document.activeElement).toBe(launcher());
  });

  it("Esc in the quick-questions menu closes only the menu", async () => {
    await mount();
    await openByLauncher();
    const box = screen.getByPlaceholderText(/Ask Iris AI/);
    fireEvent.change(box, { target: { value: "/" } });
    expect(screen.getByRole("listbox")).toBeTruthy();
    await act(async () => { fireEvent.keyDown(box, { key: "Escape" }); });
    expect(screen.queryByRole("listbox")).toBeNull();
    expect(win()).not.toBeNull();
  });

  it("focus goes back to whatever opened it when that was not the launcher", async () => {
    await mount();
    const pageBtn = screen.getByRole("button", { name: "Page A action" });
    pageBtn.focus();
    await act(async () => { fireEvent.keyDown(window, { key: "i", ctrlKey: true }); });
    await settle();
    expect(win()).not.toBeNull();
    await act(async () => { fireEvent.keyDown(screen.getByPlaceholderText(/Ask Iris AI/), { key: "Escape" }); });
    expect(document.activeElement).toBe(pageBtn);
  });

  it("Tab and Shift+Tab stay inside the window", async () => {
    await mount();
    await openByLauncher();
    const w = win()!;
    const tabbable = Array.from(w.querySelectorAll<HTMLElement>("a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled])"));
    const first = tabbable[0];
    const last = tabbable[tabbable.length - 1];
    last.focus();
    fireEvent.keyDown(last, { key: "Tab" });
    expect(document.activeElement).toBe(first);
    fireEvent.keyDown(first, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(last);
  });
});

describe("full screen", () => {
  it("expands to full screen and collapses back, keeping the same conversation", async () => {
    aiAsk.mockResolvedValue(answer());
    await mount();
    await openByLauncher();
    await ask("what is going on?");
    expect(screen.getByText("what is going on?")).toBeTruthy();
    expect(win()!.className).not.toContain("expanded");
    expect(win()).not.toHaveAttribute("aria-modal");

    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Full screen" })); });
    expect(win()!.className).toContain("expanded");
    expect(win()).toHaveAttribute("aria-modal", "true");
    expect(sessionStorage.getItem(IRIS_EXPANDED_KEY)).toBe("1");
    expect(screen.getByText("what is going on?")).toBeTruthy(); // same conversation, not a new one

    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Exit full screen" })); });
    expect(win()!.className).not.toContain("expanded");
    expect(sessionStorage.getItem(IRIS_EXPANDED_KEY)).toBeNull();
    expect(screen.getByText("what is going on?")).toBeTruthy();
  });

  it("remembers full screen for the tab", async () => {
    sessionStorage.setItem(IRIS_EXPANDED_KEY, "1");
    await mount();
    await openByLauncher();
    expect(win()!.className).toContain("expanded");
  });

  it("following a citation leaves full screen but keeps the window open", async () => {
    aiAsk.mockResolvedValue(answer());
    await mount();
    await openByLauncher();
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Full screen" })); });
    await ask("what is going on?");
    const cite = await screen.findByRole("link", { name: /dia-egress/ });
    await act(async () => { fireEvent.click(cite); });
    expect(win()).not.toBeNull();
    expect(win()!.className).not.toContain("expanded");
  });
});

describe("the keyboard shortcut", () => {
  it("Ctrl+I and ⌘I toggle the window", async () => {
    await mount();
    await act(async () => { fireEvent.keyDown(window, { key: "i", ctrlKey: true }); });
    await settle();
    expect(win()).not.toBeNull();
    await act(async () => { fireEvent.keyDown(window, { key: "i", metaKey: true }); });
    expect(win()).toBeNull();
  });

  it("leaves Ctrl+Shift+I (developer tools) and plain I alone", () => {
    expect(isIrisShortcut({ key: "I", ctrlKey: true, shiftKey: true, metaKey: false, altKey: false })).toBe(false);
    expect(isIrisShortcut({ key: "i", ctrlKey: false, shiftKey: false, metaKey: false, altKey: false })).toBe(false);
    expect(isIrisShortcut({ key: "i", ctrlKey: true, shiftKey: false, metaKey: false, altKey: true })).toBe(false);
    expect(isIrisShortcut({ key: "k", ctrlKey: true, shiftKey: false, metaKey: false, altKey: false })).toBe(false);
  });
});

describe("state across pages and reopening", () => {
  it("stays open with its conversation on screen when the page changes", async () => {
    aiAsk.mockResolvedValue(answer());
    const { rerender } = await mount("a");
    await openByLauncher();
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Full screen" })); });
    await ask("what is going on?");

    rerender(<Harness page="b" />);
    await settle();
    expect(screen.getByRole("region", { name: "Page B" })).toBeTruthy();
    expect(win()).not.toBeNull();
    expect(win()!.className).toContain("expanded");
    expect(screen.getByText("what is going on?")).toBeTruthy();
  });

  it("the server conversation id survives closing and reopening", async () => {
    features.mockResolvedValue({ copilot: true, ai_entitlements: ["ai.chat", "ai.nlquery"] });
    startIrisConversation.mockReset().mockResolvedValue({ id: "conv-1", turns: [] });
    aiAsk.mockResolvedValue(answer({ conversation_id: "conv-1" }));
    await mount();
    await openByLauncher();
    await ask("top 3 devices by cpu");
    await waitFor(() => expect(aiAsk).toHaveBeenCalledTimes(1));
    expect(sessionStorage.getItem("iris.conversation")).toBe("conv-1");

    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Close Iris" })); });
    expect(win()).toBeNull();
    await openByLauncher();
    await ask("memory on that device");
    await waitFor(() => expect(aiAsk).toHaveBeenCalledTimes(2));
    expect(startIrisConversation).toHaveBeenCalledTimes(1);
    expect(aiAsk.mock.calls.map((c) => c[2])).toEqual(["conv-1", "conv-1"]);
  });
});

describe("model output stays text (OWASP LLM02)", () => {
  it("renders hostile markup in an answer as visible text, never as HTML", async () => {
    aiAsk.mockResolvedValue(answer({ text: `Top talker is ${XSS}`, title: XSS }));
    await mount();
    await openByLauncher();
    await ask("top talkers");
    await waitFor(() => expect(win()!.textContent).toContain(XSS));
    expect(document.querySelector('img[src="x"]')).toBeNull();
    expect((window as unknown as { __irisXss?: number }).__irisXss).toBeUndefined();
  });
});

describe("AskIris", () => {
  it("the (i) event opens the window and asks with the topic as context", async () => {
    aiAsk.mockResolvedValue(answer());
    await mount();
    await act(async () => { askIris("kpi.confirmed-rca", "Confirmed RCA"); });
    await settle();
    expect(win()).not.toBeNull();
    await waitFor(() => expect(aiAsk).toHaveBeenCalled());
    expect(aiAsk.mock.calls[0][1]).toEqual({ topic: "kpi.confirmed-rca" });
  });
});
