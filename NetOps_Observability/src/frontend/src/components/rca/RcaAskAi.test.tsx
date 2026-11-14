// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// RcaAskAi.test.tsx — Iris docked in the RCA view (RCA document v2 §5): a
// conversation scoped to the problem. Every turn carries the correlation id;
// follow-ups carry the conversation id; citations are links (same-origin only);
// model text is escaped (CLAUDE.md §15 LLM02); feedback lands on the answer.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup, within, waitFor } from "@testing-library/react";

const aiAsk = vi.fn();
const aiAskStream = vi.fn();
const aiFeedback = vi.fn();
const startIrisConversation = vi.fn();
const features = vi.fn();

vi.mock("../../services/api", () => {
  class StreamBrokenError extends Error {}
  return {
    StreamBrokenError,
    api: {
      aiAsk: (...a: unknown[]) => aiAsk(...a),
      aiAskStream: (...a: unknown[]) => aiAskStream(...a),
      aiFeedback: (...a: unknown[]) => aiFeedback(...a),
      startIrisConversation: (...a: unknown[]) => startIrisConversation(...a),
      features: (...a: unknown[]) => features(...a),
    },
  };
});

import RcaAskAi, { RCA_SUGGESTED_QUESTIONS } from "./RcaAskAi";
import { StreamBrokenError } from "../../services/api";

const CORR = "3e0400bc-aa22-543b-95e4-1b6afa9cf75e";

const answer = (over: Record<string, unknown> = {}) => ({
  mode: "problem_explanation", intent: "explain", modules: ["rca"],
  text: "Evidence concentrates on cedge-60-07ae8615; not independently localised.",
  citations: [
    { id: CORR, kind: "problem", label: "", href: `#/investigate/rca?id=${CORR}` },
    { id: "sig-1", kind: "evidence", label: "Gi4 interface counter change", href: "/#/explore/metrics?q=Gi4" },
    { id: "sig-2", kind: "evidence", label: "external", href: "https://evil.example/x" },
  ],
  disclaimers: [], provider: "anthropic", model: "claude-test",
  conversation_id: "conv-1", answer_id: "ans-1",
  ...over,
});

beforeEach(() => {
  aiAsk.mockReset(); aiAskStream.mockReset(); aiFeedback.mockReset(); startIrisConversation.mockReset();
  features.mockReset();
  features.mockResolvedValue({ ai_entitlements: ["ai.chat", "ai.nlquery"] });
  startIrisConversation.mockResolvedValue({ id: "conv-1", created_at: "", updated_at: "", turns: [] });
  aiFeedback.mockResolvedValue(undefined);
});
afterEach(cleanup);

async function ready() {
  render(<RcaAskAi correlationId={CORR} />);
  return screen.findByTestId("rca-iris-chat");
}

describe("RcaAskAi — docked, problem-scoped conversation", () => {
  it("offers the RCA question set and scopes the panel to the problem id", async () => {
    const panel = await ready();
    expect(within(panel).getByText("About P-3E0400")).toBeTruthy();
    for (const q of RCA_SUGGESTED_QUESTIONS) expect(within(panel).getByRole("button", { name: q })).toBeTruthy();
    expect(RCA_SUGGESTED_QUESTIONS).toEqual(expect.arrayContaining([
      "Explain this problem", "Why is this only suspected?", "What should I check next?",
      "Who is affected?", "What changed before this?", "Top talkers on the affected link",
    ]));
  });

  it("sends context.correlation_id on every turn and the conversation id on follow-ups", async () => {
    aiAskStream.mockResolvedValueOnce(answer()).mockResolvedValueOnce(answer({ text: "NetOps owns it." }));
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Explain this problem" }));
    expect(await screen.findByText(/Evidence concentrates on cedge-60-07ae8615/)).toBeTruthy();
    const [q1, ctx1, conv1] = aiAskStream.mock.calls[0] as [string, Record<string, string>, string | undefined];
    expect(q1).toBe("Explain this problem");
    expect(ctx1).toEqual({ correlation_id: CORR });
    expect(conv1).toBe("conv-1");

    fireEvent.change(screen.getByRole("textbox", { name: "Ask Iris about P-3E0400" }), { target: { value: "and who owns it?" } });
    fireEvent.click(screen.getByRole("button", { name: "Ask" }));
    expect(await screen.findByText("NetOps owns it.")).toBeTruthy();
    const [q2, ctx2, conv2] = aiAskStream.mock.calls[1] as [string, Record<string, string>, string | undefined];
    expect(q2).toBe("and who owns it?");
    expect(ctx2).toEqual({ correlation_id: CORR });
    expect(conv2).toBe("conv-1");
    // one conversation for the whole panel, not one per question
    expect(startIrisConversation).toHaveBeenCalledTimes(1);
  });

  it("asks without a conversation when the caller has no ai.nlquery", async () => {
    features.mockResolvedValue({ ai_entitlements: ["ai.chat"] });
    aiAskStream.mockResolvedValue(answer({ conversation_id: undefined }));
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Who is affected?" }));
    await screen.findByText(/Evidence concentrates/);
    expect(startIrisConversation).not.toHaveBeenCalled();
    expect(aiAskStream.mock.calls[0][2]).toBeUndefined();
    expect(aiAskStream.mock.calls[0][1]).toEqual({ correlation_id: CORR });
  });

  it("drops a conversation the server no longer has and asks once without it", async () => {
    aiAskStream
      .mockRejectedValueOnce(new Error('404 Not Found: {"error":"not found"}'))
      .mockResolvedValueOnce(answer({ conversation_id: "conv-2" }));
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Explain this problem" }));
    await screen.findByText(/Evidence concentrates/);
    expect(aiAskStream).toHaveBeenCalledTimes(2);
    expect(aiAskStream.mock.calls[1][2]).toBeUndefined();
    expect(aiAskStream.mock.calls[1][1]).toEqual({ correlation_id: CORR });
  });

  it("falls back to the plain ask once when the stream is cut", async () => {
    aiAskStream.mockRejectedValueOnce(new StreamBrokenError("cut"));
    aiAsk.mockResolvedValueOnce(answer());
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Explain this problem" }));
    await screen.findByText(/Evidence concentrates/);
    expect(aiAsk).toHaveBeenCalledWith("Explain this problem", { correlation_id: CORR }, "conv-1");
  });

  it("renders citations as links — the problem as P-xxxx — and an off-site href as text", async () => {
    aiAskStream.mockResolvedValue(answer());
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Explain this problem" }));
    await screen.findByText(/Evidence concentrates/);
    const evidence = screen.getByLabelText("Evidence");
    const problem = within(evidence).getByRole("link", { name: "P-3E0400" });
    expect(problem.getAttribute("href")).toBe(`#/investigate/rca?id=${CORR}`);
    expect(within(evidence).getByRole("link", { name: "Gi4 interface counter change" }).getAttribute("href")).toBe("/#/explore/metrics?q=Gi4");
    // an absolute off-site href is never a link
    expect(within(evidence).queryByRole("link", { name: "external" })).toBeNull();
    expect(within(evidence).getByText("external").tagName).toBe("SPAN");
  });

  it("escapes model text — an XSS payload renders as text, never markup", async () => {
    const payload = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>**bold**';
    aiAskStream.mockResolvedValue(answer({
      text: payload,
      citations: [{ id: "x", kind: "evidence", label: '<b onmouseover="x()">hi</b>', href: "javascript:alert(1)" }],
      disclaimers: ["<a href='https://evil'>click</a>"],
    }));
    const panel = await ready();
    fireEvent.click(screen.getByRole("button", { name: "Explain this problem" }));
    expect(await screen.findByText(payload)).toBeTruthy();
    expect(panel.querySelector("img")).toBeNull();
    expect(panel.querySelector("script")).toBeNull();
    expect(panel.querySelector("b")).toBeNull();
    expect(panel.querySelector('a[href^="javascript"]')).toBeNull();
    expect(panel.querySelector('a[href^="https://evil"]')).toBeNull();
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });

  it("names what answered and takes one rating on the answer", async () => {
    aiAskStream.mockResolvedValue(answer());
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Explain this problem" }));
    await screen.findByText(/Evidence concentrates/);
    expect(screen.getByText(/Grounded in this problem's evidence · claude-test/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Helpful" }));
    expect(aiFeedback).toHaveBeenCalledWith("up", "explain", "conv-1", "ans-1");
    fireEvent.click(screen.getByRole("button", { name: "Not helpful" }));
    expect(aiFeedback).toHaveBeenCalledTimes(1);
  });

  it("says 'evidence only' when no model answered", async () => {
    aiAskStream.mockResolvedValue(answer({ provider: "none", model: undefined }));
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Explain this problem" }));
    expect(await screen.findByText("Evidence only — no model answered")).toBeTruthy();
  });

  it("shows an operator sentence on failure, never the raw api envelope", async () => {
    aiAskStream.mockRejectedValue(new Error('502 Bad Gateway: {"error":"dial tcp 172.18.0.9:8080: connect: connection refused"}'));
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Explain this problem" }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).not.toMatch(/172\.18\.0\.9|Bad Gateway/);
  });

  it("is absent for a caller without ai.chat", async () => {
    features.mockResolvedValue({ ai_entitlements: ["ai.nlquery"] });
    render(<RcaAskAi correlationId={CORR} />);
    await waitFor(() => expect(features).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 0));
    expect(screen.queryByTestId("rca-iris-chat")).toBeNull();
  });

  // N-E3: the classic RCA answer shows the same grounded recommendation cards
  // the Iris box does — escaped text, cited, and "no action has been executed".
  it("renders the answer's recommendation cards", async () => {
    aiAskStream.mockResolvedValue(answer({
      recommendations: [{ id: "r1", title: "Check the Gi4 optics <b>now</b>", steps: ["Read the DOM levels"], why: "Errors rose first on Gi4", basis: ["sig-1"] }],
    }));
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Explain this problem" }));
    expect(await screen.findByText("Check the Gi4 optics <b>now</b>")).toBeTruthy();
    expect(screen.getAllByText(/No action has been executed/).length).toBeGreaterThan(0);
    expect(document.querySelector(".ric b")).toBeNull();
  });

  // N-E4: while the RCA view is open, the problem is what the Iris box binds.
  it("registers the problem as what is in view, and clears it on close", async () => {
    const vc = await import("../../iris/viewContext");
    const { unmount } = render(<RcaAskAi correlationId={CORR} />);
    expect(vc.currentIrisView()).toMatchObject({ kind: "incident", id: CORR });
    unmount();
    expect(vc.currentIrisView()).toBeNull();
  });
});
