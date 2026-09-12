// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// api.aiFeedback.test.ts — IRIS Phase B: a thumbs rating must name the answer
// it judges. POST /api/ai/feedback accepts an optional `answer_id`; when it is
// absent the server falls back to "this principal's most recent conclusion".
// That fallback is a convenience, not a substitute for being exact — so the
// client sends the id whenever the answer carries one, and sends NO key at all
// (never an empty string, which is not an id) when it does not.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { api, clearSession } from "./api";

type Captured = { url: string; init: RequestInit };

function captureFetch(): { calls: Captured[] } {
  const calls: Captured[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return new Response(null, { status: 204 });
    }),
  );
  return { calls };
}

function bodyOf(c: Captured): Record<string, unknown> {
  return JSON.parse(String(c.init.body));
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  clearSession();
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("aiFeedback carries the judged answer's id", () => {
  it("sends answer_id when the answer stamped one", async () => {
    const { calls } = captureFetch();
    await api.aiFeedback("up", "current_state", undefined, "ans-42");
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("/api/ai/feedback");
    expect(calls[0].init.method).toBe("POST");
    const body = bodyOf(calls[0]);
    expect(body.answer_id).toBe("ans-42");
    expect(body.rating).toBe("up");
    expect(body.intent).toBe("current_state");
  });

  it("omits the key entirely when the answer stamped no id", async () => {
    const { calls } = captureFetch();
    await api.aiFeedback("down", "rca");
    const body = bodyOf(calls[0]);
    expect("answer_id" in body).toBe(false);
    expect(body.rating).toBe("down");
  });

  it("never sends an empty string as an id", async () => {
    const { calls } = captureFetch();
    await api.aiFeedback("up", "rca", "conv-1", "");
    const body = bodyOf(calls[0]);
    expect("answer_id" in body).toBe(false);
    expect(body.conversation_id).toBe("conv-1");
  });

  it("still sends rating/intent/conversation_id unchanged (existing contract)", async () => {
    const { calls } = captureFetch();
    await api.aiFeedback("up", "module_health", "conv-9", "ans-9");
    expect(bodyOf(calls[0])).toEqual({
      rating: "up",
      intent: "module_health",
      conversation_id: "conv-9",
      answer_id: "ans-9",
    });
  });
});
