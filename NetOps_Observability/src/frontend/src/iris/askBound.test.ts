// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// askBound.test.ts — the ONE Iris ask path (N-E4): streamed first, one JSON
// fallback when the stream is cut, one retry without a conversation the server
// no longer has; the context passes through untouched.

import { describe, it, expect, vi, beforeEach } from "vitest";

const aiAsk = vi.fn();
const aiAskStream = vi.fn();

vi.mock("../services/api", () => {
  class StreamBrokenError extends Error {}
  return {
    StreamBrokenError,
    api: {
      aiAsk: (...a: unknown[]) => aiAsk(...a),
      aiAskStream: (...a: unknown[]) => aiAskStream(...a),
    },
  };
});
vi.mock("../lib/errors", () => ({
  httpFailure: (e: unknown) => ((e as { status?: number })?.status ? { status: (e as { status: number }).status } : null),
}));

import { askBound } from "./askBound";
import { StreamBrokenError } from "../services/api";

const ans = (over: Record<string, unknown> = {}) => ({ text: "ok", citations: [], disclaimers: [], conversation_id: "c-1", ...over });

beforeEach(() => { aiAsk.mockReset(); aiAskStream.mockReset(); });

describe("askBound", () => {
  it("streams with the caller's context and conversation", async () => {
    aiAskStream.mockResolvedValue(ans());
    const onEvent = vi.fn();
    const r = await askBound("why is this down?", { device_id: "dev-1" }, "c-1", onEvent);
    expect(aiAskStream).toHaveBeenCalledWith("why is this down?", { device_id: "dev-1" }, "c-1", onEvent);
    expect(r.conversationId).toBe("c-1");
    expect(aiAsk).not.toHaveBeenCalled();
  });

  it("falls back ONCE to the JSON ask when a proxy cuts the stream", async () => {
    aiAskStream.mockRejectedValue(new StreamBrokenError());
    aiAsk.mockResolvedValue(ans({ text: "json" }));
    const r = await askBound("q", { correlation_id: "x" }, undefined);
    expect(aiAsk).toHaveBeenCalledTimes(1);
    expect(aiAsk).toHaveBeenCalledWith("q", { correlation_id: "x" }, undefined);
    expect(r.answer.text).toBe("json");
  });

  it("drops a conversation the server no longer has and asks once without it", async () => {
    aiAskStream.mockRejectedValueOnce({ status: 404 }).mockResolvedValueOnce(ans({ conversation_id: undefined }));
    const r = await askBound("q", undefined, "gone");
    expect(aiAskStream).toHaveBeenCalledTimes(2);
    expect(aiAskStream.mock.calls[1][2]).toBeUndefined();
    expect(r.conversationId).toBeNull();
  });

  it("surfaces any other failure", async () => {
    aiAskStream.mockRejectedValue({ status: 502 });
    await expect(askBound("q", undefined, "c-1")).rejects.toEqual({ status: 502 });
    expect(aiAskStream).toHaveBeenCalledTimes(1);
  });
});
