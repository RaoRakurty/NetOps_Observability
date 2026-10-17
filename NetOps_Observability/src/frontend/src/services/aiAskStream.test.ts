// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, vi, afterEach } from "vitest";
import { api, StreamBrokenError } from "./api";
import { httpFailure } from "../lib/errors";

function sseResponse(body: string, status = 200): Response {
  const enc = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(c) {
      // Two chunks, split mid-event, like a real network.
      const mid = Math.floor(body.length / 2);
      c.enqueue(enc.encode(body.slice(0, mid)));
      c.enqueue(enc.encode(body.slice(mid)));
      c.close();
    },
  });
  return new Response(stream, { status, headers: { "Content-Type": "text/event-stream; charset=utf-8" } });
}

const answer = { text: "BGP down", mode: "problem_explanation", citations: [] };

afterEach(() => vi.restoreAllMocks());

describe("api.aiAskStream", () => {
  it("reports progress and resolves to the streamed answer", async () => {
    const body =
      'event: planning\ndata: {"seq":1,"type":"planning"}\n\n' +
      ': hb\n\n' +
      'event: tool_started\ndata: {"seq":2,"type":"tool_started","tool":"get_problem"}\n\n' +
      `event: answer\ndata: ${JSON.stringify(answer)}\n\n` +
      'event: done\ndata: {"type":"done","dropped":0}\n\n';
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(sseResponse(body));
    const seen: string[] = [];
    const ans = await api.aiAskStream("why?", undefined, undefined, (e) => seen.push(`${e.type}:${e.tool ?? ""}`));
    expect(ans).toEqual(answer);
    expect(seen).toEqual(["planning:", "tool_started:get_problem"]);
    const init = fetchSpy.mock.calls[0][1] as RequestInit;
    expect((init.headers as Record<string, string>).Accept).toBe("text/event-stream");
  });

  it("reads a JSON response as the answer (older server, or no stream)", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify(answer), { status: 200, headers: { "Content-Type": "application/json" } }));
    expect(await api.aiAskStream("why?", undefined, undefined, () => {})).toEqual(answer);
  });

  it("throws the error the JSON path would have thrown", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(sseResponse('event: error\ndata: {"error":"provider down","status":502}\n\nevent: done\ndata: {}\n\n'));
    const err = await api.aiAskStream("why?", undefined, undefined, () => {}).catch((e) => e);
    expect(httpFailure(err)?.status).toBe(502);
    expect(String(err)).toContain("provider down");
  });

  it("a refusal before the answer is the usual error (404 conversation)", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response('{"error":"not found"}', { status: 404, statusText: "Not Found" }));
    const err = await api.aiAskStream("why?", undefined, "c-1", () => {}).catch((e) => e);
    expect(httpFailure(err)?.status).toBe(404);
  });

  it("a stream that ends without an answer is StreamBrokenError", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(sseResponse('event: planning\ndata: {"type":"planning"}\n\n'));
    await expect(api.aiAskStream("why?", undefined, undefined, () => {})).rejects.toBeInstanceOf(StreamBrokenError);
  });
});
