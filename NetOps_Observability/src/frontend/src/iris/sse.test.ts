// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { readSSE, SSELimitError } from "./sse";

function streamOf(chunks: (string | Uint8Array)[]): ReadableStream<Uint8Array> {
  const enc = new TextEncoder();
  return new ReadableStream({
    start(c) {
      for (const ch of chunks) c.enqueue(typeof ch === "string" ? enc.encode(ch) : ch);
      c.close();
    },
  });
}

async function all(s: ReadableStream<Uint8Array>, limits?: Parameters<typeof readSSE>[1]) {
  const out = [];
  for await (const m of readSSE(s, limits)) out.push(m);
  return out;
}

describe("readSSE", () => {
  it("reads events split anywhere — mid-line, mid-field, mid-UTF-8", async () => {
    const enc = new TextEncoder().encode("event: answer\ndata: {\"text\":\"naïve ✓\"}\n\n");
    const cut = 30; // inside the multi-byte characters
    const evs = await all(streamOf(["event: plan", "ning\ndata: {\"seq\":1}\n", "\n", enc.slice(0, cut), enc.slice(cut)]));
    expect(evs).toEqual([
      { event: "planning", data: '{"seq":1}' },
      { event: "answer", data: '{"text":"naïve ✓"}' },
    ]);
  });

  it("handles CRLF and CR line ends, comments, multi-line data and a missing final blank line", async () => {
    const evs = await all(streamOf([": hb\r\n\r\nevent: a\r\ndata: x\r\ndata: y\r\n\r\n", "event: b\rdata: z\r\r", "event: c\ndata: w"]));
    expect(evs).toEqual([
      { event: "a", data: "x\ny" },
      { event: "b", data: "z" },
      { event: "c", data: "w" },
    ]);
  });

  it("enforces its limits instead of growing without bound", async () => {
    await expect(all(streamOf(["data: " + "x".repeat(100) + "\n\n"]), { maxEventBytes: 50, maxEvents: 10 })).rejects.toBeInstanceOf(SSELimitError);
    await expect(all(streamOf(["data: a\n\n".repeat(5)]), { maxEventBytes: 50, maxEvents: 3 })).rejects.toBeInstanceOf(SSELimitError);
  });
});
