// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// sse.ts — a bounded Server-Sent Events reader over a fetch body (tracker 337
// N-E2). EventSource cannot POST, so the Iris ask reads its stream here.
// Handles chunks split mid-line and mid-UTF-8, CR / LF / CRLF line ends,
// comments (heartbeats), multi-line data. Limits are hard: a stream past them
// throws instead of growing without bound.

export interface SSEMessage {
  event: string;
  data: string;
}

export interface SSELimits {
  maxEventBytes: number;
  maxEvents: number;
}

export const DEFAULT_SSE_LIMITS: SSELimits = { maxEventBytes: 4 * 1024 * 1024, maxEvents: 256 };

export class SSELimitError extends Error {}

export async function* readSSE(body: ReadableStream<Uint8Array>, limits: SSELimits = DEFAULT_SSE_LIMITS): AsyncGenerator<SSEMessage> {
  const reader = body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buf = "";
  let event = "";
  let data: string[] = [];
  let size = 0;
  let count = 0;
  const dispatch = (): SSEMessage | null => {
    if (data.length === 0 && event === "") return null;
    const msg = { event: event || "message", data: data.join("\n") };
    event = "";
    data = [];
    size = 0;
    count++;
    if (count > limits.maxEvents) throw new SSELimitError(`more than ${limits.maxEvents} events`);
    return msg;
  };
  const line = (l: string): SSEMessage | null => {
    if (l === "") return dispatch();
    if (l.startsWith(":")) return null; // comment / heartbeat
    const colon = l.indexOf(":");
    const field = colon === -1 ? l : l.slice(0, colon);
    let value = colon === -1 ? "" : l.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    size += value.length;
    if (size > limits.maxEventBytes) throw new SSELimitError(`an event larger than ${limits.maxEventBytes} bytes`);
    if (field === "event") event = value;
    else if (field === "data") data.push(value);
    return null; // id / retry / unknown fields: ignored
  };
  try {
    for (;;) {
      const { value, done } = await reader.read();
      buf += done ? decoder.decode() : decoder.decode(value, { stream: true });
      if (buf.length > limits.maxEventBytes + 1024) {
        // a single line this long cannot be a valid event
        const nl = buf.search(/[\r\n]/);
        if (nl === -1) throw new SSELimitError(`a line longer than ${limits.maxEventBytes} bytes`);
      }
      for (;;) {
        const m = /\r\n|\r|\n/.exec(buf);
        if (!m) break;
        // A lone \r at the very end may be the first half of \r\n.
        if (m[0] === "\r" && m.index === buf.length - 1 && !done) break;
        const l = buf.slice(0, m.index);
        buf = buf.slice(m.index + m[0].length);
        const msg = line(l);
        if (msg) yield msg;
      }
      if (done) {
        if (buf !== "") {
          const msg = line(buf);
          buf = "";
          if (msg) yield msg;
        }
        const last = dispatch();
        if (last) yield last;
        return;
      }
    }
  } finally {
    reader.releaseLock();
  }
}
