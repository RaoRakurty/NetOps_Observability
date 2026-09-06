// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { operatorError } from "./errors";

const FB = "The audit log could not be loaded.";

describe("operatorError — the api envelope never reaches an operator", () => {
  it("drops the HTTP prefix and the internal body of a 500", () => {
    const e = new Error(
      '500 Internal Server Error: {"error":"clickhouse: dial tcp 172.18.0.9:9000: connect: connection refused"}',
    );
    const out = operatorError(e, FB);
    expect(out).toBe("The service did not answer.");
    // The specifics an operator must never be shown are gone.
    expect(out).not.toMatch(/500|clickhouse|172\.18|tcp/);
  });

  it("maps each status class to a sentence about what happened", () => {
    expect(operatorError(new Error("401 Unauthorized: please sign in"), FB)).toBe(
      "Please sign in.",
    );
    expect(operatorError(new Error("403 Forbidden: "), FB)).toBe("You do not have access to this.");
    expect(operatorError(new Error("404 Not Found: "), FB)).toBe("That is not available.");
    expect(operatorError(new Error("429 Too Many Requests: "), FB)).toBe(
      "Too many requests just now — try again shortly.",
    );
    expect(operatorError(new Error("502 Bad Gateway: "), FB)).toBe("The service did not answer.");
  });

  it("unwraps a server sentence out of a JSON error body", () => {
    const e = new Error('409 Conflict: {"error":"a capture is already running on this device"}');
    expect(operatorError(e, FB)).toBe("A capture is already running on this device.");
  });

  it("refuses a JSON body that is itself developer text", () => {
    const e = new Error('500 Internal Server Error: {"error":"pq: relation \\"foo\\" does not exist"}');
    expect(operatorError(e, FB)).toBe("The service did not answer.");
  });

  it("handles the bare-status shapes the export/download paths throw", () => {
    expect(operatorError(new Error("503"), FB)).toBe("The service did not answer.");
    expect(operatorError(new Error("404: not found"), FB)).toBe("Not found.");
  });
});

describe("operatorError — a real sentence is kept, not replaced", () => {
  it("passes a plain server sentence through, normalized", () => {
    expect(operatorError(new Error("That profile name is already in use"), FB)).toBe(
      "That profile name is already in use.",
    );
  });

  it("keeps an existing terminal punctuation mark", () => {
    expect(operatorError(new Error("Discovery is already running."), FB)).toBe(
      "Discovery is already running.",
    );
  });

  it("strips the String(err) 'Error: ' prefix", () => {
    expect(operatorError(String(new Error("the device refused the connection")), FB)).toBe(
      "The device refused the connection.",
    );
  });
});

describe("operatorError — developer text falls back to the caller's sentence", () => {
  it.each([
    ["a stack frame", "at loadDevices (/app/src/pages/Devices.tsx:141:9)"],
    ["a TypeError", "TypeError: undefined is not an object"],
    ["a property read", "Cannot read properties of undefined (reading 'hits')"],
    ["a raw JSON body", '{"code":13,"details":"internal"}'],
    ["an HTML error page", "<html><head><title>502 Bad Gateway</title></head></html>"],
    ["nothing at all", ""],
  ])("%s", (_label, msg) => {
    expect(operatorError(new Error(msg), FB)).toBe(FB);
  });

  it("falls back for a non-Error throw with no prose", () => {
    expect(operatorError(undefined, FB)).toBe(FB);
    expect(operatorError(null, FB)).toBe(FB);
    expect(operatorError({ code: 7 }, FB)).toBe(FB);
  });

  it("falls back rather than dumping a novel at the operator", () => {
    expect(operatorError(new Error("x".repeat(300)), FB)).toBe(FB);
  });
});
