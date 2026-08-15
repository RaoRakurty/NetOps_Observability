import { describe, it, expect } from "vitest";
import { sshSocketUrl } from "./DeviceTerminal";

// DeviceTerminal.ticket.test.ts — WS-3: the session JWT is no longer placed in
// the WebSocket URL.
//
// Before: `/api/devices/{id}/ssh?token=<session JWT>`. nginx logs the request
// line, so every terminal open wrote a reusable, privileged, still-valid JWT
// into stdout → Vector → OpenSearch. After: the socket carries only a one-time
// ticket obtained over an authenticated HTTPS POST.

const FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.DO_NOT_LOG_SESSION_JWT.sig";
const FAKE_TICKET = "t_DO_NOT_LOG_WS_TICKET_9f8e7d6c";

describe("sshSocketUrl", () => {
  it("carries the ticket and only the ticket", () => {
    const url = sshSocketUrl("dev-1", FAKE_TICKET, { protocol: "https:", host: "correlix.example" });
    expect(url).toBe(`wss://correlix.example/api/devices/dev-1/ssh?ticket=${FAKE_TICKET}`);
    expect(url).toContain("ticket=");
    expect(url).not.toContain("token=");
  });

  it("never interpolates a session JWT even if one is handed to it by mistake", () => {
    // Defensive: the parameter is a ticket, but pin that a JWT-shaped value is
    // at least never labelled `token=` — the query key the backend USED to
    // accept as a session credential and no longer does.
    const url = sshSocketUrl("dev-1", FAKE_JWT, { protocol: "https:", host: "h" });
    expect(url).not.toContain("token=");
  });

  it("uses wss on https and ws otherwise, and URL-encodes the device id", () => {
    expect(sshSocketUrl("a/b c", "t", { protocol: "https:", host: "h" }))
      .toBe("wss://h/api/devices/a%2Fb%20c/ssh?ticket=t");
    expect(sshSocketUrl("d", "t", { protocol: "http:", host: "h:8000" }))
      .toBe("ws://h:8000/api/devices/d/ssh?ticket=t");
  });

  it("URL-encodes the ticket so a hostile value cannot smuggle a second parameter", () => {
    const url = sshSocketUrl("d", "x&token=" + FAKE_JWT, { protocol: "https:", host: "h" });
    // The literal `&token=` must not survive as a separate query parameter.
    expect(url).not.toMatch(/[?&]token=/);
  });
});
