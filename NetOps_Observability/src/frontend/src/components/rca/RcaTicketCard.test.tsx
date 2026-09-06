// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// RcaTicketCard.test.tsx — the live external-ticket card (#78): honest empty
// state (no ticket), an open ticket's number → deep link, the Create vs Sync
// action by state, and the permission gate (no buttons without write).

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import type { CorrelationTickets } from "../../services/api";

const NONE: CorrelationTickets = { status: { state: "not_created" }, audit: [] };
const OPEN: CorrelationTickets = {
  status: {
    state: "open", system: "servicenow", ticket_number: "INC0012345", sys_id: "abc",
    instance_url: "https://acme.service-now.com", url: "https://acme.service-now.com/nav_to.do?uri=incident.do?sys_id=abc",
    last_verdict: "confirmed", last_synced_at: "2026-06-27T12:00:00Z",
  },
  audit: [{ action: "create", actor: "system", result: "ok", at: "2026-06-27T12:00:00Z" }],
};

function mockApi(tickets: CorrelationTickets, infra: number) {
  vi.doMock("../../services/api", () => ({
    api: {
      correlationTickets: vi.fn(() => Promise.resolve(tickets)),
      permissions: vi.fn(() => Promise.resolve({ role: "operator", permissions: { infrastructure: infra } })),
      correlationTicketCreate: vi.fn(() => Promise.resolve({ enqueued: "create", corr_object_id: "x", system: "servicenow" })),
      correlationTicketSync: vi.fn(() => Promise.resolve({ enqueued: "update", corr_object_id: "x", system: "servicenow" })),
    },
  }));
}

afterEach(() => { cleanup(); vi.resetModules(); });

describe("RcaTicketCard", () => {
  it("shows an honest empty state + a Create button when no ticket and writer", async () => {
    mockApi(NONE, 2);
    const { default: Card } = await import("./RcaTicketCard");
    render(<Card correlationId="x" />);
    expect(await screen.findByText("No ticket")).toBeTruthy();
    expect(screen.getByText(/No external ticket opened for this RCA yet\./)).toBeTruthy();
    expect(await screen.findByRole("button", { name: "Create ticket" })).toBeTruthy();
  });

  it("renders an open ticket's number as a deep link and offers Sync", async () => {
    mockApi(OPEN, 2);
    const { default: Card } = await import("./RcaTicketCard");
    render(<Card correlationId="x" />);
    const link = (await screen.findByText(/INC0012345/)).closest("a") as HTMLAnchorElement;
    expect(link?.getAttribute("href")).toContain("service-now.com");
    expect(await screen.findByRole("button", { name: "Sync ticket" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Create ticket" })).toBeNull();
  });

  it("hides all action buttons without infrastructure:write", async () => {
    mockApi(NONE, 1);
    const { default: Card } = await import("./RcaTicketCard");
    render(<Card correlationId="x" />);
    expect(await screen.findByText("No ticket")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Create ticket" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Sync ticket" })).toBeNull();
  });
});
