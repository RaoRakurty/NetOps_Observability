// TicketDelivery.test.tsx — the ITSM delivery outbox + audit trail.
//
// What has to hold: the controls call the routes they claim to, a failed read
// never renders as an empty outbox, a bounded page never claims to be the whole
// set, and "Sync now" reports what it actually swept rather than implying it
// filed something.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";

const ticketsOutbox = vi.fn();
const ticketsAudit = vi.fn();
const integrationsReconcile = vi.fn();
const correlationTicketSync = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    ticketsOutbox: (...a: unknown[]) => ticketsOutbox(...a),
    ticketsAudit: (...a: unknown[]) => ticketsAudit(...a),
    integrationsReconcile: (...a: unknown[]) => integrationsReconcile(...a),
    correlationTicketSync: (...a: unknown[]) => correlationTicketSync(...a),
  },
}));

import TicketDelivery from "./TicketDelivery";

const CASE_A = "11111111-2222-4333-8444-555555555555";
const CASE_B = "66666666-7777-4888-8999-aaaaaaaaaaaa";

const FAILED = {
  tenant_id: "acme",
  id: "ob-1",
  corr_object_id: CASE_A,
  external_system: "servicenow",
  action: "create",
  idempotency_key: "k1",
  status: "failed",
  retry_count: 3,
  max_retries: 5,
  next_retry_at: "2026-09-05T11:00:00Z",
  last_error: "ServiceNow rejected the payload: u_correlix_seam is mandatory",
  created_at: "2026-09-05T10:00:00Z",
  updated_at: "2026-09-05T10:30:00Z",
};
const PENDING = { ...FAILED, id: "ob-2", corr_object_id: CASE_B, status: "pending", retry_count: 0, last_error: "" };
const SENT = { ...FAILED, id: "ob-3", corr_object_id: CASE_B, status: "sent", retry_count: 1, last_error: "" };

const AUDIT = {
  tenant_id: "acme",
  id: "au-1",
  corr_object_id: CASE_A,
  external_system: "servicenow",
  action: "create",
  actor: "system",
  old_status: "not_created",
  new_status: "failed",
  payload_hash: "abc",
  result: "error",
  error: "u_correlix_seam is mandatory",
  at: "2026-09-05T10:30:00Z",
};

afterEach(cleanup);
beforeEach(() => {
  for (const m of [ticketsOutbox, ticketsAudit, integrationsReconcile, correlationTicketSync]) m.mockReset();
  ticketsOutbox.mockResolvedValue({ outbox: [FAILED, PENDING, SENT], total: 3, limit: 50, offset: 0, has_more: false });
  ticketsAudit.mockResolvedValue({ audit: [AUDIT], total: 1, limit: 50, offset: 0, has_more: false });
});

describe("TicketDelivery — the outbox", () => {
  it("reads both routes on mount, paged", async () => {
    render(<TicketDelivery />);
    await screen.findByRole("table", { name: /delivery outbox/i });
    expect(ticketsOutbox).toHaveBeenCalledWith(50, 0);
    expect(ticketsAudit).toHaveBeenCalledWith(expect.objectContaining({ limit: 50, offset: 0 }));
  });

  it("shows the provider's own refusal on the failed row", async () => {
    render(<TicketDelivery />);
    const table = await screen.findByRole("table", { name: /delivery outbox/i });
    expect(within(table).getByText(/u_correlix_seam is mandatory/)).toBeTruthy();
    expect(within(table).getByText("failed")).toBeTruthy();
  });

  it("filters by delivery state without re-asking the server", async () => {
    render(<TicketDelivery />);
    await screen.findByRole("table", { name: /delivery outbox/i });
    fireEvent.click(screen.getByRole("button", { name: "Delivered" }));
    const table = screen.getByRole("table", { name: /delivery outbox/i });
    expect(within(table).getAllByRole("row")).toHaveLength(2); // header + the one sent row
    expect(ticketsOutbox).toHaveBeenCalledTimes(1);
  });

  it("a failed read says the outbox is UNKNOWN, not empty", async () => {
    ticketsOutbox.mockRejectedValue(new Error("502 Bad Gateway: "));
    render(<TicketDelivery />);
    expect(await screen.findByText(/unknown, not empty/i)).toBeTruthy();
    expect(screen.queryByRole("table", { name: /delivery outbox/i })).toBeNull();
  });

  it("an empty outbox is not read as proof a ticket was filed", async () => {
    ticketsOutbox.mockResolvedValue({ outbox: [], total: 0, limit: 50, offset: 0, has_more: false });
    render(<TicketDelivery />);
    expect(await screen.findByText(/not evidence that a ticket was filed/i)).toBeTruthy();
  });

  it("a bounded page says it is not the whole outbox", async () => {
    ticketsOutbox.mockResolvedValue({ outbox: [FAILED], total: 900, limit: 50, offset: 0, has_more: true });
    render(<TicketDelivery />);
    expect(await screen.findByText(/first 1 of 900 rows — this page is not the whole outbox/i)).toBeTruthy();
  });
});

describe("TicketDelivery — Sync now", () => {
  it("POSTs the reconcile route and reports what it swept", async () => {
    integrationsReconcile.mockResolvedValue({ reconciled_providers: 2 });
    render(<TicketDelivery />);
    fireEvent.click(await screen.findByRole("button", { name: /sync now/i }));
    await waitFor(() => expect(integrationsReconcile).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/Swept 2 two-way integrations for drift/i)).toBeTruthy();
  });

  it("zero swept providers is explained, not rendered as a failure", async () => {
    integrationsReconcile.mockResolvedValue({ reconciled_providers: 0 });
    render(<TicketDelivery />);
    fireEvent.click(await screen.findByRole("button", { name: /sync now/i }));
    expect(await screen.findByText(/No two-way integration is configured/i)).toBeTruthy();
  });

  it("a 409 says integrations are unavailable here", async () => {
    integrationsReconcile.mockRejectedValue(new Error("409 Conflict: "));
    render(<TicketDelivery />);
    fireEvent.click(await screen.findByRole("button", { name: /sync now/i }));
    expect(await screen.findByText(/not available on this deployment/i)).toBeTruthy();
  });
});

describe("TicketDelivery — per-case sync and the audit trail", () => {
  it("the row control syncs THAT case and says it does not replay the stuck row", async () => {
    correlationTicketSync.mockResolvedValue({ enqueued: "x", corr_object_id: CASE_A, system: "servicenow" });
    render(<TicketDelivery />);
    const table = await screen.findByRole("table", { name: /delivery outbox/i });
    const row = within(table).getByTitle(CASE_A).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: /sync this case/i }));
    await waitFor(() => expect(correlationTicketSync).toHaveBeenCalledWith(CASE_A));
    expect(await screen.findByText(/does not replay the stuck one/i)).toBeTruthy();
  });

  it("filters the audit trail by a case id, and refuses a malformed one client-side", async () => {
    render(<TicketDelivery />);
    await screen.findByRole("table", { name: /ticket audit trail/i });

    fireEvent.change(screen.getByPlaceholderText(/filter by case id/i), { target: { value: "not-an-id" } });
    fireEvent.click(screen.getByRole("button", { name: "Filter" }));
    expect(screen.getByText(/36-character identifier/i)).toBeTruthy();
    expect(ticketsAudit).toHaveBeenCalledTimes(1);

    fireEvent.change(screen.getByPlaceholderText(/filter by case id/i), { target: { value: CASE_A } });
    fireEvent.click(screen.getByRole("button", { name: "Filter" }));
    await waitFor(() =>
      expect(ticketsAudit).toHaveBeenLastCalledWith(expect.objectContaining({ corrObjectId: CASE_A })));
  });

  it("an empty filtered trail says nothing was sent for that case", async () => {
    ticketsAudit.mockResolvedValue({ audit: [], total: 0, limit: 50, offset: 0, has_more: false });
    render(<TicketDelivery />);
    fireEvent.change(await screen.findByPlaceholderText(/filter by case id/i), { target: { value: CASE_B } });
    fireEvent.click(screen.getByRole("button", { name: "Filter" }));
    expect(await screen.findByText(/Nothing was sent for it, in either direction/i)).toBeTruthy();
  });

  it("renders the recorded transition and its error", async () => {
    render(<TicketDelivery />);
    const trail = await screen.findByRole("table", { name: /ticket audit trail/i });
    expect(within(trail).getByText("not_created → failed")).toBeTruthy();
    expect(within(trail).getByText(/u_correlix_seam is mandatory/)).toBeTruthy();
  });
});
