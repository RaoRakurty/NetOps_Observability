// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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
const tacConnectors = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    ticketsOutbox: (...a: unknown[]) => ticketsOutbox(...a),
    ticketsAudit: (...a: unknown[]) => ticketsAudit(...a),
    integrationsReconcile: (...a: unknown[]) => integrationsReconcile(...a),
    correlationTicketSync: (...a: unknown[]) => correlationTicketSync(...a),
    tacConnectors: (...a: unknown[]) => tacConnectors(...a),
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

// The vendor research that used to print twelve-deep on the escalation step and
// now lives here, behind each connector's own disclosure.
const NOKIA_RESEARCH =
  "NSP publishes exactly five APIs (NSP REST, RESTCONF, Kafka, NFM-P REST, NFM-P XML) and none is a " +
  "case/ticket/TSR API (checked 2026-09-05). phone is the vendor-preferred channel for outages.";
const JIRA_RESEARCH =
  "Cloud defaults to 1 GB per attachment on /rest/api/3, Data Center to 10 MB on /rest/api/2. " +
  "Jira Cloud rate-limits 20 writes per 2 s PER ISSUE.";

const CONNECTORS = [
  {
    id: "jira", display: "Jira issue", vendor: "jira",
    capabilities: ["create", "attach", "poll_status", "link"],
    max_attachment_bytes: 1_073_741_824, profile: "full", configured: true, note: JIRA_RESEARCH,
  },
  {
    id: "portal-nokia", display: "Nokia portal (copy & paste)", vendor: "nokia",
    capabilities: [], max_attachment_bytes: 0, profile: "link_only", configured: true, note: NOKIA_RESEARCH,
  },
  {
    id: "juniper", display: "Juniper Service Case", vendor: "juniper",
    capabilities: ["create", "attach"], max_attachment_bytes: 8_589_934_592, profile: "full",
    configured: false, status_note: "No credentials for this tenant yet — bring your own to use it.",
  },
];

afterEach(cleanup);
beforeEach(() => {
  for (const m of [ticketsOutbox, ticketsAudit, integrationsReconcile, correlationTicketSync, tacConnectors]) m.mockReset();
  tacConnectors.mockResolvedValue({ connectors: CONNECTORS });
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
    // The CLAIM stays: an empty outbox proves nothing about a filed ticket. The
    // sentence that said why moved to ai/skills/explain/ticketing.empty-outbox.md,
    // so the (i) that carries it is pinned beside the state.
    expect(await screen.findByText(/Nothing is in flight/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: /Ask Iris about nothing in flight/ })).toBeTruthy();
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
    expect(await screen.findByText(/a new row, not a replay/i)).toBeTruthy();
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
    expect(await screen.findByText(/No ticket action recorded for that case/i)).toBeTruthy();
  });

  it("renders the recorded transition and its error", async () => {
    render(<TicketDelivery />);
    const trail = await screen.findByRole("table", { name: /ticket audit trail/i });
    expect(within(trail).getByText("not_created → failed")).toBeTruthy();
    expect(within(trail).getByText(/u_correlix_seam is mandatory/)).toBeTruthy();
  });
});

// ── case connectors (owner, 2026-09-06) ─────────────────────────────────────
//
// The escalation step used to print every connector's research paragraph —
// attachment ceilings, API caveats, "checked 2026-09-05", rate limits — twelve
// deep. The paragraph belongs where the credentials are brought, and it belongs
// behind a disclosure even here: this page states facts and offers actions.

describe("TicketDelivery — case connectors", () => {
  it("lists each vendor path with what it does and its state", async () => {
    render(<TicketDelivery />);
    const list = await screen.findByTestId("ticket-connectors");
    expect(tacConnectors).toHaveBeenCalled();

    const jira = within(list).getByTestId("ticket-conn-jira");
    expect(jira).toHaveTextContent("Opens the case and attaches the bundle");
    expect(jira).toHaveTextContent("Ready");
    expect(jira).toHaveTextContent("attaches up to 1.0 GB");

    const juniper = within(list).getByTestId("ticket-conn-juniper");
    expect(juniper).toHaveTextContent("Not configured");
    expect(juniper).toHaveTextContent("No credentials for this tenant yet");
  });

  it("keeps every research paragraph behind its own disclosure, closed", async () => {
    render(<TicketDelivery />);
    const list = await screen.findByTestId("ticket-connectors");
    for (const id of ["jira", "portal-nokia"]) {
      const row = within(list).getByTestId(`ticket-conn-${id}`);
      const fold = row.querySelector("details") as HTMLDetailsElement;
      expect(fold, `${id} carries no disclosure`).toBeTruthy();
      expect(fold.open).toBe(false);
      expect(within(fold).getByText("What this vendor path needs")).toBeTruthy();
    }
    // The paragraph is inside the disclosure, not beside the row.
    const nokia = within(list).getByTestId("ticket-conn-portal-nokia");
    const summaryLine = nokia.querySelector(".tdc-head") as HTMLElement;
    expect(summaryLine.textContent).not.toContain("NSP publishes exactly five APIs");
    expect(nokia.querySelector("details")).toHaveTextContent("NSP publishes exactly five APIs");
    expect(nokia.querySelector("details")).toHaveTextContent("checked 2026-09-05");
  });

  it("puts an (i) on every connector, keyed on its id", async () => {
    render(<TicketDelivery />);
    const list = await screen.findByTestId("ticket-connectors");
    expect(within(list).getByTestId("ticket-conn-portal-nokia").querySelector("button.ask-iris"))
      .toHaveAttribute("data-topic", "tac.connector.portal-nokia");
  });

  it("a failed read says so and never renders as 'no connectors'", async () => {
    tacConnectors.mockRejectedValue(new Error("TypeError: fetch failed"));
    render(<TicketDelivery />);
    expect(await screen.findByText(/case connectors could not be read/i)).toBeTruthy();
    expect(screen.queryByTestId("ticket-connectors")).toBeNull();
  });
});
