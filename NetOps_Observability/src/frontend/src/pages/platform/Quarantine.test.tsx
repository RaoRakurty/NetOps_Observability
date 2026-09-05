// Quarantine.test.tsx — the sealed-quarantine viewer.
//
// The assertions that matter are the ones that keep three different "nothing
// here" states apart: sealing is off (no quarantine STAGE), the index could not
// be read (depth unknown), and the quarantine is genuinely empty. Plus: the
// page must never offer re-attribution, and never render a payload.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, within } from "@testing-library/react";

const quarantineList = vi.fn();

vi.mock("../../services/api", () => ({
  api: { quarantineList: (...a: unknown[]) => quarantineList(...a) },
}));

import Quarantine from "./Quarantine";

const HELD = {
  _index: "netops-quarantine-2026.09.05",
  cx_event_id: "ev-1",
  received_at: "2026-09-05T09:00:00Z",
  lane: "syslog",
  identity_sha: "a".repeat(64),
  source_ip: "192.0.2.10",
  reason: "TENANT_UNATTRIBUTABLE",
};
const STRANDED = {
  ...HELD,
  cx_event_id: "ev-2",
  lane: "flows",
  identity_sha: "b".repeat(64),
  cx_restored_at: "2026-09-05T09:30:00Z",
};
const REINJECTED = {
  ...HELD,
  cx_event_id: "ev-3",
  lane: "snmptrap",
  identity_sha: "c".repeat(64),
  cx_restored_at: "2026-09-05T09:30:00Z",
  cx_restored_produced: "2026-09-05T09:31:00Z",
};

const LISTING = {
  quarantine: [HELD, STRANDED, REINJECTED],
  summary: { total: 3, oldest_received_at: "2026-09-05T09:00:00Z" },
};

afterEach(cleanup);
beforeEach(() => {
  quarantineList.mockReset();
  quarantineList.mockResolvedValue(LISTING);
});

describe("Quarantine — reading the index", () => {
  it("reads /api/quarantine paged and renders the held envelopes", async () => {
    render(<Quarantine />);
    const table = await screen.findByRole("table", { name: /quarantined envelopes/i });
    expect(quarantineList).toHaveBeenCalledWith(50, 0);
    expect(within(table).getAllByRole("row")).toHaveLength(4); // header + 3
    expect(within(table).getAllByText("TENANT_UNATTRIBUTABLE")).toHaveLength(3);
  });

  it("keeps the three restore states apart, including a STRANDED claim", async () => {
    render(<Quarantine />);
    const table = await screen.findByRole("table", { name: /quarantined envelopes/i });
    expect(within(table).getByText("held")).toBeTruthy();
    expect(within(table).getByText("stranded claim")).toBeTruthy();
    expect(within(table).getByText("re-injected")).toBeTruthy();
  });

  it("counts lanes ON THIS PAGE and says so beside the real depth", async () => {
    quarantineList.mockResolvedValue({ quarantine: [HELD, STRANDED], summary: { total: 900, oldest_received_at: HELD.received_at } });
    render(<Quarantine />);
    expect(await screen.findByText(/Lanes on this page \(2 of 900 envelopes\)/i)).toBeTruthy();
  });

  it("never offers re-attribution and never shows a payload", async () => {
    render(<Quarantine />);
    await screen.findByRole("table", { name: /quarantined envelopes/i });
    expect(screen.queryByRole("button", { name: /re-?attribut/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /unseal|restore/i })).toBeNull();
    expect(screen.getByText(/break-glass/i)).toBeTruthy();
  });

  it("shows the hashed identity truncated, never a raw hostname column", async () => {
    render(<Quarantine />);
    const table = await screen.findByRole("table", { name: /quarantined envelopes/i });
    expect(within(table).getByTitle("a".repeat(64))).toBeTruthy();
    expect(within(table).queryByText("a".repeat(64))).toBeNull();
  });
});

describe("Quarantine — the states that must not be confused", () => {
  it("a 501 says there is no quarantine STAGE on this deployment", async () => {
    quarantineList.mockRejectedValue(new Error("501 Not Implemented: "));
    render(<Quarantine />);
    expect(await screen.findByText(/Sealing custody is not enabled/i)).toBeTruthy();
    expect(screen.getByText(/different from a quarantine\s+that is empty/i)).toBeTruthy();
  });

  it("a 503 says the depth is UNKNOWN — explicitly not an empty quarantine", async () => {
    quarantineList.mockRejectedValue(new Error("503 Service Unavailable: "));
    render(<Quarantine />);
    expect(await screen.findByText(/NOT an empty quarantine/i)).toBeTruthy();
  });

  it("a 403 names the platform-owner gate", async () => {
    quarantineList.mockRejectedValue(new Error("403 Forbidden: "));
    render(<Quarantine />);
    expect(await screen.findByText(/needs platform-owner access/i)).toBeTruthy();
  });

  it("a genuinely empty quarantine says every event resolved to a device", async () => {
    quarantineList.mockResolvedValue({ quarantine: [], summary: { total: 0, oldest_received_at: null } });
    render(<Quarantine />);
    expect(await screen.findByText(/resolved to a device in the\s+inventory/i)).toBeTruthy();
  });
});

describe("Quarantine — paging", () => {
  it("asks for the next page by offset", async () => {
    quarantineList.mockResolvedValue({ quarantine: [HELD], summary: { total: 120, oldest_received_at: HELD.received_at } });
    render(<Quarantine />);
    fireEvent.click(await screen.findByRole("button", { name: "Next" }));
    await waitFor(() => expect(quarantineList).toHaveBeenLastCalledWith(50, 50));
  });
});
