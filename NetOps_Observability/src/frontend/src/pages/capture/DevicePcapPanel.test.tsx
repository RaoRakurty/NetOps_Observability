// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// DevicePcapPanel.test.tsx — the device Packet capture panel.
//
// What is pinned here:
//  · the feature-off card on 404/501 — a product state, not an error
//  · the capture list: status chips, packets/bytes, honest "no filter" wording,
//    and an empty state that says an empty list means nothing was captured
//  · the guardrails refuse BEFORE the wire (61 s, 10 001 packets, `; rm -rf`)
//    and the POST body is exactly the contract when they pass
//  · 409 → "already running", 400 → the server's own reason inline,
//    403 → the no-permission line (the SERVER is the authority)
//  · polling is bounded and STOPS the moment a capture reports done or failed
//  · delete asks for confirmation and only then sends DELETE
//  · the status line is a live region (role=status, aria-live=polite)

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, act } from "@testing-library/react";
import type { Device, PcapCapture } from "../../services/api";

const pcapList = vi.fn();
const pcapStart = vi.fn();
const pcapCapture = vi.fn();
const pcapDelete = vi.fn();
const pcapDownload = vi.fn();
const portInterfaces = vi.fn();
const permissions = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    pcapList: (...a: unknown[]) => pcapList(...a),
    pcapStart: (...a: unknown[]) => pcapStart(...a),
    pcapCapture: (...a: unknown[]) => pcapCapture(...a),
    pcapDelete: (...a: unknown[]) => pcapDelete(...a),
    pcapDownload: (...a: unknown[]) => pcapDownload(...a),
    portInterfaces: (...a: unknown[]) => portInterfaces(...a),
    permissions: (...a: unknown[]) => permissions(...a),
  },
}));

import DevicePcapPanel from "./DevicePcapPanel";
import { FEATURE_OFF_MESSAGE, NO_PERMISSION_MESSAGE, RUNNING_MESSAGE } from "./pcapModel";

const DEVICE = {
  id: "leaf1", name: "leaf1", address: "10.0.0.1", vendor: "cisco", source: "static",
  last_seen: "2026-09-01T10:00:00Z",
} as Device;

const DONE: PcapCapture = {
  capture_id: "cap-done", interface: "GigabitEthernet0/0/1",
  started_at: "2026-09-01T12:00:00Z", ended_at: "2026-09-01T12:00:15Z",
  status: "done", packets: 4210, bytes: 2048, filter: "host 10.0.0.1 and port 179",
};
const FAILED: PcapCapture = {
  capture_id: "cap-failed", interface: "GigabitEthernet0/0/2",
  started_at: "2026-09-01T11:00:00Z", ended_at: "2026-09-01T11:00:03Z",
  status: "failed", packets: 0, bytes: 0, filter: "", error: "interface is administratively down",
};
const RUNNING: PcapCapture = {
  capture_id: "cap-run", interface: "GigabitEthernet0/0/1",
  started_at: "2026-09-01T12:30:00Z", ended_at: null,
  status: "running", packets: 12, bytes: 900, filter: "",
};

/** Default happy path: two finished captures, write permission, no port inventory. */
function ok(items: PcapCapture[] = [DONE, FAILED], infra = 2) {
  pcapList.mockResolvedValue({ items });
  permissions.mockResolvedValue({ role: "operator", permissions: { infrastructure: infra } });
  portInterfaces.mockResolvedValue({ interfaces: [], total: 0, limit: 500, offset: 0 });
}

/** Fill the form's free-text fields (no port inventory ⇒ a text interface field). */
function fillForm(over: { iface?: string; packets?: string; filter?: string } = {}) {
  fireEvent.change(screen.getByPlaceholderText("GigabitEthernet0/0/1"), {
    target: { value: over.iface ?? "GigabitEthernet0/0/1" },
  });
  fireEvent.change(screen.getByLabelText(/Max packets/i), { target: { value: over.packets ?? "1000" } });
  if (over.filter !== undefined) {
    fireEvent.change(screen.getByPlaceholderText("host 10.0.0.1 and port 179"), { target: { value: over.filter } });
  }
}

const startBtn = () => screen.getByRole("button", { name: /Start a packet capture/i });

beforeEach(() => {
  for (const m of [pcapList, pcapStart, pcapCapture, pcapDelete, pcapDownload, portInterfaces, permissions]) m.mockReset();
});
afterEach(() => { cleanup(); vi.useRealTimers(); });

describe("feature flag — 404/501 is a product state", () => {
  it("renders the not-enabled card on a 404", async () => {
    pcapList.mockRejectedValue(new Error("404 Not Found: "));
    permissions.mockResolvedValue({ role: "operator", permissions: { infrastructure: 2 } });
    portInterfaces.mockResolvedValue({ interfaces: [] });
    render(<DevicePcapPanel device={DEVICE} />);
    expect(await screen.findByText(new RegExp(FEATURE_OFF_MESSAGE))).toBeTruthy();
    expect(screen.getByText(/FEATURE_PACKET_CAPTURE/)).toBeTruthy();
    // No form is offered for a family that does not exist here.
    expect(screen.queryByRole("button", { name: /Start a packet capture/i })).toBeNull();
  });

  it("renders the not-enabled card on a 501 too", async () => {
    pcapList.mockRejectedValue(new Error("501 Not Implemented: "));
    permissions.mockResolvedValue({ role: "operator", permissions: { infrastructure: 2 } });
    portInterfaces.mockResolvedValue({ interfaces: [] });
    render(<DevicePcapPanel device={DEVICE} />);
    expect(await screen.findByText(new RegExp(FEATURE_OFF_MESSAGE))).toBeTruthy();
  });
});

describe("the capture list", () => {
  it("renders each capture with its status chip, packets, size and filter", async () => {
    ok();
    const { container } = render(<DevicePcapPanel device={DEVICE} />);
    await screen.findByText("cap-done");
    const rows = container.querySelectorAll("tbody tr");
    expect(rows.length).toBe(2);
    expect(rows[0].textContent).toContain("Done");
    expect(rows[0].textContent).toContain("4,210");
    expect(rows[0].textContent).toContain("2.0 KB");
    expect(rows[0].textContent).toContain("host 10.0.0.1 and port 179");
    expect(rows[1].textContent).toContain("Failed");
    // A failed capture carries the reason the backend gave, as escaped text.
    expect(rows[1].textContent).toContain("interface is administratively down");
    // An absent filter is named, never left as a blank cell.
    expect(rows[1].textContent).toContain("no filter (all traffic)");
  });

  it("offers a sized download only for a finished capture that holds bytes", async () => {
    ok();
    render(<DevicePcapPanel device={DEVICE} />);
    await screen.findByText("cap-done");
    expect(screen.getByRole("button", { name: /Download capture cap-done \(2\.0 KB\)/ })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Download capture cap-failed/ })).toBeNull();
    expect(screen.getByText("Nothing to download")).toBeTruthy();
  });

  it("says an empty list means nothing was captured, not that the link is quiet", async () => {
    ok([]);
    render(<DevicePcapPanel device={DEVICE} />);
    expect(await screen.findByText(/No packet capture has been run on this device yet/)).toBeTruthy();
    expect(screen.getByText(/not that the interface is quiet/)).toBeTruthy();
  });

  it("renders the status line as a polite live region", async () => {
    ok();
    const { container } = render(<DevicePcapPanel device={DEVICE} />);
    await screen.findByText("cap-done");
    const live = container.querySelector('[role="status"][aria-live="polite"]');
    expect(live).toBeTruthy();
  });
});

describe("client-side guardrails refuse before the wire", () => {
  it("makes 61 s unreachable: the slider is hard-capped at 60 and clamps a forced 61", async () => {
    ok([]);
    pcapStart.mockResolvedValue({ capture_id: "cap-new", status: "running", expires_at: "2026-09-01T13:00:00Z" });
    render(<DevicePcapPanel device={DEVICE} />);
    await screen.findByText(/No packet capture has been run/);
    fillForm();
    const slider = screen.getByLabelText(/Capture duration in seconds/i) as HTMLInputElement;
    expect(slider.min).toBe("1");
    expect(slider.max).toBe("60");
    // A forced 61 is clamped by the control itself; the request that leaves is
    // the ceiling, never past it. (validateCapture refuses a raw 61 outright —
    // pinned in pcapModel.test.ts, where no DOM can clamp it first.)
    fireEvent.change(slider, { target: { value: "61" } });
    fireEvent.click(startBtn());
    await waitFor(() => expect(pcapStart).toHaveBeenCalledTimes(1));
    expect(pcapStart.mock.calls[0][1].duration_s).toBe(60);
  });

  it("refuses 10 001 packets without POSTing", async () => {
    ok([]);
    render(<DevicePcapPanel device={DEVICE} />);
    await screen.findByText(/No packet capture has been run/);
    fillForm({ packets: "10001" });
    fireEvent.click(startBtn());
    await waitFor(() => expect(screen.getByText(/A capture may collect 1-10,000 packets/)).toBeTruthy());
    expect(pcapStart).not.toHaveBeenCalled();
  });

  it("refuses a filter injection (`; rm -rf`) inline and never POSTs it", async () => {
    ok([]);
    render(<DevicePcapPanel device={DEVICE} />);
    await screen.findByText(/No packet capture has been run/);
    fillForm({ filter: "; rm -rf" });
    // The refusal is live — it shows before the operator even clicks Start.
    await waitFor(() => expect(screen.getByText(/Shell metacharacters are not allowed/)).toBeTruthy());
    fireEvent.click(startBtn());
    await waitFor(() => expect(screen.getAllByText(/Shell metacharacters are not allowed/).length).toBeGreaterThan(0));
    expect(pcapStart).not.toHaveBeenCalled();
  });
});

describe("starting a capture", () => {
  it("POSTs exactly the contracted body and announces the accepted capture", async () => {
    ok([]);
    pcapStart.mockResolvedValue({ capture_id: "cap-new", status: "running", expires_at: "2026-09-01T13:00:00Z" });
    render(<DevicePcapPanel device={DEVICE} />);
    await screen.findByText(/No packet capture has been run/);
    fillForm({ iface: "ge-0/0/0", packets: "500", filter: "host 10.0.0.1 and port 179" });
    fireEvent.change(screen.getByLabelText(/Capture duration in seconds/i), { target: { value: "30" } });
    fireEvent.click(startBtn());
    await waitFor(() => expect(pcapStart).toHaveBeenCalledTimes(1));
    expect(pcapStart).toHaveBeenCalledWith("leaf1", {
      interface: "ge-0/0/0",
      duration_s: 30,
      max_packets: 500,
      filter: "host 10.0.0.1 and port 179",
    });
    expect(await screen.findByText(/Capture cap-new started on ge-0\/0\/0/)).toBeTruthy();
  });

  it("omits an empty filter from the POST body", async () => {
    ok([]);
    pcapStart.mockResolvedValue({ capture_id: "cap-new", status: "running", expires_at: "2026-09-01T13:00:00Z" });
    render(<DevicePcapPanel device={DEVICE} />);
    await screen.findByText(/No packet capture has been run/);
    fillForm();
    fireEvent.click(startBtn());
    await waitFor(() => expect(pcapStart).toHaveBeenCalledTimes(1));
    expect(pcapStart.mock.calls[0][1]).toEqual({
      interface: "GigabitEthernet0/0/1", duration_s: 15, max_packets: 1000,
    });
  });

  it("renders a 409 as 'already running' rather than an error", async () => {
    ok([]);
    pcapStart.mockRejectedValue(new Error("409 Conflict: "));
    render(<DevicePcapPanel device={DEVICE} />);
    await screen.findByText(/No packet capture has been run/);
    fillForm();
    fireEvent.click(startBtn());
    expect(await screen.findByText(RUNNING_MESSAGE)).toBeTruthy();
  });

  it("renders a 400 guardrail breach with the server's own reason inline", async () => {
    ok([]);
    pcapStart.mockRejectedValue(new Error('400 Bad Request: {"error":"duration_s must be between 1 and 60"}'));
    render(<DevicePcapPanel device={DEVICE} />);
    await screen.findByText(/No packet capture has been run/);
    fillForm();
    fireEvent.click(startBtn());
    expect(await screen.findByText("duration_s must be between 1 and 60")).toBeTruthy();
  });

  it("renders a server 403 inline even though the client thought it could write", async () => {
    ok([]);
    pcapStart.mockRejectedValue(new Error("403 Forbidden: "));
    render(<DevicePcapPanel device={DEVICE} />);
    await screen.findByText(/No packet capture has been run/);
    fillForm();
    fireEvent.click(startBtn());
    expect(await screen.findByText(NO_PERMISSION_MESSAGE)).toBeTruthy();
  });

  it("disables the form and says why for a read-only operator", async () => {
    ok([DONE], 1);
    render(<DevicePcapPanel device={DEVICE} />);
    await screen.findByText("cap-done");
    await waitFor(() => expect(screen.getByText(NO_PERMISSION_MESSAGE)).toBeTruthy());
    expect((startBtn() as HTMLButtonElement).disabled).toBe(true);
    // No destructive action is offered at all below write.
    expect(screen.queryByRole("button", { name: /Delete capture/ })).toBeNull();
  });
});

describe("download", () => {
  it("fetches the file and reports the size, with the blocked-download caveat", async () => {
    ok();
    pcapDownload.mockResolvedValue(undefined);
    render(<DevicePcapPanel device={DEVICE} />);
    await screen.findByText("cap-done");
    fireEvent.click(screen.getByRole("button", { name: /Download capture cap-done/ }));
    await waitFor(() => expect(pcapDownload).toHaveBeenCalledWith("leaf1", "cap-done"));
    expect(await screen.findByText(/Downloading 2\.0 KB of capture cap-done/)).toBeTruthy();
    expect(screen.getByText(/this browser blocked the download/)).toBeTruthy();
  });

  it("notes a 403 on download inline", async () => {
    ok();
    pcapDownload.mockRejectedValue(new Error("403 Forbidden: "));
    render(<DevicePcapPanel device={DEVICE} />);
    await screen.findByText("cap-done");
    fireEvent.click(screen.getByRole("button", { name: /Download capture cap-done/ }));
    expect(await screen.findByText(NO_PERMISSION_MESSAGE)).toBeTruthy();
  });
});

describe("delete", () => {
  it("asks for confirmation and only then sends DELETE", async () => {
    ok();
    pcapDelete.mockResolvedValue(undefined);
    render(<DevicePcapPanel device={DEVICE} />);
    await screen.findByText("cap-done");

    fireEvent.click(screen.getByRole("button", { name: "Delete capture cap-done" }));
    expect(pcapDelete).not.toHaveBeenCalled();
    expect(screen.getByText(/removes the capture file for everyone/)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Confirm deleting capture cap-done" }));
    await waitFor(() => expect(pcapDelete).toHaveBeenCalledWith("leaf1", "cap-done"));
    expect(await screen.findByText("Capture cap-done deleted.")).toBeTruthy();
    // The list is re-read from the server, never patched optimistically.
    expect(pcapList).toHaveBeenCalledTimes(2);
  });

  it("cancels without sending anything", async () => {
    ok();
    render(<DevicePcapPanel device={DEVICE} />);
    await screen.findByText("cap-done");
    fireEvent.click(screen.getByRole("button", { name: "Delete capture cap-done" }));
    fireEvent.click(screen.getByRole("button", { name: "Cancel deleting capture cap-done" }));
    expect(pcapDelete).not.toHaveBeenCalled();
    expect(screen.queryByText(/removes the capture file for everyone/)).toBeNull();
  });
});

describe("polling — bounded, and it stops", () => {
  const tick = async (ms: number) => {
    await act(async () => {
      vi.advanceTimersByTime(ms);
      await Promise.resolve();
      await Promise.resolve();
    });
  };

  it("polls a running capture every 2 s and STOPS once it reports done", async () => {
    vi.useFakeTimers();
    ok([RUNNING]);
    // The list re-read that follows a terminal poll must agree with it, or the
    // panel would legitimately re-arm on a capture the server still calls running.
    const finished = { ...RUNNING, status: "done" as const, ended_at: "2026-09-01T12:30:15Z", packets: 300, bytes: 4096 };
    pcapList.mockResolvedValueOnce({ items: [RUNNING] }).mockResolvedValue({ items: [finished] });
    pcapCapture.mockResolvedValueOnce({ ...RUNNING, packets: 90 }).mockResolvedValueOnce(finished);
    render(<DevicePcapPanel device={DEVICE} />);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });

    await tick(2000);
    expect(pcapCapture).toHaveBeenCalledTimes(1);
    await tick(2000);
    expect(pcapCapture).toHaveBeenCalledTimes(2);

    // Terminal: no further poll is ever armed, however long we wait.
    await tick(2000);
    await tick(20000);
    expect(pcapCapture).toHaveBeenCalledTimes(2);
  });

  it("stops polling when the capture reports failed", async () => {
    vi.useFakeTimers();
    ok([RUNNING]);
    const broken = { ...RUNNING, status: "failed" as const, ended_at: "2026-09-01T12:30:04Z", error: "no such interface" };
    pcapList.mockResolvedValueOnce({ items: [RUNNING] }).mockResolvedValue({ items: [broken] });
    pcapCapture.mockResolvedValue(broken);
    render(<DevicePcapPanel device={DEVICE} />);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });

    await tick(2000);
    expect(pcapCapture).toHaveBeenCalledTimes(1);
    await tick(20000);
    expect(pcapCapture).toHaveBeenCalledTimes(1);
  });

  it("never polls at all when no capture is running", async () => {
    vi.useFakeTimers();
    ok([DONE, FAILED]);
    render(<DevicePcapPanel device={DEVICE} />);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    await tick(30000);
    expect(pcapCapture).not.toHaveBeenCalled();
  });
});

describe("interface picker", () => {
  it("offers the device's discovered ports when the inventory has any", async () => {
    pcapList.mockResolvedValue({ items: [] });
    permissions.mockResolvedValue({ role: "operator", permissions: { infrastructure: 2 } });
    portInterfaces.mockResolvedValue({
      interfaces: [
        { device: "leaf1", port_id: "leaf1:Gi0/0/2", port_name: "Gi0/0/2", if_alias: "to-spine1" },
        { device: "leaf1", port_id: "leaf1:Gi0/0/1", port_name: "Gi0/0/1", if_alias: "" },
      ],
      total: 2,
    });
    render(<DevicePcapPanel device={DEVICE} />);
    await screen.findByText(/No packet capture has been run/);
    await waitFor(() => expect(screen.getByRole("option", { name: "Gi0/0/1" })).toBeTruthy());
    expect(screen.getByRole("option", { name: "Gi0/0/2 — to-spine1" })).toBeTruthy();
    // With a picker there is no free-text field and no vendor hint.
    expect(screen.queryByPlaceholderText("GigabitEthernet0/0/1")).toBeNull();
  });

  it("falls back to a free-text field carrying the vendor's naming hint", async () => {
    ok([]);
    render(<DevicePcapPanel device={DEVICE} />);
    await screen.findByText(/No packet capture has been run/);
    expect(screen.getByPlaceholderText("GigabitEthernet0/0/1")).toBeTruthy();
    expect(screen.getByText(/Type the interface name exactly as the device reports it/)).toBeTruthy();
  });
});
