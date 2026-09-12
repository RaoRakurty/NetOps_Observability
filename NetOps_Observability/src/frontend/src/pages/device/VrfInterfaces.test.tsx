// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// VrfInterfaces render contract. The panel exists to be HONEST as much as
// useful, so these tests assert what it must NEVER show as much as what it does:
// no fabricated "default" instance, no zero where nothing was measured, no
// green dot on an interface whose state was never read.
import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, waitFor, fireEvent } from "@testing-library/react";
import type { Device, VrfInterfacesResponse } from "../../services/api";

// The API is stubbed with a PLAIN function rather than a vi.fn(): vitest's spy
// records every call's settled result, and clearing that record between tests
// re-surfaces an already-handled rejection as a test failure. A plain stub with
// its own call log gives the same assertions without the artefact.
type Reply = () => Promise<VrfInterfacesResponse>;
let reply: Reply = () => Promise.resolve(ungrouped());
const calls: Array<[string, string | undefined]> = [];
const lastCall = () => calls[calls.length - 1];

vi.mock("../../services/api", async (orig) => {
  const actual = await orig<typeof import("../../services/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      deviceInterfacesByVrf: (id: string, window?: string) => {
        calls.push([id, window]);
        return reply();
      },
    },
  };
});

import VrfInterfaces from "./VrfInterfaces";

const device = (over: Partial<Device> = {}): Device =>
  ({ id: "core-1", name: "core-1", address: "10.0.0.1", vendor: "cisco", last_seen: new Date().toISOString() } as Device);

const iface = (name: string, over: Record<string, unknown> = {}) => ({
  ifname: name, oper: "up", oper_value: 1, admin: "up", admin_value: 1,
  in_bps: null, out_bps: null, speed_bps: null, in_util_pct: null, out_util_pct: null,
  in_errors_per_s: null, out_errors_per_s: null, ...over,
});

const ungrouped = (vendorTerm = "VRF", members = [iface("Ethernet1")]): VrfInterfacesResponse => ({
  device: { id: "core-1", name: "core-1", vendor: "cisco" },
  window: "5m",
  dialect: { term: vendorTerm, term_plural: `${vendorTerm}s`, vendor: "cisco", vendor_known: true },
  coverage: {
    vrf_labels: false, transport: "snmp", transport_inferred: true,
    interfaces: members.length, in_groups: 0, ungrouped: members.length,
    utilisation: false, errors: false, truncated: false,
    notes: [`${vendorTerm} membership is not collected on this transport.`],
  },
  groups: [{
    vrf: "", label: `${vendorTerm} membership not collected on this transport`,
    membership: "not_collected", count: members.length, up: members.length, down: 0, unknown: 0,
    members,
  }],
  routing_instances: [],
});

beforeEach(() => { calls.length = 0; reply = () => Promise.resolve(ungrouped()); });
afterEach(() => cleanup());

describe("VrfInterfaces — the five honest states", () => {
  it("shows loading while the fetch is in flight", async () => {
    let release: (r: VrfInterfacesResponse) => void = () => {};
    const pending = new Promise<VrfInterfacesResponse>((res) => { release = res; });
    reply = () => pending;
    render(<VrfInterfaces device={device()} />);
    expect(screen.getByTestId("vrf-state-loading")).toBeTruthy();
    release(ungrouped());
    await screen.findByTestId("vrf-state-ready");
  });

  it("shows the API's own message on error, and no table", async () => {
    reply = () => Promise.reject(new Error("502 bad gateway"));
    render(<VrfInterfaces device={device()} />);
    const err = await screen.findByTestId("vrf-state-error");
    expect(err.textContent).toContain("502 bad gateway");
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("distinguishes not_connected from empty", async () => {
    const base = ungrouped();
    reply = () => Promise.resolve({
      ...base,
      coverage: { ...base.coverage, interfaces: 0, transport: "none", notes: ["No interface state series exists for this device."] },
      groups: [],
    });
    const { unmount } = render(<VrfInterfaces device={device()} />);
    expect((await screen.findByTestId("vrf-state-not_connected")).textContent)
      .toContain("No interface state series");
    unmount();
    cleanup();

    reply = () => Promise.resolve({ ...base, coverage: { ...base.coverage, interfaces: 4 }, groups: [] });
    render(<VrfInterfaces device={device()} />);
    expect(await screen.findByTestId("vrf-state-empty")).toBeTruthy();
  });

  it("renders the grouped tables when there are rows", async () => {
    reply = () => Promise.resolve(ungrouped());
    render(<VrfInterfaces device={device()} />);
    expect(await screen.findByTestId("vrf-state-ready")).toBeTruthy();
    expect(screen.getByText("Ethernet1")).toBeTruthy();
  });
});

describe("VrfInterfaces — honesty about what is not collected", () => {
  it("shows the coverage strip and NEVER labels the bucket a default instance", async () => {
    reply = () => Promise.resolve(ungrouped());
    render(<VrfInterfaces device={device()} />);
    const strip = await screen.findByTestId("vrf-coverage");
    expect(strip.textContent).toMatch(/not collected/i);
    expect(strip.textContent).toMatch(/not as members of a default VRF/);
    // Nothing anywhere in the panel presents a "default" group as real.
    const panel = screen.getByTestId("vrf-interfaces");
    expect(panel.textContent).not.toMatch(/VRF default\b/);
  });

  it("renders an unmeasured counter as an em dash and a measured zero as 0/s", async () => {
    reply = () => Promise.resolve(ungrouped("VRF", [
      iface("Ethernet1", { in_errors_per_s: 0, out_errors_per_s: null }),
    ]));
    render(<VrfInterfaces device={device()} />);
    await screen.findByTestId("vrf-state-ready");
    const row = screen.getByText("Ethernet1").closest("tr")!;
    const cells = Array.from(row.querySelectorAll("td")).map((c) => c.textContent);
    expect(cells).toContain("0/s"); // measured: clean
    expect(cells).toContain("—");   // not measured: unknown
  });

  it("names the routing instances the control plane reports, without claiming membership", async () => {
    const base = ungrouped();
    reply = () => Promise.resolve({
      ...base,
      routing_instances: [{ name: "CORP-WAN", source: "bgp_control_plane" }],
    });
    render(<VrfInterfaces device={device()} />);
    const strip = await screen.findByTestId("vrf-coverage");
    expect(strip.textContent).toContain("CORP-WAN");
    expect(strip.textContent).toMatch(/not its interface membership/);
  });

  it("footnotes an unrecognized vendor rather than presenting the default word as an identification", async () => {
    const base = ungrouped();
    reply = () => Promise.resolve({
      ...base,
      dialect: { ...base.dialect, vendor: "acme-os", vendor_known: false },
    });
    render(<VrfInterfaces device={device()} />);
    expect((await screen.findByTestId("vrf-coverage")).textContent)
      .toMatch(/No vendor profile matched "acme-os"/);
  });
});

describe("VrfInterfaces — dialect per vendor", () => {
  const cases: [string, string][] = [
    ["VRF", "Interfaces by VRF"],
    ["routing-instance", "Interfaces by routing-instance"],
    ["VPRN", "Interfaces by VPRN"],
    ["VPN instance", "Interfaces by VPN instance"],
  ];
  for (const [term, heading] of cases) {
    it(`titles the panel "${heading}" and heads the bucket in the same word`, async () => {
      reply = () => Promise.resolve(ungrouped(term));
      render(<VrfInterfaces device={device()} />);
      expect(await screen.findByText(heading)).toBeTruthy();
      expect(screen.getByText(`${term} membership not collected on this transport`)).toBeTruthy();
      cleanup();
    });
  }

  it("groups real instances under the vendor's word when the label IS collected", async () => {
    const base = ungrouped("routing-instance");
    reply = () => Promise.resolve({
      ...base,
      coverage: {
        ...base.coverage, vrf_labels: true, in_groups: 1, ungrouped: 0,
        transport: "gnmi", transport_inferred: false, notes: [],
      },
      groups: [{
        vrf: "CORP-WAN", label: "CORP-WAN", membership: "observed",
        count: 1, up: 1, down: 0, unknown: 0, members: [iface("ge-0/0/0", { vrf: "CORP-WAN" })],
      }],
    });
    render(<VrfInterfaces device={device()} />);
    expect(await screen.findByText("routing-instance CORP-WAN")).toBeTruthy();
    expect(screen.getByTestId("vrf-coverage").textContent).not.toMatch(/not collected/i);
  });
});

describe("VrfInterfaces — controls", () => {
  it("collapses and expands a group", async () => {
    reply = () => Promise.resolve(ungrouped());
    render(<VrfInterfaces device={device()} />);
    await screen.findByTestId("vrf-state-ready");
    const toggle = screen.getByRole("button", { expanded: true });
    fireEvent.click(toggle);
    await waitFor(() => expect(screen.queryByText("Ethernet1")).toBeNull());
    fireEvent.click(screen.getByRole("button", { expanded: false }));
    expect(await screen.findByText("Ethernet1")).toBeTruthy();
  });

  it("re-reads with the chosen rate window", async () => {
    reply = () => Promise.resolve(ungrouped());
    render(<VrfInterfaces device={device()} />);
    await screen.findByTestId("vrf-state-ready");
    expect(lastCall()).toEqual(["core-1", "5m"]);
    fireEvent.click(screen.getByRole("button", { name: "1 hour" }));
    await waitFor(() => expect(lastCall()).toEqual(["core-1", "1h"]));
  });
});
