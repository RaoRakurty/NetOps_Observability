// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Administration → Discovery (owner 2026-10-18): five pages in one, in setup
// order. The contract:
//   1. Tenant isolation, UI half — Sensors (requireCrossTenant, switches
//      requirePlatformAdmin) is neither rendered nor MOUNTED for a tenant,
//      even when a deep link names it. The server gate stays the boundary.
//   2. A closed section is not mounted, so the hub does not start five
//      refresh loops at once.
//   3. Deep links open their section; a bare #/admin/discovery opens Network
//      Scan, the page the old leaf at this address was.
import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, act } from "@testing-library/react";

const mockUseAuth = vi.fn();
vi.mock("../../hooks/useAuth", () => ({ useAuth: (...a: unknown[]) => mockUseAuth(...a) }));

// Each section is the page it replaces; here a marker that records it mounted
// (the real pages fetch on mount, so "mounted" is "fetched").
const { mounted, marker, boom } = vi.hoisted(() => {
  const mounted: string[] = [];
  const boom = { section: "" };
  const marker = (name: string) => () => {
    mounted.push(name);
    if (boom.section === name) throw new Error(`${name} exploded`);
    return <div data-testid={`page-${name}`}>{name}</div>;
  };
  return { mounted, marker, boom };
});
vi.mock("../../tabs/SnmpProfileManager", () => ({ default: marker("snmp") }));
vi.mock("../SubnetDiscovery", () => ({ default: marker("scan") }));
vi.mock("../../tabs/Collectors", () => ({ default: marker("sensors") }));
vi.mock("../DataSources", () => ({ default: marker("coverage") }));
vi.mock("../telemetry/TelemetryCoverage", () => ({ default: marker("telemetry") }));
vi.mock("../../components/AskIris", () => ({ default: () => null }));

import DiscoveryHub, { sectionFromHash, visibleSections } from "./DiscoveryHub";

const PLATFORM = { user: { username: "root", platform_admin: true }, loading: false };
const TENANT = { user: { username: "ops", platform_admin: false }, loading: false };

function at(hash: string) {
  window.location.hash = hash;
}

afterEach(() => {
  cleanup();
  mounted.length = 0;
  boom.section = "";
  at("");
});

describe("DiscoveryHub", () => {
  it("lists the sections in setup order, numbered", () => {
    mockUseAuth.mockReturnValue(PLATFORM);
    at("#/admin/discovery");
    render(<DiscoveryHub />);
    expect(screen.getByText("1. SNMP Profiles")).toBeTruthy();
    expect(screen.getByText("2. Network Scan")).toBeTruthy();
    expect(screen.getByText("3. Sensors")).toBeTruthy();
    expect(screen.getByText("4. Collection Coverage")).toBeTruthy();
    expect(screen.getByText("5. Telemetry Coverage")).toBeTruthy();
  });

  it("a bare address opens Network Scan and mounts nothing else", () => {
    mockUseAuth.mockReturnValue(PLATFORM);
    at("#/admin/discovery");
    render(<DiscoveryHub />);
    expect(mounted).toEqual(["scan"]);
    expect(screen.getByRole("button", { name: /Network Scan/ }).getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByRole("button", { name: /SNMP Profiles/ }).getAttribute("aria-expanded")).toBe("false");
  });

  it("a deep link opens its section", () => {
    mockUseAuth.mockReturnValue(PLATFORM);
    at("#/admin/discovery/coverage");
    render(<DiscoveryHub />);
    expect(mounted).toEqual(["coverage"]);
  });

  it("opening a section mounts it; closing it unmounts it", () => {
    mockUseAuth.mockReturnValue(PLATFORM);
    at("#/admin/discovery");
    render(<DiscoveryHub />);
    fireEvent.click(screen.getByRole("button", { name: /SNMP Profiles/ }));
    expect(screen.getByTestId("page-snmp")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /SNMP Profiles/ }));
    expect(screen.queryByTestId("page-snmp")).toBeNull();
  });

  it("a sub-item clicked while already here opens that section", () => {
    mockUseAuth.mockReturnValue(PLATFORM);
    at("#/admin/discovery");
    render(<DiscoveryHub />);
    act(() => {
      at("#/admin/discovery/telemetry");
      window.dispatchEvent(new HashChangeEvent("hashchange"));
    });
    expect(screen.getByTestId("page-telemetry")).toBeTruthy();
  });

  it("a Sensors link read before sign-in resolves still opens Sensors for the platform administrator", () => {
    mockUseAuth.mockReturnValue({ user: null, loading: true });
    at("#/admin/discovery/sensors");
    const r = render(<DiscoveryHub />);
    expect(mounted).not.toContain("sensors"); // not yet known to be allowed
    mockUseAuth.mockReturnValue(PLATFORM);
    r.rerender(<DiscoveryHub />);
    expect(screen.getByTestId("page-sensors")).toBeTruthy();
    expect(screen.queryByTestId("page-scan")).toBeNull(); // the fallback did not linger
  });

  it("an old link's redirect landing after the first render opens ONLY its section", () => {
    mockUseAuth.mockReturnValue(PLATFORM);
    at("#/admin/snmp"); // the pre-merge address, before canonicalHash rewrites it
    render(<DiscoveryHub />);
    act(() => {
      at("#/admin/discovery/snmp");
      window.dispatchEvent(new HashChangeEvent("hashchange"));
    });
    expect(screen.getByTestId("page-snmp")).toBeTruthy();
    expect(screen.queryByTestId("page-scan")).toBeNull();
  });

  it("TENANT: Sensors is never rendered or mounted — not even by its own deep link", () => {
    mockUseAuth.mockReturnValue(TENANT);
    at("#/admin/discovery/sensors");
    render(<DiscoveryHub />);
    expect(screen.queryByText(/Sensors/)).toBeNull();
    expect(mounted).not.toContain("sensors");
    // The deep link falls back to Network Scan rather than a blank page.
    expect(mounted).toEqual(["scan"]);
    expect(screen.getByText("3. Collection Coverage")).toBeTruthy();
  });

  it("one section failing does not blank the page or the other sections", () => {
    mockUseAuth.mockReturnValue(PLATFORM);
    boom.section = "telemetry";
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    at("#/admin/discovery/telemetry");
    render(<DiscoveryHub />);
    expect(screen.getByText(/Telemetry Coverage could not be displayed/)).toBeTruthy();
    expect(screen.getByText("Discovery")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /SNMP Profiles/ }));
    expect(screen.getByTestId("page-snmp")).toBeTruthy();
    spy.mockRestore();
  });

  it("section routing helpers", () => {
    expect(visibleSections(false).map((s) => s.id)).toEqual(["snmp", "scan", "coverage", "telemetry"]);
    expect(visibleSections(true).map((s) => s.id)).toEqual(["snmp", "scan", "sensors", "coverage", "telemetry"]);
    expect(sectionFromHash("#/admin/discovery/sensors", true)).toBe("sensors");
    expect(sectionFromHash("#/admin/discovery/sensors", false)).toBe("scan");
    expect(sectionFromHash("#/admin/discovery/nope", true)).toBe("scan");
    expect(sectionFromHash("#/admin/discovery/snmp?x=1", false)).toBe("snmp");
  });
});
