// TransportSecurity.test.tsx — the SEC-021.1 read-only posture view: the
// platform owner sees the full path inventory (drift disclosed, export
// offered); a tenant admin sees only its device lanes (no export); a 503
// inventory outage renders the error, never an empty-but-green table.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, waitFor } from "@testing-library/react";
import { fmtDate } from "../lib/time";
import type { PostureRow, TransportPosture } from "../services/api";

const transportPosture = vi.fn();
const exportTransportPosture = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    transportPosture: (...a: unknown[]) => transportPosture(...a),
    exportTransportPosture: (...a: unknown[]) => exportTransportPosture(...a),
  },
}));

import TransportSecurity from "./TransportSecurity";

const baseRow: PostureRow = {
  edge: "api→postgres",
  source: "api",
  destination: "postgres",
  channel: "sql",
  protocol: "tcp",
  port: 5432,
  trust_domain: "internal",
  owning_epic: "SEC-002",
  current_tier: "mtls",
  declared_tier: "mtls",
  target_tier: "mtls",
  identity: "CN=api.internal",
  observed: { probe_ok: true, cert_not_after: "2027-01-15T00:00:00Z", last_checked: "2026-08-06T10:00:00Z" },
};

const driftRow: PostureRow = {
  ...baseRow,
  edge: "router→valkey",
  destination: "valkey",
  channel: "resp",
  port: 6379,
  identity: "CN=router.internal",
  observed: null,
  drift: "declared tls, running plaintext",
};

const exceptionRow: PostureRow = {
  ...baseRow,
  edge: "collector→device",
  destination: "device",
  channel: "snmp",
  port: 161,
  trust_domain: "device",
  identity: undefined,
  observed: { probe_ok: false },
  exception: { owner: "rao", accepted: "2026-07-01T00:00:00Z", reason: "SNMPv2 fleet, retirement tracked" },
  exception_age_days: 36,
};

const platformPosture: TransportPosture = {
  scope: "platform",
  generated: "2026-08-06T11:00:00Z",
  rows: [baseRow, driftRow, exceptionRow],
  validator: { profile: "strict", findings: [], fatal: 1, warn: 2, info: 0 },
};

const tenantPosture: TransportPosture = {
  scope: "tenant",
  generated: "2026-08-06T11:00:00Z",
  device_lanes: [exceptionRow],
  device_count: 42,
};

afterEach(cleanup);
beforeEach(() => {
  vi.clearAllMocks();
});

describe("TransportSecurity — platform scope", () => {
  beforeEach(() => transportPosture.mockResolvedValue(platformPosture));

  it("renders the path inventory rows with the probe verdict per path", async () => {
    render(<TransportSecurity />);
    await waitFor(() => expect(transportPosture).toHaveBeenCalled());

    expect(await screen.findByText("api→postgres")).toBeInTheDocument();
    expect(screen.getByText("router→valkey")).toBeInTheDocument();
    expect(screen.getByText("collector→device")).toBeInTheDocument();
    // Peer identity column is present in platform scope.
    expect(screen.getByText("Peer identity")).toBeInTheDocument();
    expect(screen.getByText("CN=api.internal")).toBeInTheDocument();
    // Observed: probed-with-cert vs unprobed vs certless — all three honest.
    expect(screen.getByText(`cert ok, expires ${fmtDate("2027-01-15T00:00:00Z")}`)).toBeInTheDocument();
    expect(screen.getByText("not probed")).toBeInTheDocument();
    expect(screen.getByText("No certificate presented")).toBeInTheDocument();
    // The device-domain row is labelled as a device lane.
    expect(screen.getByText("device lane")).toBeInTheDocument();
  });

  it("discloses drift in a warning badge and exceptions with owner/date/age/reason", async () => {
    render(<TransportSecurity />);
    const drift = await screen.findByText("declared tls, running plaintext");
    expect(drift).toHaveClass("badge", "warn");
    expect(screen.getByText(new RegExp(`rao, accepted ${fmtDate("2026-07-01T00:00:00Z")}, 36d, SNMPv2 fleet`))).toBeInTheDocument();
  });

  it("renders the stat row (paths, drifting, exceptions, validator fatal/warn) and the export button", async () => {
    render(<TransportSecurity />);
    await screen.findByText("api→postgres");
    expect(screen.getByText("Paths")).toBeInTheDocument();
    expect(screen.getByText("Drifting")).toBeInTheDocument();
    expect(screen.getByText("Exceptions")).toBeInTheDocument();
    expect(screen.getByText("Critical problems")).toBeInTheDocument();
    expect(screen.getByText("Warnings")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Export report (HTML)" })).toBeInTheDocument();
  });
});

describe("TransportSecurity — tenant scope", () => {
  beforeEach(() => transportPosture.mockResolvedValue(tenantPosture));

  it("renders the device count, the lanes, and the platform-only explainer — with NO export button", async () => {
    render(<TransportSecurity />);
    expect(await screen.findByText("Your fleet: 42 devices")).toBeInTheDocument();
    expect(screen.getByText("collector→device")).toBeInTheDocument();
    // The identity column is platform-only.
    expect(screen.queryByText("Peer identity")).toBeNull();
    expect(screen.getByText(/Platform-internal transport paths are visible to platform administrators only/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Export report (HTML)" })).toBeNull();
  });
});

describe("TransportSecurity — failed load", () => {
  it("renders the backend error (503 inventory outage), not a loading or empty state", async () => {
    transportPosture.mockRejectedValue(new Error("transport inventory unavailable (503)"));
    render(<TransportSecurity />);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("transport inventory unavailable (503)");
    expect(screen.queryByText(/Loading transport posture/)).toBeNull();
    expect(screen.queryByRole("button", { name: "Export report (HTML)" })).toBeNull();
  });
});
