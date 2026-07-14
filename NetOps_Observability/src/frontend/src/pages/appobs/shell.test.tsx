// shell.test.tsx — the trust chrome renders honest scope, freshness, data mode,
// and source status (#81 P3F+1). Acceptance: the header/strip never says "mock",
// scope shows tenant/provider/account/region/env, and unmeasured values render as
// "not measured" rather than a fabricated number.

import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { CloudScopeBar, DataModeChip, SourceStatusBadge, MeasuredValue } from "./shell";
import type { CloudScope, ReadinessSummary } from "./readiness";

afterEach(cleanup);

const scope: CloudScope = {
  tenant: "Retail-US", provider: "AWS", account: "123456789012",
  region: "us-east-1", env: "prod", timeRange: "Last 1h",
};
const summary: ReadinessSummary = {
  connectedAccounts: 1, flowing: 1, stale: 0, off: 10, permissionErrors: 0, partial: 0,
  lastSyncIso: "2026-06-25T12:00:00Z",
};

describe("CloudScopeBar", () => {
  it("renders tenant/provider/account/region/env/range", () => {
    render(<CloudScopeBar scope={scope} mode="demo" summary={summary} />);
    expect(screen.getByText("Retail-US")).toBeTruthy();
    expect(screen.getByText("AWS")).toBeTruthy();
    expect(screen.getByText("123456789012")).toBeTruthy();
    expect(screen.getByText("us-east-1")).toBeTruthy();
    expect(screen.getByText("prod")).toBeTruthy();
    expect(screen.getByText("Last 1h")).toBeTruthy();
  });
  it("handles an all-cloud / empty scope without crashing", () => {
    const empty: CloudScope = { tenant: "—", provider: "—", account: "—", region: "—", env: "—", timeRange: "Last 1h" };
    const emptySummary: ReadinessSummary = { connectedAccounts: 0, flowing: 0, stale: 0, off: 11, permissionErrors: 0, partial: 0 };
    render(<CloudScopeBar scope={empty} mode="empty" summary={emptySummary} />);
    expect(screen.getByText("No cloud data connected")).toBeTruthy();
  });
  it("never renders the word 'mock'", () => {
    const { container } = render(<CloudScopeBar scope={scope} mode="demo" summary={summary} />);
    expect(container.textContent?.toLowerCase()).not.toContain("mock");
  });
});

describe("DataModeChip", () => {
  it("labels each mode honestly and never says 'mock'", () => {
    for (const mode of ["live", "demo", "synthetic", "empty"] as const) {
      const { container } = render(<DataModeChip mode={mode} lastSyncIso="2026-06-25T12:00:00Z" />);
      expect(container.textContent?.toLowerCase()).not.toContain("mock");
      cleanup();
    }
  });
  it("live mode shows a freshness detail", () => {
    render(<DataModeChip mode="live" lastSyncIso={new Date().toISOString()} />);
    expect(screen.getByText(/Live telemetry/)).toBeTruthy();
  });
});

describe("SourceStatusBadge", () => {
  it("renders each status with a human label", () => {
    render(<SourceStatusBadge status="permission_denied" />);
    expect(screen.getByText("Permission denied")).toBeTruthy();
    cleanup();
    render(<SourceStatusBadge status="off" />);
    expect(screen.getByText("Not configured")).toBeTruthy();
    cleanup();
    render(<SourceStatusBadge status="not_supported" />);
    expect(screen.getByText("Coming soon")).toBeTruthy();
    cleanup();
    render(<SourceStatusBadge status="flowing" />);
    expect(screen.getByText("Flowing")).toBeTruthy();
  });
});

describe("MeasuredValue — honest empties", () => {
  it("renders the value when the source is flowing", () => {
    render(<MeasuredValue value={1234} status="flowing" fmt={(n) => `${n} req/s`} />);
    expect(screen.getByText("1234 req/s")).toBeTruthy();
  });
  it("renders 'not measured' when the source is off (not 0)", () => {
    const { container } = render(<MeasuredValue value={0} status="off" fmt={(n) => `${n} req/s`} />);
    expect(container.textContent).toContain("not measured");
    expect(container.textContent).not.toContain("req/s");
  });
  it("tags stale values as stale", () => {
    const { container } = render(<MeasuredValue value={500} status="stale" fmt={(n) => `${n} req/s`} />);
    expect(container.textContent).toContain("500 req/s");
    expect(container.textContent?.toLowerCase()).toContain("stale");
  });
});
