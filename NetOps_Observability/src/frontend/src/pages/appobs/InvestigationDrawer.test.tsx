// InvestigationDrawer.test — the close/verification loop renders ONLY what the
// engine's recovery assessment earned: verified-clear enables a plain close; any
// weaker state demands an explicit, labeled override; absent recovery data says
// "not yet observable" (never implied-clear); a recorded close shows WHO.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor, cleanup } from "@testing-library/react";

const h = vi.hoisted(() => ({
  mock: {
    rcaReportJson: vi.fn(async (): Promise<any> => ({ states: {}, times: {} })),
    correlationTimeEvents: vi.fn(async (): Promise<any> => ({ events: [] })),
    correlationTimeEventSet: vi.fn(async (_id: string, body: any): Promise<any> => ({
      id: "ev1", correlation_id: "c1", event_type: "closed",
      event_time: body.event_time, timestamp_source: "user_entered", confidence: 1,
      source_system: "manual", note: "server-labeled note", created_at: body.event_time,
      created_by: "noc-op",
    })),
  },
}));
vi.mock("../../services/api", () => ({ api: h.mock }));
// the RCA Inspector body is exercised by its own page/tests — stub it here.
vi.mock("../../tabs/Correlations", () => ({
  CorrelationDetail: ({ id }: { id: string }) => <div data-testid="corr-detail">{id}</div>,
}));
// the resolution action row has its own test file (ResolutionActions.test.tsx).
vi.mock("./ResolutionActions", () => ({
  default: ({ id }: { id: string }) => <div data-testid="resolution-actions">{id}</div>,
}));
// so does the change→incident card (InvestigationChanges.test.tsx).
vi.mock("./InvestigationChanges", () => ({
  default: ({ id }: { id: string }) => <div data-testid="investigation-changes">{id}</div>,
}));

import InvestigationDrawer, {
  InvestigationVerification, deriveVerify, parseReportTime, fmtClearFor,
} from "./InvestigationDrawer";

const mock = h.mock;
beforeEach(() => {
  Object.values(mock).forEach((m) => m.mockClear());
  mock.rcaReportJson.mockResolvedValue({ states: {}, times: {} });
  mock.correlationTimeEvents.mockResolvedValue({ events: [] });
});
afterEach(cleanup);

const verifiedReport = {
  states: {
    recovery: "explicitly_confirmed",
    recovery_basis: "2 recovery signals; last recovery evidence observed 2026-07-16 04:10:00 UTC.",
    monitoring: "active",
  },
  times: {
    recovered_at: "2026-07-16 04:10:00 UTC",
    monitoring_until: "2026-07-16 04:40:00 UTC",
  },
};

describe("deriveVerify (pure)", () => {
  it("maps engine recovery states honestly", () => {
    expect(deriveVerify(null).kind).toBe("unavailable");
    expect(deriveVerify({ states: {} }).kind).toBe("not_observable");
    expect(deriveVerify({ states: { recovery: "not_observed" } }).kind).toBe("not_observable");
    expect(deriveVerify({ states: { recovery: "failed_validation" } }).kind).toBe("signal_present");
    expect(deriveVerify({ states: { recovery: "component_only" } }).kind).toBe("component_only");
    expect(deriveVerify({ states: { recovery: "inferred" } }).kind).toBe("inferred");
    expect(deriveVerify(verifiedReport as any).kind).toBe("verified_clear");
  });
  it("parses the report's UTC times and formats clear-for durations", () => {
    const t = parseReportTime("2026-07-16 04:10:00 UTC")!;
    expect(t.toISOString()).toBe("2026-07-16T04:10:00.000Z");
    expect(parseReportTime(undefined)).toBeUndefined();
    expect(fmtClearFor(t, new Date(t.getTime() + 12 * 60000))).toBe("12 min");
    expect(fmtClearFor(t, new Date(t.getTime() + 95 * 60000))).toBe("1 h 35 min");
  });
});

describe("verification-gated close", () => {
  it("verified-clear: recovery banner + clear-for + close WITHOUT override", async () => {
    mock.rcaReportJson.mockResolvedValue(verifiedReport);
    render(<InvestigationVerification id="c1" />);
    await screen.findByText("Recovered — signal verified clear");
    expect(screen.getByText(/signal clear for/)).toBeTruthy();
    // no override checkbox on a verified-clear close
    expect(screen.queryByRole("checkbox")).toBeNull();
    const btn = screen.getByRole("button", { name: /verified clear/i });
    expect((btn as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(btn);
    await waitFor(() => expect(mock.correlationTimeEventSet).toHaveBeenCalledTimes(1));
    expect(mock.correlationTimeEventSet.mock.calls[0][1]).toMatchObject({
      event_type: "closed", verification: "verified_clear",
    });
    // the recorded close shows WHO
    await screen.findByText("noc-op");
  });

  it("no recovery data: says 'not yet observable' and gates close behind a labeled override", async () => {
    mock.rcaReportJson.mockResolvedValue({ states: { recovery: "not_observed" }, times: {} });
    render(<InvestigationVerification id="c1" />);
    await screen.findByText("Recovery not yet observable");
    const btn = screen.getByRole("button", { name: /close with override/i }) as HTMLButtonElement;
    expect(btn.disabled).toBe(true); // never a silent override
    // the override is explicit + labeled
    const box = screen.getByRole("checkbox");
    expect(screen.getByText(/recorded as an explicit override/i)).toBeTruthy();
    fireEvent.click(box);
    expect(btn.disabled).toBe(false);
    fireEvent.click(btn);
    await waitFor(() => expect(mock.correlationTimeEventSet).toHaveBeenCalledTimes(1));
    expect(mock.correlationTimeEventSet.mock.calls[0][1]).toMatchObject({
      verification: "override_recovery_unobserved",
    });
  });

  it("signal still present: override records override_signal_present", async () => {
    mock.rcaReportJson.mockResolvedValue({
      states: { recovery: "failed_validation", recovery_basis: "Checks continued failing." }, times: {},
    });
    render(<InvestigationVerification id="c1" />);
    await screen.findByText("Signal still present");
    expect(screen.getByText("Checks continued failing.")).toBeTruthy();
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: /close with override/i }));
    await waitFor(() => expect(mock.correlationTimeEventSet).toHaveBeenCalledTimes(1));
    expect(mock.correlationTimeEventSet.mock.calls[0][1]).toMatchObject({
      verification: "override_signal_present",
    });
  });

  it("an already-recorded close renders WHO + the labeled note and offers no close button", async () => {
    mock.correlationTimeEvents.mockResolvedValue({
      events: [{
        id: "e1", correlation_id: "c1", event_type: "closed",
        event_time: "2026-07-16T04:20:00Z", timestamp_source: "user_entered",
        confidence: 1, source_system: "manual",
        note: "Override — closed while the signal was still present; recovery validation had failed.",
        created_at: "2026-07-16T04:20:00Z", created_by: "alice",
      }],
    });
    render(<InvestigationVerification id="c1" />);
    await screen.findByText("alice");
    expect(screen.getByText(/Override — closed while the signal was still present/)).toBeTruthy();
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("report unavailable never implies clear", async () => {
    mock.rcaReportJson.mockRejectedValue(new Error("500"));
    render(<InvestigationVerification id="c1" />);
    await screen.findByText("Recovery status unavailable");
    expect(screen.queryByText(/verified clear/i)).toBeNull();
  });
});

describe("drawer content", () => {
  it("keeps the full-analysis escape hatch and embeds the real inspector", async () => {
    render(<InvestigationDrawer id="11111111-2222-3333-4444-555555555555" />);
    const link = await screen.findByRole("link", { name: /open full analysis/i });
    expect(link.getAttribute("href")).toContain("#/monitoring/correlations?id=");
    expect(screen.getByTestId("corr-detail").textContent).toBe("11111111-2222-3333-4444-555555555555");
  });
});
