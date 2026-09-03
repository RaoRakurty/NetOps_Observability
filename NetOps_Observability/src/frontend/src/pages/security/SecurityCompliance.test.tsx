// SecurityCompliance.test.tsx — the Frameworks view. The vocabulary is the
// point: this page reports which frameworks THIS TENANT is assessed against and
// the control evidence behind each, and it must never claim certified
// compliance, never show a percentage for something nobody assessed, and never
// list a CIS device benchmark as a framework.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, within } from "@testing-library/react";

const securityFrameworks = vi.fn();
const securityFrameworksUpdate = vi.fn();
const securityCompliance = vi.fn();
const securityFindings = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    securityFrameworks: (...a: unknown[]) => securityFrameworks(...a),
    securityFrameworksUpdate: (...a: unknown[]) => securityFrameworksUpdate(...a),
    securityCompliance: (...a: unknown[]) => securityCompliance(...a),
    securityFindings: (...a: unknown[]) => securityFindings(...a),
  },
}));
vi.mock("../ComplianceMonitoring", () => ({ default: () => <div>drift board</div> }));

import SecurityCompliance from "./SecurityCompliance";
import { COMPLIANCE, FRAMEWORK_CATALOG, UNASSESSED_PAGE } from "./fixtures";

afterEach(cleanup);
beforeEach(() => {
  securityFrameworks.mockReset();
  securityFrameworksUpdate.mockReset();
  securityCompliance.mockReset();
  securityFindings.mockReset();
  securityFrameworks.mockResolvedValue(FRAMEWORK_CATALOG);
  securityFrameworksUpdate.mockResolvedValue({ ...FRAMEWORK_CATALOG, configured: true });
  securityCompliance.mockResolvedValue(COMPLIANCE);
  securityFindings.mockResolvedValue(UNASSESSED_PAGE);
});

describe("Compliance — framework selection", () => {
  it("lists only the frameworks this tenant runs, and says the default set is a default", async () => {
    render(<SecurityCompliance />);
    const inUse = await screen.findByRole("list", { name: /frameworks in use/i });
    expect(within(inUse).getByText("NIST SP 800-53 Rev5")).toBeTruthy();
    expect(within(inUse).getByText("CIS Controls v8.1")).toBeTruthy();
    // The regulatory frameworks are NOT run until somebody adds them.
    expect(within(inUse).queryByText("HIPAA Security Rule")).toBeNull();
    expect(within(inUse).queryByText("PCI DSS v4.0.1")).toBeNull();
    expect(screen.queryByRole("list", { name: /frameworks available to add/i })).toBeNull();
    expect(screen.getByText(/shipped default set is shown/i)).toBeTruthy();
  });

  it("offers the opt-in frameworks behind 'Add framework' and saves only what changed", async () => {
    render(<SecurityCompliance />);
    fireEvent.click(await screen.findByRole("button", { name: /add framework/i }));
    fireEvent.click(screen.getByRole("checkbox", { name: /HIPAA Security Rule enabled/i }));
    fireEvent.click(screen.getByRole("button", { name: /save selection/i }));
    await screen.findByText(/1 framework updated/i);
    expect(securityFrameworksUpdate).toHaveBeenCalledWith([
      { framework_id: "hipaa-security-rule", enabled: true },
    ]);
  });

  it("a framework with nothing assessed says so — never 0% and never 100%", async () => {
    render(<SecurityCompliance />);
    const card = await screen.findByRole("button", { name: /CIS Controls v8\.1/i });
    expect(within(card).getByText(/not assessed/i)).toBeTruthy();
    expect(within(card).queryByText("0%")).toBeNull();
    expect(within(card).queryByText("100%")).toBeNull();
  });

  it("scores the base framework over its own assessed controls and captions the claim", async () => {
    render(<SecurityCompliance />);
    const card = await screen.findByRole("button", { name: /NIST SP 800-53 Rev5/i });
    expect(within(card).getByText("50%")).toBeTruthy();      // 1 pass of 2 assessed
    expect(screen.getByText(/not certified compliance/i)).toBeTruthy();
  });

  it("shows a benchmark section as a citation INSIDE the control row, never as a framework", async () => {
    render(<SecurityCompliance />);
    const table = await screen.findByRole("table", { name: /NIST SP 800-53 Rev5 controls/i });
    const row = within(table).getAllByText("AC-17")[0].closest("tr")!;
    expect(within(row).getByText(/CIS Cisco IOS XE 17\.x Benchmark v2\.2\.1 §1\.2 Access Rules/)).toBeTruthy();
    // …and it is not offered as something to enable.
    expect(screen.queryByRole("checkbox", { name: /Benchmark enabled/i })).toBeNull();
  });

  it("a control this platform cannot evidence is named, not silently passed", async () => {
    render(<SecurityCompliance />);
    const table = await screen.findByRole("table", { name: /NIST SP 800-53 Rev5 controls/i });
    const row = within(table).getByText("SI-7").closest("tr")!;
    expect(within(row).getByText(/no check for this control/i)).toBeTruthy();
    expect(within(row).getByText("Unassessed")).toBeTruthy();
  });

  it("keeps the existing drift board as a sub-view rather than replacing it", async () => {
    render(<SecurityCompliance />);
    await screen.findByRole("list", { name: /frameworks in use/i });
    fireEvent.click(screen.getByRole("button", { name: "Drift & baselines" }));
    expect(screen.getByText("drift board")).toBeTruthy();
  });
});

// ── §5g: the compliance reader is told WHY a control has no verdict ─────────
//
// A passing share says nothing about the controls that reached no conclusion,
// and on the lab stack (2026-09-03) that was ALL of them. This panel names the
// reasons in the producer's own words so "unassessed" is actionable rather than
// a grey nothing.

describe("Compliance — unassessed controls and why", () => {
  it("groups the unassessed current verdicts by the reason the provider gave", async () => {
    render(<SecurityCompliance />);
    const list = await screen.findByRole("list", { name: /unassessed controls by reason/i });
    const rows = within(list).getAllByRole("listitem");
    // Commonest reason first, with its count.
    expect(rows[0].textContent).toContain("running-config unavailable — control not assessed (fail-closed)");
    expect(rows[0].textContent).toContain("2 controls");
    expect(list.textContent).toContain("SR Linux has no telnet server in its model");
    expect(list.textContent).toContain("unassessed: platform unresolved");
    expect(rows.some((r) => /1 control$/.test(r.textContent ?? ""))).toBe(true);
  });

  it("names a missing reason as missing rather than dropping the finding", async () => {
    render(<SecurityCompliance />);
    const list = await screen.findByRole("list", { name: /unassessed controls by reason/i });
    expect(within(list).getByText(/No reason recorded/i)).toBeTruthy();
  });

  it("says the unassessed are counted in NO passing share — unknown, not compliant", async () => {
    render(<SecurityCompliance />);
    await screen.findByRole("list", { name: /unassessed controls by reason/i });
    expect(screen.getByText(/an unassessed control is UNKNOWN, not compliant/i)).toBeTruthy();
  });

  it("asks the server for the unassessed statuses only, over current verdicts", async () => {
    render(<SecurityCompliance />);
    await screen.findByRole("list", { name: /unassessed controls by reason/i });
    const q = securityFindings.mock.calls[0][0];
    expect(q.current).toBe(true);
    expect(q.status).toBe("unknown,not_applicable,error");
  });

  it("a failure to load the reasons is stated, never rendered as 'none unassessed'", async () => {
    // A developer-shaped failure: operatorError substitutes the caller's own
    // description rather than showing the wrap chain.
    securityFindings.mockRejectedValue(new Error("500 Internal Server Error: {\"error\":\"opensearch: dial tcp 10.0.0.9:9200: connect: connection refused\"}"));
    render(<SecurityCompliance />);
    await screen.findByRole("table", { name: /NIST SP 800-53 Rev5 controls/i });
    // operatorError turns the wrap chain into an operator sentence; what this
    // test pins is that the panel raises an ALERT and never falls back to the
    // "nothing was unassessed" empty state, which would be a false clear.
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/did not answer|could not be loaded/i);
    expect(screen.queryByText(/no control reached this scan without a verdict/i)).toBeNull();
    expect(screen.queryByRole("list", { name: /unassessed controls by reason/i })).toBeNull();
    // …and the scores are unaffected: the two loads are independent.
    expect(screen.getByRole("table", { name: /NIST SP 800-53 Rev5 controls/i })).toBeTruthy();
  });

  it("an estate with nothing unassessed says exactly that", async () => {
    securityFindings.mockResolvedValue({ items: [], next_cursor: null, total: 0 });
    render(<SecurityCompliance />);
    expect(await screen.findByText(/no control reached this scan without a verdict/i)).toBeTruthy();
  });
});
