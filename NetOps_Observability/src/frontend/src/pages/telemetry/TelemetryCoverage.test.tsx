// TelemetryCoverage.test.tsx — the Administration → Data Collection coverage
// page. What is asserted here is the product contract, not the layout:
//   · the header stats read the parser rev / rules hash / promotion rate, and a
//     null rate is worded honestly.
//   · the rules table sorts by hits and filters.
//   · the unrecognized table renders escaped device text and every note state.
//   · the propose flow shows the YAML as TEXT — a row containing <script> is
//     escaped, never parsed (§15 LLM02 / §3 zero trust).
//   · a 403 on the platform-only stats endpoint is a "platform-admin only"
//     card, never an error (§3a).

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor, within, fireEvent } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const parserStats = vi.fn();
const unrecognizedTemplates = vi.fn();
const proposeCatalogRow = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    parserStats: (...a: unknown[]) => parserStats(...a),
    unrecognizedTemplates: (...a: unknown[]) => unrecognizedTemplates(...a),
    proposeCatalogRow: (...a: unknown[]) => proposeCatalogRow(...a),
  },
}));

const openInspector = vi.fn();
let wsEnabled = false;
vi.mock("../../context/workspace", () => ({
  useWorkspace: () => ({ enabled: wsEnabled, openInspector }),
  INS_MIN: 280,
}));

import TelemetryCoverage from "./TelemetryCoverage";
import {
  parserStatsFixture,
  parserStatsNoLinesFixture,
  proposalFixture,
  unrecognizedFixture,
  unrecognizedNotMinedFixture,
} from "./fixtures";

const forbidden = () => new Error("403 Forbidden: platform admin required");

afterEach(cleanup);
beforeEach(() => {
  vi.clearAllMocks();
  wsEnabled = false;
  parserStats.mockResolvedValue(parserStatsFixture);
  unrecognizedTemplates.mockResolvedValue(unrecognizedFixture);
  proposeCatalogRow.mockResolvedValue(proposalFixture);
});

const ruleRowsOf = (c: HTMLElement) =>
  Array.from(c.querySelectorAll('[aria-label="Parser rules"] .dtv-row')) as HTMLElement[];
const shapeRowsOf = (c: HTMLElement) =>
  Array.from(c.querySelectorAll('[aria-label="Unrecognized message shapes"] .dtv-row')) as HTMLElement[];

describe("header stats", () => {
  it("shows the parser rev and rules hash in mono, plus the prefilter and fallback counts", async () => {
    const { container } = render(<TelemetryCoverage />);
    const rev = await screen.findByText("parser-2026.09.02-a6");
    expect(rev).toHaveClass("mono");
    expect(screen.getByText("sha256:9f3c1b7ad2e5")).toHaveClass("mono");

    expect(screen.getByText("Semantic promotion rate")).toBeInTheDocument();
    expect(screen.getByText("81.3%")).toBeInTheDocument();
    expect(screen.getByText("over the last 240,000 admitted lines")).toBeInTheDocument();

    expect(screen.getByText("Prefilter passed")).toBeInTheDocument();
    expect(screen.getByText("Prefilter rejected")).toBeInTheDocument();
    expect(screen.getByText("18,422")).toBeInTheDocument();
    expect(screen.getByText("Generic fallback (syslog)")).toBeInTheDocument();
    expect(screen.getByText("Generic fallback (trap)")).toBeInTheDocument();
    expect(screen.getByText("1,204")).toBeInTheDocument();
    expect(screen.getByText("87")).toBeInTheDocument();
    expect(ruleRowsOf(container).length).toBe(5);
  });

  it("words a null promotion rate as 'no admitted lines yet' rather than 0%", async () => {
    parserStats.mockResolvedValue(parserStatsNoLinesFixture);
    const { container } = render(<TelemetryCoverage />);
    expect(await screen.findByText("no admitted lines yet")).toBeInTheDocument();
    expect(container.querySelector(".ds-stat-num")?.textContent).toBe("—");
    expect(screen.queryByText("0.0%")).toBeNull();
  });
});

describe("rules table", () => {
  it("renders one row per rule with a fidelity badge coloured by tier and a shadow chip", async () => {
    const { container } = render(<TelemetryCoverage />);
    await screen.findByText("cisco.ios.link_updown");

    expect(screen.getAllByText("live validated")[0]).toHaveClass("badge", "tier-t1");
    expect(screen.getByText("lab validated")).toHaveClass("badge", "tier-t3");
    expect(screen.getByText("doc claimed")).toHaveClass("badge", "tier-t4");
    expect(screen.getByText("code")).toHaveClass("badge", "tier-t5");
    expect(screen.getAllByText("shadow").length).toBe(2);
    expect(ruleRowsOf(container).length).toBe(5);
  });

  it("sorts by hits — descending by default, ascending when the header is clicked", async () => {
    const { container } = render(<TelemetryCoverage />);
    await screen.findByText("cisco.ios.link_updown");

    expect(ruleRowsOf(container)[0].textContent).toContain("cisco.ios.link_updown"); // 9,120 hits
    fireEvent.click(screen.getByText("Hits"));
    await waitFor(() => expect(ruleRowsOf(container)[0].textContent).toContain("port.optic_rx_low")); // 5 hits
  });

  it("filters the rule inventory from the filter box", async () => {
    const { container } = render(<TelemetryCoverage />);
    await screen.findByText("cisco.ios.link_updown");

    fireEvent.change(screen.getByLabelText("Filter rules"), { target: { value: "trap" } });
    await waitFor(() => expect(ruleRowsOf(container).length).toBe(1));
    expect(ruleRowsOf(container)[0].textContent).toContain("snmp.linkDown");

    fireEvent.change(screen.getByLabelText("Filter rules"), { target: { value: "nothing-matches" } });
    await waitFor(() => expect(ruleRowsOf(container).length).toBe(0));
    expect(screen.getByText(/No parser rules are registered/)).toBeInTheDocument();
  });
});

describe("unrecognized message shapes", () => {
  it("renders the masked template in mono with count, devices, severity and sample", async () => {
    const { container } = render(<TelemetryCoverage />);
    const tpl = await screen.findByText("%LINK-3-UPDOWN: Interface <*>, changed state to <*>");
    expect(tpl).toHaveClass("mono");
    expect(screen.getByText("812")).toBeInTheDocument();
    expect(screen.getByText("14")).toBeInTheDocument();
    expect(screen.getByText("error")).toHaveClass("badge", "sev-error");
    expect(screen.getByText("notice")).toHaveClass("badge", "sev-notice");
    expect(screen.getByText(/GigabitEthernet0\/3, changed state to down/)).toBeInTheDocument();
    expect(shapeRowsOf(container).length).toBe(2);
    expect(screen.getByText("2 shapes over the last 7 days.")).toBeInTheDocument();
  });

  it("asks for the contracted window and honours the lane filter", async () => {
    render(<TelemetryCoverage />);
    await waitFor(() => expect(unrecognizedTemplates).toHaveBeenCalledWith({ days: 7, limit: 50 }));

    fireEvent.click(screen.getByRole("button", { name: "Trap" }));
    await waitFor(() =>
      expect(unrecognizedTemplates).toHaveBeenLastCalledWith({ days: 7, limit: 50, lane: "trap" }));
  });

  it("renders the backend's honest note when nothing has been mined yet", async () => {
    unrecognizedTemplates.mockResolvedValue(unrecognizedNotMinedFixture);
    const { container } = render(<TelemetryCoverage />);
    await waitFor(() => expect(screen.getAllByText("mining not yet run").length).toBeGreaterThan(0));
    expect(shapeRowsOf(container).length).toBe(0);
  });

  it("says the window is clean when the list is empty with no note", async () => {
    unrecognizedTemplates.mockResolvedValue({ ...unrecognizedNotMinedFixture, note: undefined });
    render(<TelemetryCoverage />);
    await waitFor(() =>
      expect(screen.getAllByText("No unrecognized message shapes in the last 7 days.").length).toBeGreaterThan(0));
  });

  it("surfaces a load failure as an alert instead of an empty-but-green table", async () => {
    unrecognizedTemplates.mockRejectedValue(new Error("503 Service Unavailable: miner down"));
    render(<TelemetryCoverage />);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("503 Service Unavailable: miner down");
  });
});

describe("draft catalog row", () => {
  it("calls propose for the row's template and shows the YAML + fixture read-only", async () => {
    render(<TelemetryCoverage />);
    await screen.findByText("%LINK-3-UPDOWN: Interface <*>, changed state to <*>");

    fireEvent.click(screen.getAllByRole("button", { name: "Draft catalog row" })[0]);
    await waitFor(() => expect(proposeCatalogRow).toHaveBeenCalledWith("t-0001"));

    const yaml = await screen.findByText(/rule_id: cisco\.link_updown_draft/);
    expect(yaml.tagName).toBe("CODE");
    expect(yaml.closest("pre")).not.toBeNull();
    expect(screen.getByText("Draft catalog row (YAML)")).toBeInTheDocument();
    expect(screen.getByText("Fixture")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy Draft catalog row (YAML)" })).toBeInTheDocument();
    expect(screen.getByText(/land a catalog row via a pull request/i).closest("a")?.getAttribute("href"))
      .toMatch(/^https:\/\//);
    expect(screen.getByText(/Nothing has been\s+applied/)).toBeInTheDocument();
  });

  it("hands the draft to the Inspector when the workspace shell is enabled", async () => {
    wsEnabled = true;
    render(<TelemetryCoverage />);
    await screen.findByText("%LINK-3-UPDOWN: Interface <*>, changed state to <*>");
    fireEvent.click(screen.getAllByRole("button", { name: "Draft catalog row" })[0]);
    await waitFor(() => expect(openInspector).toHaveBeenCalled());
    expect(openInspector.mock.calls[0][1]).toMatchObject({ title: "Draft catalog row", subtitle: "t-0001" });

    // The Inspector body renders the same read-only YAML.
    render(openInspector.mock.calls[0][0] as JSX.Element);
    expect(screen.getByText(/rule_id: cisco\.link_updown_draft/).tagName).toBe("CODE");
  });

  it("renders a YAML row containing <script> as ESCAPED TEXT — never as markup", async () => {
    const hostile = {
      ...proposalFixture,
      catalog_row: '- rule_id: "<script>alert(1)</script>"\n  lane: syslog',
      fixture: '{"msg":"<img src=x onerror=alert(2)>"}',
    };
    proposeCatalogRow.mockResolvedValue(hostile);
    const { container } = render(<TelemetryCoverage />);
    await screen.findByText("%LINK-3-UPDOWN: Interface <*>, changed state to <*>");
    fireEvent.click(screen.getAllByRole("button", { name: "Draft catalog row" })[0]);

    const code = await screen.findByText(/<script>alert\(1\)<\/script>/);
    expect(code.tagName).toBe("CODE");
    // The literal characters survive as TEXT; no element was created from them.
    expect(code.textContent).toContain("<script>alert(1)</script>");
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
  });

  it("reports a propose failure (e.g. missing alerts:write) instead of failing silently", async () => {
    proposeCatalogRow.mockRejectedValue(new Error("403 Forbidden: alerts:write required"));
    render(<TelemetryCoverage />);
    await screen.findByText("%LINK-3-UPDOWN: Interface <*>, changed state to <*>");
    fireEvent.click(screen.getAllByRole("button", { name: "Draft catalog row" })[0]);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("alerts:write required");
  });
});

describe("permission states (§3a)", () => {
  it("renders a 'platform-admin only' card for a tenant admin — no error, and the tenant table still works", async () => {
    parserStats.mockRejectedValue(forbidden());
    const { container } = render(<TelemetryCoverage />);

    expect(await screen.findByText("Parser coverage — platform-admin only")).toBeInTheDocument();
    expect(screen.getByText(/visible to platform administrators only/)).toBeInTheDocument();
    // Not an error, and none of the platform-global numbers leaked.
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByText("Semantic promotion rate")).toBeNull();
    expect(screen.queryByText("parser-2026.09.02-a6")).toBeNull();
    // The tenant half is unaffected.
    await waitFor(() => expect(shapeRowsOf(container).length).toBe(2));
  });

  it("still reports a non-permission stats failure as an alert", async () => {
    parserStats.mockRejectedValue(new Error("500 Internal Server Error: parser stats unavailable"));
    render(<TelemetryCoverage />);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("parser stats unavailable");
    expect(screen.queryByText("Parser coverage — platform-admin only")).toBeNull();
  });
});

describe("output-handling guarantee (§15 LLM02)", () => {
  it("uses no innerHTML sink anywhere in the page or its adapters", () => {
    for (const f of ["TelemetryCoverage.tsx", "coverageModel.ts"]) {
      const src = readFileSync(join(process.cwd(), "src/pages/telemetry", f), "utf8");
      expect(src).not.toMatch(/dangerouslySetInnerHTML/);
      expect(src).not.toMatch(/\.innerHTML/);
      expect(src).not.toMatch(/\beval\(/);
      expect(src).not.toMatch(/new Function\(/);
    }
  });
});
