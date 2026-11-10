// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Logs.test.tsx — two contracts for the Logs page.
//
// Sample honesty for the flows signal (finder 2026-08-14): netops-flows-* holds
// the router's 1:50 OpenSearch sample (ClickHouse keeps the canonical flow store).
// The Logs view previously rendered the sample's counts as exact — "showing X of Y
// matched", "This store holds N logs", "Export all (N)" — so an operator concluded
// ~50x too little traffic existed. These tests pin the disclosure: flows results
// SAY they are a 1:50 sample and that totals are estimates (×50); exact signals
// (syslog) stay undisclosed.
//
// The event stream: a calm row per record, details in the Event Intelligence panel,
// quick filters that add a real search clause, and no secret in any of it.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { act, render, screen, cleanup, waitFor, fireEvent, within } from "@testing-library/react";

const searchLogs = vi.fn();
const logsRetention = vi.fn();
const exportLogRows = vi.fn();
const openInspector = vi.fn();
let wsEnabled = false;

vi.mock("../services/api", () => ({
  api: {
    searchLogs: (...a: unknown[]) => searchLogs(...a),
    logsRetention: (...a: unknown[]) => logsRetention(...a),
    createSaved: vi.fn(),
    exportLogRows: (...a: unknown[]) => exportLogRows(...a),
    exportLogQuery: vi.fn(),
    exportStatus: vi.fn(),
    createIncident: vi.fn(),
    metricsQueryRange: vi.fn().mockResolvedValue({ status: "success", data: { resultType: "matrix", result: [] } }),
  },
}));
vi.mock("../context/workspace", () => ({
  useWorkspace: () => ({ enabled: wsEnabled, openInspector: (...a: unknown[]) => openInspector(...a) }),
}));
vi.mock("../hooks/useAuth", () => ({
  useAuth: () => ({ user: { platform_admin: true } }),
}));

import Logs from "./Logs";

afterEach(cleanup);

const flowHit = {
  _index: "netops-flows-acme-2026.08.14",
  _id: "f1",
  _source: {
    timestamp: "2026-08-14T10:00:00Z",
    src_addr: "10.0.0.5",
    dst_addr: "10.0.0.9",
    src_port: 161,
    dst_port: 38204,
    proto: 17,
    sampler_address: "10.0.0.1",
    in_if: 1,
    out_if: 4,
    bytes: 1003,
    packets: 13,
    message: "flow record",
    sample_rate: 50,
    sampling_rate: 0,
    tenant_attribution: "unmatched",
  },
};
const syslogHit = {
  _index: "netops-syslog-acme-2026.08.14",
  _id: "s1",
  _source: {
    timestamp: "2026-08-14T10:00:00Z",
    hostname: "router-01",
    source_ip: "192.0.2.7",
    appname: "ifmgr",
    severity: "err",
    vendor: "unknown",
    tenant_attribution: "unmatched",
    message: "%LINK-3-UPDOWN: Interface Gi0/1, changed state to down",
    topic: "netops.syslog",
    partition: 4,
  },
};
const trapHit = {
  _index: "netops-snmptrap-acme-2026.08.14",
  _id: "t1",
  _source: {
    timestamp: "2026-08-14T10:00:01Z",
    host: "192.0.2.8",
    hostname: "192.0.2.8",
    severity: "notice",
    trap_name: "enterpriseSpecific",
    trap_oid: "1.3.6.1.4.1.41916.100.2.27",
    snmp_community: "s3cr3t-community",
    tenant_attribution: "unmatched",
    message: "enterpriseSpecific 1.3.6.1.4.1.41916.100.2.27 snmp_community=s3cr3t-community",
    varbinds: [{ oid: "1.3.6.1.4.1.41916.100.1.54.0", value: "System cpu usage back to normal level" }],
  },
};

const respond = (hits: unknown[], total = hits.length) => {
  searchLogs.mockResolvedValue({ hits: { total: { value: total }, hits } });
  logsRetention.mockResolvedValue({ signal: "", total, oldest: "2026-08-01T00:00:00Z", days: 13 });
};

beforeEach(() => {
  searchLogs.mockReset();
  logsRetention.mockReset();
  exportLogRows.mockReset();
  openInspector.mockReset();
  wsEnabled = false;
});

describe("Logs flows sample honesty", () => {
  it("disclosing the 1:50 sample on flows results (server metadata)", async () => {
    searchLogs.mockResolvedValue({
      hits: { total: { value: 123 }, hits: [flowHit] },
      sampling: { rate: 50, note: "1:50 sample - counts and totals are estimates" },
    });
    logsRetention.mockResolvedValue({
      signal: "flows", total: 1000, oldest: "2026-08-01T00:00:00Z", days: 13,
      sampling: { rate: 50 },
    });
    render(<Logs initialSignal="flows" />);
    const note = await screen.findByTestId("flows-sampling-note");
    expect(note.textContent).toContain("1:50 sample");
    expect(note.textContent).toContain("totals are estimates (×50)");
    // The retention line also carries the sample caveat, not a bare count.
    await waitFor(() => expect(logsRetention).toHaveBeenCalled());
    expect((await screen.findByText(/This store holds/)).textContent).toContain("1:50 sample");
  });

  it("falls back to the pinned rate when a response carries no metadata", async () => {
    // An older backend (or a proxy stripping the key) must not silently
    // re-present the sample as exact — the UI's own constant backstops it.
    searchLogs.mockResolvedValue({ hits: { total: { value: 7 }, hits: [flowHit] } });
    logsRetention.mockResolvedValue({ signal: "flows", total: 7, oldest: null, days: 0 });
    render(<Logs initialSignal="flows" />);
    const note = await screen.findByTestId("flows-sampling-note");
    expect(note.textContent).toContain("1:50 sample");
  });

  it("exact signals carry NO sampling note (syslog)", async () => {
    searchLogs.mockResolvedValue({ hits: { total: { value: 5 }, hits: [syslogHit] } });
    logsRetention.mockResolvedValue({ signal: "syslog", total: 5, oldest: "2026-08-01T00:00:00Z", days: 13 });
    render(<Logs initialSignal="syslog" />);
    await screen.findAllByText(/router-01/);
    expect(screen.queryByTestId("flows-sampling-note")).toBeNull();
    expect(screen.queryByText(/totals are estimates/)).toBeNull();
  });
});

const grid = () => screen.findByRole("grid", { name: "Log results" });
const lastQuery = () => searchLogs.mock.calls[searchLogs.mock.calls.length - 1][0];

describe("event stream", () => {
  it("reads as device name, address, severity word and message", async () => {
    respond([syslogHit]);
    render(<Logs />);
    const table = within(await grid());
    expect(table.getByTitle("router-01")).toBeTruthy();
    expect(table.getByTitle("192.0.2.7")).toBeTruthy();
    expect(table.getByText("Error")).toBeTruthy();
    expect(table.getByText("Syslog")).toBeTruthy();
    expect(table.getByText("ifmgr")).toBeTruthy();
  });

  it("a flow row shows source → destination, protocol, port and bytes, not a dump", async () => {
    respond([flowHit]);
    render(<Logs />);
    const table = within(await grid());
    expect(table.getByText("10.0.0.5 → 10.0.0.9")).toBeTruthy();
    expect(table.getByText("UDP 161 → 38204 · 1,003 bytes · 13 packets")).toBeTruthy();
    expect((await grid()).textContent).not.toContain("{");
  });

  it("an undecoded trap says so, quietly, with its OID", async () => {
    respond([trapHit]);
    render(<Logs />);
    const table = within(await grid());
    expect(table.getByText("Not decoded yet")).toBeTruthy();
    expect((await grid()).textContent).toContain("1.3.6.1.4.1.41916.100.2.27");
  });

  it("never shows 'unmatched' or 'unknown' from the record", async () => {
    respond([syslogHit, trapHit, flowHit]);
    const { container } = render(<Logs />);
    await grid();
    expect(container.textContent).not.toContain("unmatched");
    expect(container.textContent?.toLowerCase()).not.toContain("unknown");
  });

  it("the Type control searches the chosen store", async () => {
    respond([syslogHit]);
    render(<Logs />);
    await grid();
    fireEvent.click(screen.getByRole("button", { name: "Traps" }));
    await waitFor(() => expect(lastQuery().signal).toBe("snmptrap"));
    expect(screen.getByRole("button", { name: "Traps" }).getAttribute("aria-pressed")).toBe("true");
  });

  it("the search examples sit behind the help button", async () => {
    respond([syslogHit]);
    render(<Logs />);
    await grid();
    expect(screen.queryByTestId("logs-search-help")).toBeNull();
    const help = screen.getByRole("button", { name: "Search examples" });
    expect(help.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(help);
    expect(screen.getByTestId("logs-search-help").textContent).toContain("severity:err");
    expect(help.getAttribute("aria-expanded")).toBe("true");
  });
});

describe("quick filters", () => {
  const facet = (name: RegExp) => within(screen.getByTestId("logs-facets")).getByRole("button", { name });

  it("say they count the loaded rows, not the store", async () => {
    respond([syslogHit, trapHit], 5000);
    render(<Logs />);
    await grid();
    const bar = screen.getByTestId("logs-facets");
    expect(bar.textContent).toContain("In these 2 loaded rows");
    expect(facet(/severity Error, 1 in the loaded rows/)).toBeTruthy();
  });

  it("add a quoted clause, re-run, and take it back off on a second click", async () => {
    respond([syslogHit]);
    render(<Logs />);
    await grid();
    searchLogs.mockClear();
    fireEvent.click(facet(/device router-01/));
    await waitFor(() => expect(searchLogs).toHaveBeenCalledTimes(1));
    expect(lastQuery().query).toBe('hostname:"router-01"');
    expect((screen.getByRole("textbox", { name: "Search query" }) as HTMLInputElement).value).toBe('hostname:"router-01"');
    expect(facet(/device router-01/).getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(facet(/device router-01/));
    await waitFor(() => expect(lastQuery().query).toBe("*"));
  });

  it("escape a hostile value so it cannot break out of its clause", async () => {
    const evil = 'x" OR tenant_id:"other';
    respond([{ ...syslogHit, _source: { ...syslogHit._source, hostname: evil } }]);
    render(<Logs />);
    await grid();
    searchLogs.mockClear();
    fireEvent.click(within(screen.getByTestId("logs-facets")).getByTitle(evil));
    await waitFor(() => expect(searchLogs).toHaveBeenCalled());
    expect(lastQuery().query).toBe('hostname:"x\\" OR tenant_id:\\"other"');
  });

  it("a flow filters on the exporter's mapped field and offers no severity", async () => {
    respond([flowHit]);
    render(<Logs />);
    await grid();
    searchLogs.mockClear();
    expect(screen.getByTestId("logs-facets").textContent).not.toMatch(/Info|Notice/);
    fireEvent.click(facet(/device 10\.0\.0\.1,/));
    await waitFor(() => expect(lastQuery().query).toBe('sampler_address:"10.0.0.1"'));
  });

  it("a type filter switches the Type control rather than adding a clause that finds nothing", async () => {
    respond([syslogHit, flowHit]);
    render(<Logs />);
    await grid();
    searchLogs.mockClear();
    fireEvent.click(facet(/Show only Flow/));
    await waitFor(() => expect(lastQuery().signal).toBe("flows"));
    expect(lastQuery().query).toBe("*");
  });

  it("a stale answer cannot overwrite a newer search", async () => {
    respond([syslogHit]);
    render(<Logs />);
    await grid();
    let answerOld: (v: unknown) => void = () => undefined;
    searchLogs.mockImplementationOnce(() => new Promise((r) => { answerOld = r; }));
    fireEvent.click(facet(/severity Error/));
    searchLogs.mockResolvedValueOnce({ hits: { total: { value: 1 }, hits: [trapHit] } });
    fireEvent.submit(screen.getByRole("textbox", { name: "Search query" }).closest("form") as HTMLFormElement);
    await screen.findByText("Not decoded yet");
    // Inside act, with time to spare: the table commits in a transition, and a check
    // that runs before it lands would pass whether or not the guard exists.
    await act(async () => {
      answerOld({ hits: { total: { value: 1 }, hits: [syslogHit] } });
      await new Promise((r) => setTimeout(r, 50));
    });
    expect(screen.getByText("Not decoded yet")).toBeTruthy();
    expect(within(await grid()).queryByTitle("router-01")).toBeNull();
  });
});

describe("record details: the Event Intelligence panel", () => {
  const openFirst = async () => {
    const rows = (await grid()).querySelectorAll(".dtv-row");
    fireEvent.click(rows[0]);
    return screen.findByTestId("event-detail");
  };
  const tab = (name: string) => screen.getByRole("tab", { name });

  it("opens as a dialog on the overview, not a JSON dump, with pipeline fields behind a closed section", async () => {
    respond([syslogHit]);
    render(<Logs />);
    const detail = await openFirst();
    expect(screen.getByRole("dialog").getAttribute("aria-modal")).toBe("true");
    expect(tab("Overview").getAttribute("aria-selected")).toBe("true");
    expect(detail.querySelector(".lf-json")).toBeNull();
    expect(within(detail).getByTestId("event-visual").dataset.kind).toBe("syslog_fault");
    expect(detail.textContent).not.toContain("partition");

    fireEvent.click(tab("Technical Details"));
    const section = screen.getByTestId("pipeline-details") as HTMLDetailsElement;
    expect(section.open).toBe(false);
    expect(section.textContent).toContain("Pipeline details");
    expect(section.textContent).toContain("partition");
    const fieldsTable = within(screen.getByTestId("event-all-fields")).getAllByRole("table")[0];
    expect(fieldsTable.textContent).not.toContain("partition");
    expect(fieldsTable.textContent).toContain("hostname");
  });

  it("a trap shows its values with OIDs set in mono", async () => {
    respond([trapHit]);
    render(<Logs />);
    const detail = within(await openFirst());
    const oid = detail.getByText("1.3.6.1.4.1.41916.100.1.54.0");
    expect(oid.className).toContain("evd-mono");
    expect(detail.getByText("System cpu usage back to normal level")).toBeTruthy();
  });

  it("a flow shows the exporter, both ends and the sampling values as reported", async () => {
    respond([flowHit]);
    render(<Logs />);
    const detail = await openFirst();
    expect(detail.textContent).toContain("Exporter 10.0.0.1");
    expect(within(detail).getByTestId("flow-strip").textContent).toContain("10.0.0.5:161");
    expect(within(detail).getByTestId("flow-strip").textContent).toContain("10.0.0.9:38204");
    expect(detail.textContent).toContain("Search index keeps1 in 50");
    expect(detail.textContent).toContain("Exporter samplingNone reported");
    expect(detail.textContent).not.toContain("sampling_rate");
    expect(detail.textContent).not.toMatch(/estimate/i);
  });

  it("a syslog line shows its process and message", async () => {
    respond([syslogHit]);
    render(<Logs />);
    const detail = await openFirst();
    expect(detail.textContent).toContain("Process ifmgr");
    expect(detail.textContent).toContain("changed state to down");
  });

  it("the tabs answer the arrow keys", async () => {
    respond([syslogHit]);
    render(<Logs />);
    await openFirst();
    fireEvent.keyDown(tab("Overview"), { key: "ArrowRight" });
    expect(tab("Metrics").getAttribute("aria-selected")).toBe("true");
    fireEvent.keyDown(tab("Metrics"), { key: "End" });
    expect(tab("Raw Event").getAttribute("aria-selected")).toBe("true");
    fireEvent.keyDown(tab("Raw Event"), { key: "ArrowRight" });
    expect(tab("Overview").getAttribute("aria-selected")).toBe("true");
  });

  it("Esc closes the panel and the close button does too", async () => {
    respond([syslogHit]);
    render(<Logs />);
    await openFirst();
    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() => expect(screen.queryByTestId("event-detail")).toBeNull());
    await openFirst();
    fireEvent.click(screen.getByRole("button", { name: "Close event details" }));
    await waitFor(() => expect(screen.queryByTestId("event-detail")).toBeNull());
  });

  it("opens the same panel under the new shell, not the Inspector", async () => {
    wsEnabled = true;
    respond([syslogHit]);
    render(<Logs />);
    await openFirst();
    expect(openInspector).not.toHaveBeenCalled();
    expect(screen.getByTestId("event-title").textContent).toContain("changed state to down");
  });
});

describe("secrets", () => {
  const SECRET = "s3cr3t-community";
  // The panel is a portal on document.body, so the whole document is what is checked.
  const seen = () => document.body.innerHTML;

  it("never reach the page in any tab", async () => {
    respond([trapHit]);
    render(<Logs />);
    fireEvent.click((await grid()).querySelectorAll(".dtv-row")[0]);
    await screen.findByTestId("event-detail");
    expect(seen()).not.toContain(SECRET);
    for (const name of ["Metrics", "Timeline", "Technical Details"]) {
      fireEvent.click(screen.getByRole("tab", { name }));
      expect(seen()).not.toContain(SECRET);
    }
    expect(seen()).toContain("snmp_community");
    fireEvent.click(screen.getByRole("tab", { name: "Raw Event" }));
    expect(seen()).not.toContain(SECRET);
    expect(document.querySelector(".lf-json")?.textContent).toContain('"snmp_community": "hidden"');
  });

  it("never reach the clipboard", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    respond([trapHit]);
    render(<Logs />);
    fireEvent.click((await grid()).querySelectorAll(".dtv-row")[0]);
    await screen.findByTestId("event-detail");
    fireEvent.click(screen.getByRole("tab", { name: "Raw Event" }));
    fireEvent.click(screen.getByRole("button", { name: /Copy JSON/ }));
    await screen.findByText("Copied");
    expect(writeText.mock.calls[0][0]).not.toContain(SECRET);
    expect(writeText.mock.calls[0][0]).toContain("snmp_community");
  });

  it("never reach a client-built export, with the columns unchanged", async () => {
    exportLogRows.mockResolvedValue(undefined);
    // No message, so the export falls back to the whole record as JSON. The nested
    // secret is one only the record-level redaction can catch: text scrubbing alone
    // would stop at the first value inside the object.
    const bare = {
      ...trapHit,
      _id: "t2",
      _source: { ...trapHit._source, message: undefined, credentials: { user: "u", other: "nested-secret-value" } },
    };
    respond([trapHit, bare]);
    render(<Logs />);
    const g = await grid();
    fireEvent.click(within(g).getByRole("checkbox", { name: "Select all rows in view" }));
    fireEvent.click(screen.getByTitle("Export 2 selected rows as CSV"));
    await waitFor(() => expect(exportLogRows).toHaveBeenCalledTimes(1));
    const [format, columns, rows, name] = exportLogRows.mock.calls[0];
    expect(format).toBe("csv");
    expect(columns).toEqual(["time", "source", "level", "application", "message"]);
    expect(name).toBe("logs-selected");
    expect(rows[0].slice(0, 3)).toEqual(["2026-08-14T10:00:01Z", "192.0.2.8", "notice"]);
    expect(JSON.stringify(rows)).not.toContain(SECRET);
    expect(JSON.stringify(rows)).not.toContain("nested-secret-value");
  });
});

describe("hostile values", () => {
  it("render as text in the row and in every tab", async () => {
    const xss = '<img src=x onerror="window.__pwned=1">';
    const hit = {
      _index: "netops-syslog-acme-2026.08.14",
      _id: "x1",
      _source: { timestamp: "2026-08-14T10:00:00Z", hostname: xss, appname: xss, message: xss, extra: xss },
    };
    respond([hit]);
    render(<Logs />);
    fireEvent.click((await grid()).querySelectorAll(".dtv-row")[0]);
    await screen.findByTestId("event-detail");
    for (const name of ["Overview", "Metrics", "Timeline", "Technical Details", "Raw Event"]) {
      fireEvent.click(screen.getByRole("tab", { name }));
      expect(document.querySelector("img")).toBeNull();
    }
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });
});
