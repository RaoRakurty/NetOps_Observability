// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { flowEmptyReason, parseCoverage, platformTrafficNote, FlowEmpty, FlowSamplingNote, samplingNote, resetCoverageCache, type FlowCoverage } from "./flowEmpty";
import { api } from "../services/api";

const cov = (o: Partial<FlowCoverage>): FlowCoverage => ({
  flows: 0, tcp_flows: 0, tcp_flows_with_flags: 0, flows_with_as: 0, private_only_flows: 0, flows_sampling_reported: 0, exporters: 0,
  platform_monitoring_flows: 0, platform_addresses_configured: false, asn_dataset_loaded: false, flows_with_dataset_as: 0, ...o,
});

describe("flowEmptyReason — an empty panel says why", () => {
  it("keeps the plain 'no flow records' only when there are no flows or coverage is unknown", () => {
    expect(flowEmptyReason("as", null)).toBeNull();
    expect(flowEmptyReason("tcp_flags", cov({ flows: 0 }))).toBeNull();
  });

  it("AS: all-private traffic is explained as private, not as a broken exporter", () => {
    const r = flowEmptyReason("as", cov({ flows: 29697, private_only_flows: 29697, exporters: 5 }));
    expect(r?.msg).toBe("29,697 flows from 5 exporters in this window — none carry an AS number.");
    expect(r?.hint).toMatch(/private addresses/);
  });

  it("AS: public traffic with AS = 0 points at the exporter's BGP fields", () => {
    const r = flowEmptyReason("as", cov({ flows: 10, private_only_flows: 4, exporters: 1 }));
    expect(r?.msg).toMatch(/^10 flows from 1 exporter in this window/);
    expect(r?.hint).toMatch(/BGP/);
  });

  it("TCP flags: no TCP at all vs TCP without the tcpControlBits field", () => {
    expect(flowEmptyReason("tcp_flags", cov({ flows: 5 }))?.msg).toMatch(/none are TCP/);
    const r = flowEmptyReason("tcp_flags", cov({ flows: 5, tcp_flows: 3 }));
    expect(r?.msg).toBe("3 TCP flows in this window — none carry TCP flags.");
    expect(r?.hint).toMatch(/IE 6/);
  });

  it("flows exist and the field is present: the filters are what emptied the view", () => {
    expect(flowEmptyReason("as", cov({ flows: 2, flows_with_as: 2 }))?.msg).toMatch(/none match this view/);
    expect(flowEmptyReason("generic", cov({ flows: 1 }))?.msg).toMatch(/^1 flow in this window/);
  });

  it("parses ClickHouse's quoted 64-bit counts and rejects junk", () => {
    expect(parseCoverage({ flows: "12", tcp_flows: "x", exporters: -1 })).toEqual(cov({ flows: 12 }));
    expect(parseCoverage(undefined)).toBeNull();
  });
});

describe("samplingNote — says what the exporters reported, multiplies nothing", () => {
  it("no rate reported: shown as received, and it says when that would be wrong", () => {
    const s = samplingNote(cov({ flows: 29875 }));
    expect(s).toMatch(/report no sampling rate/);
    expect(s).toMatch(/1:1/);
    expect(s).toMatch(/read low/);
    expect(s).not.toMatch(/×|x50|estimate/i);
  });
  it("every flow reports a rate: scaled by it", () => {
    expect(samplingNote(cov({ flows: 10, flows_sampling_reported: 10 })))
      .toBe("Every flow here reports a sampling rate, and counts are scaled by it.");
  });
  it("a mix names both halves", () => {
    expect(samplingNote(cov({ flows: 10, flows_sampling_reported: 4 })))
      .toBe("4 flows report a sampling rate and are scaled by it. The other 6 report none and are shown as received (1:1).");
    expect(samplingNote(cov({ flows: 10, flows_sampling_reported: 1 })))
      .toMatch(/^1 flow reports a sampling rate and is scaled by it/);
  });
  it("no flows or no answer: the general rule, never a claim about these exporters", () => {
    for (const c of [null, cov({ flows: 0 })]) {
      expect(samplingNote(c)).toMatch(/when it reports one/);
    }
  });
  it("renders the sentence for the window on screen, and survives a failed read", async () => {
    resetCoverageCache();
    vi.spyOn(api, "flowsCoverage").mockResolvedValue({ data: [{ flows: "7", flows_sampling_reported: "7" }] } as never);
    const q = { since: 3600, ftype: "", filters: {}, fkey: "" };
    const { unmount } = render(<FlowSamplingNote q={q} />);
    expect(await screen.findByText(/Every flow here reports a sampling rate/)).toBeInTheDocument();
    unmount();
    resetCoverageCache();
    vi.spyOn(api, "flowsCoverage").mockRejectedValue(new Error("boom"));
    render(<FlowSamplingNote q={q} />);
    expect(await screen.findByTestId("flow-sampling-note")).toHaveTextContent(/when it reports one/);
  });
});

describe("FlowEmpty", () => {
  beforeEach(() => {
    resetCoverageCache();
    vi.restoreAllMocks();
  });
  const q = { since: 3600, ftype: "", filters: {}, fkey: "" };

  it("renders the reason from /api/flows/coverage", async () => {
    vi.spyOn(api, "flowsCoverage").mockResolvedValue({ data: [{ flows: "7", private_only_flows: "7", exporters: "2" }] } as never);
    render(<FlowEmpty q={q} dim="as" />);
    expect(await screen.findByText(/7 flows from 2 exporters/)).toBeTruthy();
  });

  it("falls back to the onboarding hint when the coverage read fails", async () => {
    vi.spyOn(api, "flowsCoverage").mockRejectedValue(new Error("boom"));
    render(<FlowEmpty q={q} dim="as" />);
    expect(await screen.findByText("No flow records in this window.")).toBeTruthy();
  });

  it("shares one coverage request between panels", async () => {
    const spy = vi.spyOn(api, "flowsCoverage").mockResolvedValue({ data: [{ flows: "0" }] } as never);
    render(<><FlowEmpty q={q} dim="as" /><FlowEmpty q={q} dim="tcp_flags" /></>);
    await screen.findAllByText("No flow records in this window.");
    expect(spy).toHaveBeenCalledTimes(1);
  });
});

describe("platformTrafficNote — Correlix's own polling is hidden out loud (tracker 387 PR 13)", () => {
  const base = parseCoverage({ flows: 100, platform_monitoring_flows: "52", platform_addresses_configured: 1 })!;
  it("says how many flows the views leave out, and that they are included when shown", () => {
    expect(platformTrafficNote(base, false)).toBe("52 flows of Correlix's own polling are hidden.");
    expect(platformTrafficNote(base, true)).toBe("Includes 52 flows of Correlix's own polling.");
    expect(platformTrafficNote({ ...base, platform_monitoring_flows: 1 }, false)).toBe("1 flow of Correlix's own polling is hidden.");
  });
  it("an unconfigured appliance separates nothing and says so", () => {
    const off = parseCoverage({ flows: 100, platform_monitoring_flows: 0, platform_addresses_configured: 0 })!;
    expect(off.platform_addresses_configured).toBe(false);
    expect(platformTrafficNote(off, false)).toMatch(/not separated/);
  });
  it("no coverage, no claim", () => {
    expect(platformTrafficNote(null, false)).toBe("");
  });
});
