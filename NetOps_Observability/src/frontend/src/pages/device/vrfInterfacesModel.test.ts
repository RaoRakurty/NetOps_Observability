// vrfInterfacesModel — the pure model. Every assertion here is about the ONE
// thing this panel can get catastrophically wrong: presenting an absence as a
// fact (a fabricated "default" instance, a null counter rendered as zero, a
// missing state rendered as green).
import { describe, it, expect } from "vitest";
import type {
  VrfCoverage, VrfDialect, VrfInterface, VrfInterfaceGroup, VrfInterfacesResponse,
} from "../../services/api";
import {
  coverageHeadline, dialectFootnote, fmtErrRate, fmtPct, fmtRate, groupHeading,
  groupKey, groupSummary, initiallyOpen, panelState, panelTitle, rowTone, totalInterfaces,
  transportLabel,
} from "./vrfInterfacesModel";

const iface = (over: Partial<VrfInterface> = {}): VrfInterface => ({
  ifname: "Ethernet1", oper: "up", oper_value: 1, admin: "up", admin_value: 1,
  in_bps: null, out_bps: null, speed_bps: null, in_util_pct: null, out_util_pct: null,
  in_errors_per_s: null, out_errors_per_s: null, ...over,
});

const group = (over: Partial<VrfInterfaceGroup> = {}): VrfInterfaceGroup => ({
  vrf: "", label: "VRF membership not collected on this transport",
  membership: "not_collected", count: 1, up: 1, down: 0, unknown: 0,
  members: [iface()], ...over,
});

const coverage = (over: Partial<VrfCoverage> = {}): VrfCoverage => ({
  vrf_labels: false, transport: "snmp", transport_inferred: true, interfaces: 1,
  in_groups: 0, ungrouped: 1, utilisation: false, errors: false, truncated: false,
  notes: ["VRF membership is not collected on this transport."], ...over,
});

const dialect = (over: Partial<VrfDialect> = {}): VrfDialect => ({
  term: "VRF", term_plural: "VRFs", vendor: "cisco", vendor_known: true, ...over,
});

const response = (over: Partial<VrfInterfacesResponse> = {}): VrfInterfacesResponse => ({
  device: { id: "core-1", name: "core-1", vendor: "cisco" },
  window: "5m", dialect: dialect(), coverage: coverage(), groups: [group()],
  routing_instances: [], ...over,
});

describe("panelState — the five honest states", () => {
  it("is loading while the fetch is in flight", () => {
    expect(panelState(true, null, null).state).toBe("loading");
  });

  it("is error when the API said no, and shows its message verbatim", () => {
    const r = panelState(false, "502 bad gateway", null);
    expect(r.state).toBe("error");
    expect(r.note).toBe("502 bad gateway");
  });

  it("is error — never a reassuring blank — when nothing came back at all", () => {
    expect(panelState(false, null, null).state).toBe("error");
  });

  it("is not_connected when NOTHING collects interface state for the device", () => {
    const r = panelState(false, null, response({
      coverage: coverage({ interfaces: 0, transport: "none", notes: ["No interface state series exists for this device."] }),
      groups: [],
    }));
    expect(r.state).toBe("not_connected");
    expect(r.note).toMatch(/No interface state series/);
  });

  it("is empty — a DIFFERENT fact from not_connected — when the source is collected but returned no groups", () => {
    const r = panelState(false, null, response({ coverage: coverage({ interfaces: 3 }), groups: [] }));
    expect(r.state).toBe("empty");
    expect(r.note).not.toMatch(/nothing is collecting/i);
  });

  it("is ready when there are groups", () => {
    expect(panelState(false, null, response()).state).toBe("ready");
  });

  it("survives a null groups list rather than crashing the device page", () => {
    const r = panelState(false, null, response({
      coverage: coverage({ interfaces: 2 }),
      groups: null as unknown as VrfInterfaceGroup[],
    }));
    expect(r.state).toBe("empty");
  });
});

describe("coverageHeadline — the sentence above the tables", () => {
  it("refuses to imply a default instance when the binding is not collected", () => {
    const h = coverageHeadline(coverage(), dialect());
    expect(h).toMatch(/not collected/i);
    expect(h).toMatch(/not as members of a default VRF/);
  });

  it("uses the device's own dialect word", () => {
    expect(coverageHeadline(coverage(), dialect({ term: "routing-instance" })))
      .toMatch(/routing-instance membership is not collected/);
    expect(coverageHeadline(coverage(), dialect({ term: "VPRN" }))).toMatch(/VPRN/);
    expect(coverageHeadline(coverage(), dialect({ term: "VPN instance" }))).toMatch(/VPN instance/);
  });

  it("says so when nothing is collected at all", () => {
    expect(coverageHeadline(coverage({ interfaces: 0 }), dialect()))
      .toMatch(/No interface telemetry is collected/);
  });

  it("reports a partial labelling as its own third fact", () => {
    const h = coverageHeadline(
      coverage({ vrf_labels: true, interfaces: 5, in_groups: 3, ungrouped: 2 }), dialect());
    expect(h).toMatch(/3 of 5/);
    expect(h).toMatch(/listed separately/);
  });
});

describe("transportLabel", () => {
  it("marks the SNMP lane as an INFERENCE when the series carry no stamp", () => {
    expect(transportLabel(coverage({ transport: "snmp", transport_inferred: true })))
      .toMatch(/inferred/);
  });
  it("does not hedge a stamped lane", () => {
    expect(transportLabel(coverage({ transport: "gnmi", transport_inferred: false }))).toBe("gNMI");
  });
  it("names the mixed and absent cases", () => {
    expect(transportLabel(coverage({ transport: "mixed" }))).toBe("Mixed transports");
    expect(transportLabel(coverage({ transport: "none" }))).toBe("No transport");
  });
});

describe("dialect rendering per vendor", () => {
  it("titles the panel with the vendor's word", () => {
    expect(panelTitle(dialect({ term: "VRF" }))).toBe("Interfaces by VRF");
    expect(panelTitle(dialect({ term: "routing-instance" }))).toBe("Interfaces by routing-instance");
    expect(panelTitle(dialect({ term: "VPRN" }))).toBe("Interfaces by VPRN");
    expect(panelTitle(dialect({ term: "VPN instance" }))).toBe("Interfaces by VPN instance");
  });

  it("heads an observed group with the dialect word plus the instance name", () => {
    const g = group({ vrf: "CORP-WAN", membership: "observed", label: "CORP-WAN" });
    expect(groupHeading(g, dialect({ term: "routing-instance" }))).toBe("routing-instance CORP-WAN");
  });

  it("uses the server's own label for the not-collected bucket, and never says default", () => {
    const h = groupHeading(group(), dialect());
    expect(h).toBe("VRF membership not collected on this transport");
    expect(h.toLowerCase()).not.toContain("default");
  });

  it("footnotes an unrecognized vendor so the word is not read as an identification", () => {
    expect(dialectFootnote(dialect())).toBeNull();
    const note = dialectFootnote(dialect({ vendor_known: false, vendor: "acme-os" }));
    expect(note).toMatch(/No vendor profile matched "acme-os"/);
  });
});

describe("groupSummary", () => {
  it("surfaces state-unknown separately from down", () => {
    expect(groupSummary(group({ count: 3, up: 1, down: 1, unknown: 1 })))
      .toBe("3 interfaces · 1 up · 1 down · 1 state unknown");
  });
  it("omits the unknown clause when everything was measured", () => {
    expect(groupSummary(group({ count: 1, up: 1, down: 0, unknown: 0 })))
      .toBe("1 interface · 1 up · 0 down");
  });
});

describe("rowTone — never green without evidence", () => {
  it("gives an unmeasured interface NO tone", () => {
    expect(rowTone(iface({ oper_value: null, oper: "unknown" }))).toBe("");
  });
  it("is good for a clean up interface", () => {
    expect(rowTone(iface({ in_errors_per_s: 0, out_errors_per_s: 0, in_util_pct: 5 }))).toBe("good");
  });
  it("warns on errors, even one", () => {
    expect(rowTone(iface({ in_errors_per_s: 0.1 }))).toBe("warn");
  });
  it("warns on saturation", () => {
    expect(rowTone(iface({ out_util_pct: 91 }))).toBe("warn");
  });
  it("is bad for an operationally-down interface that is admin up", () => {
    expect(rowTone(iface({ oper: "down", oper_value: 2 }))).toBe("bad");
  });
  it("does not alarm on an intentionally shut interface", () => {
    expect(rowTone(iface({ oper: "down", oper_value: 2, admin: "down", admin_value: 2 }))).toBe("");
  });
});

describe("formatters — null is never zero", () => {
  it("renders an absent rate as an em dash, not 0", () => {
    expect(fmtRate(null)).toBe("—");
    expect(fmtErrRate(null)).toBe("—");
    expect(fmtPct(null)).toBe("—");
  });
  it("renders a MEASURED zero error rate as 0/s — clean is not the same as unmeasured", () => {
    expect(fmtErrRate(0)).toBe("0/s");
    expect(fmtErrRate(0)).not.toBe(fmtErrRate(null));
  });
  it("scales bit rates", () => {
    expect(fmtRate(0)).toBe("0 bps");
    expect(fmtRate(1500)).toBe("1.5 Kbps");
    expect(fmtRate(2.5e9)).toBe("2.5 Gbps");
  });
  it("rejects non-finite values", () => {
    expect(fmtRate(Number.NaN)).toBe("—");
    expect(fmtPct(Number.POSITIVE_INFINITY)).toBe("—");
  });
  it("formats percentages readably", () => {
    expect(fmtPct(3.14)).toBe("3.1%");
    expect(fmtPct(87.6)).toBe("88%");
  });
});

describe("group bookkeeping", () => {
  it("keys the unnamed bucket by index and named instances by name", () => {
    expect(groupKey(group({ vrf: "CORP-WAN" }), 0)).toBe("vrf:CORP-WAN");
    expect(groupKey(group(), 2)).toBe("ungrouped:2");
  });

  it("opens observed instances, and the lone ungrouped bucket", () => {
    const only = [group()];
    expect(initiallyOpen(only)[groupKey(only[0], 0)]).toBe(true);

    const many = [group({ vrf: "BLUE", membership: "observed" }), group()];
    const open = initiallyOpen(many);
    expect(open[groupKey(many[0], 0)]).toBe(true);
    expect(open[groupKey(many[1], 1)]).toBe(false);
  });

  it("counts what is actually rendered", () => {
    expect(totalInterfaces([
      group({ members: [iface({ ifname: "e1" }), iface({ ifname: "e2" })] }),
      group({ members: [iface({ ifname: "e3" })] }),
    ])).toBe(3);
    expect(totalInterfaces([])).toBe(0);
  });
});
