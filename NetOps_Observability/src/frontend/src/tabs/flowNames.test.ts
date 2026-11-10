// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, expect, it } from "vitest";
import { TopNRow, ifaceLabel, topNDisplay, topNRowId } from "./flowNames";

const row = (over: Partial<TopNRow>): TopNRow => ({ k: "4", bytes_total: 1, packets_total: 1, flows: 1, ...over });

describe("Flows top-N names (tracker 387 PR 13b)", () => {
  it("an interface the API named reads name (index) with its exporter", () => {
    const r = row({ exporter: "10.70.245.104", in_if_name: "ge0/3", in_if_name_basis: "resolved" });
    expect(topNDisplay(r, "in_if")).toBe("ge0/3 (4) · 10.70.245.104");
  });

  it("an index nobody named stays the number, never a guess", () => {
    expect(ifaceLabel(row({ in_if_name: "", in_if_name_basis: "absent" }), "in_if")).toBe("4");
    // A name without the resolved basis is not shown either.
    expect(ifaceLabel(row({ in_if_name: "ge0/3", in_if_name_basis: "absent" }), "in_if")).toBe("4");
  });

  it("the IPFIX no-interface sentinel reads as such", () => {
    const r = row({ k: "4294967295", out_if_name: "", out_if_name_basis: "sentinel", exporter: "10.0.0.1" });
    expect(topNDisplay(r, "out_if")).toBe("none reported (4294967295) · 10.0.0.1");
  });

  it("reads the column of its own dimension", () => {
    const r = row({ in_if_name: "Gi1", in_if_name_basis: "resolved", out_if_name: "Gi2", out_if_name_basis: "resolved" });
    expect(ifaceLabel(r, "in_if")).toBe("Gi1 (4)");
    expect(ifaceLabel(r, "out_if")).toBe("Gi2 (4)");
  });

  it("one index on two exporters is two rows", () => {
    expect(topNRowId(row({ exporter: "10.0.0.1" }))).not.toBe(topNRowId(row({ exporter: "10.0.0.2" })));
    expect(topNRowId(row({}))).toBe("4");
  });

  it("protocols and services carry the IANA name beside the number", () => {
    expect(topNDisplay(row({ k: "17", label: "UDP", label_basis: "iana_protocol" }), "proto")).toBe("UDP (17)");
    expect(topNDisplay(row({ k: "200", label: "", label_basis: "absent" }), "proto")).toBe("200");
    const fmt = (k: string) => (k === "17/161" ? "161/udp · SNMP" : `${k.split("/")[1]}/udp`);
    expect(topNDisplay(row({ k: "17/161", label: "snmp", label_basis: "iana_service" }), "service_port", fmt)).toBe("161/udp · SNMP");
    expect(topNDisplay(row({ k: "17/5000", label: "commplex-main", label_basis: "iana_service" }), "service_port", fmt)).toBe("5000/udp · commplex-main");
  });

  it("an AS from the dataset says so; the exporter's own reads plainly", () => {
    expect(topNDisplay(row({ k: "13335", as_basis: "dataset" }), "dst_as")).toBe("13335 (from the AS dataset)");
    expect(topNDisplay(row({ k: "15169", as_basis: "exporter" }), "dst_as")).toBe("15169");
    expect(topNDisplay(row({ k: "15169" }), "src_as")).toBe("15169");
  });
});
