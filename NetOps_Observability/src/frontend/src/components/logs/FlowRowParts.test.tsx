// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import { FlowDetail, FlowTitle, humanBytes, protoTone } from "./FlowRowParts";
import type { FlowView } from "../../lib/logEvent";

const flow = (over: Partial<FlowView> = {}): FlowView => ({
  exporter: "192.0.2.4", exporterName: "vEdge-1",
  source: { address: "192.0.2.10", port: "51515" }, destination: { address: "198.51.100.7", port: "443" },
  protocol: "tcp", inInterface: "1", outInterface: "4",
  inInterfaceLabel: "ge0/0 (1)", outInterfaceLabel: "ge0/3 (4)",
  service: "HTTPS", platformMonitoring: false, packets: "12", bytes: "15360", sampling: [], ...over,
});

describe("protoTone", () => {
  it.each([["tcp", "tcp"], ["TCP", "tcp"], ["6", "tcp"], ["udp", "udp"], ["17", "udp"], ["icmp", "icmp"], ["58", "icmp"], ["gre", "other"], ["", "other"]])(
    "%s → %s", (p, want) => expect(protoTone(p)).toBe(want),
  );
});

describe("humanBytes", () => {
  it.each([["0", "0 B"], ["512", "512 B"], ["15360", "15 KB"], ["5242880", "5.0 MB"], ["123456789", "118 MB"], ["1,003", "1,003 B"], ["2,097,152", "2.0 MB"], ["n/a", "n/a"], ["", ""]])(
    "%s → %s", (raw, want) => expect(humanBytes(raw)).toBe(want),
  );
});

describe("FlowTitle", () => {
  it("shows both endpoints, a toned protocol badge and the service", () => {
    const { container, getByTestId } = render(<FlowTitle flow={flow()} />);
    expect(container.querySelector(".fl-ep-src")?.textContent).toBe("192.0.2.10:51515");
    expect(container.querySelector(".fl-ep-dst")?.textContent).toBe("198.51.100.7:443");
    expect(getByTestId("flow-proto").textContent).toBe("TCP");
    expect(getByTestId("flow-proto").className).toContain("fl-proto-tcp");
    expect(getByTestId("flow-service").textContent).toBe("HTTPS");
    expect(container.querySelector("[data-testid=flow-own]")).toBeNull();
  });
  it("marks Correlix's own monitoring traffic and leaves out what the record lacks", () => {
    const { getByTestId, container } = render(<FlowTitle flow={flow({ platformMonitoring: true, service: "", protocol: "udp" })} />);
    expect(getByTestId("flow-own").textContent).toBe("Correlix monitoring");
    expect(getByTestId("flow-proto").className).toContain("fl-proto-udp");
    expect(container.querySelector("[data-testid=flow-service]")).toBeNull();
  });
});

describe("FlowDetail", () => {
  it("reads interfaces, volume in units, packets and the exporter", () => {
    const { getByTestId } = render(<FlowDetail flow={flow()} />);
    const t = getByTestId("flow-detail").textContent ?? "";
    expect(t).toContain("ge0/0 (1)");
    expect(t).toContain("ge0/3 (4)");
    expect(t).toContain("15 KB");
    expect(t).toContain("12 packets");
    expect(t).toContain("vEdge-1");
  });
  it("says 1 packet, not 1 packets", () => {
    const { getByTestId } = render(<FlowDetail flow={flow({ packets: "1" })} />);
    expect(getByTestId("flow-detail").textContent).toContain("1 packet");
    expect(getByTestId("flow-detail").textContent).not.toContain("1 packets");
  });
});
