// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// FlowRowParts — how one flow record reads in the Logs stream (owner 2026-11-11:
// "too basic, give it colour"). The tuple becomes two endpoint pills joined by an
// arrow, the protocol a coloured badge, the likely service a chip, and the volume
// readable units. Every colour comes from theme tokens (styles.css), so all six
// themes keep their contrast; nothing here invents data the presenter did not give.

import type { FlowEndpoint, FlowView } from "../../lib/logEvent";

/** The badge tone of a transport protocol. Unknown protocols stay neutral. */
export type ProtoTone = "tcp" | "udp" | "icmp" | "other";

export function protoTone(protocol: string): ProtoTone {
  const p = protocol.trim().toLowerCase();
  if (p === "tcp" || p === "6") return "tcp";
  if (p === "udp" || p === "17") return "udp";
  if (p === "icmp" || p === "1" || p === "icmpv6" || p === "ipv6-icmp" || p === "58") return "icmp";
  return "other";
}

/** Bytes as an operator reads them: 512 B, 1.2 KB, 3.4 MB. Not a number → as given. */
export function humanBytes(raw: string): string {
  // The presenter may already have grouped the digits ("1,003").
  const n = Number(raw.replace(/,/g, ""));
  if (!raw || !/^[\d,]+$/.test(raw.trim()) || !Number.isFinite(n) || n < 0) return raw;
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return i === 0 ? `${v.toLocaleString("en-US")} B` : `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

function Endpoint({ ep, side }: { ep: FlowEndpoint; side: "src" | "dst" }) {
  if (!ep.address && !ep.port) return <span className="fl-ep fl-ep-none">—</span>;
  return (
    <span className={`fl-ep fl-ep-${side}`} title={`${side === "src" ? "Source" : "Destination"} ${ep.address}${ep.port ? `:${ep.port}` : ""}`}>
      <span className="fl-addr">{ep.address || "—"}</span>
      {ep.port && <span className="fl-port">:{ep.port}</span>}
    </span>
  );
}

/** The row's headline: source → destination, protocol, service. */
export function FlowTitle({ flow }: { flow: FlowView }) {
  const tone = protoTone(flow.protocol);
  return (
    <span className="fl-title" data-testid="flow-title">
      <Endpoint ep={flow.source} side="src" />
      <span className="fl-arrow" aria-label="to">→</span>
      <Endpoint ep={flow.destination} side="dst" />
      {flow.protocol && <span className={`fl-proto fl-proto-${tone}`} data-testid="flow-proto">{flow.protocol.toUpperCase()}</span>}
      {flow.service && <span className="fl-service" data-testid="flow-service">{flow.service}</span>}
      {flow.platformMonitoring && <span className="fl-own" data-testid="flow-own">Correlix monitoring</span>}
    </span>
  );
}

/** The second line: interfaces, then the volume. */
export function FlowDetail({ flow }: { flow: FlowView }) {
  const ifaces = flow.inInterfaceLabel || flow.outInterfaceLabel;
  return (
    <span className="fl-detail" data-testid="flow-detail">
      {ifaces && (
        <span className="fl-ifaces">
          <span className="fl-k">in</span> {flow.inInterfaceLabel || "—"}
          <span className="fl-k"> out</span> {flow.outInterfaceLabel || "—"}
        </span>
      )}
      {flow.bytes && <span className="fl-vol"><strong>{humanBytes(flow.bytes)}</strong></span>}
      {flow.packets && <span className="fl-vol">{flow.packets} {flow.packets === "1" ? "packet" : "packets"}</span>}
      {flow.exporterName && <span className="fl-exp"><span className="fl-k">via</span> {flow.exporterName}</span>}
    </span>
  );
}
