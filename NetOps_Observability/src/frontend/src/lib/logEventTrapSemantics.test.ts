// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Tracker 387, trap semantics: the Logs presenter shows the receiver's sentence and
// peer, and folds one BGP transition's reports into one row. It never derives a peer,
// a transition or a count of its own.
import { describe, it, expect } from "vitest";
import { groupTransitions, toLogEvent } from "./logEvent";

const IDX = "netops-snmptrap-untagged-2026.11.10";

function bgpTrap(id: string, seq: number, extra: Record<string, unknown> = {}) {
  return {
    _index: IDX,
    _id: id,
    _source: {
      timestamp: `2026-11-10T04:05:3${seq}.000Z`,
      trap_oid: "1.3.6.1.4.1.9.9.187.0.8",
      trap_name: "cbgpPeer2BackwardTransition",
      summary: "Cisco cbgpPeer2BackwardTransition",
      title: "BGP neighbour 192.168.200.34 on cEDGE-81 went from Active to Idle (never established)",
      title_basis: "templated",
      device: "cedge-81-11060ae2",
      device_name: "cEDGE-81",
      host: "192.168.200.33",
      lifecycle_state: "repeat",
      transition_id: "tr-0123456789abcdef",
      transition_seq: seq,
      bgp: { peer_address: "192.168.200.34", peer_afi: "ipv4", peer_basis: "index_vendor_form",
        state: "idle", prev_state: "active", transition_class: "never_established" },
      ...extra,
    },
  };
}

describe("trap semantics on the Logs stream", () => {
  it("reads the receiver's title, device name, peer and transition", () => {
    const ev = toLogEvent(bgpTrap("a", 1));
    expect(ev.title).toBe("BGP neighbour 192.168.200.34 on cEDGE-81 went from Active to Idle (never established)");
    expect(ev.deviceLabel).toBe("cEDGE-81");
    expect(ev.deviceAddress).toBe("192.168.200.33");
    expect(ev.trap?.peer).toBe("192.168.200.34");
    expect(ev.trap?.peerHow).toBe("from the table index (vendor form)");
    expect(ev.trap?.transition).toBe("Never established");
    expect(ev.lifecycle).toBe("repeat");
    expect(ev.chips.filter((c) => c.stream).map((c) => c.label)).toEqual(
      expect.arrayContaining(["Peer 192.168.200.34", "Never established"]));
  });

  it("keeps the summary when the receiver worded nothing", () => {
    const rec = bgpTrap("a", 1);
    delete (rec._source as Record<string, unknown>).title;
    expect(toLogEvent(rec).title).toBe("Cisco cbgpPeer2BackwardTransition");
  });

  it("never shows a peer the receiver could not decode", () => {
    const ev = toLogEvent(bgpTrap("a", 1, {
      bgp: { peer_address: "192.168.200.34", peer_basis: "unparsed", state: "idle" },
    }));
    expect(ev.trap?.peer).toBe("");
    expect(ev.chips.some((c) => c.label.startsWith("Peer "))).toBe(false);
  });

  it("shows no transition wording for a class it does not know", () => {
    const ev = toLogEvent(bgpTrap("a", 1, { bgp: { peer_address: "10.0.0.1", peer_basis: "index", transition_class: "unknown" } }));
    expect(ev.trap?.transition).toBe("");
  });

  it("folds one transition's reports into one row, keeping the rest as its evidence", () => {
    const lines = [1, 2, 3, 4, 5, 6].map((n) => ({ id: `r${n}`, ev: toLogEvent(bgpTrap(`r${n}`, n)) }));
    const cpu = { id: "cpu", ev: toLogEvent({ _index: IDX, _id: "cpu", _source: { trap_oid: "1.3.6.1.4.1.41916.100.2.114", title: "CPU" } }) };
    const out = groupTransitions([lines[0], cpu, ...lines.slice(1)]);
    expect(out.map((l) => l.id)).toEqual(["r1", "cpu"]);
    expect(out[0].group).toEqual({
      id: "tr-0123456789abcdef", count: 6, members: ["r1", "r2", "r3", "r4", "r5", "r6"],
      firstSeen: "2026-11-10T04:05:31.000Z", lastSeen: "2026-11-10T04:05:36.000Z",
    });
    expect(out[1].group).toBeUndefined();
  });

  it("leaves a lone report and a trap with no transition untouched", () => {
    const one = { id: "r1", ev: toLogEvent(bgpTrap("r1", 1)) };
    const out = groupTransitions([one]);
    expect(out).toEqual([one]);
  });
});
