// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// flowNames — how a Flows "Top N" row is labelled (tracker 387 PR 13b).
//
// The API names interfaces from the device's own IF-MIB (per exporter, keyed by the
// row's tenant) and protocols/services from the IANA registries. This module only
// renders what the API said: a name it did not give is never shown, the number is
// always kept beside it, and the IPFIX "no interface" sentinels read as such.

export type TopNRow = {
  k: string;
  bytes_total: number;
  packets_total: number;
  flows: number;
  /** Interface rows group per exporter: the same ifIndex on two devices is two ports. */
  exporter?: string;
  in_if_name?: string;
  in_if_name_basis?: string;
  out_if_name?: string;
  out_if_name_basis?: string;
  /** IANA protocol or service name for proto / service_port rows. */
  label?: string;
  label_basis?: string;
};

export const IFACE_DIMS = new Set(["in_if", "out_if"]);

/** A row id that stays unique when one ifIndex appears on several exporters. */
export function topNRowId(r: TopNRow): string {
  return r.exporter ? `${r.exporter}|${r.k}` : r.k;
}

/** The interface label: `ge0/3 (4)`, `4`, or `none reported (4294967295)`. */
export function ifaceLabel(r: TopNRow, by: string): string {
  const name = by === "out_if" ? r.out_if_name : r.in_if_name;
  const basis = by === "out_if" ? r.out_if_name_basis : r.in_if_name_basis;
  if (basis === "sentinel") return `none reported (${r.k})`;
  const n = (name ?? "").trim();
  return basis === "resolved" && n ? `${n} (${r.k})` : r.k;
}

/**
 * The label a Top N row shows. Interface rows add the exporter, since an index means
 * nothing without its device. A protocol reads `UDP (17)`; a service row keeps the
 * caller's formatting of the key and adds the registry name, which is a heuristic.
 */
export function topNDisplay(r: TopNRow, by: string, fmtKey?: (k: string) => string): string {
  if (IFACE_DIMS.has(by)) {
    const iface = ifaceLabel(r, by);
    return r.exporter ? `${iface} · ${r.exporter}` : iface;
  }
  const base = fmtKey ? fmtKey(r.k) : r.k;
  const label = (r.label ?? "").trim();
  if (!label || r.label_basis === "absent") return base;
  if (by === "proto") return `${label} (${r.k})`;
  // A service row: the caller's own name for a well-known port wins; otherwise the
  // registry's, which is a port heuristic either way.
  if (by === "service_port") return base.includes("·") ? base : `${base} · ${label}`;
  return base;
}
