// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IP protocol number → name. Single source of truth shared by the Flows tab
// and the Overview "Traffic by protocol" panel so the two never drift.
export const PROTO_NAMES: Record<number, string> = {
  1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 89: 'OSPF', 132: 'SCTP',
}

// protoLabel maps a flow's protocol (numeric IANA number or already-named
// string) to a display name, falling back to "IP/<n>" for unknown numbers.
export function protoLabel(p: number | string | null | undefined): string {
  if (p === null || p === undefined || p === '') return 'unknown'
  const n = typeof p === 'number' ? p : parseInt(p, 10)
  if (!isNaN(n) && PROTO_NAMES[n]) return PROTO_NAMES[n]
  return typeof p === 'string' && isNaN(n) ? p : `IP/${p}`
}
