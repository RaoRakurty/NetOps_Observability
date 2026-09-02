// Typed fixtures for the Telemetry coverage surface. They exist so the tests
// (and any future storybook-style harness) exercise the EXACT contract shape —
// if the backend contract drifts, tsc breaks here first.

import type { CatalogProposal, ParserStats, UnrecognizedPage } from "../../services/api";

export const parserStatsFixture: ParserStats = {
  parser_rev: "parser-2026.09.02-a6",
  rules_hash: "sha256:9f3c1b7ad2e5",
  generated_at: "2026-09-02T10:00:00Z",
  promotion_rate: 0.8125,
  window_lines: 240000,
  prefilter: { passed: 240000, rejected: 18422 },
  generic_fallback: { syslog: 1204, trap: 87 },
  rules: [
    { rule_id: "cisco.ios.link_updown", lane: "syslog", kind: "interface_state", fidelity: "live_validated", hits: 9120, shadow: false },
    { rule_id: "juniper.bgp_peer_down", lane: "syslog", kind: "bgp_state", fidelity: "lab_validated", hits: 431, shadow: false },
    { rule_id: "arista.ospf_adj", lane: "syslog", kind: "ospf_state", fidelity: "doc_claimed", hits: 77, shadow: true },
    { rule_id: "snmp.linkDown", lane: "trap", kind: "interface_state", fidelity: "live_validated", hits: 2044, shadow: false },
    { rule_id: "port.optic_rx_low", lane: "port", kind: "optics", fidelity: "code", hits: 5, shadow: true },
  ],
};

export const parserStatsNoLinesFixture: ParserStats = {
  ...parserStatsFixture,
  promotion_rate: null,
  window_lines: 0,
  prefilter: { passed: 0, rejected: 0 },
  generic_fallback: { syslog: 0, trap: 0 },
};

export const unrecognizedFixture: UnrecognizedPage = {
  generated_at: "2026-09-02T10:00:00Z",
  days: 7,
  total: 2,
  items: [
    {
      template_id: "t-0001",
      template: "%LINK-3-UPDOWN: Interface <*>, changed state to <*>",
      count: 812,
      devices: 14,
      severity_max: 3,
      first_seen: "2026-08-27T04:11:00Z",
      last_seen: "2026-09-02T09:41:00Z",
      sample: "%LINK-3-UPDOWN: Interface GigabitEthernet0/3, changed state to down",
      appname: "LINK",
      mnemonic: "UPDOWN",
    },
    {
      template_id: "t-0002",
      template: "PFE_FW_SYSLOG_IP: FW: <*> A icmp <*> -> <*>",
      count: 33,
      devices: 2,
      severity_max: 5,
      first_seen: "2026-09-01T22:02:00Z",
      last_seen: "2026-09-02T08:58:00Z",
      sample: "PFE_FW_SYSLOG_IP: FW: ge-0/0/1.0 A icmp 10.1.1.5 -> 10.9.9.9",
    },
  ],
};

export const unrecognizedNotMinedFixture: UnrecognizedPage = {
  generated_at: "2026-09-02T10:00:00Z",
  days: 7,
  total: 0,
  items: [],
  note: "mining not yet run",
};

export const proposalFixture: CatalogProposal = {
  proposal_id: "prop-7f21",
  status: "drafted",
  catalog_row: [
    "- rule_id: cisco.link_updown_draft",
    "  lane: syslog",
    "  kind: interface_state",
    "  fidelity: code",
    "  match:",
    '    template: "%LINK-3-UPDOWN: Interface <*>, changed state to <*>"',
  ].join("\n"),
  fixture: '{"appname":"LINK","mnemonic":"UPDOWN","msg":"Interface GigabitEthernet0/3, changed state to down"}',
};
