// fixtures.ts — the typed Security fixture set the section's tests render.
//
// No MSW: the repo's pattern is `vi.mock("../services/api")` with typed
// fixtures, so these objects ARE the contract under test. They are typed
// against the real client types, so a backend contract change that lands in
// services/api.ts breaks the fixtures at compile time rather than producing a
// green suite against a shape that no longer exists.
//
// The set is deliberately awkward: it carries a NotApplicable verdict, an
// untagged finding, a seam with no findings and an asset that was never
// assessed — the honesty rules are only testable against data that could
// tempt the UI into claiming "clear".

import type {
  CorrObject, SecFacets, SecFinding, SecFindingsPage, SecPosture, SecRule,
  SecSavedView, SecTrend, Seam,
} from "../../services/api";

export const finding = (over: Partial<SecFinding> = {}): SecFinding => ({
  id: "doc-1",
  native_id: "nat-1",
  scan_id: "scan-7",
  time: "2026-09-01T10:00:00Z",
  source: "correlix-netrule",
  evidence_class: "exposure",
  status: "Fail",
  status_id: 3,
  standards: ["CIS", "NIST-CSF"],
  control: "NDM-1.2",
  control_title: "Telnet on VTY — ISP seam",
  category_name: "policy",
  severity: "critical",
  resource: { uid: "d-core-01", name: "core-01", type: "network-device", platform: "Cisco IOS-XE 17.9", ip: "10.0.0.1" },
  observed: "transport input telnet ssh; no access-class on vty 0 4",
  intended: "transport input ssh with an access-class bound to the mgmt prefix",
  status_detail: "Management services reachable from the ISP seam.",
  remediation: "transport input ssh",
  evidence_ref: { locator: "netops-secfindings-acme-2026.09.01/doc-1", kind: "config-line", ruleset_version: "netrule-v3", digest: "sha256:abc" },
  raw_rule_id: "netrule.telnet_vty",
  seam: { seam_id: "seam-isp-1", seam_type: "ISP", internet_facing: true },
  ...over,
});

export const FINDINGS: SecFinding[] = [
  finding(),
  finding({
    id: "doc-2", native_id: "nat-2", severity: "high", status: "Fail", status_id: 3,
    evidence_class: "posture", control_title: "Non-TLS HTTP server", control: "NDM-2.1",
    resource: { uid: "d-edge-02", name: "edge-02", type: "network-device", platform: "Juniper Junos 22.4" },
    remediation: "delete system services web-management http",
    seam: undefined, standards: ["CIS"],
  }),
  finding({
    id: "doc-3", native_id: "nat-3", severity: "medium", status: "Warning", status_id: 2,
    evidence_class: "posture", control_title: "SNMP v2c community", control: "NDM-3.4",
    resource: { uid: "d-spine-01", name: "spine-01", platform: "Nokia SR Linux" },
    remediation: "snmp v3 authPriv", standards: ["PCI-DSS"],
  }),
  finding({
    // NotApplicable — the trap: status_id 4 is NOT a pass and must never colour
    // a screen green or be counted as a clean control.
    id: "doc-4", native_id: "nat-4", severity: "", status: "NotApplicable", status_id: 4,
    evidence_class: "posture", control_title: "AAA / TACACS+ posture", control: "NDM-4.1",
    resource: { uid: "d-fw-01", name: "fw-01" },
    observed: "", intended: "", remediation: "", standards: [], evidence_ref: undefined,
  }),
  finding({
    id: "doc-5", native_id: "nat-5", severity: "high", status: "Fail", status_id: 3,
    evidence_class: "threat", control_title: "Outbound beacon to a rare destination",
    raw_rule_id: "netrule.beacon", standards: ["T1071"],
    resource: { uid: "d-core-01", name: "core-01" },
    time: "2026-09-01T11:30:00Z",
  }),
  finding({
    id: "doc-6", native_id: "nat-1", status: "Pass", status_id: 1, severity: "critical",
    // a SUPERSEDED verdict for nat-1 — only visible in history mode
    time: "2026-08-20T10:00:00Z", control_title: "Telnet on VTY — ISP seam",
  }),
];

export const PAGE_1: SecFindingsPage = { items: FINDINGS.slice(0, 3), next_cursor: "cur-2", total: 6 };
export const PAGE_2: SecFindingsPage = { items: FINDINGS.slice(3), next_cursor: null, total: 6 };

export const FACETS: SecFacets = {
  severity: { crit: 2, high: 2, medium: 1, low: 0, info: 0 },
  status: { pass: 1, warn: 1, fail: 4 },
  seam: { ISP: 2, internet: 1 },
  framework: { CIS: 3, "NIST-CSF": 1, "PCI-DSS": 1 },
  evidence_class: { posture: 3, exposure: 1, threat: 1 },
};

export const POSTURE: SecPosture = {
  funnel: { scope: 2547, discover: 1284, prioritize: 47, validate: 12, mobilize: 5 },
  coverage: { assessed_assets: 1900, total_assets: 2547, unassessed: 647 },
  last_scan: { scan_id: "scan-7", time: "2026-09-01T10:00:00Z" },
};

/** The estate nothing has been assessed on — must never read as clear. */
export const POSTURE_UNASSESSED: SecPosture = {
  funnel: { scope: 120, discover: 0, prioritize: 0, validate: 0, mobilize: 0 },
  coverage: { assessed_assets: 0, total_assets: 120, unassessed: 120 },
  last_scan: { scan_id: "", time: "" },
};

export const TREND: SecTrend = {
  buckets: [
    { t: "2026-08-30", fail: 5, warn: 2, pass: 30 },
    { t: "2026-08-31", fail: 4, warn: 3, pass: 31 },
    { t: "2026-09-01", fail: 4, warn: 1, pass: 32 },
  ],
};

export const SEAMS: Seam[] = [
  { seam_id: "seam-isp-1", seam_type: "ISP", state: "active", display_name: "ISP", control_plane_owner: "isp", visibility: "partial" },
  { seam_id: "seam-inet-1", seam_type: "internet", state: "active", display_name: "Internet", control_plane_owner: "enterprise", visibility: "full" },
  // Known to the inventory, never scored — must render "—", never 0.
  { seam_id: "seam-saas-1", seam_type: "SaaS", state: "active", display_name: "SaaS", control_plane_owner: "cloud", visibility: "blind" },
];

export const RULES: SecRule[] = [
  { rule_id: "netrule.telnet_vty", family: "hardening", enabled: true, fidelity: "high", seam_aware: true },
  { rule_id: "netrule.beacon", family: "behavior", enabled: false, fidelity: "medium", mitre: ["T1071"], seam_aware: false },
  { rule_id: "netrule.logging_disabled", family: "tamper", enabled: true, fidelity: "low", mitre: ["T1562.001"], seam_aware: false },
];

export const VIEWS: SecSavedView[] = [
  { id: "v1", name: "ISP criticals", filters: { severity: "critical", seam: "ISP", current: true } },
  { id: "v2", name: "Everything ever", filters: { current: false } },
];

export const STORY: CorrObject = {
  correlation_id: "corr-9",
  version: 3,
  state: "active",
  window_start: "2026-09-01T09:00:00Z",
  window_end: "2026-09-01T12:00:00Z",
  top_hypothesis: "core-01's management plane is reachable from the ISP seam",
  top_confidence: 0.72,
  verdict_tier: "suspected",
  evidence_missing: "[]",
  affected: '{"devices":["core-01"]}',
  signal_count: 14,
  node_count: 3,
  engine_version: "e-2026.09",
  catalog_version: "c-12",
  created_at: "2026-09-01T12:01:00Z",
  owner: "isp",
  grounding: "seam+topo",
  plane_count: 3,
};
