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
  CorrObject, SecCompliance, SecFacets, SecFinding, SecFindingsPage,
  SecFrameworkCatalog, SecPosture, SecRule, SecSavedView, SecTrend, Seam,
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
    // a screen green or be counted as a clean control. Its status_detail is the
    // provider's REASON (secbus attrs.status_detail), not narrative colour.
    id: "doc-4", native_id: "nat-4", severity: "", status: "NotApplicable", status_id: 4,
    evidence_class: "posture", control_title: "AAA / TACACS+ posture", control: "NDM-4.1",
    resource: { uid: "d-fw-01", name: "fw-01" },
    observed: "", intended: "", remediation: "", standards: [], evidence_ref: undefined,
    status_detail: "SR Linux has no telnet server in its model — SSHv2 only",
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

// ── /api/security/rules — the CONTRACT PIN ──────────────────────────────────
//
// RULES above is a hand-written illustrative set. These two are the real wire
// bodies, copied from the running backend, and they exist because the page once
// white-screened on a shape no fixture covered:
//
//  · RULES_WIRE is what the API serves TODAY (mitre as an ARRAY, omitted on a
//    rule that carries none). It is typed SecRule[], so a client-type change
//    that drifts from the served body fails the TypeScript build, and
//    secapi/rules_test.go's golden test pins the same bytes on the server side.
//  · RULES_WIRE_LEGACY is the BROKEN body a production backend actually
//    returned — `mitre` as a bare string. It is deliberately `unknown[]`
//    because it does NOT satisfy SecRule: it is the regression input, kept so
//    the page can be proven to survive the exact payload that took it down.
export const RULES_WIRE: SecRule[] = [
  { rule_id: "bootp-server", family: "hardening", enabled: true, fidelity: "high", seam_aware: false },
  { rule_id: "exposure-ssh", family: "exposure", enabled: true, fidelity: "high", seam_aware: true },
  { rule_id: "flow-beaconing", family: "threat", enabled: true, fidelity: "medium", mitre: ["T1071"], seam_aware: false },
  { rule_id: "log-logging-disabled", family: "threat", enabled: true, fidelity: "high", mitre: ["T1562.001"], seam_aware: false },
];

export const RULES_WIRE_LEGACY: unknown[] = [
  { rule_id: "bootp-server", family: "hardening", enabled: true, fidelity: "high", seam_aware: false },
  { rule_id: "exposure-ssh", family: "exposure", enabled: true, fidelity: "high", seam_aware: true },
  { rule_id: "flow-beaconing", family: "threat", enabled: true, fidelity: "medium", mitre: "T1071", seam_aware: false },
  { rule_id: "log-logging-disabled", family: "threat", enabled: true, fidelity: "high", mitre: "T1562.001", seam_aware: false },
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

/**
 * The unassessed slice, one entry per REASON the producer can state, plus the
 * one that states none. These are the exact strings the hardening engine emits
 * (internal/hardening/engine.go) — the fixture is the contract between the
 * producer's wording and what the screens promise to show.
 */
export const UNASSESSED_FINDINGS: SecFinding[] = [
  finding({
    id: "u-1", native_id: "u-1", status: "Unknown", status_id: 0, severity: "high",
    evidence_class: "posture", control_title: "No NTP time source configured",
    raw_rule_id: "no-ntp-server", resource: { uid: "spine1", name: "spine1", platform: "nokia SR Linux" },
    observed: "", intended: "", remediation: "", evidence_ref: undefined, seam: undefined,
    status_detail: "running-config unavailable — control not assessed (fail-closed)",
  }),
  finding({
    id: "u-2", native_id: "u-2", status: "Unknown", status_id: 0, severity: "high",
    evidence_class: "posture", control_title: "Management TLS profile does not authenticate the client",
    raw_rule_id: "tls-no-client-auth", resource: { uid: "spine2", name: "spine2", platform: "nokia SR Linux" },
    observed: "", intended: "", remediation: "", evidence_ref: undefined, seam: undefined,
    status_detail: "running-config unavailable — control not assessed (fail-closed)",
  }),
  finding({
    id: "u-3", native_id: "u-3", status: "NotApplicable", status_id: 4, severity: "",
    evidence_class: "posture", control_title: "Telnet permitted on management lines",
    raw_rule_id: "telnet-vty-enabled", resource: { uid: "spine1", name: "spine1", platform: "nokia SR Linux" },
    observed: "", intended: "", remediation: "", evidence_ref: undefined, seam: undefined,
    status_detail: "SR Linux has no telnet server in its model — SSHv2 only",
  }),
  finding({
    id: "u-4", native_id: "u-4", status: "Unknown", status_id: 0, severity: "info",
    evidence_class: "posture", control_title: "Device platform unresolved — no hardening control assessed",
    raw_rule_id: "platform-unresolved", resource: { uid: "mystery", name: "mystery", platform: "acme WidgetOS 1.0" },
    observed: "acme WidgetOS 1.0", intended: "", remediation: "", evidence_ref: undefined, seam: undefined,
    status_detail: 'unassessed: platform unresolved — the platform label "acme WidgetOS 1.0" matches no vendor profile, so NO hardening control was evaluated for this device',
  }),
  finding({
    // A provider that stated NO reason — the case the UI must NOT paper over.
    id: "u-5", native_id: "u-5", status: "Unknown", status_id: 0, severity: "",
    evidence_class: "posture", control_title: "Legacy check from an older producer",
    raw_rule_id: "legacy", resource: { uid: "d-old-01", name: "old-01" },
    observed: "", intended: "", remediation: "", evidence_ref: undefined, seam: undefined,
    status_detail: undefined,
  }),
];

export const UNASSESSED_PAGE: SecFindingsPage = {
  items: UNASSESSED_FINDINGS, next_cursor: null, total: UNASSESSED_FINDINGS.length,
};

/**
 * The framework catalogue as a tenant that has NOT chosen reads it: the shipped
 * default set on (NIST 800-53 + CIS Controls), the regulatory three off, and the
 * benchmarks in their own list with the citation join onto controls.
 *
 * The awkward parts are the point: one benchmark whose section taxonomy was
 * never verified (so nothing may cite it), and a framework whose scope this
 * platform cannot fully evidence.
 */
export const FRAMEWORK_CATALOG: SecFrameworkCatalog = {
  configured: false,
  frameworks: [
    {
      id: "nist-800-53-r5", name: "NIST SP 800-53 Rev5", version: "Rev 5 (Release 5.2.0)",
      source: "base", default_on: true, enabled: true,
      scope: "The control catalogue this platform models directly.",
    },
    {
      id: "cis-controls-v8", name: "CIS Controls v8.1", version: "8.1",
      source: "projection-of-800-53", default_on: true, enabled: true,
      scope: "The vendor-neutral CIS Critical Security Controls.",
    },
    {
      id: "hipaa-security-rule", name: "HIPAA Security Rule", version: "45 CFR 164.312",
      source: "projection-of-800-53", default_on: false, enabled: false,
      scope: "The §164.312 technical safeguards only.",
    },
    {
      id: "pci-dss-v4", name: "PCI DSS v4.0.1", version: "4.0.1",
      source: "projection-of-800-53", default_on: false, enabled: false,
      scope: "The PCI DSS technical requirements a network device is in scope for.",
    },
  ],
  benchmarks: [
    {
      id: "cis-cisco-ios-xe-17", title: "CIS Cisco IOS XE 17.x Benchmark", version: "v2.2.1",
      platform: "Cisco IOS-XE 17.x", sections_verified: true,
    },
    {
      id: "cis-arista-eos", title: "CIS Arista EOS Benchmark", version: "v1.0.0",
      platform: "Arista EOS", sections_verified: false,
      note: "Its section taxonomy could not be read from a published document, so no rule cites a section of it.",
    },
  ],
  benchmark_citations: [
    {
      rule_id: "telnet-vty-enabled", benchmark_id: "cis-cisco-ios-xe-17", section: "1.2",
      title: "Access Rules", controls: ["AC-17", "SC-8"],
      label: "CIS Cisco IOS XE 17.x Benchmark v2.2.1 §1.2 Access Rules",
    },
  ],
};

/**
 * One scorecard with a real verdict and one with NOTHING assessed — the pair
 * that proves an unassessed framework renders its sentence rather than 0%.
 */
export const COMPLIANCE: SecCompliance = {
  configured: false,
  enabled: ["nist-800-53-r5", "cis-controls-v8"],
  assessed_findings: 1,
  current_findings: 1,
  frameworks: [
    {
      framework: "NIST SP 800-53 Rev5", version: "Rev 5 (Release 5.2.0)",
      controls_in_scope: 4, controls_with_check: 2, coverage_percent: 50,
      assessed: 2, passed: 1, warned: 0, failed: 1, unassessed: 0,
      verdict_id: 3, verdict: "Fail", score_percent: 50,
      caption: "Evidence, not certification.",
      controls: [
        {
          control_id: "AC-17", family: "AC", title: "Remote Access", has_check: true,
          status_id: 3, status: "Fail", findings: 1,
          requirements: [{ framework: "NIST SP 800-53 Rev5", requirement_id: "AC-17", title: "Remote Access" }],
        },
        {
          control_id: "SC-8", family: "SC", title: "Transmission Confidentiality and Integrity",
          has_check: true, status_id: 1, status: "Pass", findings: 1,
          requirements: [{ framework: "NIST SP 800-53 Rev5", requirement_id: "SC-8" }],
        },
        {
          control_id: "SI-7", family: "SI", title: "Software, Firmware, and Information Integrity",
          has_check: false, status_id: 0, status: "Unknown", findings: 0, requirements: [],
        },
        {
          control_id: "AU-2", family: "AU", title: "Event Logging", has_check: true,
          status_id: 0, status: "Unknown", findings: 0, requirements: [],
        },
      ],
    },
    {
      framework: "CIS Controls v8.1", version: "8.1",
      controls_in_scope: 3, controls_with_check: 1, coverage_percent: 33.3,
      assessed: 0, passed: 0, warned: 0, failed: 0, unassessed: 1,
      verdict_id: 0, verdict: "Unknown", score_percent: null,
      caption: "Evidence, not certification.",
      note: "No assessed control maps to this framework yet — this is an absence of assessment, not a passing or failing result.",
      controls: [
        {
          control_id: "CM-7", family: "CM", title: "Least Functionality", has_check: true,
          status_id: 0, status: "Unknown", findings: 0,
          requirements: [{ framework: "CIS Controls v8.1", requirement_id: "CIS-4" }],
        },
      ],
    },
  ],
};
