// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package logroutine decides which log records are ROUTINE MANAGEMENT
// SESSIONS: the sessions monitoring systems and SD-WAN controllers open on a
// device all day. The Logs page hides them by default and offers a toggle
// (owner decision 2026-11-11), the same pattern the flows views use for
// Correlix's own polling traffic (internal/flownames/platform.go).
//
// Why: on the lab, 96 % of a 12-minute syslog sample (10,617 lines) was
// event_category=management_audit from the SD-WAN edges: SNMP sessions that our
// own polls open on the edge's ConfD (they arrive through the edge's local snmpd
// proxy, so their source reads 127.0.0.1), their group and close lines, and the
// NETCONF/SSH sessions the vManage controller opens from its system IP. They are
// real records and are never deleted; they drown everything else on the page.
//
// # Where the classification is computed
//
// The per-record facts are computed ONCE, at parse time, by the vendor packs
// (telemetry-catalog/vendor-packs/standard.yaml and cisco_sdwan.yaml):
// `event_category`, `event_type`, `audit_via`, `audit_source`, `audit_action`.
// They are mapped keyword fields on netops-syslog-* (index-templates.json), so
// the rule below is a structured term query, never a regex over message text.
//
// Only the POLICY is applied at query time: which addresses belong to
// automated systems. Those addresses are configuration that changes after the
// record was stored (an integration is added, the appliance moves), so baking
// them into each document would freeze a stale answer. Applying them at read
// time also classifies every document stored since the packs started
// stamping these fields (tracker 387 PR 11) with no reindex.
//
// # The rule
//
// A record is routine when it is event_category=management_audit, carries no
// failure word in event_type or audit_action, and one of these holds:
//
//   - RulePoll: an SNMP session (audit_via=snmp) or an SNMP agent poll record
//     (event_type snmp_*). SNMP is a polling protocol: it never carries an
//     interactive login. Its refusals are security_audit, never routine.
//   - RuleMonitoringSource: a session on a machine interface (SNMP, NETCONF,
//     RESTCONF, gNMI, gRPC) whose source is one of Correlix's own addresses
//     (CX_PLATFORM_ADDRESSES and the probers' PATH_GRAPH_VANTAGE_ADDRESSES).
//     An SSH or CLI session from Correlix's address is NOT routine: a person
//     using Correlix's device terminal arrives from that address.
//   - RuleControllerSource: a session on a machine interface, or an sshd
//     login line, whose source is an address of the caller's own SD-WAN
//     controller nodes (the controller integration's inventory: vManage,
//     vSmart and vBond system IPs, and the integration's own address). A
//     person using the controller's SSH terminal still shows: ConfD logs that
//     session as `via cli` and IOS XE as %SEC_LOGIN-5-LOGIN_SUCCESS, neither of
//     which is routine.
//   - RuleSessionDetail: a step INSIDE a management session that names no
//     source of its own (groups assigned, session closed, NETCONF RPC,
//     NETCONF notification or action, PAM session opened/closed). The record
//     that OPENED the session is classified on its own merits, so a person's
//     login is always visible even when the steps after it are folded away.
//
// # Always visible
//
// security_audit (snmp_auth_failed_community and every other refusal), any
// record whose event_type or audit_action names a failure, every interactive
// login (`via cli`, SSH logins from anywhere but a controller, IOS XE
// LOGIN_SUCCESS), ssh_banner_probe, and every record without
// event_category=management_audit.
//
// # Documents without the fields
//
// A document stored before the packs classified management records has no
// event_category, so it is never routine and is always shown. That is the
// safe direction: an old record is never hidden on a guess.
package logroutine
