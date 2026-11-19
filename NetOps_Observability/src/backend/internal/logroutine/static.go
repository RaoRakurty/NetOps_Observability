// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package logroutine

import "strings"

// StaticRoutine reports whether one stored record is routine by the
// ADDRESS-FREE half of Clause: RulePoll or RuleSessionDetail, inside
// management_audit, with no failure word in event_type or audit_action. It is
// the rule the router applies at WRITE time to send a record to the routine
// family (tracker 410, deployment/docker/vector-router/vector.yaml
// syslog_store_route.routine) — the router has no per-tenant address lists, so
// RuleMonitoringSource and RuleControllerSource stay read-time only.
//
// It reads the same package lists Clause renders (sessionDetailTypes,
// sessionDetailPrefixes, failureWords), with the same case rules: audit_via
// and the snmp_ prefix compare case-insensitively (Clause's termCI /
// case_insensitive prefix); event_type terms and the netconf_action_ prefix
// compare exactly (keyword terms, case-sensitive prefix); failure words are
// case-insensitive substrings (Clause's case-insensitive wildcards).
//
// Clause stays the ONE authority on what the Logs page hides: this function
// only decides retention, and tests/fixtures/logroutine/static.json pins it
// and the router's VRL to the same answers.
func StaticRoutine(rec map[string]string) bool {
	if rec["event_category"] != Category {
		return false
	}
	et := rec["event_type"]
	etl := strings.ToLower(et)
	act := strings.ToLower(rec["audit_action"])
	for _, w := range failureWords {
		if strings.Contains(etl, w) || strings.Contains(act, w) {
			return false
		}
	}
	if strings.EqualFold(rec["audit_via"], "snmp") || strings.HasPrefix(etl, "snmp_") {
		return true
	}
	for _, t := range sessionDetailTypes {
		if et == t {
			return true
		}
	}
	for _, p := range sessionDetailPrefixes {
		if strings.HasPrefix(et, p) {
			return true
		}
	}
	return false
}

// StaticLists exposes the write-time rule's vocabularies so the router's VRL
// can be checked against them (tests/test_syslog_routine_split.py reads this
// file's Go source; the function keeps the lists reachable from a Go test).
func StaticLists() (detailTypes, detailPrefixes, failure []string) {
	return append([]string(nil), sessionDetailTypes...),
		append([]string(nil), sessionDetailPrefixes...),
		append([]string(nil), failureWords...)
}
