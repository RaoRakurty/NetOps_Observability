// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import "time"

// specs.go — the verified per-vendor connector specifications (auth matrix,
// streams, rate limits). Facts confirmed against current vendor docs, 2026:
//   - Meraki: OAuth 2.0 (GA 2025, auth-code) or API key; 10 req/s per org.
//   - Catalyst Center: Basic → X-Auth-Token (60m); no OAuth.
//   - vManage / Catalyst SD-WAN Mgr: user/pass → JWT+refresh (≥20.18) or
//     session; no OAuth.
//   - NDFC / Nexus Dashboard: user/pass → JWT (20m) or API key; no OAuth.
//   - Prime (legacy): raw Basic only.
//   - Versa Director: Basic or OAuth. Versa Concerto: OAuth.
//
// Per the auth policy: Basic (or API key for Meraki) is always a supported
// path for testing; OAuth is PreferredAuth wherever the vendor supports it.

// Specs returns the built-in connector specifications, keyed by vendor.
func Specs() map[string]ConnectorSpec {
	return map[string]ConnectorSpec{
		"meraki": {
			Vendor: "meraki", Product: "Cisco Meraki Dashboard", SourceSystem: "meraki",
			// Meraki has no username/password; its testing credential is the API key.
			SupportedAuth: []AuthKind{AuthAPIKey, AuthOAuth},
			PreferredAuth: AuthOAuth,
			Webhook:       true, Poll: true,
			Streams:     []string{"alarms", "inventory"},
			DefaultPoll: 5 * time.Minute,
			RatePerSec:  10, // 10 req/s per org (verified)
		},
		"catalyst_center": {
			Vendor: "catalyst_center", Product: "Cisco Catalyst Center", SourceSystem: "catalyst_center",
			SupportedAuth: []AuthKind{AuthBasic, AuthToken},
			PreferredAuth: AuthToken, // Basic exchanged for X-Auth-Token
			Webhook:       true, Poll: true,
			Streams:     []string{"assurance_issues", "inventory", "events"},
			DefaultPoll: 5 * time.Minute,
		},
		"catalyst_9800": {
			Vendor: "catalyst_9800", Product: "Cisco Catalyst 9800 WLC", SourceSystem: "catalyst_9800",
			SupportedAuth: []AuthKind{AuthBasic}, // RESTCONF = HTTP Basic (RFC 8040); no OAuth on IOS-XE
			PreferredAuth: AuthBasic,
			Poll:          true,
			Streams:       []string{"wireless_aps", "wireless_radios", "wireless_wlans", "wireless_clients", "wireless_rf"},
			// Poll budget (#128 report §14): inventory-class streams are cheap;
			// per-client detail deliberately is NOT a stream here. 5 min default
			// keeps a 500-AP estate well under WLC rate limits.
			DefaultPoll: 5 * time.Minute,
			// EVERY capability is doc_claimed (report B7: no live 9800 exists;
			// the ladder is earned, never assumed). Absent = FidelityNone.
			Capabilities: []CapabilityDecl{
				{CapAPInventory, FidelityDocClaimed, 5 * time.Minute, "Cisco-IOS-XE-wireless-access-point-oper: capwap-data"},
				{CapRadioState, FidelityDocClaimed, 5 * time.Minute, "Cisco-IOS-XE-wireless-access-point-oper: radio-oper-data"},
				{CapChannelUtil, FidelityDocClaimed, 5 * time.Minute, "Cisco-IOS-XE-wireless-rrm-oper: rrm-measurement/load"},
				{CapClientSessions, FidelityDocClaimed, 0, "Cisco-IOS-XE-wireless-client-oper: common-oper-data — counts only until Phase 4"},
				{CapAPUplinkMapping, FidelityNone, 0, "not in the wireless oper models — uplink comes from switch-side LLDP/CDP (the rank-1 join)"},
				{CapRoamEvents, FidelityNone, 0, "mobility oper model not yet mapped — do not claim"},
				{CapOnboardingFailures, FidelityNone, 0, "reason detail comes from syslog (Phase 4), not RESTCONF"},
				{CapMLOLinks, FidelityNone, 0, "Wi-Fi 7 MLO oper model not yet mapped — do not claim"},
			},
		},
		"vmanage": {
			Vendor: "vmanage", Product: "Cisco Catalyst SD-WAN Manager", SourceSystem: "vmanage",
			SupportedAuth: []AuthKind{AuthBasic, AuthToken, AuthSession},
			PreferredAuth: AuthToken, // JWT+refresh (≥20.18); session fallback
			Poll:          true,
			Streams:       []string{"alarms", "events", "tunnels", "control_connections", "bfd", "inventory"},
			DefaultPoll:   2 * time.Minute,
		},
		"ndfc": {
			Vendor: "ndfc", Product: "Cisco Nexus Dashboard / NDFC", SourceSystem: "ndfc",
			SupportedAuth: []AuthKind{AuthBasic, AuthToken, AuthAPIKey},
			PreferredAuth: AuthToken, // login → JWT
			Poll:          true,
			Streams:       []string{"fabric_alarms", "switch_health", "interface_alarms", "deployments", "inventory"},
			DefaultPoll:   5 * time.Minute,
		},
		"prime": {
			Vendor: "prime", Product: "Cisco Prime Infrastructure", SourceSystem: "prime",
			SupportedAuth: []AuthKind{AuthBasic}, // legacy: raw Basic only
			PreferredAuth: AuthBasic,
			Poll:          true,
			Streams:       []string{"alarms", "inventory"},
			DefaultPoll:   10 * time.Minute, // conservative (legacy)
			RatePerSec:    2,
		},
		"versa_director": {
			Vendor: "versa_director", Product: "Versa Director", SourceSystem: "versa_director",
			SupportedAuth: []AuthKind{AuthBasic, AuthOAuth},
			PreferredAuth: AuthOAuth,
			Poll:          true,
			Streams:       []string{"alarms", "appliances", "interfaces", "tunnels", "events"},
			DefaultPoll:   5 * time.Minute,
		},
		"versa_concerto": {
			Vendor: "versa_concerto", Product: "Versa Concerto", SourceSystem: "versa_concerto",
			SupportedAuth: []AuthKind{AuthBasic, AuthOAuth},
			PreferredAuth: AuthOAuth,
			Poll:          true,
			Streams:       []string{"tenants", "sase", "policy", "events"},
			DefaultPoll:   5 * time.Minute,
		},
		"generic": {
			Vendor: "generic", Product: "Generic REST/Webhook", SourceSystem: "generic",
			SupportedAuth: []AuthKind{AuthBasic, AuthAPIKey, AuthToken, AuthOAuth},
			PreferredAuth: AuthBasic,
			Webhook:       true, Poll: true,
			Streams:     []string{"events"},
			DefaultPoll: 5 * time.Minute,
		},
	}
}
