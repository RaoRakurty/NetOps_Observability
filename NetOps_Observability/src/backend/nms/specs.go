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
		"vmanage": {
			Vendor: "vmanage", Product: "Cisco Catalyst SD-WAN Manager", SourceSystem: "vmanage",
			SupportedAuth: []AuthKind{AuthBasic, AuthToken, AuthSession},
			PreferredAuth: AuthToken, // JWT+refresh (≥20.18); session fallback
			Poll:          true,
			Streams:     []string{"alarms", "events", "tunnels", "control_connections", "bfd", "inventory"},
			DefaultPoll: 2 * time.Minute,
		},
		"ndfc": {
			Vendor: "ndfc", Product: "Cisco Nexus Dashboard / NDFC", SourceSystem: "ndfc",
			SupportedAuth: []AuthKind{AuthBasic, AuthToken, AuthAPIKey},
			PreferredAuth: AuthToken, // login → JWT
			Poll:          true,
			Streams:     []string{"fabric_alarms", "switch_health", "interface_alarms", "deployments", "inventory"},
			DefaultPoll: 5 * time.Minute,
		},
		"prime": {
			Vendor: "prime", Product: "Cisco Prime Infrastructure", SourceSystem: "prime",
			SupportedAuth: []AuthKind{AuthBasic}, // legacy: raw Basic only
			PreferredAuth: AuthBasic,
			Poll:          true,
			Streams:     []string{"alarms", "inventory"},
			DefaultPoll: 10 * time.Minute, // conservative (legacy)
			RatePerSec:  2,
		},
		"versa_director": {
			Vendor: "versa_director", Product: "Versa Director", SourceSystem: "versa_director",
			SupportedAuth: []AuthKind{AuthBasic, AuthOAuth},
			PreferredAuth: AuthOAuth,
			Poll:          true,
			Streams:     []string{"alarms", "appliances", "interfaces", "tunnels", "events"},
			DefaultPoll: 5 * time.Minute,
		},
		"versa_concerto": {
			Vendor: "versa_concerto", Product: "Versa Concerto", SourceSystem: "versa_concerto",
			SupportedAuth: []AuthKind{AuthBasic, AuthOAuth},
			PreferredAuth: AuthOAuth,
			Poll:          true,
			Streams:     []string{"tenants", "sase", "policy", "events"},
			DefaultPoll: 5 * time.Minute,
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
