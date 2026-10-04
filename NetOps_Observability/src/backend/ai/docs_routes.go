// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// docs_routes.go — in-app deep links for documentation answers.
//
// A portal page answers with a Help-drawer link (/docs/<slug>#<anchor>). The
// curated concept doc (ai/product_knowledge) and the runbook brief
// (copilot_knowledge.md) are NOT portal pages, so they have no /docs link at
// all — a product answer grounded in them used to carry no link for the reader
// to follow. For those chunks the answer now offers the Correlix page the
// concept lives on ("what is a seam" → the RCA board).
//
// This table came from the retired ProductKB (product_kb.go, removed
// 2026-09-26: production always wired the docs index, so ProductKB was never
// reached). It is deliberately applied to the curated tiers only: its terms
// were chosen for those concept-titled sections, and on the portal corpus a
// generic term would send a reader to the wrong page ("configuration" would
// turn "Configuration drift" into a link to Administration settings). A wrong
// deep link is worse than none.
//
// EVERY ROUTE MUST BE A ROUTE THE SHELL RESOLVES. The SPA router never says
// "not found": an unknown section falls back to the first section and an
// unknown leaf to that section's first page. The routes below are CANONICAL
// "#/<section>/<leaf>" ids taken from src/frontend/src/nav.tsx, and
// docs_routes_links_test.go resolves every one of them through the same nav
// tables the SPA router uses — a leaf id that is renamed or moved fails the
// build here rather than in an answer.

// docRouteRule maps a concept term (one or more words, matched against the
// chunk's folded page and section title terms — every word must be present) to
// a UI deep link.
type docRouteRule struct {
	terms string
	route string
}

// docRouteRules is ORDERED: the first rule whose words all appear wins, so a
// more specific concept precedes a broader one ("discovery" before "snmp",
// because "How to set up SNMP discovery" is done on the discovery page).
var docRouteRules = []docRouteRule{
	// The guided device-troubleshooting workspace, not the RCA board.
	{"troubleshooting", "#/investigate/troubleshooting"},
	{"discovery", "#/admin/discovery"},
	// SNMP credentials/profiles live in Administration → Data sources.
	{"snmp", "#/admin/snmp"},
	// Authentication is PROVIDER-only plumbing and moved to the Platform
	// section in the 2026-09-05 IA (docs/design/ADMIN_IA_2026-09-05.md §2).
	{"sso", "#/platform/auth"},
	{"authentication", "#/platform/auth"},
	{"report", "#/analytics/reports"},
	{"itsm", "#/admin/integrations"},
	{"notification", "#/admin/notifications"},
	// Tenants are a view inside Identity & Access.
	{"tenant", "#/admin/identity"},
	{"configuration", "#/admin/settings"},
	// "Key UI sections" in the runbook brief ("ui" is below the tokenizer's
	// three-letter minimum, so the rule is spelled with the word that counts).
	{"sections", "#/overview/home"},
	{"architecture", "#/investigate/topology"},
	{"incident", "#/operations/incidents"},
	{"correlation", "#/investigate/rca"},
	{"rca", "#/investigate/rca"},
	{"verdict", "#/investigate/rca"},
	{"seam", "#/investigate/rca"},
	{"evidence", "#/investigate/rca"},
}

// docRoute returns the in-app page for a documentation chunk, or "" when there
// is none. Only curated and runbook chunks are mapped (see the file comment).
// Deterministic: the rules are an ordered slice, never a map walk.
func docRoute(c DocChunk) string {
	if c.Tier != DocTierCurated && c.Tier != DocTierRunbook {
		return ""
	}
	have := map[string]bool{}
	for _, t := range docTerms(c.PageTitle + " " + c.SectionTitle) {
		have[t] = true
	}
	for _, r := range docRouteRules {
		words := docTerms(r.terms)
		ok := len(words) > 0
		for _, w := range words {
			if !have[w] {
				ok = false
				break
			}
		}
		if ok {
			return r.route
		}
	}
	return ""
}
