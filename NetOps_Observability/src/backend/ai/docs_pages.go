// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// docs_pages.go — page-aware help (plan N-G3): which documentation describes
// the console page the operator is looking at.
//
// The Iris box sends the current route ("#/operations/alerts") as the ui
// context key "route". Two things use it, and only these two:
//
//  1. a product question asked from a page ranks that page's documentation
//     first among the hits that ALREADY cleared every relevance floor — a boost
//     reorders, it never admits a chunk the question alone would not retrieve;
//  2. "what am I looking at?" / "what is this page?" is answered from that
//     page's own documentation (and its authored `(i)` explanation, when one
//     exists) instead of being guessed from the question's words.
//
// THE ROUTE IS UNTRUSTED CLIENT INPUT (CLAUDE.md §3, §15 LLM01). It is looked up
// in the table below by exact key after a bounded normalisation, and anything
// that is not a key — an unknown page, a legacy alias, a path with a traversal,
// an instruction smuggled into the string — is ignored exactly as if no route
// had been sent. It selects public product documentation only: it never reaches
// a data read, never scopes one, and never widens what the caller may see
// (§3a is untouched: the docs corpus is tenant-free by construction).
//
// EVERY NAV LEAF HAS AN ENTRY. docs_pages_test.go reads src/frontend/src/nav.tsx
// and fails when a leaf has no row here, when a row names a leaf that no longer
// exists, or when a row names a slug or anchor that is not in the embedded
// corpus — so a renamed page or a new screen fails the build, not an answer.
// The same table is the N-G1 coverage list: a leaf's row names the portal
// pages that document it.

import (
	"regexp"
	"strings"
)

// PageRouteContextKey is the ui-context key the Iris box sends the current
// console route under.
const PageRouteContextKey = "route"

// PageHelpIntent is the intent stamped on a "what is this page?" answer.
const PageHelpIntent = "page_help"

// docPageBoost multiplies the score of a chunk from the current page's docs.
// Mild on purpose: it settles close calls toward the page the operator is on,
// and a clearly better answer from another page still wins (pinned by
// TestPageBoostKeepsGoldenRetrieval, which asks every golden question from an
// unrelated page).
const docPageBoost = 1.35

// maxRouteLen bounds the route before any parsing. The longest real route is
// under 50 characters; anything longer is not a route.
const maxRouteLen = 200

// pageDoc names one documentation section. Anchor "" means the whole page.
type pageDoc struct {
	Slug   string
	Anchor string
}

// navPage is the documentation of one console page.
type navPage struct {
	// Label is the console path as the sidebar shows it.
	Label string
	// Docs lists the portal pages that document it, primary first. The
	// primary is what "what is this page?" answers from.
	Docs []pageDoc
	// Explain is the page's authored `(i)` topic (skills/explain), if any.
	Explain string
}

// wholePage is a table shorthand for a pageDoc naming a whole page.
func wholePage(slug string) pageDoc { return pageDoc{Slug: slug} }

// navPageDocs maps a canonical "section/leaf" route (nav.tsx ids) to its docs.
var navPageDocs = map[string]navPage{
	// Overview
	"overview/home":       {Label: "Overview → Home (Command Center)", Docs: []pageDoc{wholePage("dashboards-reports/command-center"), wholePage("noc-guide/where-to-start")}, Explain: "page.command-center"},
	"overview/operations": {Label: "Overview → Operations Overview", Docs: []pageDoc{wholePage("dashboards-reports/operations-overview")}},
	"overview/board":      {Label: "Overview → My Dashboard", Docs: []pageDoc{wholePage("dashboards-reports/my-dashboard")}},

	// Operations
	"operations/incidents":          {Label: "Operations → Incidents", Docs: []pageDoc{wholePage("incidents/working-incidents"), wholePage("incidents/reading-an-incident"), wholePage("incidents/overview")}, Explain: "page.incidents"},
	"operations/alerts":             {Label: "Operations → Active Alerts", Docs: []pageDoc{wholePage("monitoring/manage-alerts")}, Explain: "page.active-alerts"},
	"operations/queue":              {Label: "Operations → Action Queue", Docs: []pageDoc{wholePage("incidents/action-queue")}},
	"operations/digital-experience": {Label: "Operations → Digital Experience", Docs: []pageDoc{wholePage("monitoring/digital-experience")}},
	"operations/cloud":              {Label: "Operations → Cloud", Docs: []pageDoc{wholePage("monitoring/cloud")}},
	"operations/network-health":     {Label: "Operations → Network Health", Docs: []pageDoc{wholePage("monitoring/link-quality")}},
	"operations/rules":              {Label: "Operations → Monitors → Monitor Rules", Docs: []pageDoc{wholePage("monitoring/monitor-rules"), wholePage("reference/alert-rules")}},
	"operations/new":                {Label: "Operations → Monitors → Create Monitor", Docs: []pageDoc{wholePage("monitoring/create-a-monitor")}},
	"operations/maintenance":        {Label: "Operations → Monitors → Maintenance Windows", Docs: []pageDoc{wholePage("monitoring/maintenance-windows")}},

	// Investigate
	"investigate/rca":             {Label: "Investigate → RCA", Docs: []pageDoc{wholePage("investigate/read-an-rca-case"), wholePage("investigate/rca-explained")}},
	"investigate/findings":        {Label: "Investigate → Findings", Docs: []pageDoc{wholePage("investigate/detected-findings")}},
	"investigate/topology":        {Label: "Investigate → Topology", Docs: []pageDoc{wholePage("infrastructure/topology-canvas")}},
	"investigate/flowtrace":       {Label: "Investigate → Paths → Flow Trace", Docs: []pageDoc{wholePage("infrastructure/paths-and-tunnels")}},
	"investigate/tunnels":         {Label: "Investigate → Paths → Tunnels", Docs: []pageDoc{{Slug: "infrastructure/paths-and-tunnels", Anchor: "tunnels"}, wholePage("infrastructure/paths-and-tunnels")}},
	"investigate/wan-paths":       {Label: "Investigate → Paths → WAN Paths", Docs: []pageDoc{wholePage("infrastructure/wan-interface-metrics")}},
	"investigate/troubleshooting": {Label: "Investigate → Troubleshooting", Docs: []pageDoc{wholePage("investigate/investigate-a-symptom"), wholePage("investigate/collect-from-a-device"), wholePage("investigate/protocol-diagnostics"), wholePage("investigate/send-to-tac")}},

	// Infrastructure
	"infrastructure/devices":      {Label: "Infrastructure → Devices", Docs: []pageDoc{wholePage("infrastructure/devices")}, Explain: "page.devices"},
	"infrastructure/applications": {Label: "Infrastructure → Applications", Docs: []pageDoc{wholePage("infrastructure/applications"), wholePage("explore/application-attribution")}},
	"infrastructure/interfaces":   {Label: "Infrastructure → Interfaces & Optics", Docs: []pageDoc{wholePage("infrastructure/interfaces-and-optics")}},
	"infrastructure/sites":        {Label: "Infrastructure → Sites", Docs: []pageDoc{wholePage("infrastructure/geomap"), wholePage("automation/sites-and-inventory")}},
	"infrastructure/wireless":     {Label: "Infrastructure → Wireless", Docs: []pageDoc{wholePage("infrastructure/wireless"), wholePage("infrastructure/review-a-wireless-remediation")}},
	"infrastructure/discovery":    {Label: "Infrastructure → Discovery & NMS", Docs: []pageDoc{wholePage("onboard-devices/snmp-discovery"), wholePage("infrastructure/nms-integrations")}},
	"infrastructure/config-drift": {Label: "Infrastructure → Config Drift", Docs: []pageDoc{wholePage("security/config-drift"), wholePage("security/config-backup")}},
	"infrastructure/sot":          {Label: "Infrastructure → Source of Truth", Docs: []pageDoc{wholePage("automation/sites-and-inventory"), wholePage("automation/import-and-sync")}},

	// Explore
	"explore/metrics": {Label: "Explore → Metrics", Docs: []pageDoc{wholePage("explore/metrics")}},
	"explore/logs":    {Label: "Explore → Logs", Docs: []pageDoc{wholePage("explore/logs"), wholePage("noc-guide/reading-logs")}},
	"explore/flows":   {Label: "Explore → Flows", Docs: []pageDoc{wholePage("explore/flows")}},
	"explore/events":  {Label: "Explore → Events", Docs: []pageDoc{wholePage("explore/events")}},
	"explore/saved":   {Label: "Explore → Saved Searches", Docs: []pageDoc{wholePage("explore/saved-searches")}},

	// Security
	"security/overview":   {Label: "Security → Security Overview", Docs: []pageDoc{wholePage("security/security-overview"), wholePage("security/ctem"), wholePage("security/overview")}},
	"security/exposures":  {Label: "Security → Exposures", Docs: []pageDoc{wholePage("security/exposures"), wholePage("security/investigate-a-finding")}},
	"security/stories":    {Label: "Security → Exposure Stories", Docs: []pageDoc{wholePage("security/exposure-stories")}},
	"security/vuln":       {Label: "Security → Vulnerabilities", Docs: []pageDoc{wholePage("security/vulnerabilities"), wholePage("security/run-a-scan")}},
	"security/threat":     {Label: "Security → Threat Detection", Docs: []pageDoc{wholePage("security/threat-detection"), wholePage("security/packet-capture")}},
	"security/compliance": {Label: "Security → Compliance", Docs: []pageDoc{wholePage("security/compliance")}},
	"security/rules":      {Label: "Security → Configuration → Detection Rules", Docs: []pageDoc{wholePage("security/detection-rules")}},
	"security/views":      {Label: "Security → Configuration → Saved Views", Docs: []pageDoc{wholePage("security/saved-views")}},

	// Analytics
	"analytics/dashboards":            {Label: "Analytics → Dashboards → Dashboard List", Docs: []pageDoc{wholePage("dashboards-reports/built-in-dashboards")}},
	"analytics/demo":                  {Label: "Analytics → Dashboards → Demo Showcase", Docs: []pageDoc{wholePage("dashboards-reports/demo-showcase")}, Explain: "demo.showcase"},
	"analytics/device-monitoring":     {Label: "Analytics → Metric Dashboards → Device Monitoring", Docs: []pageDoc{{Slug: "dashboards-reports/built-in-dashboards", Anchor: "device-metrics"}}},
	"analytics/interface-performance": {Label: "Analytics → Metric Dashboards → Interface Performance", Docs: []pageDoc{{Slug: "dashboards-reports/built-in-dashboards", Anchor: "interface-metrics"}, wholePage("infrastructure/interfaces-and-optics")}},
	"analytics/protocols":             {Label: "Analytics → Metric Dashboards → Protocol Monitoring", Docs: []pageDoc{{Slug: "dashboards-reports/built-in-dashboards", Anchor: "bgp-metrics"}, wholePage("investigate/igp-health"), wholePage("investigate/interfaces-by-routing-instance")}},
	"analytics/bgp-ops":               {Label: "Analytics → Metric Dashboards → BGP Operations", Docs: []pageDoc{wholePage("bgp/overview"), wholePage("bgp/watchlist"), wholePage("bgp/investigate-a-prefix")}},
	"analytics/reports":               {Label: "Analytics → Reports", Docs: []pageDoc{wholePage("dashboards-reports/reports")}},
	"analytics/rca-reports":           {Label: "Analytics → RCA Reports", Docs: []pageDoc{wholePage("dashboards-reports/rca-reports")}},
	"analytics/scorecard":             {Label: "Analytics → Recovery Scorecard", Docs: []pageDoc{wholePage("dashboards-reports/recovery-scorecard"), wholePage("incident-response/rca-time-intelligence")}},

	// Administration (tenant-level)
	"admin/integrations":          {Label: "Administration → Incident Response → Integrations", Docs: []pageDoc{wholePage("incident-response/integrations")}},
	"admin/notifications":         {Label: "Administration → Incident Response → Notifications", Docs: []pageDoc{wholePage("incident-response/notifications")}},
	"admin/ticketing":             {Label: "Administration → Incident Response → Ticketing & Automation", Docs: []pageDoc{wholePage("incident-response/rca-ticketing")}},
	"admin/ticket-delivery":       {Label: "Administration → Incident Response → Ticket Delivery", Docs: []pageDoc{wholePage("incident-response/ticket-delivery")}},
	"admin/datasources":           {Label: "Administration → Data sources → Data Sources", Docs: []pageDoc{wholePage("onboard-devices/data-sources")}},
	"admin/snmp":                  {Label: "Administration → Data sources → SNMP Profiles", Docs: []pageDoc{wholePage("onboard-devices/snmp-profiles"), wholePage("onboard-devices/vendor-snmp-configs")}},
	"admin/sensors":               {Label: "Administration → Data sources → Sensors", Docs: []pageDoc{wholePage("administration/sensors")}},
	"admin/telemetry-coverage":    {Label: "Administration → Data sources → Telemetry Coverage", Docs: []pageDoc{wholePage("administration/telemetry-coverage")}},
	"admin/processors":            {Label: "Administration → Data handling → Processors", Docs: []pageDoc{wholePage("administration/processors")}},
	"admin/sensitive-data-access": {Label: "Administration → Data handling → Sensitive Data Access", Docs: []pageDoc{wholePage("administration/sensitive-data-access")}},
	"admin/identity":              {Label: "Administration → Identity & Access", Docs: []pageDoc{wholePage("administration/identity-access"), wholePage("administration/tenants-orgs"), wholePage("administration/identity-faq")}},
	"admin/access":                {Label: "Administration → Access & Audit → Access Explorer", Docs: []pageDoc{wholePage("administration/access-explorer")}},
	"admin/sessions":              {Label: "Administration → Access & Audit → Sessions", Docs: []pageDoc{wholePage("administration/sessions")}},
	"admin/audit":                 {Label: "Administration → Access & Audit → Audit Log", Docs: []pageDoc{wholePage("administration/audit-log")}},
	"admin/transport":             {Label: "Administration → Access & Audit → Transport Security", Docs: []pageDoc{wholePage("security/transport-security")}},
	"admin/api":                   {Label: "Administration → API Access", Docs: []pageDoc{wholePage("administration/api-access"), wholePage("reference/api")}},
	"admin/settings":              {Label: "Administration → Settings", Docs: []pageDoc{wholePage("administration/system-settings")}},
	"admin/licence":               {Label: "Administration → Licence", Docs: []pageDoc{wholePage("administration/licence"), wholePage("reference/licensing")}},

	// Platform (provider-only)
	"platform/auth":              {Label: "Platform → Security → Authentication", Docs: []pageDoc{wholePage("administration/authentication"), wholePage("administration/okta-sso"), wholePage("administration/tenant-sign-in")}},
	"platform/data-protection":   {Label: "Platform → Security → Data Protection", Docs: []pageDoc{wholePage("administration/data-protection"), wholePage("deploy/back-up-and-restore")}},
	"platform/health":            {Label: "Platform → Tools → Stack Health", Docs: []pageDoc{wholePage("administration/stack-health")}},
	"platform/grafana":           {Label: "Platform → Tools → Self-Monitoring", Docs: []pageDoc{wholePage("administration/self-monitoring")}},
	"platform/opensearch":        {Label: "Platform → Tools → Search Dashboards", Docs: []pageDoc{wholePage("administration/search-dashboards")}},
	"platform/pipeline-debugger": {Label: "Platform → Tools → Pipeline Debugger", Docs: []pageDoc{wholePage("administration/pipeline-debugger"), wholePage("send-data/debug-the-pipeline")}},
	"platform/regions":           {Label: "Platform → Tools → Regions", Docs: []pageDoc{wholePage("administration/regions")}},
	"platform/graphql":           {Label: "Platform → Tools → GraphQL Explorer", Docs: []pageDoc{wholePage("administration/graphql-explorer")}},
	"platform/quarantine":        {Label: "Platform → Tools → Quarantine", Docs: []pageDoc{wholePage("administration/review-quarantined-telemetry")}},
}

// pageRouteKey normalises an untrusted route to a table key, or "" when it is
// not one. Accepted spellings: "operations/alerts", "/operations/alerts",
// "#/operations/alerts", with an optional in-page sub-item and/or ?query
// ("#/operations/cloud/resources?x=1" → "operations/cloud"). Nothing else: the
// result must be an exact key, so no string that is not a known page survives.
func pageRouteKey(raw string) string {
	r := strings.TrimSpace(raw)
	if r == "" || len(r) > maxRouteLen {
		return ""
	}
	r = strings.TrimPrefix(r, "#")
	r = strings.TrimPrefix(r, "/")
	if i := strings.IndexAny(r, "?#"); i >= 0 {
		r = r[:i]
	}
	segs := strings.Split(r, "/")
	if len(segs) < 2 {
		return ""
	}
	key := segs[0] + "/" + segs[1]
	if _, ok := navPageDocs[key]; !ok {
		return ""
	}
	return key
}

// pageForContext resolves the ui context's route to its page, or ok=false when
// the context carries no valid route.
func pageForContext(uiContext map[string]string) (string, navPage, bool) {
	key := pageRouteKey(uiContext[PageRouteContextKey])
	if key == "" {
		return "", navPage{}, false
	}
	return key, navPageDocs[key], true
}

// slugSet is the set of portal slugs a page's docs name (the boost target).
func (p navPage) slugSet() map[string]bool {
	out := make(map[string]bool, len(p.Docs))
	for _, doc := range p.Docs {
		out[doc.Slug] = true
	}
	return out
}

// rePageQuestion recognises a question about the page itself. It is anchored
// at both ends so it matches only the whole question: "what is this page?"
// asks about the page, "what is this page's alert count for spine1?" does not.
var rePageQuestion = regexp.MustCompile(`(?i)^\s*(?:` +
	`what\s+am\s+i\s+(?:looking\s+at|seeing)` +
	`|what(?:\s+is|['’]s)\s+(?:this|the)\s+(?:page|screen|view)(?:\s+(?:for|about|showing\s+me|telling\s+me))?` +
	`|what(?:\s+is|['’]s)\s+on\s+this\s+(?:page|screen)` +
	`|what\s+does\s+this\s+(?:page|screen|view)\s+(?:show|do|mean|tell\s+me)` +
	`|(?:explain|describe)\s+this\s+(?:page|screen|view)` +
	`|how\s+do\s+i\s+(?:use|read)\s+this\s+(?:page|screen|view)` +
	`|help\s+(?:me\s+)?with\s+this\s+(?:page|screen|view)` +
	`|what\s+can\s+i\s+do\s+(?:here|on\s+this\s+(?:page|screen))` +
	`|where\s+am\s+i` +
	`)\s*[?.!]*\s*$`)

// isPageQuestion reports whether a question asks about the current page.
func isPageQuestion(question string) bool {
	return len(question) <= 120 && rePageQuestion.MatchString(question)
}

// maxPageHelpBody bounds the page-help answer body, like the product answer.
const maxPageHelpBody = 1200

// answerPageHelp answers "what am I looking at?" from the current page's own
// documentation. handled=false when the question is not about the page, when
// no valid route came with it, or when the docs index is not wired — the
// classic path then runs unchanged.
func (o *Orchestrator) answerPageHelp(question string, uiContext map[string]string) (Answer, bool) {
	if o.Docs == nil || !isPageQuestion(question) {
		return Answer{}, false
	}
	_, page, ok := pageForContext(uiContext)
	if !ok {
		return Answer{}, false
	}
	primary := page.Docs[0]
	lead, found := o.Docs.chunkFor(primary.Slug, primary.Anchor)
	if !found {
		return Answer{}, false
	}

	var b strings.Builder
	b.WriteString("You are on " + page.Label + ".")
	cites := []Citation{}
	if e, ok := o.Explain.ByTopic(page.Explain); ok && page.Explain != "" {
		b.WriteString(" " + e.Body)
		cites = append(cites, explainCitation(e.Topic, e.File))
	}
	body := lead.Body
	if room := maxPageHelpBody - b.Len(); room > 0 {
		if len(body) > room {
			body = strings.TrimSpace(body[:room]) + " …"
		}
		b.WriteString("\n\n" + body)
	}

	// The lead section first, then every other page the row names, so the
	// reader can open the rest of what documents this screen.
	docCites := []Citation{{ID: lead.ID, Kind: "doc", Label: lead.Breadcrumb, Href: lead.Href}}
	var related []string
	for _, doc := range page.Docs[1:] {
		if c, ok := o.Docs.chunkFor(doc.Slug, doc.Anchor); ok && c.ID != lead.ID {
			docCites = append(docCites, Citation{ID: c.ID, Kind: "doc", Label: c.Breadcrumb, Href: c.Href})
			related = append(related, "See also: "+c.Breadcrumb)
		}
	}
	cites = append(docCites, cites...)
	return Answer{
		Mode: ModeProductAnswer, Intent: PageHelpIntent, Modules: []string{},
		Title: page.Label, Text: b.String(), Citations: cites, NextActions: related,
		Module:       &ModuleHealthSummary{Module: "product_navigation", DisplayName: "Correlix", Headline: page.Label},
		ModeBadges:   []string{"Product help", "This page"},
		Disclaimers:  []string{},
		EvidenceOnly: true,
	}, true
}
