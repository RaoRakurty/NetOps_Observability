// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"netops/backend/internal/noclabel"
	"netops/backend/internal/ticketing"
	"strings"

	"netops/backend/ai"
	"netops/backend/internal/chschema"
)

// ai_datasource.go — the server-side implementation of ai.DataSource. It is the
// ONLY place the AI path touches a store. Isolation is TWO layers, both required
// (the CH row policies deliberately share untagged rows to every scope — the
// hybrid model — so the policy alone is NOT sufficient for a scoped caller):
//
//  1. every query rides the caller's tenant_scope (row policy: tagged rows);
//  2. app-layer narrowing for untagged rows — telemetry reads narrow to the
//     principal's own devices (addrTenantClauseFor/deviceTenantCondFor, the same
//     guards the REST surfaces use), and correlation reads are STRICT
//     (corrRowVisible: untagged correlation intel is platform-only — device
//     names are not globally unique, so device-matching would cross-match).
//
// A non-cross caller can never retrieve another tenant's (or the platform's)
// problem: unknown AND foreign ids both yield ErrNotFound, never revealing
// existence. No DB driver, no SQL outside this file's seam.
type aiDataSource struct {
	srv    *server
	ctx    context.Context
	scope  string    // chTenantScope(r) — encodes tenant / __all__ for cross-tenant
	claims jwtClaims // caller claims for OS/VM scoping helpers (visibleDevice*)
}

// corrRowVisible enforces strict tenancy on correlation intel app-side, as
// defense-in-depth alongside the strict corr row policies: a scoped principal
// sees ONLY rows stamped with its own tenant — never untagged (platform) rows.
func (d aiDataSource) corrRowVisible(row map[string]any) bool {
	tenant, cross := principalTenant(d.claims)
	if cross {
		return true
	}
	return asStr(row["tenant_id"]) == tenant
}

// GetProblem fetches one correlation object (tenant-scoped) and maps it to the
// ai.Problem the assistant explains. Unknown / cross-tenant id → ErrNotFound.
func (d aiDataSource) GetProblem(_ context.Context, _ ai.Principal, id string) (*ai.Problem, error) {
	if !isUUIDToken(id) {
		return nil, ai.ErrNotFound
	}
	sql := `
SELECT toString(o.correlation_id) AS correlation_id, tenant_id,
       top_hypothesis, top_confidence, verdict_tier,
       evidence_missing, affected, hypotheses,
       signal_count, node_count,
       ` + chschema.ISO("created_at") + ` AS created_at
  FROM netops.corr_objects AS o
 WHERE o.correlation_id = '` + id + `'
 ORDER BY version DESC
 LIMIT 1
 FORMAT JSON`
	rows, err := d.srv.chRowsScope(d.ctx, d.scope, sql)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 || !d.corrRowVisible(rows[0]) {
		return nil, ai.ErrNotFound // not found OR another tenant's / untagged — don't reveal
	}
	r := rows[0]
	pr := &ai.Problem{
		ID:              id,
		DisplayID:       noclabel.ProblemDisplayID(id),
		Title:           noclabel.ProblemTitle(asStr(r["top_hypothesis"]), id),
		Verdict:         asStr(r["verdict_tier"]),
		Confidence:      asFloat(r["top_confidence"]),
		SignalCount:     int(asFloat(r["signal_count"])),
		NodeCount:       int(asFloat(r["node_count"])),
		CreatedAt:       asStr(r["created_at"]),
		Devices:         noclabel.Entities(affectedDevices(r["affected"])),
		MissingEvidence: noclabel.HumanizeMissing(jsonStrings(r["evidence_missing"])),
	}
	// v1 NOC catalog voice contract: the matched signature's own operator
	// wording + lexical confidence label ride the hypotheses blob — the AI
	// narrates the engine's phrase instead of re-deriving a cause statement.
	pr.OperatorPhrase, pr.ConfidenceLabel = ai.TopHypothesisVoice(r["hypotheses"])
	return pr, nil
}

// GetProblemEvidence derives bounded, cited evidence items for the problem from
// its candidate hypotheses + affected entities (already in the object — no extra
// heavy query). Each item carries a stable citation id + a UI deep link.
func (d aiDataSource) GetProblemEvidence(_ context.Context, p ai.Principal, id string) ([]ai.EvidenceItem, error) {
	if !isUUIDToken(id) {
		return nil, ai.ErrNotFound
	}
	sql := `
SELECT hypotheses, affected, tenant_id
  FROM netops.corr_objects
 WHERE correlation_id = '` + id + `'
 ORDER BY version DESC
 LIMIT 1
 FORMAT JSON`
	rows, err := d.srv.chRowsScope(d.ctx, d.scope, sql)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 || !d.corrRowVisible(rows[0]) {
		return nil, ai.ErrNotFound
	}
	href := "#/monitoring/correlations?id=" + id
	var items []ai.EvidenceItem

	// Candidate root-cause hypotheses + evidence basis (modalities, controller
	// corroboration, contradictions) from the engine's ranking blob.
	if hyps := ai.ParseRankedHypotheses(rows[0]["hypotheses"]); len(hyps) > 0 {
		items = append(items, ai.RankedHypothesisItems(id, href, hyps)...)
	} else {
		// Legacy pre-v1 blob: a bare array of {signature|hypothesis|name, score}.
		for i, h := range jsonObjects(rows[0]["hypotheses"]) {
			if i >= 5 {
				break
			}
			name := aiFirst(asStr(h["signature"]), asStr(h["hypothesis"]), asStr(h["name"]))
			if name == "" {
				continue
			}
			if strings.HasPrefix(name, "sig.") { // humanize the engine signature to NOC language
				name = noclabel.SignatureTitle(name)
			}
			text := "candidate cause: " + name
			if sc := asFloat(h["score"]); sc > 0 {
				text += fmt.Sprintf(" (score %.2f)", sc)
			}
			items = append(items, ai.EvidenceItem{
				CitationID: fmt.Sprintf("hypothesis:%s:%d", shortID(id), i),
				Kind:       "finding", Text: text, Href: href,
			})
		}
	}
	// Affected entities — humanized + de-duplicated for NOC readability.
	if devs := noclabel.Entities(affectedDevices(rows[0]["affected"])); len(devs) > 0 {
		items = append(items, ai.EvidenceItem{
			CitationID: "affected:" + shortID(id), Kind: "topology",
			Text: "impacted entities: " + strings.Join(devs, ", "), Href: href,
		})
	}
	return items, nil
}

// ListActiveProblems returns the tenant-scoped recent correlation problems
// (newest first) for the Command Center summary (P2). Bounded by limit; the
// corr_objects row policy keeps it to the caller's tenant.
func (d aiDataSource) ListActiveProblems(_ context.Context, _ ai.Principal, limit int) ([]ai.Problem, error) {
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	sql := fmt.Sprintf(`
SELECT toString(o.correlation_id) AS correlation_id, tenant_id,
       top_hypothesis, top_confidence, verdict_tier,
       affected, signal_count, node_count
  FROM netops.corr_objects AS o
 WHERE state = 'open'
 ORDER BY created_at DESC
 LIMIT 1 BY o.correlation_id
 LIMIT %d
 FORMAT JSON`, limit)
	rows, err := d.srv.chRowsScope(d.ctx, d.scope, sql)
	if err != nil {
		return nil, err
	}
	out := make([]ai.Problem, 0, len(rows))
	for _, r := range rows {
		if !d.corrRowVisible(r) {
			continue // strict: untagged correlation intel is platform-only
		}
		id := asStr(r["correlation_id"])
		out = append(out, ai.Problem{
			ID:          id,
			DisplayID:   noclabel.ProblemDisplayID(id),
			Title:       noclabel.ProblemTitle(asStr(r["top_hypothesis"]), id),
			Verdict:     asStr(r["verdict_tier"]),
			Confidence:  asFloat(r["top_confidence"]),
			SignalCount: int(asFloat(r["signal_count"])),
			NodeCount:   int(asFloat(r["node_count"])),
			Devices:     affectedDevices(r["affected"]),
		})
	}
	return out, nil
}

// corrPartitionSkewSlackSeconds widens a created_at bound that exists only to
// let ClickHouse prune daily partitions (corr_objects is partitioned by
// toYYYYMMDD(created_at), see chschema/corr_repartition.go).
//
// An object is persisted at or after its window opens, so `window_start >= X`
// normally implies `created_at >= X` and the extra predicate is redundant — but
// window_start is EVENT time off device clocks and created_at is now64() on the
// engine host, so a device an hour into the future could otherwise make the
// redundant bound drop a row the query is supposed to return. A full day of
// slack costs one extra daily partition and makes the predicate provably
// non-narrowing for any clock skew short of 24 h.
const corrPartitionSkewSlackSeconds = 86400

// ListProblemsInWindow implements the WindowDataSource seam: correlation problems
// whose onset falls in the past window, tenant-scoped via the corr_objects row
// policy. NOT filtered to open, so a time-range summary can distinguish still-open
// from resolved. One row per correlation (latest version).
func (d aiDataSource) ListProblemsInWindow(_ context.Context, _ ai.Principal, sinceSeconds int) ([]ai.Problem, error) {
	if sinceSeconds <= 0 {
		sinceSeconds = 12 * 3600
	}
	sql := fmt.Sprintf(`
SELECT toString(o.correlation_id) AS correlation_id, tenant_id,
       top_hypothesis, top_confidence, verdict_tier, state,
       affected, signal_count, node_count
  FROM netops.corr_objects AS o
 WHERE window_start >= now() - INTERVAL %d SECOND
   AND created_at >= now() - INTERVAL %d SECOND
 ORDER BY window_start DESC
 LIMIT 1 BY o.correlation_id
 LIMIT 1000
 FORMAT JSON`, sinceSeconds, sinceSeconds+corrPartitionSkewSlackSeconds)
	rows, err := d.srv.chRowsScope(d.ctx, d.scope, sql)
	if err != nil {
		return nil, err
	}
	out := make([]ai.Problem, 0, len(rows))
	for _, r := range rows {
		if !d.corrRowVisible(r) {
			continue // strict: untagged correlation intel is platform-only
		}
		id := asStr(r["correlation_id"])
		out = append(out, ai.Problem{
			ID:          id,
			DisplayID:   noclabel.ProblemDisplayID(id),
			Title:       noclabel.ProblemTitle(asStr(r["top_hypothesis"]), id),
			Verdict:     asStr(r["verdict_tier"]),
			Confidence:  asFloat(r["top_confidence"]),
			State:       asStr(r["state"]),
			SignalCount: int(asFloat(r["signal_count"])),
			NodeCount:   int(asFloat(r["node_count"])),
			Devices:     affectedDevices(r["affected"]),
		})
	}
	return out, nil
}

// ModuleQuery is the server-side ModuleDataSource seam (HLD P4). It maps a FIXED,
// allowlisted query name (chosen by the AI tool, never by the model) to exactly
// ONE tenant-scoped ClickHouse read, so a module-aware answer ("top talkers",
// "metric anomalies") is grounded in the caller's own data. Isolation is the
// netops.flows / netops.findings tenant_iso row policy via d.scope (a non-cross
// caller sees only its own + untagged rows). Unknown query → ErrNotImplemented;
// no data → empty result (honest, not an error).
func (d aiDataSource) ModuleQuery(_ context.Context, p ai.Principal, query string, args ai.ToolArgs) (ai.ToolResult, error) {
	switch query {
	case "top_talkers":
		return d.moduleTopTalkers()
	case "flow_summary":
		return d.moduleFlowSummary()
	case "service_flow_summary":
		return d.moduleServiceFlows()
	case "metric_anomalies":
		return d.moduleMetricAnomalies()
	case "app_identity_summary":
		return d.moduleAppIdentity(false)
	case "low_confidence_apps":
		return d.moduleAppIdentity(true)
	case "integration_health":
		return d.moduleIntegrationHealth(p)
	case "ticket_status":
		return d.moduleTicketStatus(p, args["problem_id"])
	case "search_logs":
		return d.moduleSearchLogs(p, args)
	case "device_health":
		return d.moduleDeviceHealth(p, args["device"])
	default:
		return ai.ToolResult{}, ai.ErrNotImplemented
	}
}

// moduleServiceFlows — top destination services (by well-known port) over the
// recent window: the "what services are busiest / app-to-DB" read. Tenant-scoped
// by the flows row policy via d.scope.
func (d aiDataSource) moduleServiceFlows() (ai.ToolResult, error) {
	clause, empty := d.srv.addrTenantClauseFor(d.claims, "src_addr", "dst_addr")
	if empty {
		return ai.ToolResult{}, nil // no visible devices — honest empty, never platform data
	}
	sql := `
SELECT dst_port AS port,
       sum(bytes * if(sampling_rate = 0, 1, sampling_rate)) AS bytes_total,
       count() AS flows
  FROM netops.flows
 WHERE ts >= now() - INTERVAL 24 HOUR AND dst_port > 0` + clause + `
 GROUP BY port
 ORDER BY bytes_total DESC
 LIMIT 8
 FORMAT JSON`
	rows, err := d.srv.chRowsScope(d.ctx, d.scope, sql)
	if err != nil {
		return ai.ToolResult{}, err
	}
	items := make([]ai.EvidenceItem, 0, len(rows))
	for i, r := range rows {
		port := int(asFloat(r["port"]))
		label := servicePortLabel(port)
		items = append(items, ai.EvidenceItem{
			CitationID: fmt.Sprintf("flow:svc:%d", i), Kind: "flow",
			Text: fmt.Sprintf("%s (port %d) — %s over 24h, %s flows",
				label, port, humanBytes(asFloat(r["bytes_total"])), humanCount(asFloat(r["flows"]))),
			Href: "#/flows",
		})
	}
	return ai.ToolResult{Items: items}, nil
}

// moduleIntegrationHealth — connector configuration health (ServiceNow/Jira/
// Slack/…), tenant-scoped via the integration store (p.Tenant/Cross). Read-only.
func (d aiDataSource) moduleIntegrationHealth(p ai.Principal) (ai.ToolResult, error) {
	if d.srv.integrations == nil {
		return ai.ToolResult{}, nil
	}
	cfgs, err := d.srv.integrations.ListConfigs(d.ctx, p.Tenant, p.Cross)
	if err != nil {
		return ai.ToolResult{}, err
	}
	items := make([]ai.EvidenceItem, 0, len(cfgs))
	for _, c := range cfgs {
		state := "configured"
		if !c.Enabled {
			state = "disabled"
		}
		items = append(items, ai.EvidenceItem{
			CitationID: "integration:" + c.Provider, Kind: "integration",
			Text: fmt.Sprintf("%s — %s", c.Provider, state),
			Href: "#/incident/integrations",
		})
	}
	return ai.ToolResult{Items: items}, nil
}

// moduleTicketStatus — the ITSM ticket(s) linked to one problem, used to enrich
// an RCA explanation ("is there a ticket, what state?"). Tenant-scoped via the
// ticketing store; empty (not error) when nothing is linked. problem_id is the
// tool arg supplied on the problem-explanation path.
func (d aiDataSource) moduleTicketStatus(p ai.Principal, problemID string) (ai.ToolResult, error) {
	if d.srv.ticketing == nil || problemID == "" {
		return ai.ToolResult{}, nil
	}
	audit, _, err := d.srv.ticketing.ListAudit(d.ctx, p.Tenant, p.Cross, problemID, ticketing.AuditDefaultPage, 0)
	if err != nil {
		return ai.ToolResult{}, nil // degrade quietly — ticket status is enrichment, not core
	}
	if len(audit) == 0 {
		return ai.ToolResult{}, nil
	}
	last := audit[len(audit)-1]
	sys := aiFirst(last.ExternalSystem, "ITSM")
	state := aiFirst(last.NewStatus, last.Action)
	text := fmt.Sprintf("ITSM: %s ticket linked — latest action %q, state %s", sys, last.Action, state)
	return ai.ToolResult{Items: []ai.EvidenceItem{{
		CitationID: "ticket:" + shortID(problemID), Kind: "ticket",
		Text: text, Href: "#/incident/rca-ticketing",
	}}}, nil
}

// servicePortLabel maps a well-known port to a service name (customer-facing,
// not raw "port 3306"). Unknown ports keep the numeric form via the caller.
func servicePortLabel(port int) string {
	switch port {
	case 443:
		return "HTTPS"
	case 80:
		return "HTTP"
	case 53:
		return "DNS"
	case 3306:
		return "MySQL"
	case 5432:
		return "PostgreSQL"
	case 1433:
		return "SQL Server"
	case 1521:
		return "Oracle DB"
	case 6379:
		return "Redis"
	case 27017:
		return "MongoDB"
	case 22:
		return "SSH"
	case 25, 587:
		return "SMTP"
	case 389, 636:
		return "LDAP"
	case 3389:
		return "RDP"
	default:
		return "service"
	}
}

// moduleAppIdentity summarizes identified applications (App Identification) from
// the tenant-scoped netops.app_identities table. lowConfidence=true narrows to
// weak matches (the "which apps have low identification confidence?" question).
func (d aiDataSource) moduleAppIdentity(lowConfidence bool) (ai.ToolResult, error) {
	clause, empty := d.srv.addrTenantClauseFor(d.claims, "src_ip", "dst_ip")
	if empty {
		return ai.ToolResult{}, nil
	}
	having := ""
	if lowConfidence {
		having = "HAVING conf < 0.5"
	}
	sql := `
SELECT app, count() AS flows, round(avg(confidence), 2) AS conf, any(provider) AS provider
  FROM netops.app_identities
 WHERE fused_at >= now() - INTERVAL 24 HOUR AND app != ''` + clause + `
 GROUP BY app
 ` + having + `
 ORDER BY flows DESC
 LIMIT 10
 FORMAT JSON`
	rows, err := d.srv.chRowsScope(d.ctx, d.scope, sql)
	if err != nil {
		return ai.ToolResult{}, err
	}
	items := make([]ai.EvidenceItem, 0, len(rows))
	for i, r := range rows {
		app, conf := asStr(r["app"]), asFloat(r["conf"])
		text := fmt.Sprintf("%s — %s flows, %.0f%% identification confidence", app, humanCount(asFloat(r["flows"])), conf*100)
		if prov := asStr(r["provider"]); prov != "" {
			text += " (" + prov + ")"
		}
		items = append(items, ai.EvidenceItem{
			CitationID: fmt.Sprintf("appid:%d", i), Kind: "app",
			Text: text, Href: "#/monitoring/appobs",
		})
	}
	return ai.ToolResult{Items: items}, nil
}

// moduleTopTalkers — the heaviest conversations (bidirectional pairs) over the
// recent window, sampling-rate corrected, tenant-scoped.
func (d aiDataSource) moduleTopTalkers() (ai.ToolResult, error) {
	clause, empty := d.srv.addrTenantClauseFor(d.claims, "src_addr", "dst_addr")
	if empty {
		return ai.ToolResult{}, nil
	}
	sql := `
SELECT least(src_addr, dst_addr)  AS a,
       greatest(src_addr, dst_addr) AS b,
       sum(bytes * if(sampling_rate = 0, 1, sampling_rate)) AS bytes_total
  FROM netops.flows
 WHERE ts >= now() - INTERVAL 24 HOUR` + clause + `
 GROUP BY a, b
 ORDER BY bytes_total DESC
 LIMIT 8
 FORMAT JSON`
	rows, err := d.srv.chRowsScope(d.ctx, d.scope, sql)
	if err != nil {
		return ai.ToolResult{}, err
	}
	items := make([]ai.EvidenceItem, 0, len(rows))
	for i, r := range rows {
		a, b := asStr(r["a"]), asStr(r["b"])
		items = append(items, ai.EvidenceItem{
			CitationID: fmt.Sprintf("flow:talker:%d", i), Kind: "flow",
			Text: fmt.Sprintf("%s ↔ %s — %s over 24h", a, b, humanBytes(asFloat(r["bytes_total"]))),
			Href: "#/flows",
		})
	}
	return ai.ToolResult{Items: items}, nil
}

// moduleFlowSummary — one-line traffic totals over the recent window.
func (d aiDataSource) moduleFlowSummary() (ai.ToolResult, error) {
	clause, empty := d.srv.addrTenantClauseFor(d.claims, "src_addr", "dst_addr")
	if empty {
		return ai.ToolResult{}, nil
	}
	sql := `
SELECT sum(bytes * if(sampling_rate = 0, 1, sampling_rate))   AS bytes_total,
       sum(packets * if(sampling_rate = 0, 1, sampling_rate)) AS packets_total,
       count() AS flows,
       uniqExact(src_addr) AS sources
  FROM netops.flows
 WHERE ts >= now() - INTERVAL 24 HOUR` + clause + `
 FORMAT JSON`
	rows, err := d.srv.chRowsScope(d.ctx, d.scope, sql)
	if err != nil {
		return ai.ToolResult{}, err
	}
	if len(rows) == 0 || asFloat(rows[0]["flows"]) == 0 {
		return ai.ToolResult{}, nil // honest empty — no flow data in window
	}
	r := rows[0]
	return ai.ToolResult{Items: []ai.EvidenceItem{{
		CitationID: "flow:summary", Kind: "flow",
		Text: fmt.Sprintf("24h flow volume: %s across %s flows from %d sources",
			humanBytes(asFloat(r["bytes_total"])), humanCount(asFloat(r["flows"])), int(asFloat(r["sources"]))),
		Href: "#/flows",
	}}}, nil
}

// moduleMetricAnomalies — recent detected metric anomalies (z-score findings),
// worst-first, tenant-scoped via the findings row policy.
func (d aiDataSource) moduleMetricAnomalies() (ai.ToolResult, error) {
	cond, empty := d.srv.deviceTenantCondFor(d.claims, "device")
	if empty {
		return ai.ToolResult{}, nil
	}
	if cond != "" {
		cond = " AND " + cond
	}
	// NB: don't alias toString(ts) AS ts — a String alias named `ts` collides with
	// the DateTime `ts` in ORDER BY (NO_COMMON_TYPE). ts isn't shown, so omit it.
	sql := `
SELECT id, severity, score, device, component, summary
  FROM netops.findings
 WHERE kind = 'anomaly' AND ts >= now() - INTERVAL 6 HOUR` + cond + `
 ORDER BY score DESC, ts DESC
 LIMIT 10
 FORMAT JSON`
	rows, err := d.srv.chRowsScope(d.ctx, d.scope, sql)
	if err != nil {
		return ai.ToolResult{}, err
	}
	items := make([]ai.EvidenceItem, 0, len(rows))
	seen := map[string]bool{} // collapse identical anomaly lines (the engine writes repeats)
	for _, r := range rows {
		dev, comp := asStr(r["device"]), asStr(r["component"])
		text := aiFirst(asStr(r["summary"]), comp+" on "+dev)
		if sev := asStr(r["severity"]); sev != "" {
			text = "[" + sev + "] " + text
		}
		if seen[text] {
			continue
		}
		seen[text] = true
		items = append(items, ai.EvidenceItem{
			CitationID: "finding:" + asStr(r["id"]), Kind: "metric",
			Text: text, Href: "#/monitoring/findings",
		})
	}
	return ai.ToolResult{Items: items}, nil
}

// humanCount renders large counts compactly (humanBytes lives in dependency_view.go).
func humanCount(v float64) string {
	switch {
	case v >= 1e9:
		return fmt.Sprintf("%.1fB", v/1e9)
	case v >= 1e6:
		return fmt.Sprintf("%.1fM", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.1fk", v/1e3)
	default:
		return fmt.Sprintf("%.0f", v)
	}
}

// ---- small JSON/value helpers (ClickHouse FORMAT JSON yields any-typed cells) ----

// jsonStrings parses a value that is either a JSON array string or already a
// []any into a []string (e.g. evidence_missing).
func jsonStrings(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s := asStr(e); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if strings.TrimSpace(x) == "" {
			return nil
		}
		var arr []string
		if json.Unmarshal([]byte(x), &arr) == nil {
			return arr
		}
	}
	return nil
}

func jsonObjects(v any) []map[string]any {
	switch x := v.(type) {
	case []any:
		out := make([]map[string]any, 0, len(x))
		for _, e := range x {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	case string:
		if strings.TrimSpace(x) == "" {
			return nil
		}
		var arr []map[string]any
		if json.Unmarshal([]byte(x), &arr) == nil {
			return arr
		}
	}
	return nil
}

func aiFirst(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func shortID(id string) string {
	if i := strings.IndexByte(id, '-'); i > 0 {
		return id[:i]
	}
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// ── Wireless seam (#128 Phase 6 — ai.WirelessDataSource) ─────────────────────
//
// Reads ride the SAME tenant-enforced wireless store the REST surface uses
// (mem tenant-keyed / PG FORCE-RLS; TestWirelessCrossTenantIsolation), scoped
// by the caller's claims — never the scope string. Projections are PII-free
// by construction: no client MAC, username or session data crosses this seam.

func (d aiDataSource) ListWirelessAPs(ctx context.Context, _ ai.Principal, limit int) ([]ai.WirelessAPSummary, error) {
	if d.srv.wireless == nil {
		return nil, nil
	}
	tenant, cross := principalTenant(d.claims)
	aps, err := d.srv.wireless.ListAPs(ctx, tenant, cross)
	if err != nil {
		return nil, err
	}
	if limit > 0 && len(aps) > limit {
		aps = aps[:limit]
	}
	out := make([]ai.WirelessAPSummary, 0, len(aps))
	for _, ap := range aps {
		down := 0
		for _, r := range ap.Radios {
			if r.OperState == "down" {
				down++
			}
		}
		out = append(out, ai.WirelessAPSummary{
			Name: aiFirst(ap.Name, ap.APID), Model: ap.Model, SiteID: ap.SiteID,
			ControllerRef: ap.ControllerRef,
			RadioCount:    len(ap.Radios), RadiosDown: down, Stale: ap.Stale,
			UplinkSwitch: ap.UplinkSwitchRef, UplinkPort: ap.UplinkPortRef,
		})
	}
	return out, nil
}

func (d aiDataSource) ListWirelessControllers(ctx context.Context, _ ai.Principal) ([]ai.WirelessControllerSummary, error) {
	if d.srv.wireless == nil {
		return nil, nil
	}
	tenant, cross := principalTenant(d.claims)
	cs, err := d.srv.wireless.ListControllers(ctx, tenant, cross)
	if err != nil {
		return nil, err
	}
	aps, err := d.srv.wireless.ListAPs(ctx, tenant, cross)
	if err != nil {
		return nil, err
	}
	apCount := map[string]int{}
	for _, ap := range aps {
		apCount[ap.ControllerRef]++
	}
	out := make([]ai.WirelessControllerSummary, 0, len(cs))
	for _, c := range cs {
		out = append(out, ai.WirelessControllerSummary{
			Name: aiFirst(c.Name, c.ControllerID), Vendor: c.Vendor,
			ClusterRole: string(c.ClusterRole), Visibility: c.Visibility,
			Members: len(c.Members), APCount: apCount[c.ControllerID], Stale: c.Stale,
		})
	}
	return out, nil
}
