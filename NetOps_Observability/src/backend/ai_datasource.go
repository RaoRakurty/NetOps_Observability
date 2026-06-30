package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"netops/backend/ai"
)

// ai_datasource.go — the server-side implementation of ai.DataSource. It is the
// ONLY place the AI path touches a store, and every query is tenant-scoped via
// the ClickHouse row policy (chTenantScope), so a non-cross caller can never
// retrieve another tenant's problem (the corr_objects row policy returns 0 rows
// → ErrNotFound, never revealing existence). No DB driver, no SQL, lives in the
// ai package — only here, in the trusted server.
type aiDataSource struct {
	srv   *server
	ctx   context.Context
	scope string // chTenantScope(r) — encodes tenant / __all__ for cross-tenant
}

// GetProblem fetches one correlation object (tenant-scoped) and maps it to the
// ai.Problem the assistant explains. Unknown / cross-tenant id → ErrNotFound.
func (d aiDataSource) GetProblem(_ context.Context, _ ai.Principal, id string) (*ai.Problem, error) {
	if !isUUIDToken(id) {
		return nil, ai.ErrNotFound
	}
	sql := `
SELECT toString(correlation_id) AS correlation_id,
       top_hypothesis, top_confidence, verdict_tier,
       evidence_missing, affected, hypotheses,
       signal_count, node_count,
       toString(created_at) AS created_at
  FROM netops.corr_objects
 WHERE correlation_id = '` + id + `'
 ORDER BY version DESC
 LIMIT 1
 FORMAT JSON`
	rows, err := d.srv.chRowsScope(d.ctx, d.scope, sql)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ai.ErrNotFound // not found OR another tenant's (row policy) — don't reveal
	}
	r := rows[0]
	pr := &ai.Problem{
		ID:              id,
		DisplayID:       problemDisplayID(id),
		Title:           aiProblemTitle(asStr(r["top_hypothesis"]), id),
		Verdict:         asStr(r["verdict_tier"]),
		Confidence:      asFloat(r["top_confidence"]),
		SignalCount:     int(asFloat(r["signal_count"])),
		NodeCount:       int(asFloat(r["node_count"])),
		CreatedAt:       asStr(r["created_at"]),
		Devices:         aiEntityLabels(affectedDevices(r["affected"])),
		MissingEvidence: aiHumanizeMissing(jsonStrings(r["evidence_missing"])),
	}
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
SELECT hypotheses, affected
  FROM netops.corr_objects
 WHERE correlation_id = '` + id + `'
 ORDER BY version DESC
 LIMIT 1
 FORMAT JSON`
	rows, err := d.srv.chRowsScope(d.ctx, d.scope, sql)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ai.ErrNotFound
	}
	href := "#/monitoring/correlations?id=" + id
	var items []ai.EvidenceItem

	// Candidate root-cause hypotheses (bounded to top 5).
	for i, h := range jsonObjects(rows[0]["hypotheses"]) {
		if i >= 5 {
			break
		}
		name := aiFirst(asStr(h["signature"]), asStr(h["hypothesis"]), asStr(h["name"]))
		if name == "" {
			continue
		}
		if strings.HasPrefix(name, "sig.") { // humanize the engine signature to NOC language
			name = signatureNocTitle(name)
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
	// Affected entities — humanized + de-duplicated for NOC readability.
	if devs := aiEntityLabels(affectedDevices(rows[0]["affected"])); len(devs) > 0 {
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
SELECT toString(correlation_id) AS correlation_id,
       top_hypothesis, top_confidence, verdict_tier,
       affected, signal_count, node_count
  FROM netops.corr_objects
 WHERE state = 'open'
 ORDER BY created_at DESC
 LIMIT 1 BY correlation_id
 LIMIT %d
 FORMAT JSON`, limit)
	rows, err := d.srv.chRowsScope(d.ctx, d.scope, sql)
	if err != nil {
		return nil, err
	}
	out := make([]ai.Problem, 0, len(rows))
	for _, r := range rows {
		id := asStr(r["correlation_id"])
		out = append(out, ai.Problem{
			ID:          id,
			DisplayID:   problemDisplayID(id),
			Title:       aiProblemTitle(asStr(r["top_hypothesis"]), id),
			Verdict:     asStr(r["verdict_tier"]),
			Confidence:  asFloat(r["top_confidence"]),
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
func (d aiDataSource) ModuleQuery(_ context.Context, _ ai.Principal, query string, _ ai.ToolArgs) (ai.ToolResult, error) {
	switch query {
	case "top_talkers":
		return d.moduleTopTalkers()
	case "flow_summary":
		return d.moduleFlowSummary()
	case "metric_anomalies":
		return d.moduleMetricAnomalies()
	case "app_identity_summary":
		return d.moduleAppIdentity(false)
	case "low_confidence_apps":
		return d.moduleAppIdentity(true)
	default:
		return ai.ToolResult{}, ai.ErrNotImplemented
	}
}

// moduleAppIdentity summarizes identified applications (App Identification) from
// the tenant-scoped netops.app_identities table. lowConfidence=true narrows to
// weak matches (the "which apps have low identification confidence?" question).
func (d aiDataSource) moduleAppIdentity(lowConfidence bool) (ai.ToolResult, error) {
	having := ""
	if lowConfidence {
		having = "HAVING conf < 0.5"
	}
	sql := `
SELECT app, count() AS flows, round(avg(confidence), 2) AS conf, any(provider) AS provider
  FROM netops.app_identities
 WHERE fused_at >= now() - INTERVAL 24 HOUR AND app != ''
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
	const sql = `
SELECT least(src_addr, dst_addr)  AS a,
       greatest(src_addr, dst_addr) AS b,
       sum(bytes * if(sampling_rate = 0, 1, sampling_rate)) AS bytes_total
  FROM netops.flows
 WHERE ts >= now() - INTERVAL 24 HOUR
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
	const sql = `
SELECT sum(bytes * if(sampling_rate = 0, 1, sampling_rate))   AS bytes_total,
       sum(packets * if(sampling_rate = 0, 1, sampling_rate)) AS packets_total,
       count() AS flows,
       uniqExact(src_addr) AS sources
  FROM netops.flows
 WHERE ts >= now() - INTERVAL 24 HOUR
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
	// NB: don't alias toString(ts) AS ts — a String alias named `ts` collides with
	// the DateTime `ts` in ORDER BY (NO_COMMON_TYPE). ts isn't shown, so omit it.
	const sql = `
SELECT id, severity, score, device, component, summary
  FROM netops.findings
 WHERE kind = 'anomaly' AND ts >= now() - INTERVAL 6 HOUR
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

func asStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", x)
	}
}

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

// affectedDevices extracts device names from the affected field, which is a
// {"devices":[...],"paths":[...]} object (string-encoded or already parsed).
func affectedDevices(v any) []string {
	parse := func(m map[string]any) []string {
		var out []string
		if ds, ok := m["devices"].([]any); ok {
			for _, e := range ds {
				if s := asStr(e); s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	}
	switch x := v.(type) {
	case map[string]any:
		return parse(x)
	case string:
		if strings.TrimSpace(x) == "" {
			return nil
		}
		var m map[string]any
		if json.Unmarshal([]byte(x), &m) == nil {
			return parse(m)
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
