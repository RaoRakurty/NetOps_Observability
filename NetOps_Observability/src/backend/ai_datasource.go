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
		Title:           aiFirst(asStr(r["top_hypothesis"]), "Correlation "+shortID(id)),
		Verdict:         asStr(r["verdict_tier"]),
		Confidence:      asFloat(r["top_confidence"]),
		SignalCount:     int(asFloat(r["signal_count"])),
		NodeCount:       int(asFloat(r["node_count"])),
		CreatedAt:       asStr(r["created_at"]),
		Devices:         affectedDevices(r["affected"]),
		MissingEvidence: jsonStrings(r["evidence_missing"]),
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
		text := "candidate cause: " + name
		if sc := asFloat(h["score"]); sc > 0 {
			text += fmt.Sprintf(" (score %.2f)", sc)
		}
		items = append(items, ai.EvidenceItem{
			CitationID: fmt.Sprintf("hypothesis:%s:%d", shortID(id), i),
			Kind:       "finding", Text: text, Href: href,
		})
	}
	// Affected entities.
	if devs := affectedDevices(rows[0]["affected"]); len(devs) > 0 {
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
			Title:       aiFirst(asStr(r["top_hypothesis"]), "Correlation "+shortID(id)),
			Verdict:     asStr(r["verdict_tier"]),
			Confidence:  asFloat(r["top_confidence"]),
			SignalCount: int(asFloat(r["signal_count"])),
			NodeCount:   int(asFloat(r["node_count"])),
			Devices:     affectedDevices(r["affected"]),
		})
	}
	return out, nil
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
