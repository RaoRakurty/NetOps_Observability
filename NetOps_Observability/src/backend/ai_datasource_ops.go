// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"netops/backend/ai"

	"netops/backend/internal/oslog"
)

// ai_datasource_ops.go — the P2 operational reads behind the agent loop's two
// new tools: search_logs (device syslog, OpenSearch) and get_device_health
// (inventory + VictoriaMetrics). Both are ModuleQuery cases on aiDataSource, so
// they inherit the governed-tool contract: fixed query names, caller Principal,
// bounded output. Tenant isolation is enforced the same way the human-facing
// handlers do it — per-tenant index pattern + doc-level osTenantFilter for
// logs, tenant-scoped inventory resolution BEFORE any metrics query for device
// health — never by trusting the model's arguments.

// aiLogWindows is the allowlist for the search_logs lookback (fixed tokens, not
// model-controlled durations — no unbounded scans).
var aiLogWindows = map[string]time.Duration{
	"15m": 15 * time.Minute,
	"1h":  time.Hour,
	"6h":  6 * time.Hour,
	"24h": 24 * time.Hour,
	"7d":  7 * 24 * time.Hour, // widest allowed — results stay capped at 50 lines
}

const (
	aiLogMaxLines   = 50  // plan §3.b: ≤50 redacted lines
	aiLogMaxQueryCh = 256 // bound the model-supplied query text
	aiLogMaxLineCh  = 300 // per-line render cap
)

// redactAILogLine masks secret-ish values AND direct identifiers, then caps the
// line length. The masking itself is ai.Redact — the ONE outbound-DLP dialect
// (ai/redact.go), shared with the orchestrator's grounded prompts and the agent
// loop's rendered tool replies. This function used to own a private secret-KV
// regex that was the only redaction anywhere on the egress path; it now
// contributes only the per-line length cap on top of the shared filter, so
// widening coverage means editing one dialect instead of discovering three.
func redactAILogLine(s string) string {
	s = ai.Redact(s)
	s = strings.TrimSpace(s)
	if len(s) > aiLogMaxLineCh {
		s = s[:aiLogMaxLineCh] + " …"
	}
	return s
}

// moduleSearchLogs — bounded, tenant-scoped device-syslog search for the AI.
// Deliberately restricted to the syslog signal: app logs are platform-internal
// (owner-only) and flows have their own tools, so the AI never needs the "all
// indices" pattern — the narrowest index set that answers the question.
func (d aiDataSource) moduleSearchLogs(p ai.Principal, args ai.ToolArgs) (ai.ToolResult, error) {
	query := strings.TrimSpace(args["query"])
	if len(query) > aiLogMaxQueryCh {
		query = query[:aiLogMaxQueryCh]
	}
	window, ok := aiLogWindows[strings.ToLower(strings.TrimSpace(args["window"]))]
	if !ok {
		window = time.Hour
	}
	end := time.Now().UTC()
	start := end.Add(-window)

	filters := []any{
		map[string]any{"range": map[string]any{"timestamp": map[string]string{
			"gte": start.Format(time.RFC3339), "lte": end.Format(time.RFC3339),
		}}},
	}
	// Same doc-level tenant boundary as the human Logs tab (osTenantFilter):
	// own tagged docs + untagged docs from own devices only.
	keys, _ := d.srv.visibleDeviceKeys(d.claims)
	addrs, _ := d.srv.visibleDeviceAddrs(d.claims)
	if f := oslog.TenantFilter(p.Tenant, p.Cross, keys, addrs); f != nil {
		filters = append(filters, f)
	}
	// Optional device narrowing — a filter clause, never string-built into the
	// query text (the device name is model-supplied data).
	if dev := strings.TrimSpace(args["device"]); dev != "" {
		filters = append(filters, map[string]any{"bool": map[string]any{
			"should": []any{
				map[string]any{"match": map[string]any{"host": dev}},
				map[string]any{"match": map[string]any{"hostname": dev}},
				map[string]any{"match": map[string]any{"device": dev}},
			},
			"minimum_should_match": 1,
		}})
	}
	boolQuery := map[string]any{
		"must": []any{map[string]any{"query_string": map[string]any{
			"query": oslog.QueryOrAll(query), "analyze_wildcard": true,
		}}},
		"filter": filters,
	}
	// Operator-visibility compliance — identical to the human search path.
	if exclude, deny := d.srv.operatorTelemetryRestriction(d.claims, p.Tenant, p.Cross); deny {
		boolQuery["filter"] = append(filters, map[string]any{"match_none": map[string]any{}})
	} else if len(exclude) > 0 {
		boolQuery["must_not"] = []any{map[string]any{"terms": map[string]any{"tenant_id": exclude}}}
	}
	body := map[string]any{
		"size":  aiLogMaxLines,
		"sort":  []any{map[string]any{"timestamp": map[string]string{"order": "desc", "unmapped_type": "date"}}},
		"query": map[string]any{"bool": boolQuery},
	}

	resp, err := openSearch("POST", "/"+oslog.TenantIndexPattern("syslog", p.Tenant, p.Cross)+"/_search", body)
	if err != nil {
		return ai.ToolResult{}, fmt.Errorf("log search unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ai.ToolResult{}, fmt.Errorf("log search unavailable")
	}
	var out struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []struct {
				Source map[string]any `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return ai.ToolResult{}, fmt.Errorf("log search unavailable")
	}
	tr := ai.ToolResult{}
	for i, h := range out.Hits.Hits {
		line := aiFirst(asStr(h.Source["message"]), asStr(h.Source["raw"]), asStr(h.Source["msg"]))
		if line == "" {
			continue
		}
		host := aiFirst(asStr(h.Source["host"]), asStr(h.Source["hostname"]), asStr(h.Source["device"]))
		ts := asStr(h.Source["timestamp"])
		text := redactAILogLine(strings.TrimSpace(strings.Join([]string{ts, host, line}, " ")))
		tr.Items = append(tr.Items, ai.EvidenceItem{
			CitationID: fmt.Sprintf("log:os:%d", i), Kind: "log",
			Text: text, Href: "#/explore/logs",
		})
	}
	if out.Hits.Total.Value > len(tr.Items) {
		tr.Truncated = true
		tr.Notes = append(tr.Notes, fmt.Sprintf("showing the newest %d of %d matching lines", len(tr.Items), out.Hits.Total.Value))
	}
	if len(tr.Items) == 0 {
		tr.Notes = append(tr.Notes, "no matching syslog lines in the window")
	}
	return tr, nil
}

// moduleDeviceHealth — a health snapshot for ONE device the caller may see.
// The device is resolved against the tenant-scoped inventory FIRST; an unknown
// or cross-tenant name returns ErrNotFound (never revealing existence), and the
// metrics queries are then pinned to the resolved device's own id/name labels.
func (d aiDataSource) moduleDeviceHealth(p ai.Principal, name string) (ai.ToolResult, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return ai.ToolResult{}, fmt.Errorf("get_device_health: device required")
	}
	var devID, devName, devVendor, devAddr string
	var lastSeen time.Time
	found := false
	for _, dev := range d.srv.discovery.Devices() {
		if !canSeeDevice(dev, p.Tenant, p.Cross) {
			continue
		}
		if strings.EqualFold(dev.Name, name) || strings.EqualFold(dev.ID, name) {
			devID, devName, devVendor, devAddr, lastSeen = dev.ID, dev.Name, dev.Vendor, dev.Address, dev.LastSeen
			found = true
			break
		}
	}
	if !found {
		return ai.ToolResult{}, ai.ErrNotFound
	}

	href := "#/infrastructure/devices"
	label := aiFirst(devName, devID)
	inv := fmt.Sprintf("%s — inventory: vendor %s, address %s", label, aiFirst(devVendor, "unknown"), aiFirst(devAddr, "unknown"))
	if !lastSeen.IsZero() {
		if age := time.Since(lastSeen); age < 5*time.Minute {
			inv += "; telemetry current (last sample under 5m ago)"
		} else {
			inv += fmt.Sprintf("; last telemetry %s ago", age.Round(time.Minute))
		}
	}
	tr := ai.ToolResult{Items: []ai.EvidenceItem{{
		CitationID: "device:" + devID, Kind: "device", Text: inv, Href: href,
	}}}

	// Metrics snapshot. The or-chain covers the three producer label schemes
	// (device=id for Go collectors, hostname/source=name for Telegraf/gnmic).
	sel := func(metric string) string {
		parts := []string{fmt.Sprintf(`max(%s{device=%q})`, metric, devID)}
		if devName != "" {
			parts = append(parts,
				fmt.Sprintf(`max(%s{hostname=%q})`, metric, devName),
				fmt.Sprintf(`max(%s{source=%q})`, metric, devName))
		}
		return strings.Join(parts, " or ")
	}
	// THREE states, never two (cloud_monitor_eval.go): the metric store did not
	// answer / it answered with no samples / we have a reading. The first two
	// used to share a branch, so a VictoriaMetrics outage reached the model as
	// "this device reports no metrics" — an assistant then says the device is
	// quiet when in truth we never asked successfully (§10, and LLM03: the model
	// must not be handed a confident absence we cannot vouch for).
	storeDown := false
	addMetric := func(cid, metric, format string) {
		samples, err := d.srv.vmInstant(d.ctx, sel(metric))
		if err != nil {
			storeDown = true
			return
		}
		if len(samples) == 0 {
			return // answered: no samples for this metric
		}
		tr.Items = append(tr.Items, ai.EvidenceItem{
			CitationID: cid + ":" + devID, Kind: "metric",
			Text: fmt.Sprintf(format, label, samples[0].Value), Href: href,
		})
	}
	addMetric("metric:cpu", "device_cpu_percent", "%s — CPU %.0f%%")
	addMetric("metric:mem", "device_mem_percent", "%s — memory %.0f%%")
	samples, ifErr := d.srv.vmInstant(d.ctx, fmt.Sprintf(`count(device_if_oper_status{device=%q} != 1)`, devID))
	if ifErr != nil {
		storeDown = true
	} else if len(samples) > 0 && samples[0].Value > 0 {
		tr.Items = append(tr.Items, ai.EvidenceItem{
			CitationID: "metric:ifdown:" + devID, Kind: "metric",
			Text: fmt.Sprintf("%s — %.0f interface(s) operationally down", label, samples[0].Value), Href: href,
		})
	}
	switch {
	case storeDown:
		// No provider/query detail here (LLM06): the model gets the FACT, not our
		// internals.
		tr.Notes = append(tr.Notes, "the metric store did not answer — this device's CPU, memory and interface state are UNKNOWN, not absent")
	case len(tr.Items) == 1:
		tr.Notes = append(tr.Notes, "no recent metric samples for this device — reachability may be down or collection not yet warmed")
	}
	return tr, nil
}
