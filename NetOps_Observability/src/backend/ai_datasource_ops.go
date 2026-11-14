// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"netops/backend/ai"

	"netops/backend/internal/flownames"
	"netops/backend/internal/flowquery"
	"netops/backend/internal/logroutine"
	nlqast "netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/plan"
	"netops/backend/internal/oslog"
	"netops/backend/internal/srcauthority"
	"netops/backend/models"
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
	out, err := d.syslogSearch(p, syslogSpec{
		query: query, start: end.Add(-window), end: end,
		deviceText:     strings.TrimSpace(args["device"]),
		includeRoutine: strings.EqualFold(strings.TrimSpace(args["include_routine"]), "true"),
		size:           aiLogMaxLines,
		auditPath:      "/api/ai/tools/search_logs", auditAction: "ai.search_logs",
	})
	if err != nil {
		return ai.ToolResult{}, err
	}
	tr := ai.ToolResult{}
	for i, h := range out.hits {
		line := aiFirst(asStr(h["message"]), asStr(h["raw"]), asStr(h["msg"]))
		if line == "" {
			continue
		}
		host := aiFirst(asStr(h["host"]), asStr(h["hostname"]), asStr(h["device"]))
		ts := asStr(h["timestamp"])
		text := redactAILogLine(strings.TrimSpace(strings.Join([]string{ts, host, line}, " ")))
		tr.Items = append(tr.Items, ai.EvidenceItem{
			CitationID: fmt.Sprintf("log:os:%d", i), Kind: "log",
			Text: text, Href: "#/explore/logs",
		})
	}
	if out.total > len(tr.Items) {
		tr.Truncated = true
		tr.Notes = append(tr.Notes, fmt.Sprintf("showing the newest %d of %d matching lines", len(tr.Items), out.total))
	}
	tr.Notes = append(tr.Notes, out.routineNote(true)...)
	if len(tr.Items) == 0 {
		tr.Notes = append(tr.Notes, "no matching syslog lines in the window")
	}
	return tr, nil
}

// syslogSpec is one bounded syslog read. The tool path may carry free text
// (query) and a model-supplied device name (matched as data, never parsed);
// the NL path carries only resolved device ids and names and closed severity
// and topic values.
type syslogSpec struct {
	query          string
	start, end     time.Time
	deviceText     string
	deviceIDs      []string
	deviceNames    []string
	severities     []string
	topics         []string
	includeRoutine bool
	size           int
	auditPath      string
	auditAction    string
}

// syslogOut is what a read returned.
type syslogOut struct {
	hits           []map[string]any
	total          int
	routine        int
	routineCounted bool
	includeRoutine bool
}

// routineNote is what an answer says about the routine management sessions;
// withHint adds how to read them (the tool path only).
func (o syslogOut) routineNote(withHint bool) []string {
	switch {
	case !o.routineCounted || o.routine == 0:
		return nil
	case o.includeRoutine:
		return []string{fmt.Sprintf("includes %d routine management-session lines (monitoring polls and controller sessions)", o.routine)}
	case withHint:
		return []string{fmt.Sprintf("left out %d routine management-session lines (monitoring polls and controller sessions); search again with include_routine=true to read them", o.routine)}
	}
	return []string{fmt.Sprintf("left out %d routine management-session lines (monitoring polls and controller sessions)", o.routine)}
}

// logTopicEventTypes maps each closed log topic (nlquery ast.LogTopics) to the
// event-type families it matches. The server owns these patterns: a model can
// name a topic, never write a pattern (TestEveryLogTopicHasPatterns pins the
// two lists equal).
var logTopicEventTypes = map[string][]string{
	"bgp":       {"*bgp*"},
	"ospf":      {"*ospf*"},
	"isis":      {"*isis*"},
	"bfd":       {"*bfd*"},
	"interface": {"*link*", "*interface*", "*lineproto*", "*updown*"},
	"tunnel":    {"*tunnel*", "*ipsec*", "*ike*"},
	"control":   {"*control*", "*omp*"},
	"auth":      {"*auth*", "*login*", "*logout*", "ssh_*"},
	"config":    {"*config*", "*commit*"},
	"cpu":       {"*cpu*"},
	"memory":    {"*mem*"},
	"ntp":       {"*ntp*", "*clock*"},
	"dns":       {"*dns*"},
	"snmp":      {"*snmp*"},
}

// syslogSearch runs one syslog read with the same tenant boundary, operator
// restriction and routine-session handling as the human Logs tab, and audits
// it (who, what was asked, how many lines — never a line).
func (d aiDataSource) syslogSearch(p ai.Principal, sp syslogSpec) (syslogOut, error) {
	filters := []any{
		map[string]any{"range": map[string]any{"timestamp": map[string]string{
			"gte": sp.start.UTC().Format(time.RFC3339), "lte": sp.end.UTC().Format(time.RFC3339),
		}}},
	}
	// Same doc-level tenant boundary as the human Logs tab (osTenantFilter):
	// own tagged docs + untagged docs from own devices only.
	// "Own devices" means identities no other owner holds (tracker 370).
	claim, _ := d.srv.untaggedClaimFor(d.claims)
	if f := oslog.TenantFilter(p.Tenant, p.Cross, claim.Keys, claim.Addrs); f != nil {
		filters = append(filters, f)
	}
	// Optional device narrowing — a filter clause, never string-built into the
	// query text (the device name is model-supplied data).
	if sp.deviceText != "" {
		filters = append(filters, map[string]any{"bool": map[string]any{
			"should": []any{
				map[string]any{"match": map[string]any{"host": sp.deviceText}},
				map[string]any{"match": map[string]any{"hostname": sp.deviceText}},
				map[string]any{"match": map[string]any{"device": sp.deviceText}},
			},
			"minimum_should_match": 1,
		}})
	}
	// Resolved devices (NL): exact ids and their inventory names.
	if len(sp.deviceIDs)+len(sp.deviceNames) > 0 {
		should := []any{}
		if len(sp.deviceIDs) > 0 {
			should = append(should, map[string]any{"terms": map[string]any{"device_id": sp.deviceIDs}})
		}
		if len(sp.deviceNames) > 0 {
			should = append(should,
				map[string]any{"terms": map[string]any{"host": sp.deviceNames}},
				map[string]any{"terms": map[string]any{"hostname": sp.deviceNames}})
		}
		filters = append(filters, map[string]any{"bool": map[string]any{"should": should, "minimum_should_match": 1}})
	}
	if len(sp.severities) > 0 {
		filters = append(filters, map[string]any{"terms": map[string]any{"normalized_severity": sp.severities}})
	}
	if len(sp.topics) > 0 {
		var should []any
		for _, t := range sp.topics {
			for _, pat := range logTopicEventTypes[t] {
				should = append(should, map[string]any{"wildcard": map[string]any{"event_type": map[string]any{"value": pat, "case_insensitive": true}}})
			}
		}
		if len(should) == 0 {
			// An unknown topic matches nothing, never everything.
			should = append(should, map[string]any{"match_none": map[string]any{}})
		}
		filters = append(filters, map[string]any{"bool": map[string]any{"should": should, "minimum_should_match": 1}})
	}
	boolQuery := map[string]any{
		"must": []any{map[string]any{"query_string": map[string]any{
			"query": oslog.QueryOrAll(sp.query), "analyze_wildcard": true,
		}}},
		"filter": filters,
	}
	// Operator-visibility compliance — identical to the human search path.
	exclude, deny := d.srv.operatorTelemetryRestriction(d.claims, p.Tenant, p.Cross)
	if deny {
		boolQuery["filter"] = append(filters, map[string]any{"match_none": map[string]any{}})
	} else if len(exclude) > 0 {
		boolQuery["must_not"] = []any{map[string]any{"terms": map[string]any{"tenant_id": exclude}}}
	}
	body := map[string]any{
		"size":  sp.size,
		"sort":  []any{map[string]any{"timestamp": map[string]string{"order": "desc", "unmapped_type": "date"}}},
		"query": map[string]any{"bool": boolQuery},
	}
	// Routine management sessions (monitoring polls, SD-WAN controller
	// sessions; internal/logroutine) are most of a managed estate's syslog —
	// about 96 % on the lab (2026-11-13). Left in, the newest lines Iris reads
	// are all polls and the question goes unanswered. They are left out the
	// way the Logs page leaves them out (only ever ANDed out, so the class can
	// never widen what the caller reads), counted, and said so;
	// includeRoutine keeps them for a question about sessions.
	out := syslogOut{includeRoutine: sp.includeRoutine, routineCounted: !deny}
	if out.routineCounted {
		src := d.srv.routineSourcesCtx(d.ctx, d.claims)
		body["aggs"] = map[string]any{logroutine.AggName: logroutine.Agg(src)}
		if !sp.includeRoutine {
			body["post_filter"] = logroutine.Exclusion(src)
		}
	}

	resp, err := openSearch("POST", "/"+oslog.TenantIndexPattern("syslog", p.Tenant, p.Cross)+"/_search", body)
	if err != nil {
		return syslogOut{}, fmt.Errorf("log search unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return syslogOut{}, fmt.Errorf("log search unavailable")
	}
	var raw struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []struct {
				Source map[string]any `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
		Aggregations map[string]struct {
			DocCount int `json:"doc_count"`
		} `json:"aggregations"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&raw); err != nil {
		return syslogOut{}, fmt.Errorf("log search unavailable")
	}
	out.total = raw.Hits.Total.Value
	for _, h := range raw.Hits.Hits {
		out.hits = append(out.hits, h.Source)
	}
	if out.routineCounted {
		out.routine = raw.Aggregations[logroutine.AggName].DocCount
	}
	// A read of device syslog on the caller's behalf, audited like the human one:
	// who, what was asked and how many lines it got, never a line.
	if d.srv.audit != nil {
		d.srv.audit.Record(AuditEvent{
			Actor: d.claims.Sub, Tenant: p.Tenant, Cross: p.Cross, SessionID: d.claims.Sid,
			Method: auditMethodLogRead, Path: sp.auditPath, Status: http.StatusOK, Decision: "allow",
			Detail: map[string]any{
				"action": sp.auditAction, "signal": "syslog", "query": auditQueryText(sp.query),
				"window": sp.end.Sub(sp.start).String(), "matched": out.total, "rows": len(out.hits),
				"severities": sp.severities, "topics": sp.topics, "devices": len(sp.deviceIDs),
				"routine_mgmt": out.routine, "include_routine_mgmt": sp.includeRoutine,
			},
		})
	}
	return out, nil
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
	var dev models.Device
	found := false
	for _, cand := range d.srv.discovery.Devices() {
		if !canSeeDevice(cand, p.Tenant, p.Cross) {
			continue
		}
		if strings.EqualFold(cand.Name, name) || strings.EqualFold(cand.ID, name) {
			dev, found = cand, true
			break
		}
	}
	if !found {
		return ai.ToolResult{}, ai.ErrNotFound
	}
	devID, devName, lastSeen := dev.ID, dev.Name, dev.LastSeen

	href := "#/infrastructure/devices"
	label := aiFirst(devName, devID)
	// N-F6: every descriptive fact is stated with the source it came from,
	// decided by the applicable source order across EVERY source that reports
	// this device — never the merged row's silent gap-fill.
	facts := d.srv.deviceFactsFor(d.ctx, dev, p.Tenant, p.Cross)
	inv := label + " — inventory: " + deviceInventoryText(facts, dev.Address)
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
	if txt := deviceDisagreementText(facts); txt != "" {
		// Its own citable item, so an answer that relies on a contested
		// fact can cite where the disagreement is stated.
		tr.Items = append(tr.Items, ai.EvidenceItem{
			CitationID: "device:" + devID + ":sources", Kind: "device", Text: label + " — " + txt, Href: href,
			Contested: srcauthority.ContestedValues(facts.Resolutions),
		})
	}
	if facts.PolicyFailed {
		tr.Notes = append(tr.Notes, "this workspace's source order could not be read, so the platform default order was used to choose between sources")
	}

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
	// The caller's device boundary rides on every read below. The selectors are
	// already pinned to the ONE device canSeeDevice cleared above, but a pin is
	// the handler remembering; extra_filters[] is VictoriaMetrics enforcing, and
	// it is the same boundary /api/metrics/query applies.
	mf := d.srv.metricsScopeFiltersFor(d.claims)
	storeDown := false
	addMetric := func(cid, metric, format string) {
		samples, err := d.srv.vmInstantScoped(d.ctx, sel(metric), mf)
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
	samples, ifErr := d.srv.vmInstantScoped(d.ctx, fmt.Sprintf(`count(device_if_oper_status{device=%q} != 1)`, devID), mf)
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

// deviceInventoryText is the inventory clause of the device item: each
// resolved fact with its winning source, then the management address (an
// identity, not a resolved fact). Device-supplied values are cleaned
// (srcauthority.Clean) — plain text the SPA renders escaped (§15).
func deviceInventoryText(f deviceFacts, addr string) string {
	parts := make([]string, 0, len(f.Resolutions)+2)
	have := map[srcauthority.Fact]bool{}
	for _, r := range f.Resolutions {
		parts = append(parts, srcauthority.FactText(r))
		have[r.Fact] = true
	}
	if !have[srcauthority.FactVendor] {
		parts = append([]string{"vendor unknown"}, parts...)
	}
	parts = append(parts, "address "+aiFirst(srcauthority.Clean(addr, srcauthority.MaxValueRunes), "unknown"))
	return strings.Join(parts, ", ")
}

// deviceDisagreementText states every fact the sources disagree on — the
// value used, the source and order that decided it, and what each other
// source said. "" when every source agreed (or only one reported).
func deviceDisagreementText(f deviceFacts) string {
	var out []string
	for _, r := range f.Resolutions {
		if t := srcauthority.DisagreementText(r, f.Order, f.Customized); t != "" {
			out = append(out, t)
		}
	}
	return strings.Join(out, " ")
}

// ── Iris flow tools with link and window arguments (tracker 406) ─────────────
//
// get_top_talkers, get_flow_summary and get_service_flow_summary read the same
// ClickHouse statements the NL flow_top query does (internal/flowquery
// tool_sql.go). Their optional arguments are model-supplied data, so each is
// validated before anything reaches SQL:
//
//   - device: a name, id or address of a device the caller can SEE; anything
//     else is ai.ErrNotFound (a foreign device and a missing one look alike,
//     §3a) and no query runs. Only the inventory's own address reaches SQL.
//   - interface: an index, or a name the interface-name export knows for that
//     device; it needs its device.
//   - window (15m/1h/6h/24h/7d) or from+to (≤ 7 days); neither is the last
//     24 hours, as before the tools took arguments.
//
// With a device the scope is the Flows page's stricter link rule (tracker 400
// decision (a): own rows, or rows whose exporter is the caller's unambiguous
// address). Correlix's own monitoring traffic is left out, as on the page
// (decision (c)), and each answer says so; the Href opens the page on the same
// device, interface and window.

// aiFlowScope is one flow tool call's validated scope.
type aiFlowScope struct {
	win      flowquery.Window
	clause   string // " AND …": tenant/link scope, device and interface, platform exclusion
	where    string // " on cEdge-80" / " on cEdge-80 interface Gi1", or ""
	exporter string // the device's flow address, "" for the whole view
	ifIndex  uint32
	notes    []string
}

// aiFlowDevice finds the one visible device a model-supplied device argument
// names (name, id or address, case-insensitive). ambiguous: more than one
// visible device carries it.
func (d aiDataSource) aiFlowDevice(arg string) (dev models.Device, found, ambiguous bool) {
	arg = strings.TrimSpace(arg)
	addr := flownames.NormAddr(arg)
	n := 0
	for _, c := range d.srv.visibleDevicesFor(d.claims) {
		if strings.EqualFold(c.Name, arg) || strings.EqualFold(c.ID, arg) ||
			(addr != "" && flownames.NormAddr(c.Address) == addr) {
			if n == 0 {
				dev = c
			}
			n++
		}
	}
	return dev, n == 1, n > 1
}

// aiFlowScopeFor validates a flow tool's arguments into a scope. empty=true
// means the caller can see no flow rows for it (no visible device, or the
// device has no flow address); notes still say why.
func (d aiDataSource) aiFlowScopeFor(args ai.ToolArgs) (sc aiFlowScope, empty bool, err error) {
	win, err := flowquery.ParseToolWindow(args["window"], args["from"], args["to"], time.Now())
	if err != nil {
		return sc, false, fmt.Errorf("%w: %v", ai.ErrBadArgs, err)
	}
	sc.win = win
	devArg, ifArg := strings.TrimSpace(args["device"]), strings.TrimSpace(args["interface"])
	if ifArg != "" && devArg == "" {
		return sc, false, fmt.Errorf("%w: interface needs its device", ai.ErrBadArgs)
	}
	if devArg == "" {
		clause, none := d.srv.flowTenantClauseFor(d.claims)
		if none {
			return sc, true, nil
		}
		sc.clause = clause
	} else {
		dev, found, ambiguous := d.aiFlowDevice(devArg)
		if ambiguous {
			return sc, false, fmt.Errorf("%w: %q names more than one device; use the device id", ai.ErrBadArgs, devArg)
		}
		if !found {
			return sc, false, ai.ErrNotFound // never reveal another tenant's device (§3a)
		}
		label := aiFirst(dev.Name, dev.ID)
		exporter := flownames.NormAddr(dev.Address)
		if exporter == "" {
			sc.notes = append(sc.notes, label+" has no IP address in inventory, so no flow record can be matched to it")
			return sc, true, nil
		}
		clause, none := d.srv.flowLinkTenantClauseFor(d.claims)
		if none {
			return sc, true, nil
		}
		sc.clause = clause + " AND sampler_address = " + flowquery.Quote(exporter)
		sc.where, sc.exporter = " on "+label, exporter
		if ifArg != "" {
			ix, ok := d.aiFlowIfIndex(dev, exporter, ifArg)
			if !ok {
				return sc, false, fmt.Errorf("%w: %q is not an interface Correlix knows on %s; use its index", ai.ErrBadArgs, ifArg, label)
			}
			sc.clause += " AND " + flowquery.Link{Exporter: exporter, IfIndex: ix}.IfCond(flowquery.DirBoth)
			sc.ifIndex = ix
			name, named := d.srv.ifaceNames.Lookup(deviceTenant(dev), exporter, ix)
			if !named {
				name, named = d.srv.ifaceNames.Lookup("", exporter, ix)
			}
			if named {
				sc.where += " interface " + name
			} else {
				sc.where += fmt.Sprintf(" interface index %d", ix)
			}
		}
	}
	if c := platformAddrsFromEnv().SQLCond(); c != "" {
		sc.clause += " AND NOT " + c
		sc.notes = append(sc.notes, "Correlix's own monitoring traffic is left out, as on the Flows page")
	}
	return sc, false, nil
}

// aiFlowIfIndex reads an interface argument: an index, or a name the
// interface-name export holds for this device (its own tenant first, then the
// untagged rows). An ambiguous name is refused, never guessed.
func (d aiDataSource) aiFlowIfIndex(dev models.Device, exporter, arg string) (uint32, bool) {
	if ix, err := flowquery.ParseIfIndex(arg); err == nil {
		return ix, true
	}
	if ix, ok := d.srv.ifaceNames.IndexOf(deviceTenant(dev), exporter, arg); ok {
		return ix, true
	}
	return d.srv.ifaceNames.IndexOf("", exporter, arg)
}

// href is the Flows page deep link for the scope's device, interface and window.
func (sc aiFlowScope) href(tab string) string {
	return flowquery.DeepLink(tab, sc.exporter, sc.ifIndex, sc.win)
}

// finish attaches the scope's notes and the sampling basis to a result.
func (sc aiFlowScope) finish(tr ai.ToolResult, flows, rateReported float64) ai.ToolResult {
	tr.Notes = append(tr.Notes, sc.notes...)
	if n := flowquery.SamplingNote(flowquery.SamplingOf(flows, rateReported)); n != "" {
		tr.Notes = append(tr.Notes, n)
	}
	return tr
}

// moduleTopTalkers — the heaviest conversations (unordered address pairs).
func (d aiDataSource) moduleTopTalkers(args ai.ToolArgs) (ai.ToolResult, error) {
	sc, empty, err := d.aiFlowScopeFor(args)
	if err != nil || empty {
		return ai.ToolResult{Notes: sc.notes}, err
	}
	rows, err := d.srv.chRowsScope(d.ctx, d.scope, flowquery.TalkersSQL(sc.win, sc.clause, 8))
	if err != nil {
		return ai.ToolResult{}, err
	}
	var flows, rated float64
	items := make([]ai.EvidenceItem, 0, len(rows))
	for i, r := range rows {
		flows += asFloat(r["flows"])
		rated += asFloat(r["rate_reported"])
		items = append(items, ai.EvidenceItem{
			CitationID: fmt.Sprintf("flow:talker:%d", i), Kind: "flow",
			Text: fmt.Sprintf("%s ↔ %s — %s over %s%s", asStr(r["a"]), asStr(r["b"]),
				humanBytes(asFloat(r["bytes_total"])), sc.win.Phrase(), sc.where),
			Href: sc.href(flowquery.TabTalking),
		})
	}
	tr := ai.ToolResult{Items: items}
	if len(items) == 0 {
		tr.Notes = append(tr.Notes, "no flow records"+sc.where+" in "+sc.win.Phrase())
	}
	return sc.finish(tr, flows, rated), nil
}

// moduleFlowSummary — one line of traffic totals.
func (d aiDataSource) moduleFlowSummary(args ai.ToolArgs) (ai.ToolResult, error) {
	sc, empty, err := d.aiFlowScopeFor(args)
	if err != nil || empty {
		return ai.ToolResult{Notes: sc.notes}, err
	}
	rows, err := d.srv.chRowsScope(d.ctx, d.scope, flowquery.TotalsSQL(sc.win, sc.clause))
	if err != nil {
		return ai.ToolResult{}, err
	}
	if len(rows) == 0 || asFloat(rows[0]["flows"]) == 0 {
		return sc.finish(ai.ToolResult{Notes: []string{"no flow records" + sc.where + " in " + sc.win.Phrase()}}, 0, 0), nil
	}
	r := rows[0]
	tr := ai.ToolResult{Items: []ai.EvidenceItem{{
		CitationID: "flow:summary", Kind: "flow",
		Text: fmt.Sprintf("Flow volume%s over %s: %s across %s flows from %d sources",
			sc.where, sc.win.Phrase(), humanBytes(asFloat(r["bytes_total"])), humanCount(asFloat(r["flows"])), int(asFloat(r["sources"]))),
		Href: sc.href(flowquery.TabNow),
	}}}
	return sc.finish(tr, asFloat(r["flows"]), asFloat(r["rate_reported"])), nil
}

// moduleServiceFlows — the busiest destination services (by well-known port).
func (d aiDataSource) moduleServiceFlows(args ai.ToolArgs) (ai.ToolResult, error) {
	sc, empty, err := d.aiFlowScopeFor(args)
	if err != nil || empty {
		return ai.ToolResult{Notes: sc.notes}, err
	}
	rows, err := d.srv.chRowsScope(d.ctx, d.scope, flowquery.ServicesSQL(sc.win, sc.clause, 8))
	if err != nil {
		return ai.ToolResult{}, err
	}
	var flows, rated float64
	items := make([]ai.EvidenceItem, 0, len(rows))
	for i, r := range rows {
		port := int(asFloat(r["port"]))
		flows += asFloat(r["flows"])
		rated += asFloat(r["rate_reported"])
		items = append(items, ai.EvidenceItem{
			CitationID: fmt.Sprintf("flow:svc:%d", i), Kind: "flow",
			Text: fmt.Sprintf("%s (port %d) — %s over %s%s, %s flows",
				servicePortLabel(port), port, humanBytes(asFloat(r["bytes_total"])), sc.win.Phrase(), sc.where, humanCount(asFloat(r["flows"]))),
			Href: sc.href(flowquery.TabTalking),
		})
	}
	tr := ai.ToolResult{Items: items}
	if len(items) == 0 {
		tr.Notes = append(tr.Notes, "no flow records"+sc.where+" in "+sc.win.Phrase())
	}
	return sc.finish(tr, flows, rated), nil
}

// ── the NL query's flow and syslog reads (tracker 337 N-C4) ─────────────────
//
// nlqFlowTop and nlqLogSearch answer plan.FlowScope / plan.LogScope for the
// root nlqScope. They receive only what the validated AST carries — visible
// device ids, a window, a closed grouping or closed severity/topic values —
// and run the SAME allowlisted reads as the Iris tools (flowquery tool_sql.go;
// syslogSearch), so an NL answer and a tool answer cannot disagree.

// nlqFlowTop ranks conversations or services for the caller.
func (d aiDataSource) nlqFlowTop(q plan.FlowQuery) (plan.FlowAnswer, error) {
	win := flowquery.Window{From: q.From.UTC().Truncate(time.Second), To: q.To.UTC().Truncate(time.Second), Explicit: true}
	ans := plan.FlowAnswer{Sampling: flowquery.SamplingNoFlows}
	var clause string
	if len(q.Devices) == 0 {
		c, none := d.srv.flowTenantClauseFor(d.claims)
		if none {
			return ans, nil
		}
		clause = c
	} else {
		// The planner's ids are visible ones already; they are re-checked
		// against the caller's own devices here, and only the inventory
		// address of each reaches SQL.
		want := stringSet(q.Devices)
		var exporters []string
		for _, dev := range d.srv.visibleDevicesFor(d.claims) {
			if !want[dev.ID] {
				continue
			}
			if a := flownames.NormAddr(dev.Address); a != "" {
				exporters = append(exporters, a)
			} else {
				ans.Notes = append(ans.Notes, aiFirst(dev.Name, dev.ID)+" has no IP address in inventory, so no flow record can be matched to it")
			}
		}
		if len(exporters) == 0 {
			return ans, nil
		}
		c, none := d.srv.flowLinkTenantClauseFor(d.claims)
		if none {
			return ans, nil
		}
		clause = c + " AND sampler_address IN (" + flowquery.QuoteList(exporters) + ")"
	}
	if c := platformAddrsFromEnv().SQLCond(); c != "" {
		clause += " AND NOT " + c
		ans.Notes = append(ans.Notes, "Correlix's own monitoring traffic is left out, as on the Flows page")
	}
	sql := flowquery.TalkersSQL(win, clause, q.Limit)
	if q.By == nlqast.FlowGroupService {
		sql = flowquery.ServicesSQL(win, clause, q.Limit)
	}
	rows, err := d.srv.chRowsScope(d.ctx, d.scope, sql, "iris:nlquery:flow_top")
	if err != nil {
		return plan.FlowAnswer{}, err
	}
	var flows, rated float64
	for _, r := range rows {
		flows += asFloat(r["flows"])
		rated += asFloat(r["rate_reported"])
		row := plan.FlowRow{Bytes: asFloat(r["bytes_total"]), Flows: asFloat(r["flows"])}
		if q.By == nlqast.FlowGroupService {
			row.Port = int(asFloat(r["port"]))
			row.Service = servicePortLabel(row.Port)
		} else {
			row.A, row.B = asStr(r["a"]), asStr(r["b"])
		}
		ans.Rows = append(ans.Rows, row)
	}
	ans.Sampling = flowquery.SamplingOf(flows, rated)
	if n := flowquery.SamplingNote(ans.Sampling); n != "" {
		ans.Notes = append(ans.Notes, n)
	}
	return ans, nil
}

// nlqLogSearch reads the newest matching syslog lines for the caller.
func (d aiDataSource) nlqLogSearch(p ai.Principal, q plan.LogQuery) (plan.LogAnswer, error) {
	sp := syslogSpec{
		start: q.From, end: q.To, topics: q.Topics, severities: q.Severities, size: q.Limit,
		auditPath: "/api/ai/query", auditAction: "ai.nlquery.log_search",
	}
	if sp.size <= 0 || sp.size > aiLogMaxLines {
		sp.size = aiLogMaxLines
	}
	if q.MinSeverity != "" {
		sp.severities = plan.SeveritiesAtOrAbove(q.MinSeverity)
	}
	if len(q.Devices) > 0 {
		want := stringSet(q.Devices)
		for _, dev := range d.srv.visibleDevicesFor(d.claims) {
			if !want[dev.ID] {
				continue
			}
			sp.deviceIDs = append(sp.deviceIDs, dev.ID)
			if dev.Name != "" {
				sp.deviceNames = append(sp.deviceNames, dev.Name)
			}
		}
		if len(sp.deviceIDs) == 0 {
			return plan.LogAnswer{}, nil // nothing visible: an honest empty, never a wider read
		}
	}
	out, err := d.syslogSearch(p, sp)
	if err != nil {
		return plan.LogAnswer{}, err
	}
	ans := plan.LogAnswer{Total: out.total, Notes: out.routineNote(false)}
	for _, h := range out.hits {
		line := aiFirst(asStr(h["summary"]), asStr(h["message"]), asStr(h["raw"]), asStr(h["msg"]))
		if line == "" {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, asStr(h["timestamp"]))
		if err != nil {
			at = time.Time{} // an unparsable stamp shows as no time; the line still reads
		}
		ans.Rows = append(ans.Rows, plan.LogRow{
			At:        at,
			Device:    aiFirst(asStr(h["host"]), asStr(h["hostname"]), asStr(h["device"])),
			Severity:  asStr(h["normalized_severity"]),
			EventType: asStr(h["event_type"]),
			Text:      redactAILogLine(line),
		})
	}
	return ans, nil
}
