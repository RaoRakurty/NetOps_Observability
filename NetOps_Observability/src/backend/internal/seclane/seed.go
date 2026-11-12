// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package seclane

// seed.go — rebuilding a tenant's open episodes from the findings store, for
// the first change-tracked scan after an upgrade (or after episode state was
// lost). See Lane.seed for why the store is the right baseline.
//
// Three bounded reads, all against ONLY the scanned tenant's own indices
// (oslog.TenantIndexPattern) AND a per-document tenant_id term underneath — the
// same two-layer §3a chokepoint the security read API uses:
//
//  1. the tenant's latest LANE scan id (scan ids are "scan-<seg>-<UTC stamp>",
//     so the lexically greatest is the newest; the prefix filter keeps other
//     producers' scan ids — config drift — out of the comparison);
//  2. that scan's documents: the set of findings the engine was last sent;
//  3. the earliest retained verdict time for each of them (first_seen, basis
//     "seed"). If only this read fails, first_seen falls back to the latest
//     verdict's time — still basis "seed", still honest about being a floor.
//
// A read that could be incomplete (more documents than one bounded page) is an
// ERROR, not a partial seed: a seed missing some open findings would announce
// them all as new, which is the burst the seed exists to prevent.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/oslog"
	"netops/backend/internal/secbus"
)

// seedPageMax bounds one seed read (OpenSearch's default max_result_window).
const seedPageMax = 10000

// seedScanWalk bounds how many stored scans the seed steps back through to find
// the newest one the engine received (§9: at most this many page reads).
const seedScanWalk = 8

// seedSource is the document projection a seed reads back.
var seedSource = []string{
	"native_id", "kind", "ts", "entity_id", "entity_type", "entity_tokens",
	"severity", "seam_id", "seam_type", "internet_facing", "attrs",
}

func (l *Lane) seedQuery(body map[string]any, tenant string) (map[string]any, error) {
	index := oslog.TenantIndexPattern("secfindings", tenant, false)
	resp, err := l.deps.Search(http.MethodPost, "/"+index+"/_search?ignore_unavailable=true", body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, osResponseCap))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("seclane: findings-store seed read returned status %d", resp.StatusCode)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("seclane: findings-store seed read is not JSON: %w", err)
	}
	return out, nil
}

func tenantTerm(tenant string) map[string]any {
	return map[string]any{"term": map[string]any{"tenant_id": strings.ToLower(strings.TrimSpace(tenant))}}
}

// seedFromIndex returns the tenant's open episodes as of its latest stored
// lane scan. A tenant with no stored lane scan returns an empty map: everything
// its first scan reports is genuinely new.
func (l *Lane) seedFromIndex(ctx context.Context, tenant string) (map[string]Episode, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	seg := l.deps.TenantSeg(tenant)
	// 1. latest lane scan id.
	latestBody := map[string]any{
		"size": 0,
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			tenantTerm(tenant),
			map[string]any{"prefix": map[string]any{"attrs.scan_id": "scan-" + seg + "-"}},
		}}},
		"aggs": map[string]any{"latest_scan": map[string]any{"terms": map[string]any{
			"field": "attrs.scan_id", "size": seedScanWalk, "order": map[string]any{"_key": "desc"},
		}}},
	}
	res, err := l.seedQuery(latestBody, tenant)
	if err != nil {
		return nil, err
	}
	buckets, ok := aggBuckets(res, "latest_scan")
	if !ok {
		return nil, errors.New("seclane: findings-store seed read carried no latest_scan aggregation")
	}

	// 2. the newest scan the engine actually received. A scan stored while
	// episode state was unreadable went to the audit topic only (transition
	// "unclassified"): it says nothing about what the engine knows, so the walk
	// steps back past it to the scan before.
	var hits []map[string]any
	for _, b := range buckets {
		scanID, _ := b["key"].(string)
		if scanID == "" {
			return nil, errors.New("seclane: findings-store seed read returned an empty scan id")
		}
		docs, err := l.seedScanDocs(tenant, scanID)
		if err != nil {
			return nil, err
		}
		known := docs[:0]
		for _, src := range docs {
			attrs, _ := src["attrs"].(map[string]any)
			if attrStr(attrs, secbus.AttrTransition) != secbus.TransitionUnclassified {
				known = append(known, src)
			}
		}
		if len(known) > 0 {
			hits = known
			break
		}
	}
	open := make(map[string]Episode, len(hits))
	for _, src := range hits {
		nid, _ := src["native_id"].(string)
		kind, _ := src["kind"].(string)
		if nid == "" || kind == "" || secbus.IsClearKind(kind) || kind == secbus.KindSignal {
			continue // signals are never tracked as episodes (episodes.go, SIGNALS)
		}
		attrs, _ := src["attrs"].(map[string]any)
		subj := EpisodeSubject{
			Kind:           kind,
			EntityID:       str(src, "entity_id"),
			EntityType:     str(src, "entity_type"),
			EntityTokens:   strList(src["entity_tokens"]),
			EvidenceClass:  attrStr(attrs, "evidence_class"),
			ControlID:      attrStr(attrs, "control_id"),
			RawRuleID:      attrStr(attrs, "raw_rule_id"),
			ProviderSource: attrStr(attrs, "provider_source"),
			Category:       attrStr(attrs, "category"),
			Severity:       str(src, "severity"),
			StatusID:       attrInt(attrs["status_id"]),
			SeamID:         str(src, "seam_id"),
			SeamType:       str(src, "seam_type"),
		}
		if b, ok := src["internet_facing"].(bool); ok {
			subj.InternetFacing = b
		}
		first := tsOf(src["ts"])
		if first.IsZero() {
			first = l.deps.Now()
		}
		open[nid] = Episode{FirstSeen: first, Basis: secbus.BasisSeed, Subject: subj.bounded()}
	}
	if len(open) == 0 {
		return open, nil
	}

	// 3. earliest retained verdict per identity. Best-effort: on failure the
	// latest verdict's time stands as the (later) floor.
	ids := make([]any, 0, len(open))
	for nid := range open {
		ids = append(ids, nid)
	}
	firstBody := map[string]any{
		"size": 0,
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			tenantTerm(tenant),
			map[string]any{"terms": map[string]any{"native_id": ids}},
		}}},
		"aggs": map[string]any{"by_native": map[string]any{
			"terms": map[string]any{"field": "native_id", "size": len(ids)},
			"aggs":  map[string]any{"first": map[string]any{"min": map[string]any{"field": "ts"}}},
		}},
	}
	res, err = l.seedQuery(firstBody, tenant)
	if err != nil {
		l.deps.LogWarn("security finding seed: earliest-verdict read failed — first_seen falls back to the latest stored verdict",
			map[string]any{"tenant_seg": seg, "err": l.deps.Scrub(err.Error())})
		return open, nil
	}
	byNative, _ := aggBuckets(res, "by_native")
	for _, b := range byNative {
		nid, _ := b["key"].(string)
		ep, ok := open[nid]
		if !ok {
			continue
		}
		agg, _ := b["first"].(map[string]any)
		if at := tsOf(agg["value"]); !at.IsZero() && at.Before(ep.FirstSeen) {
			ep.FirstSeen = at
			open[nid] = ep
		}
	}
	return open, nil
}

// seedScanDocs reads one stored scan's documents, refusing an incomplete page.
func (l *Lane) seedScanDocs(tenant, scanID string) ([]map[string]any, error) {
	docsBody := map[string]any{
		"size":             seedPageMax,
		"track_total_hits": true,
		"_source":          seedSource,
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			tenantTerm(tenant),
			map[string]any{"term": map[string]any{"attrs.scan_id": scanID}},
		}}},
	}
	res, err := l.seedQuery(docsBody, tenant)
	if err != nil {
		return nil, err
	}
	hits, total, ok := searchHits(res)
	if !ok {
		return nil, errors.New("seclane: findings-store seed read carried no hits")
	}
	if total > len(hits) {
		return nil, fmt.Errorf("seclane: findings-store seed read is incomplete (%d of %d documents)", len(hits), total)
	}
	return hits, nil
}

// aggBuckets reads aggregations.<name>.buckets.
func aggBuckets(res map[string]any, name string) ([]map[string]any, bool) {
	aggs, ok := res["aggregations"].(map[string]any)
	if !ok {
		return nil, false
	}
	agg, ok := aggs[name].(map[string]any)
	if !ok {
		return nil, false
	}
	raw, ok := agg["buckets"].([]any)
	if !ok {
		return nil, false
	}
	out := make([]map[string]any, 0, len(raw))
	for _, b := range raw {
		if m, ok := b.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out, true
}

// searchHits reads hits.hits[]._source and hits.total.value.
func searchHits(res map[string]any) ([]map[string]any, int, bool) {
	hits, ok := res["hits"].(map[string]any)
	if !ok {
		return nil, 0, false
	}
	total := 0
	switch t := hits["total"].(type) {
	case map[string]any:
		total = attrInt(t["value"])
	case float64:
		total = int(t)
	}
	raw, _ := hits["hits"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, h := range raw {
		hm, ok := h.(map[string]any)
		if !ok {
			continue
		}
		if src, ok := hm["_source"].(map[string]any); ok {
			out = append(out, src)
		}
	}
	return out, total, true
}

func strList(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		if s, ok := x.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// tsOf reads a stored time: the router normalises ts to epoch-millis, an
// aggregation returns a float of millis, and a direct writer may store RFC3339.
func tsOf(v any) time.Time {
	switch t := v.(type) {
	case float64:
		if t <= 0 {
			return time.Time{}
		}
		return time.UnixMilli(int64(t)).UTC()
	case string:
		if at, err := time.Parse(time.RFC3339Nano, t); err == nil {
			return at.UTC()
		}
		if ms, err := strconv.ParseInt(t, 10, 64); err == nil && ms > 0 {
			return time.UnixMilli(ms).UTC()
		}
	}
	return time.Time{}
}
