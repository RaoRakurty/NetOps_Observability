// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package lanepresence builds the reads that tell whether ONE device was seen
// sending on a telemetry lane — syslog, SNMP traps, flows — within a window
// (tracker 415 (c)): the per-device last-seen accessor Iris's skill
// applicability needs for fact:telemetry=syslog|trap|flow.
//
// Seen only. A lane with no record in the window is UNKNOWN, never absent:
// silence is not "not configured" (a quiet device sends no syslog), and an
// exporter may source its flows from a non-management address.
//
// Nothing here does IO or knows about principals. The api root resolves the
// device through the caller's own inventory, hands in the caller's per-document
// tenant filter / exclusions (OpenSearch) and tenant clause (ClickHouse), and
// runs the reads at the caller's scope. This package only renders a validated
// address and integers into SQL, and puts identities into JSON terms — no
// caller text reaches a query string.
package lanepresence

import (
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Window is how far back a lane counts as seen.
const Window = 24 * time.Hour

// Device is one already-resolved device of the caller.
type Device struct {
	ID, Name, Address string
}

// identities are the device's non-empty, de-duplicated names for matching the
// documents' device fields.
func (d Device) identities() []string {
	var out []string
	for _, v := range []string{d.ID, d.Name, d.Address} {
		v = strings.TrimSpace(v)
		if v == "" || len(v) > 256 {
			continue
		}
		dup := false
		for _, o := range out {
			dup = dup || o == v
		}
		if !dup {
			out = append(out, v)
		}
	}
	return out
}

// LogQuery is the OpenSearch body that answers "did this device send a
// document in [now-window, now]?" for one log index (syslog or traps): no hits
// returned, at most one counted (terminate_after), so the read is cheap.
// tenantFilter is the caller's per-document filter (oslog.TenantFilter; nil
// for a cross-tenant caller) and mustNot the caller's exclusions (operator
// restriction, synthetic probes). ok=false when the device has no identity to
// match — the caller then leaves the lane unknown without reading.
func LogQuery(d Device, now time.Time, window time.Duration, tenantFilter map[string]any, mustNot []any) (map[string]any, bool) {
	ids := d.identities()
	if len(ids) == 0 {
		return nil, false
	}
	filters := []any{
		map[string]any{"range": map[string]any{"timestamp": map[string]string{
			"gte": now.Add(-window).UTC().Format(time.RFC3339), "lte": now.UTC().Format(time.RFC3339),
		}}},
		map[string]any{"bool": map[string]any{"should": []any{
			map[string]any{"terms": map[string]any{"device_id": ids}},
			map[string]any{"terms": map[string]any{"host": ids}},
			map[string]any{"terms": map[string]any{"hostname": ids}},
		}, "minimum_should_match": 1}},
	}
	if tenantFilter != nil {
		filters = append(filters, tenantFilter)
	}
	q := map[string]any{"filter": filters}
	if len(mustNot) > 0 {
		q["must_not"] = mustNot
	}
	return map[string]any{
		"size":             0,
		"terminate_after":  1,
		"track_total_hits": 1,
		"query":            map[string]any{"bool": q},
	}, true
}

// FlowSQL is the ClickHouse statement that answers "did this device export a
// flow in the window?" — by exporter address (sampler_address), which is how a
// flow names the router that saw it. tenantClause is the caller's own flow
// clause (already-safe SQL from the api root, starting with " AND"). ok=false
// when the device's address is not a valid IP: nothing is read.
func FlowSQL(d Device, window time.Duration, tenantClause string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(d.Address))
	if err != nil || !addr.IsValid() {
		return "", false
	}
	secs := int64(window / time.Second)
	if secs <= 0 {
		return "", false
	}
	return `SELECT 1 AS hit
  FROM netops.flows
 WHERE ts >= now() - INTERVAL ` + strconv.FormatInt(secs, 10) + ` SECOND
   AND sampler_address = '` + addr.Unmap().String() + `'` + tenantClause + `
 LIMIT 1
 FORMAT JSON`, true
}
