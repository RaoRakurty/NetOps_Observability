// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package cloudtenant builds the cloud lane's tenant registry rows (tracker 392).
//
// A cloud metric sample names its resource twice: `device` is the resource NAME
// (what the Service View binds apps to) and `index` is the provider's resource
// id. Until tracker 392 the Vector metrics lane stamped every metric's tenant by
// looking `device` up in the DEVICE registry, so once tenant B owned a device
// named like tenant A's cloud resource, A's cloud series were stamped tenant B —
// in netops.metrics, in VictoriaMetrics, and (because the correlation engine
// re-derived the same answer from the same registry) as B's RCA evidence.
//
// The fix: the cloud lane never takes a tenant from the device registry. Its
// tenant comes from the cloud INVENTORY — whose tenant the backend stamps from
// the owning connector row, never from a request body — keyed by resource id.
// The rows ride the existing registry file (device_tenant.csv) under a reserved
// namespace, `cloud:<resource_id>`, so the Vector table, its reload wrapper and
// the engine's loader read them with no new file to seed or mount. A device
// identity can never enter that namespace (IsReserved), so no device can claim
// a cloud resource's key.
//
// Fail-safe, exactly like the device rows: a resource id that two tenants'
// inventories both list is omitted (a registry MISS), and the readers treat a
// miss on this lane as unattributable — refused, never defaulted to platform.
package cloudtenant

import (
	"sort"
	"strings"
)

// Prefix is the reserved identity namespace for cloud resources in the tenant
// registry. Vector (deployment/docker/vector/vector.yaml metrics_normalized) and
// the correlation engine (main.CLOUD_IDENTITY_PREFIX) build the same key.
const Prefix = "cloud:"

// Identity is the registry key of one cloud resource, or "" for a blank id.
func Identity(resourceID string) string {
	id := strings.TrimSpace(resourceID)
	if id == "" {
		return ""
	}
	return Prefix + id
}

// IsReserved reports whether a registry identity lies in the cloud namespace.
// The exporter drops any DEVICE identity that does (case-insensitively, so
// "Cloud:x" cannot slip past a reader that compares exactly).
func IsReserved(identity string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(identity)), Prefix)
}

// Resource is the part of a cloud inventory row the registry needs.
type Resource struct {
	ResourceID string
	TenantID   string
}

// Row is one registry row: identity (cloud:<resource_id>) → owning tenant.
type Row struct {
	Identity string
	Tenant   string
}

// Stats counts what Rows did, for the export's log line.
type Stats struct {
	Rows      int // rows emitted
	Ambiguous int // resource ids listed under more than one tenant — omitted
	Blank     int // inventory rows with no resource id — skipped
}

// Rows turns the whole cross-tenant cloud inventory into registry rows, sorted
// by identity (the exporter skips no-op rewrites, so the order must be stable).
// Tenant ids are lower-cased and trimmed, the form every reader compares in; ""
// is the platform tenant and is a legitimate owner (single-tenant installs).
func Rows(resources []Resource) ([]Row, Stats) {
	var st Stats
	owners := map[string]map[string]bool{}
	for _, r := range resources {
		id := Identity(r.ResourceID)
		if id == "" {
			st.Blank++
			continue
		}
		if owners[id] == nil {
			owners[id] = map[string]bool{}
		}
		owners[id][strings.ToLower(strings.TrimSpace(r.TenantID))] = true
	}
	rows := make([]Row, 0, len(owners))
	for id, ts := range owners {
		if len(ts) != 1 {
			st.Ambiguous++
			continue // two owners → neither (fail-safe; §3a)
		}
		for t := range ts {
			rows = append(rows, Row{Identity: id, Tenant: t})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Identity < rows[j].Identity })
	st.Rows = len(rows)
	return rows, st
}
