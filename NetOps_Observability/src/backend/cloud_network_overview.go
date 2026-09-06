// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// cloud_network_overview.go — GET /api/cloud/network/overview (cloud-network-
// overview design §6 P1): the tenant's cloud network rolled up provider →
// region → VPC → components-by-family, plus the first-class lateral seams.
// The pure aggregation lives in cloud/rollup.go; this file is the tenant-scoped
// read surface that feeds it:
//
//   inventory  — the caller's own P0 component rows (principalTenant-scoped
//                through the cloud store, like every other cloud read)
//   issues     — the caller's OPEN cloud investigations (corr_current, scoped by
//                the tenant_scope row policy), with the raw resource handles
//                their grounded evidence named, so the engine can localize each
//                issue to a VPC / region / seam ("issues are localized, not
//                listed", design §3.5)
//
// Bounded by construction (§9): the inventory read is the hard-capped store
// list, the issue read is LIMIT-bounded on both the objects and their archived
// signals, and every list in the response carries the engine's truncation
// disclosure. Honesty: `open_issues.total_open` is a real COUNT — when it
// exceeds the bounded `considered` set, the difference is visible, never
// silently dropped.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/noclabel"
	"strings"
	"time"

	"netops/backend/cloud"
	"netops/backend/internal/chschema"
)

const (
	// overviewMaxOpenObjects bounds how many open investigations are localized
	// per request (newest first — the ones an operator is acting on).
	overviewMaxOpenObjects = 25
	// overviewMaxIssueSignals bounds the archived-evidence read that supplies
	// each issue's resource handles.
	overviewMaxIssueSignals = 500
)

// overviewOpenObjectsSQL picks the OPEN cloud correlation objects, newest
// first. Same #100-safe read shape as the evidence ledger: the corr_current hot
// projection with named columns, archive prefiltered by the time window, and
// the caller's tenant_scope enforced by the row policies.
func overviewOpenObjectsSQL(scope string) string {
	return fmt.Sprintf(`
WITH cloud_objs AS (
     SELECT DISTINCT archived_for
       FROM netops.corr_signals_archive
      WHERE source = 'cloud' AND ts > now() - INTERVAL %d HOUR
)
SELECT toString(correlation_id)  AS cid,
       toString(verdict_tier)    AS verdict_tier_s,
       top_confidence            AS top_confidence,
       top_hypothesis            AS top_hypothesis,
       signal_count              AS signal_count,
       toString(state)           AS state_s,
       `+chschema.ISO("window_start")+` AS window_start_s,
       affected                  AS affected,
       evidence_missing          AS evidence_missing
  FROM netops.corr_current FINAL
 WHERE correlation_id IN (SELECT archived_for FROM cloud_objs)
   AND state = 'open'
 ORDER BY window_start DESC
 LIMIT %d
 SETTINGS tenant_scope = '%s'
 FORMAT JSONEachRow`, cloudSignalWindowHours, overviewMaxOpenObjects, scope)
}

// addIssueHandle records one raw resource handle an issue's evidence named,
// splitting probe-style "vantage->target" entities so the target address
// resolves against the inventory too.
func addIssueHandle(seen map[string]bool, handles *[]string, h string) {
	h = strings.TrimSpace(h)
	if h == "" {
		return
	}
	if _, dst, ok := strings.Cut(h, "->"); ok {
		addIssueHandle(seen, handles, dst)
		return
	}
	if !seen[h] {
		seen[h] = true
		*handles = append(*handles, h)
	}
}

// cloudOpenIssues reads the caller's open cloud investigations plus the raw
// handles their grounded evidence named, newest first, as the roll-up engine's
// issue input. Best-effort like every CH read surface: an unreachable store
// yields no issues (the overview still renders the inventory), never an error
// that hides the whole page.
func (s *server) cloudOpenIssues(scope string) []cloud.OverviewIssue {
	objRows := chJSONRows[chObjectRow](overviewOpenObjectsSQL(scope))
	if len(objRows) == 0 {
		return nil
	}
	issues := make([]cloud.OverviewIssue, 0, len(objRows))
	byID := map[string]int{}
	seen := map[string]map[string]bool{}
	ids := make([]string, 0, len(objRows))
	for _, o := range objRows {
		title := noclabel.SignatureTitle(o.TopHypothesis)
		is := cloud.OverviewIssue{ID: o.CorrelationID, Title: title}
		byID[o.CorrelationID] = len(issues)
		seen[o.CorrelationID] = map[string]bool{}
		ids = append(ids, o.CorrelationID)
		// The object's own declared blast radius (services / paths are the
		// addresses the probes measured) seeds the handles.
		var aff struct {
			Services []string `json:"services"`
			Paths    []string `json:"paths"`
		}
		if o.Affected != "" {
			_ = json.Unmarshal([]byte(o.Affected), &aff) // best-effort: engine-authored JSON
		}
		for _, h := range append(append([]string{}, aff.Services...), aff.Paths...) {
			addIssueHandle(seen[o.CorrelationID], &is.Handles, h)
		}
		issues = append(issues, is)
	}
	// The grounded evidence carries the provider-native identities (resource
	// ids, ENIs, hosts) and the signal kinds (seam-lane kinds route the issue
	// to a seam, §4a).
	if list := cloud.SQLList(ids); list != "" {
		for _, row := range chJSONRows[chSignalRow](cloud.EvidenceSignalsSQL(cloudSignalWindowHours, list, "", overviewMaxIssueSignals, scope)) {
			i, ok := byID[row.CorrelationID]
			if !ok {
				continue
			}
			a := cloud.ParseAttrs(row.Attrs)
			addIssueHandle(seen[row.CorrelationID], &issues[i].Handles, a.ResourceID)
			addIssueHandle(seen[row.CorrelationID], &issues[i].Handles, row.EntityID)
			addIssueHandle(seen[row.CorrelationID], &issues[i].Handles, a.Host)
			if k := strings.TrimSpace(row.Kind); k != "" {
				issues[i].Kinds = append(issues[i].Kinds, k)
			}
		}
	}
	return issues
}

// handleCloudNetworkOverview serves GET /api/cloud/network/overview — the P1
// roll-up model the Cloud Network Overview surface (P2) renders. Tenant-scoped
// end to end: the inventory through the cloud store (principalTenant), the
// issues through the ClickHouse tenant_scope row policies.
func (s *server) handleCloudNetworkOverview(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET"))
		return
	}
	var res []cloud.CloudResource
	if s.cloud != nil {
		var err error
		if res, _, _, err = s.cloudResources(r); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	scope := cloud.SafeScopeLiteral(chTenantScope(r))
	issues := s.cloudOpenIssues(scope)
	ov := cloud.BuildNetworkOverview(res, issues, cloud.DefaultOverviewLimits(), time.Now().UTC())

	// total_open is a dedicated COUNT (the same honesty rule as the evidence
	// ledger): the bounded `considered` set can never masquerade as the total.
	totalOpen := chScalarInt(cloud.OpenObjectCountSQL(cloudSignalWindowHours, "", scope))
	if totalOpen < len(issues) {
		totalOpen = len(issues) // a count the store failed to serve never understates what we hold
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"providers":       ov.Providers,
		"seams":           ov.Seams,
		"seams_truncated": ov.SeamsTruncated,
		"open_issues": map[string]any{
			"total_open":   totalOpen,
			"considered":   len(issues),
			"localized":    ov.OpenIssuesLocalized,
			"unlocalized":  ov.OpenIssuesUnlocalized,
			"window_hours": cloudSignalWindowHours,
		},
		"generated_at": ov.GeneratedAt,
	})
}
