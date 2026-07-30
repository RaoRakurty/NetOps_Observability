package main

// search_unified.go — Wave 6 #20: the search-first global nav backend.
// GET /api/search?q=… resolves a free-text query (name / id / IP) to typed,
// deep-linkable results across the product's first-class nouns:
//
//   device   — topology/discovery inventory        → Devices page
//   resource — cloud inventory (cloud_store)       → #/resource/cloud/{id} (permanent URL)
//   app      — the app registry (DeriveApps)       → Service View › Services
//   account  — connector collection scopes         → Service View › Resources (account filter)
//   case     — correlation cases by display id     → #/monitoring/correlations?id={uuid}
//
// Every sub-search is scoped to the caller's principal (CLAUDE.md §3a): devices
// via visibleDevices, cloud inventory + connector scopes via principalTenant
// against tenant-keyed stores, correlation cases via the ClickHouse tenant_scope
// row policies (chTenantScope). Bounded by design (§9): per-kind cap, total cap,
// and a hard timeout; the ClickHouse case lookup is best-effort — a storage
// error degrades that ONE kind (logged, never silent) instead of failing the
// whole search.
//
// Ranking is deliberately simple and explainable: exact id/IP/name match (0)
// > prefix (1) > substring (2); ties order by kind then label.

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"netops/backend/internal/noclabel"
	"sort"
	"strings"

	"netops/backend/cloud"
	"netops/backend/cloudconn"

	"netops/backend/internal/searchrank"
)

func (s *server) handleUnifiedSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "GET only", "method_not_allowed")
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) > searchrank.MaxQueryLen {
		q = q[:searchrank.MaxQueryLen]
	}
	if len(q) < searchrank.MinQueryLen {
		writeJSON(w, http.StatusOK, map[string]any{"query": q, "results": []searchrank.Hit{}})
		return
	}
	lq := strings.ToLower(q)

	ctx, cancel := context.WithTimeout(r.Context(), searchrank.Timeout)
	defer cancel()
	tenant, cross := principalTenant(claims)

	var hits []searchrank.ScoredHit
	hits = append(hits, s.searchDevices(claims, lq)...)
	res, apps := s.searchCloud(ctx, tenant, cross, lq)
	hits = append(hits, res...)
	hits = append(hits, apps...)
	hits = append(hits, s.searchAccounts(ctx, tenant, cross, lq)...)
	hits = append(hits, s.searchCases(ctx, chTenantScope(r), q)...)

	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].RankScore != hits[j].RankScore {
			return hits[i].RankScore < hits[j].RankScore
		}
		if ko, kp := searchrank.KindOrder[hits[i].Kind], searchrank.KindOrder[hits[j].Kind]; ko != kp {
			return ko < kp
		}
		return hits[i].Label < hits[j].Label
	})
	if len(hits) > searchrank.TotalCap {
		hits = hits[:searchrank.TotalCap]
	}
	out := make([]searchrank.Hit, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.Hit)
	}
	writeJSON(w, http.StatusOK, map[string]any{"query": q, "results": out})
}

// searchDevices matches the principal-visible device inventory by name/id/IP.
func (s *server) searchDevices(claims jwtClaims, lq string) []searchrank.ScoredHit {
	var out []searchrank.ScoredHit
	for _, d := range visibleDevices(s.discovery.Devices(), claims) {
		rank := searchrank.Rank(lq, d.Name, d.ID, d.Address)
		if rank < 0 {
			continue
		}
		sub := d.Address
		if d.Vendor != "" {
			sub = strings.TrimSpace(sub + " · " + d.Vendor)
		}
		label := firstNonEmpty(d.Name, d.ID)
		// The Devices page supports ?q= (pre-filters the table to the entity) —
		// the same deep-link Command Center's impacted-entities list uses.
		out = append(out, searchrank.ScoredHit{Hit: searchrank.Hit{
			Kind:     "device",
			ID:       d.ID,
			Label:    label,
			Sublabel: sub,
			Href:     "infrastructure/devices?q=" + url.QueryEscape(label),
		}, RankScore: rank})
	}
	return searchrank.CapKind(out)
}

// searchCloud matches the tenant's cloud inventory (name / id / IPs / URI) and
// the app registry derived from it. One store read serves both kinds.
func (s *server) searchCloud(ctx context.Context, tenant string, cross bool, lq string) (resources, apps []searchrank.ScoredHit) {
	if s.cloud == nil {
		return nil, nil
	}
	res, err := s.cloud.ListResources(ctx, tenant, cross)
	if err != nil {
		log.Printf("search: cloud inventory unavailable: %v", err)
		return nil, nil
	}
	for _, cr := range res {
		fields := append([]string{cr.ResourceName, cr.ResourceID, cr.ResourceURI}, cr.PrivateIPs...)
		fields = append(fields, cr.PublicIPs...)
		rank := searchrank.Rank(lq, fields...)
		if rank < 0 {
			continue
		}
		sub := strings.TrimSpace(string(cr.Provider) + " · " + cr.AccountID)
		if cr.Region != "" {
			sub += " · " + cr.Region
		}
		if cr.ResourceType != "" {
			sub += " · " + cr.ResourceType
		}
		resources = append(resources, searchrank.ScoredHit{Hit: searchrank.Hit{
			Kind:     "resource",
			ID:       cr.ResourceID,
			Label:    firstNonEmpty(cr.ResourceName, cr.ResourceID),
			Sublabel: sub,
			Href:     "resource/cloud/" + url.PathEscape(cr.ResourceID),
		}, RankScore: rank})
	}
	for _, a := range cloud.DeriveApps(res) {
		rank := searchrank.Rank(lq, a.AppName, a.AppID)
		if rank < 0 {
			continue
		}
		sub := strings.TrimSpace(strings.Join(searchrank.NonEmpty(a.Owner, a.Env, string(a.Provider)), " · "))
		// Service View › Services tab (no per-app URL param exists yet — the
		// tab lists the tenant's services; see the Wave 6 #20 gap note).
		apps = append(apps, searchrank.ScoredHit{Hit: searchrank.Hit{
			Kind:     "app",
			ID:       a.AppID,
			Label:    firstNonEmpty(a.AppName, a.AppID),
			Sublabel: sub,
			Href:     "monitoring/appobs/services",
		}, RankScore: rank})
	}
	return searchrank.CapKind(resources), searchrank.CapKind(apps)
}

// searchAccounts matches the tenant's onboarded provider accounts /
// subscriptions / projects — the connector collection scopes.
func (s *server) searchAccounts(ctx context.Context, tenant string, cross bool, lq string) []searchrank.ScoredHit {
	if s.cloudConn == nil {
		return nil
	}
	// F-76: connector storage is absent off the Postgres backend. Unified
	// search contributes no account hits rather than panicking.
	if s.cloudConn == nil {
		return nil
	}
	conns, err := s.cloudConn.List(ctx, tenant, cross)
	if err != nil {
		log.Printf("search: connector store unavailable: %v", err)
		return nil
	}
	seen := map[string]bool{}
	var out []searchrank.ScoredHit
	for _, c := range conns {
		for _, sc := range c.Scopes {
			switch sc.Type {
			case cloudconn.ScopeAccount, cloudconn.ScopeSubscription, cloudconn.ScopeProject:
			default:
				continue // regions/VPCs/OUs are narrowings, not account nouns
			}
			key := string(c.Provider) + "\x00" + sc.Ref
			if seen[key] {
				continue
			}
			rank := searchrank.Rank(lq, sc.Display, sc.Ref)
			if rank < 0 {
				continue
			}
			seen[key] = true
			out = append(out, searchrank.ScoredHit{Hit: searchrank.Hit{
				Kind:     "account",
				ID:       sc.Ref,
				Label:    firstNonEmpty(sc.Display, sc.Ref),
				Sublabel: strings.TrimSpace(string(c.Provider) + " " + string(sc.Type) + " · " + c.DisplayName),
				Href:     "monitoring/appobs/resources?account=" + url.QueryEscape(sc.Ref),
			}, RankScore: rank})
		}
	}
	return searchrank.CapKind(out)
}

// searchCases resolves a case-handle query (P-pathgraph.ISOZPtr(t *timepathgraph.ISOZPtr(t *timepathgraph.ISOZPtr(t *time / uuid prefix) against the
// caller's correlation objects. Tenant isolation is the corr_current ClickHouse
// row policy (tenant_scope), same as every correlations read. Best-effort: a
// storage error degrades this kind only.
func (s *server) searchCases(ctx context.Context, scope, q string) []searchrank.ScoredHit {
	hex := searchrank.CaseHex(q)
	if hex == "" {
		return nil
	}
	// hex is validated uppercase [0-9A-F] only — safe to inline.
	sql := `
SELECT toString(correlation_id) AS id, state, top_hypothesis
  FROM netops.corr_current FINAL
 WHERE startsWith(upper(replaceAll(toString(correlation_id), '-', '')), '` + hex + `')
 ORDER BY created_at DESC
 LIMIT ` + intToString(searchrank.PerKindCap)
	rows, err := s.chRowsScope(ctx, scope, sql, "api:/api/search")
	if err != nil {
		log.Printf("search: case lookup unavailable: %v", err)
		return nil
	}
	var out []searchrank.ScoredHit
	for _, row := range rows {
		id := str(row["id"])
		if id == "" {
			continue
		}
		disp := noclabel.ProblemDisplayID(id)
		// Exact when the query names at least the full 6-hex display handle
		// (the row already matched the prefix), else a prefix match.
		rank := 1
		if len(hex) >= 6 {
			rank = 0
		}
		out = append(out, searchrank.ScoredHit{Hit: searchrank.Hit{
			Kind:     "case",
			ID:       id,
			Label:    disp,
			Sublabel: strings.TrimSpace(str(row["state"]) + " · " + str(row["top_hypothesis"])),
			Href:     "monitoring/correlations?id=" + url.QueryEscape(id),
		}, RankScore: rank})
	}
	return out
}

// capKind orders one kind's hits (rank, then label) and applies the per-kind cap.
