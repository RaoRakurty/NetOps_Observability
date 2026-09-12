// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloud

import "sort"

// derive.go — pure projections over the cloud inventory (#81 P3A): the app list,
// the attribution-coverage report, and the top unattributed contributors. These
// back GET /api/cloud/apps and /api/cloud/attribution/coverage. No health/traffic
// here — those arrive with cloud_health/cloud_flow (P3B/P3C); honest until then.

// CloudApp is an app derived by grouping attributed resources. Health/traffic are
// omitted (not yet ingested) — the UI shows "unknown"/"not measured" for those.
type CloudApp struct {
	AppID      string     `json:"app_id"`
	AppName    string     `json:"app_name"`
	Owner      string     `json:"owner"`
	Env        string     `json:"env"`
	Provider   Provider   `json:"cloud_provider"`
	Account    string     `json:"account_id"`
	Region     string     `json:"region"`
	Confidence Confidence `json:"confidence"` // best across the app's resources
	Source     Source     `json:"source"`
	Resources  int        `json:"resources"`
}

// DeriveApps groups attributed resources into apps (unattributed resources — app_id
// == "" — are excluded; they surface in coverage/TopUnknown instead). The app's
// confidence/source is the strongest among its resources.
func DeriveApps(resources []CloudResource) []CloudApp {
	by := map[string]*CloudApp{}
	var order []string
	for _, r := range resources {
		if r.AppID == "" {
			continue
		}
		a := by[r.AppID]
		if a == nil {
			a = &CloudApp{AppID: r.AppID, AppName: r.AppName, Owner: r.Owner, Env: r.Env,
				Provider: r.Provider, Account: r.AccountID, Region: r.Region,
				Confidence: r.Confidence, Source: r.Source}
			by[r.AppID] = a
			order = append(order, r.AppID)
		}
		a.Resources++
		if r.Confidence.rank() > a.Confidence.rank() { // strongest attribution wins
			a.Confidence = r.Confidence
			a.Source = r.Source
		}
		if a.Owner == "" {
			a.Owner = r.Owner
		}
		if a.Env == "" {
			a.Env = r.Env
		}
	}
	out := make([]CloudApp, 0, len(order))
	for _, id := range order {
		out = append(out, *by[id])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].AppName < out[j].AppName })
	return out
}

// CoverageReport is the attribution-coverage breakdown — the "how much do we trust
// our app identity" feature. Counts are over resources.
type CoverageReport struct {
	ConfirmedTag      int `json:"confirmed_tag"`
	StrongGraph       int `json:"strong_graph"`
	FirewallAppID     int `json:"firewall_appid"`
	SuspectedDomainIP int `json:"suspected_domain_ip"`
	Unknown           int `json:"unknown"`
	Total             int `json:"total"`
}

// Coverage tallies resources by the source that attributed them.
func Coverage(resources []CloudResource) CoverageReport {
	var c CoverageReport
	for _, r := range resources {
		c.Total++
		switch r.Source {
		case SrcCloudTag, SrcOperatorCatalog:
			c.ConfirmedTag++
		case SrcCloudGraph:
			c.StrongGraph++
		case SrcFirewallAppID:
			c.FirewallAppID++
		case SrcDomain, SrcIPCatalog:
			c.SuspectedDomainIP++
		default:
			c.Unknown++
		}
	}
	return c
}

// TopUnknown returns the unattributed resources (app_id == "") — the tag-coverage
// fix list. Sorted by name (stable); capped at limit.
func TopUnknown(resources []CloudResource, limit int) []CloudResource {
	var out []CloudResource
	for _, r := range resources {
		if r.AppID == "" {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ResourceID < out[j].ResourceID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
