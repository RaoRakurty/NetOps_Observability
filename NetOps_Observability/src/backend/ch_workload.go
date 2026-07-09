package main

// ch_workload.go — ClickHouse workload profile routing (#101 SaaS fairness).
//
// The #100 2 GiB per-query cap is CONTAINMENT: any runaway query fails alone.
// This layer adds FAIRNESS on top: queries are routed to named settings
// profiles (deployment/docker/clickhouse/workload-profiles.xml) by their
// log_comment attribution tag, so the hot Command Center read path runs under
// a stricter budget than analytics panels or background sweeps, and a heavy
// background job can never occupy the memory a hot UI poll needs.
//
//	hot_ui     — corr_current-backed UI polls: small by design (#100), so a
//	             breach is a regression, not a workload. 1 GiB / 10 s.
//	background — workers (ticketing sweeps, reconcilers, backfills): may read
//	             history, must yield to interactive load. 2 GiB / 60 s,
//	             de-prioritized.
//	(default)  — everything else (flows/analytics panels) keeps the default
//	             profile with the 1.5 GiB spill thresholds + 2 GiB cap.
//
// CH_WORKLOAD_PROFILES=off is the operational kill-switch: it drops the
// profile parameter entirely (queries run under the default profile), for
// upgrades where the API image lands before the ClickHouse config does.

import "strings"

// chHotUIPrefixes: endpoints served from the corr_current hot projection (or
// equally narrow #100-shaped reads). Extend when a new hot lane ships — the
// release-gate storm tests assert the lane's list path stays inside hot_ui
// budgets.
var chHotUIPrefixes = []string{
	"api:/api/correlations",
	"api:/api/reliability",
	"api:/api/cloud/app-rca",
}

// chWorkloadProfile maps a log_comment attribution tag to a settings profile
// ("" = default profile).
func chWorkloadProfile(tag string) string {
	if envOr("CH_WORKLOAD_PROFILES", "") == "off" {
		return ""
	}
	for _, p := range chHotUIPrefixes {
		if strings.HasPrefix(tag, p) {
			return "hot_ui"
		}
	}
	if strings.HasPrefix(tag, "worker:") {
		return "background"
	}
	return ""
}
