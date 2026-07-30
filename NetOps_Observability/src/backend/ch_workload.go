package backend

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

import (
	"netops/backend/chhttp"
	"strings"
	"sync/atomic"
)

// ── F-27: server-side execution guards ───────────────────────────────────────
//
// Every ClickHouse read here goes over the HTTP interface with a Go client
// timeout. A Go client timeout does NOT stop the query: ClickHouse keeps
// executing, keeps holding memory, and keeps occupying a slot long after the
// caller gave up and returned "no data". That is the client-side shape of the
// 2026-07-09 #100 incident — the API times out, retries on the next poll, and
// each abandoned query is still running underneath.
//
// Two parameters fix it at the protocol level, and they belong on EVERY read
// path rather than on the one that was noticed:
//
//	max_execution_time                          — ClickHouse aborts by itself
//	cancel_http_readonly_queries_on_client_close — closing the socket kills the query
//
// The other half — bounding an io.ReadAll on a response whose size is a
// function of table size — is chhttp.DefaultMaxBytes. This file used to declare
// its OWN `const chMaxResponseBytes = 8 << 20`, a second source of truth for
// the same cap that could drift from the transport's silently. Extracting
// internal/chschema on 2026-07-27 surfaced the duplicate; package main now
// defers to the package that actually enforces it.
const chMaxResponseBytes = chhttp.DefaultMaxBytes

// chReadFailures counts ClickHouse reads that returned an error. Before F-27
// the shared read helper swallowed every failure and returned nil, so an
// unreachable ClickHouse and an empty result were indistinguishable — the
// report simply said "no data".
var chReadFailures atomic.Uint64

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
