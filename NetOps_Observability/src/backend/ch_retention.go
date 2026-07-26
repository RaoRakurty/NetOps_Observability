package main

// ch_retention.go — F-58: boot-time TTL convergence for the TELEMETRY family
// of ClickHouse tables.
//
// THE DEFECT THIS FIXES
// ---------------------
// Every TTL outside the correlation family existed ONLY in
// deployment/docker/clickhouse/init.sql, i.e. only inside a
// `CREATE TABLE IF NOT EXISTS`. That statement is a no-op against a table that
// already exists, so a TTL line ADDED to init.sql after an install was created
// never reached that install — and nothing else ever issued `MODIFY TTL`.
// `chConvergeStmts` touched flows / findings / tunnels on every boot (row
// policies, added columns) but never their retention, so:
//
//   * live `findings` and `tunnels` ran at 90 days against a checked-in 30;
//   * any table whose TTL line postdates the install has NO TTL at all and
//     grows forever, on a filesystem that has already hit NOT_ENOUGH_SPACE
//     once (F-55);
//   * and the drift is invisible: init.sql looks authoritative, and reading it
//     tells you nothing about the running system.
//
// The correlation family already solved this (corr_retention.go re-converges
// on every boot). This is the same mechanism applied to the SIBLINGS that were
// left behind — the instance-vs-class pattern this audit is about. The guard
// test `ch_retention_test.go` now fails the build if a new `TTL` appears in
// init.sql without a converge entry here, so the next table cannot repeat it.
//
// MIGRATION SAFETY — READ BEFORE CHANGING A DEFAULT
// -------------------------------------------------
// `MODIFY TTL` is not a config change, it is a DELETE SCHEDULE. Lowering a
// horizon destroys every row already past the new one. The defaults below are
// therefore set to the LONGEST value the contract has ever meant, so applying
// this on an existing install can only ever remove data that the install had
// already declared expendable:
//
//   * findings / tunnels default to 90 days — the value the LIVE cluster has
//     been running (init.sql said 30; nothing had enforced 30 on any
//     long-running install, so converging to 30 would have silently deleted
//     two months of RCA evidence on first boot after this change). init.sql is
//     updated to 90 in the same commit so the two agree.
//   * every other table keeps its init.sql value, which is also its live value.
//
// A shorter horizon is an explicit operator decision: set the env knob. Each
// applied TTL is logged at boot, so the schedule is never silent.
//
// Safety properties (identical to corr_retention.go, deliberately):
//   - materialize_ttl_after_modify = 0 → metadata-only ALTER, no table rewrite.
//   - ttl_only_drop_parts = 1 is already set per-table in init.sql, so expiry
//     drops whole daily/monthly parts rather than mutating live parts.
//   - a 7-day floor on every knob: a typo can slow retention down, never turn
//     it into instant deletion.
//   - 0 disables a knob explicitly (keep-forever contract); an existing TTL is
//     then left alone rather than removed, because removing one is a decision
//     no boot path should make on its own.

import (
	"log"
	"strconv"
)

// chRetentionDays is the resolved hot retention for the telemetry family, in
// days. Zero means "leave this table's TTL alone".
type chRetentionDays struct {
	Flows        int // netops.flows — highest volume, shortest horizon
	Findings     int // netops.findings — RCA output
	Tunnels      int // netops.tunnels — tunnel state history
	CorrSignals  int // netops.corr_signals — the hot normalized spine
	WriteAmp     int // netops.corr_tenant_write_amp — per-tenant write accounting
	PathObs      int // netops.path_observations / path_hops / corr_path_edges
	AppObs       int // netops.app_observations
	AppIdent     int // netops.app_identities
	CloudCosts   int // netops.cloud_costs — billing context, deliberately long
	SvcRollup    int // netops.svc_flow_rollup_1m
	PathBaseline int // netops.path_baselines — recomputed, cheap to lose
	Wireless     int // netops.wireless_* per-client event tier (#128) — one knob, five tables
}

// chRetentionDefaults mirrors deployment/docker/clickhouse/init.sql. Keep the
// two in step: ch_retention_test.go asserts that every TTL'd table in init.sql
// appears here, and that no default is SHORTER than the init.sql literal (a
// shorter default would delete data on the boot after an upgrade).
func chRetentionDefaults() chRetentionDays {
	return chRetentionDays{
		Flows:        7,
		Findings:     90,
		Tunnels:      90,
		CorrSignals:  30,
		WriteAmp:     30,
		PathObs:      90,
		AppObs:       30,
		AppIdent:     90,
		CloudCosts:   400, // ~13 months: year-over-year cost context
		SvcRollup:    90,
		PathBaseline: 14,
		Wireless:     30, // per-client events are PII (report B5) — short by default
	}
}

// chRetentionConfig resolves per-table overrides from the environment.
// Invalid values fall back to the default and say so; sub-floor values are
// clamped up, never down.
func chRetentionConfig() chRetentionDays {
	const floorDays = 7
	d := chRetentionDefaults()
	knob := func(env string, def int) int {
		raw := envOr(env, "")
		if raw == "" {
			return def
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			log.Printf("ch-retention: invalid %s=%q, using default %d", env, raw, def)
			return def
		}
		if n > 0 && n < floorDays {
			log.Printf("ch-retention: %s=%d below %d-day safety floor, clamping", env, n, floorDays)
			return floorDays
		}
		return n
	}
	return chRetentionDays{
		Flows:        knob("CH_FLOWS_RETENTION_DAYS", d.Flows),
		Findings:     knob("CH_FINDINGS_RETENTION_DAYS", d.Findings),
		Tunnels:      knob("CH_TUNNELS_RETENTION_DAYS", d.Tunnels),
		CorrSignals:  knob("CH_CORR_SIGNALS_RETENTION_DAYS", d.CorrSignals),
		WriteAmp:     knob("CH_WRITE_AMP_RETENTION_DAYS", d.WriteAmp),
		PathObs:      knob("CH_PATH_RETENTION_DAYS", d.PathObs),
		AppObs:       knob("CH_APP_OBS_RETENTION_DAYS", d.AppObs),
		AppIdent:     knob("CH_APP_IDENTITY_RETENTION_DAYS", d.AppIdent),
		CloudCosts:   knob("CH_CLOUD_COST_RETENTION_DAYS", d.CloudCosts),
		SvcRollup:    knob("CH_SVC_ROLLUP_RETENTION_DAYS", d.SvcRollup),
		PathBaseline: knob("CH_PATH_BASELINE_RETENTION_DAYS", d.PathBaseline),
		Wireless:     knob("CH_WIRELESS_RETENTION_DAYS", d.Wireless),
	}
}

// chRetentionTable names one converged table: which time column its TTL is
// expressed over, and which knob owns it. Declared as data so the guard test
// can enumerate coverage instead of trusting a comment.
type chRetentionTable struct {
	Table string
	Expr  string // the TTL expression, verbatim from init.sql
	Days  func(chRetentionDays) int
}

// chRetentionTables is the complete list of TTL'd telemetry tables. It must
// stay in step with init.sql — ch_retention_test.go fails the build otherwise.
// The correlation history tables (corr_objects/edges/evidence/signals_archive/
// corr_current) are deliberately ABSENT: corr_retention.go owns those, and two
// owners for one TTL is how drift starts.
func chRetentionTables() []chRetentionTable {
	return []chRetentionTable{
		{"flows", "toDateTime(ts)", func(d chRetentionDays) int { return d.Flows }},
		{"findings", "toDateTime(ts)", func(d chRetentionDays) int { return d.Findings }},
		{"tunnels", "toDateTime(ts)", func(d chRetentionDays) int { return d.Tunnels }},
		{"corr_signals", "toDateTime(ts)", func(d chRetentionDays) int { return d.CorrSignals }},
		{"corr_tenant_write_amp", "toDateTime(window_start)", func(d chRetentionDays) int { return d.WriteAmp }},
		{"path_observations", "toDateTime(observed_at)", func(d chRetentionDays) int { return d.PathObs }},
		{"path_hops", "toDateTime(observed_at)", func(d chRetentionDays) int { return d.PathObs }},
		{"corr_path_edges", "toDateTime(created_at)", func(d chRetentionDays) int { return d.PathObs }},
		{"app_observations", "toDateTime(event_time)", func(d chRetentionDays) int { return d.AppObs }},
		{"app_identities", "toDateTime(fused_at)", func(d chRetentionDays) int { return d.AppIdent }},
		{"cloud_costs", "day", func(d chRetentionDays) int { return d.CloudCosts }},
		{"svc_flow_rollup_1m", "minute", func(d chRetentionDays) int { return d.SvcRollup }},
		{"path_baselines", "computed_at", func(d chRetentionDays) int { return d.PathBaseline }},
		// #128 wireless per-client event tier (wireless_schema.go) — one knob:
		// sessions and their derivatives age together, and the 30-day default
		// is a PII decision (report B5/Q4), not merely a cost one.
		{"wireless_sessions", "toDateTime(assoc_start)", func(d chRetentionDays) int { return d.Wireless }},
		{"wireless_onboarding_episodes", "toDateTime(attempt_start)", func(d chRetentionDays) int { return d.Wireless }},
		{"wireless_roams", "toDateTime(ts)", func(d chRetentionDays) int { return d.Wireless }},
		{"wireless_mlo_links", "toDateTime(valid_from)", func(d chRetentionDays) int { return d.Wireless }},
		{"wireless_client_rf", "toDateTime(ts)", func(d chRetentionDays) int { return d.Wireless }},
	}
}

// chRetentionDDL renders the converge statements for the resolved config.
// Pure (no IO) so the boot path's exact statements are assertable in tests —
// the same contract chConvergeStmts keeps.
func chRetentionDDL(d chRetentionDays) []string {
	var stmts []string
	for _, t := range chRetentionTables() {
		days := t.Days(d)
		if days <= 0 {
			// Explicit keep-forever: emit nothing. Do NOT issue
			// `MODIFY TTL` with no expression — that REMOVES an existing TTL,
			// which is an operational decision, not a boot-path one.
			continue
		}
		stmts = append(stmts,
			"ALTER TABLE netops."+t.Table+" MODIFY TTL "+t.Expr+" + INTERVAL "+
				strconv.Itoa(days)+" DAY SETTINGS materialize_ttl_after_modify = 0")
	}
	return stmts
}

// logCHRetention states the schedule at boot. A retention change that nobody
// can see in the logs is a data-deletion policy applied in silence (§10).
func logCHRetention(d chRetentionDays) {
	for _, t := range chRetentionTables() {
		if days := t.Days(d); days > 0 {
			log.Printf("ch-retention: netops.%s keeps %d days (%s)", t.Table, days, t.Expr)
		} else {
			log.Printf("ch-retention: netops.%s TTL left unmanaged (knob set to 0)", t.Table)
		}
	}
}
