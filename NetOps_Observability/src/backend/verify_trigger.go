package main

// verify_trigger.go — the Active Verification auto-trigger (RCA spec item 8).
// A bounded background loop that watches the corr_current hot projection for
// OPEN cases sitting at the SUSPECTED tier ("needs a second independent
// source") in tenants that opted in, and launches at most a few bounded
// verification runs per tick, deduped per case by the cooldown window.
//
// nms_scheduler.go loop idiom: the ticker re-evaluates due-ness; the per-case
// cooldown (default 15 m) is the actual pacing. Everything is bounded: cases
// per tenant per scan, auto runs per tick, devices per run, run budget.

import (
	"context"
	"errors"
	"netops/backend/internal/verify"
	"time"

	"netops/backend/internal/chschema"
)

func verifyScanInterval() time.Duration {
	return secEnvDuration("VERIFY_SCAN_INTERVAL_SEC", 60, 15, 3600)
}
func verifyAutoPerTick() int { return clampInt(envInt("VERIFY_AUTO_PER_TICK", 3), 1, 10) }

// verifyLoop runs until ctx is done. Started from main only when
// FEATURE_ACTIVE_VERIFICATION=true.
func (s *server) verifyLoop(ctx context.Context, tick time.Duration) {
	s.verifyTickOnce(ctx)
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.verifyTickOnce(ctx)
		}
	}
}

// verifyTickOnce scans every opted-in tenant for suspected open cases and
// launches cooled-down runs, bounded per tick.
func (s *server) verifyTickOnce(ctx context.Context) {
	launched := 0
	// An unreadable config yields an EMPTY opt-in list that looks exactly like
	// "nobody opted in" — say so every tick instead of quietly doing nothing.
	if err := s.verifyCfg.Unavailable(); err != nil {
		logWarn("verify", "auto-verification idle: the opt-in config could not be read, so NO tenant can be evaluated",
			map[string]any{"err": err.Error()})
		return
	}
	for _, tenant := range s.verifyCfg.EnabledTenants() {
		if ctx.Err() != nil || launched >= verifyAutoPerTick() {
			return
		}
		// Tenant-scoped read of the hot projection (row policies enforce the
		// scope server-side as well).
		sql := `SELECT toString(correlation_id) AS cid, affected,
       toString(owner) AS owner, top_hypothesis,
       ` + chschema.ISO("window_start") + ` AS window_start
  FROM netops.corr_current FINAL
 WHERE state = 'open' AND verdict_tier = 'suspected'
 ORDER BY window_end DESC
 LIMIT 25
FORMAT JSONEachRow`
		rows, err := s.chRowsScope(ctx, tenant, sql, "verify_scan")
		if err != nil {
			logWarn("verify", "suspected-case scan failed", map[string]any{"tenant": tenant, "err": err.Error()})
			continue
		}
		for _, row := range rows {
			if launched >= verifyAutoPerTick() {
				break
			}
			cid := asStr(row["cid"])
			if cid == "" || !isUUIDToken(cid) {
				continue
			}
			// Dedupe: at most one run per case per cooldown window.
			if last, ok := s.verifyRuns.Latest(tenant, cid); ok &&
				time.Since(last.StartedAt) < verifyCooldown() {
				continue
			}
			devices := affectedDevices(row["affected"])
			if len(devices) == 0 {
				continue // localization unknown — nothing to interrogate
			}
			// Module-trigger context: the scan itself guarantees the tier.
			cc := verify.CaseContext{
				Owner:         asStr(row["owner"]),
				TopHypothesis: asStr(row["top_hypothesis"]),
				VerdictTier:   "suspected",
				WindowStart:   parseCHTime(row["window_start"]),
			}
			rec, err := s.startVerificationRun(tenant, cid, "auto", "system:verify",
				"suspected-tier case — probing for an independent second source", devices, cc)
			switch {
			case err == nil:
				launched++
				logInfo("verify", "auto verification launched", map[string]any{
					"tenant": tenant, "correlation_id": cid, "run_id": rec.RunID,
				})
			case errors.Is(err, errVerifyNoTargets), errors.Is(err, errVerifyRunning), errors.Is(err, verify.ErrDisabled):
				// expected paces/gates — quiet skip
			default:
				logWarn("verify", "auto verification failed to start", map[string]any{
					"tenant": tenant, "correlation_id": cid, "err": err.Error(),
				})
			}
		}
	}
}

// clampInt bounds v to [lo, hi] (local copy; the original moved into
// internal/verify with the engine).
func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
