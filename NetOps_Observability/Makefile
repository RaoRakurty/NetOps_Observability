# NetOps_Observability — developer make targets.
.PHONY: test-correlation-e2e mib-index test-ticketing-unit test-servicenow-mock \
        release-gate release-gate-live bundle bundle-core bundle-status \
        release-qualify release-qualify-selftest

# #97 packaging — customer-bundle lockstep. `bundle` builds the offline
# installer bundle at HEAD (scripts/make-installer.sh: images + source +
# MANIFEST/SHA256SUMS, forbidden-image guards baked in); `bundle-status`
# FAILS when the newest built bundle in dist/ lags shippable code (the same
# check runs warn-only on every `git push` via scripts/git-hooks/pre-push).
bundle:
	bash scripts/make-installer.sh

bundle-core:
	bash scripts/make-installer.sh --core

bundle-status:
	bash scripts/bundle-staleness.sh

# #101 release-gate storm SLOs — the shippable-lane contract. Every NEW signal
# lane must pass this BEFORE it ships (docs/design/correlation-data-contract.md
# §new-lane): broken-source write budget, tenant blast radius, RCA integrity
# under damping, bounded-IO SQL shapes, retention safety. Pure/offline (runs in
# normal CI too — this target exists so it is one discoverable command).
release-gate:
	cd src/correlation && python3 -m pytest -q test_lane_soak.py \
	    test_storm_release_gate.py test_corr_current_projection.py \
	    test_tenant_write_amp.py
	cd src/backend && go test . -count=1 -run \
	    'TestNoSelectStarOnCorrTables|TestNoWideColumnsThroughFolds|TestCorrCurrent|TestCorrelationsListSQLShape|TestNoWholeTableEdgesAggregation|TestCorrRetention|TestCHWorkload'

# Same gate against the LIVE stack: per-endpoint read budgets from
# system.query_log + a retention/cold-tier preview. Requires the stack up.
release-gate-live: release-gate
	scripts/ch-query-budget-check.sh
	scripts/ch-retention-dry-run.sh

# Tracker 203 — the reference-capacity regression suite. `release-qualify`
# reruns the FROZEN CORRELIX REFERENCE CAPACITY V1 qualification against the
# DEPLOYED build and grades every clause against the `storm-s11` baseline of
# record: ~1 h of exclusive rig time, owner-gated, and it refuses on an unquiet
# host. `release-qualify-selftest` proves the SUITE's own logic against the
# checked-in leg fixture instead — seconds, no rig, no stack, no .env — and is
# what CI runs; it is never qualification evidence.
# Runbook: docs/runbooks/release-qualification.md.
release-qualify:
	python3 scripts/release-qualify.py

release-qualify-selftest:
	python3 scripts/release-qualify.py --self-test

# #101 first-customer acceptance: everything release-gate-live checks PLUS the
# external critical-alert delivery gate (in-app-only alerting fails). Run with
# SEND=1 to deliver a real test push (required once before go-live). Auth via
# CORRELIX_API_TOKEN or CORRELIX_ADMIN_USER/PASSWORD.
first-customer-check: release-gate-live
	scripts/verify-critical-alert-channel.sh $(if $(SEND),--send,)

# RCA auto-ticketing (#78) — pure unit + mock-ServiceNow tests (no live stack).
# The mock is httptest-backed (ticketing_servicenow_test.go); SSRF_ALLOW_PRIVATE
# is set by the tests themselves. Integration/E2E (P3/P5) add their own targets.
test-ticketing-unit:
	cd src/backend && go test . -run 'Ticket|CorrTicket|TicketDecision' -count=1

test-servicenow-mock:
	cd src/backend && go test . -run 'ServiceNow|Outbox' -count=1

# Regenerate + validate the embedded SNMP OID index from the vendored MIB tree
# (build-time, offline; pysmi optional — validates the seed without it). Rebuild
# the Go backend afterwards so go:embed picks up the new index.
# See src/backend/collectors/mibs/README.md.
mib-index:
	python3 src/backend/collectors/mibs/gen_index.py

# End-to-end Correlation Engine validation (live stack: inject -> Redpanda ->
# correlation service -> ClickHouse/API). Requires the stack to be running.
# Env: E2E_REDPANDA, E2E_CLICKHOUSE, E2E_API, E2E_TOKEN, E2E_WAIT.
test-correlation-e2e:
	python3 src/correlation/correlation_e2e.py
