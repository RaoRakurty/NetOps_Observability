# NetOps_Observability — developer make targets.
.PHONY: test-correlation-e2e

# End-to-end Correlation Engine validation (live stack: inject -> Redpanda ->
# correlation service -> ClickHouse/API). Requires the stack to be running.
# Env: E2E_REDPANDA, E2E_CLICKHOUSE, E2E_API, E2E_TOKEN, E2E_WAIT.
test-correlation-e2e:
	python3 src/correlation/correlation_e2e.py
