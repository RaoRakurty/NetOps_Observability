# NetOps_Observability — developer make targets.
.PHONY: test-correlation-e2e mib-index

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
