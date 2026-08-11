"""Step-2 assurance contracts stay pinned to the as-built truth (tracker #151).

mtls-edges.yaml and telemetry-lanes.yaml are THIN OVERLAYS: they must never
drift from the sources they overlay — the transport inventory (edge ids), the
kafka-init topic list (lane topics), and the workload identity registry
(SPIFFE service names). Drift here would hand step 2 a test plan for a mesh
that does not exist.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEC = ROOT / "docs" / "security"


def _load(name: str) -> dict:
    return json.loads((SEC / name).read_text())


def test_mtls_edges_reference_real_inventory_edges():
    inv_ids = {e["id"] for e in _load("transport-inventory.yaml")["edges"]}
    rows = _load("mtls-edges.yaml")["edges"]
    assert rows, "mtls-edges.yaml has no rows"
    bad = [r["edge"] for r in rows if r["edge"] not in inv_ids]
    assert not bad, f"contract rows referencing nonexistent inventory edges: {bad}"


def test_every_tls_profile_edge_has_a_contract_row():
    inv = _load("transport-inventory.yaml")["edges"]
    covered = {r["edge"] for r in _load("mtls-edges.yaml")["edges"]}
    missing = [
        e["id"] for e in inv
        if "tls" in (e.get("security_profile", {}).get("transport") or "").lower()
        and e["id"] not in covered
    ]
    assert not missing, (
        f"TLS-profile inventory edges with NO assurance contract: {missing} — "
        "add a row to mtls-edges.yaml (the coverage rule in its header)")


def test_contract_identities_are_registry_services():
    """Every spiffe id named in either contract must belong to a service the
    workload registry actually issues (regex over workloadid.go — the same
    cross-language pinning preflight uses on compose)."""
    src = (ROOT / "src" / "backend" / "internal" / "workloadid" / "workloadid.go").read_text()
    services = set(re.findall(r'\{Service:\s*"([a-z0-9-]+)"', src))
    assert len(services) >= 25, "workloadid parse drift"
    spiffe_re = re.compile(r"spiffe://netops/ns/default/sa/([a-z0-9-]+)")
    for fname in ("mtls-edges.yaml", "telemetry-lanes.yaml"):
        text = (SEC / fname).read_text()
        named = set(spiffe_re.findall(text))
        unknown = named - services
        assert not unknown, f"{fname} names identities the registry does not issue: {sorted(unknown)}"


def test_lane_topics_are_created_by_kafka_init():
    """Every literal netops.* topic a lane names must be in kafka-init's
    creation list (auto-create is OFF — an uncreated topic is a dead lane)."""
    compose = (ROOT / "deployment" / "docker" / "docker-compose.yml").read_text()
    init = compose[compose.index("kafka-init:"):]
    init = init[:init.index("networks:")]
    created = set(re.findall(r"(netops\.[a-z_.0-9]+)", init))
    assert len(created) >= 14, f"kafka-init parse drift: {sorted(created)}"
    lanes = _load("telemetry-lanes.yaml")["lanes"]
    named: set[str] = set()
    for lane in lanes:
        for field in (lane.get("topic", ""), lane.get("entry", "")):
            named |= set(re.findall(r"(netops\.[a-z_.0-9]+)", field))
    missing = named - created
    assert not missing, f"lanes name topics kafka-init never creates: {sorted(missing)}"


def test_consumer_groups_match_asbuilt_names():
    lanes = _load("telemetry-lanes.yaml")["lanes"]
    groups = {c["group"] for lane in lanes for c in lane.get("consumers", [])}
    for g in groups:
        assert g == "netops-correlation" or g.startswith("netops-router-"), (
            f"unexpected consumer-group naming: {g}")


def test_schema_versions():
    for fname in ("mtls-edges.yaml", "telemetry-lanes.yaml"):
        assert _load(fname)["schema_version"] == 1


def test_router_image_provides_secret_backend_dependencies():
    """F-7 (assurance run 2026-08-09): the Sealed Fields secret backend
    (vector-router/cx-secret-backend.sh) executes `curl` for its key fetch —
    over mTLS with the router's own certificate, which BusyBox wget cannot do.
    The stock vector image ships no curl, so with a seal rule present Vector
    refused every config load: fail-closed, but the feature was undeliverable.

    Pin both halves: the compose vector-router service must use the derived
    build (not the stock image), and the derived Dockerfile must install every
    external binary the secret backend script invokes.
    """
    compose = (ROOT / "deployment" / "docker" / "docker-compose.yml").read_text()
    m = re.search(r"^  vector-router:\n(.*?)(?=^  \S)", compose, re.M | re.S)
    assert m, "vector-router service missing from docker-compose.yml"
    svc = m.group(1)
    assert "build:" in svc and "./vector-router" in svc, (
        "vector-router must build the derived image (vector-router/Dockerfile) — "
        "the stock timberio/vector image cannot run the sealed-fields secret backend (F-7)"
    )

    dockerfile = (ROOT / "deployment" / "docker" / "vector-router" / "Dockerfile").read_text()
    script = (ROOT / "deployment" / "docker" / "vector-router" / "cx-secret-backend.sh").read_text()
    # Every external fetch binary the script calls must be installed by the image.
    for binary in ("curl",):
        assert binary in script, f"secret backend no longer calls {binary}; update this pin"
        assert re.search(rf"apk add[^\n]*\b{binary}\b", dockerfile), (
            f"vector-router/Dockerfile must `apk add {binary}` — the secret backend executes it"
        )


def test_postgres_tls_entrypoint_requires_hostssl():
    """F-4 (assurance run 2026-08-09): postgres accepted non-TLS TCP.

    `host` in pg_hba matches SSL **and** non-SSL, so the image/initdb default
    `host all all all scram-sha-256` let any credentialed client on the compose
    network connect with sslmode=disable and put its password + rows on the
    wire — TLS on this store was client-side convention only. Same class as the
    plaintext clickhouse-8123 / valkey-6379 listeners the enforce wave removed;
    postgres's plaintext "listener" lives in pg_hba and was missed.

    The wrapper now OWNS the hba file (passed via -c hba_file) instead of
    editing PGDATA's copy, so the policy cannot depend on initdb order or be
    lost to a re-init. Pin the three properties that make it enforcement:
    the network row is hostssl, no bare `host` row spans non-loopback space,
    and the server is actually told to use this file.

    Live counterpart (needs a TLS-wrapped postgres, hence env-gated):
    TestPostgresRefusesPlaintextTCP in src/backend/pg_hostssl_guard_test.go.
    """
    entry = (ROOT / "deployment" / "docker" / "postgres" / "tls-entrypoint.sh").read_text()

    assert re.search(r"^-c hba_file=|hba_file=", entry, re.M), (
        "tls-entrypoint.sh must pass -c hba_file — an hba it writes but does not "
        "hand to postgres enforces nothing (F-4)"
    )

    # The heredoc the wrapper writes is the policy; read the rows out of it.
    body = re.search(r"cat > \"\$HBA\" <<'EOF'\n(.*?)\nEOF", entry, re.S)
    assert body, "tls-entrypoint.sh no longer writes the pg_hba heredoc; update this pin"
    rows = [
        line.split()
        for line in body.group(1).splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert rows, "the staged pg_hba has no rows"

    loopback = {"127.0.0.1/32", "::1/128", "samehost", "localhost"}
    network_rows = [r for r in rows if r[0] in ("host", "hostssl", "hostnossl")]
    assert network_rows, "the staged pg_hba has no TCP rows at all"

    # (a) plaintext-capable TCP is confined to loopback (in-container boundary:
    #     the healthcheck and exec'd psql), never the compose network.
    plaintext_capable = [
        r for r in network_rows
        if r[0] in ("host", "hostnossl") and (len(r) < 4 or r[3] not in loopback)
    ]
    assert not plaintext_capable, (
        "pg_hba rows reachable over the compose network must be `hostssl`, never "
        f"`host`/`hostnossl` — `host` matches non-SSL too (F-4): {plaintext_capable}"
    )

    # (b) and the network IS served: at least one hostssl row spans beyond loopback.
    assert any(
        r[0] == "hostssl" and len(r) >= 4 and r[3] not in loopback for r in network_rows
    ), "the staged pg_hba has no hostssl row for the compose network (F-4)"


def test_syslog_hop_serves_and_requires_mesh_tls():
    """F-1 (assurance run 2026-08-09): syslog-ng → vector-aggregator:6601 was
    plaintext TCP with no exception row — the last silent intra-stack hop, in
    the same trust segment every converted hop lives in. Both ends speak TLS
    and both identities already exist (aggregator server SVID serves the four
    ingest lanes; the syslog-ng client identity was registered for exactly
    this hop, SEC-014.1).

    Pin the four halves of the conversion:
    (a) vector.yaml `syslog_in` carries the env-gated tls block — same idiom
        as the ingest lanes, with verify_certificate so a mesh client
        certificate is REQUIRED when the hop is enabled (proven semantics,
        SEC-013.1);
    (b) the tracked syslog-ng TLS variant drives the hop over transport(tls),
        verifies the mesh CA (peer-verify required-trusted), presents the
        syslog-ng SVID, and KEEPS the F-48 reliable disk-buffer — losing the
        buffer in the variant would silently re-open the restart-drop hole;
    (c) compose.tls.yml flips both ends together (variant conf + CA/SVID
        mounts on syslog-ng; SYSLOG_TLS_ENABLED on the aggregator);
    (d) the inventory row records the shape in security_profile, which drags
        the hop into the mtls-edges coverage rule (a contract row with
        negatives becomes mandatory).
    """
    import yaml

    # (a) the vector source: enabled + verify_certificate ride the SAME env
    # gate so "TLS on" always means "client cert required", never server-only.
    vec = yaml.safe_load(
        (ROOT / "deployment" / "docker" / "vector" / "vector.yaml").read_text())
    tls = (vec["sources"]["syslog_in"] or {}).get("tls") or {}
    gate = "${SYSLOG_TLS_ENABLED:-false}"
    assert tls.get("enabled") == gate, (
        "vector.yaml syslog_in needs an env-gated tls block (F-1); plaintext "
        "must remain the base-compose default")
    assert tls.get("verify_certificate") == gate, (
        "syslog_in tls must set verify_certificate on the same gate — without "
        "it any client on the compose network reaches the source unauthenticated")
    for key in ("crt_file", "key_file", "ca_file"):
        assert tls.get(key), f"syslog_in tls block is missing {key}"

    # (b) the syslog-ng variant conf.
    d = ROOT / "deployment" / "docker" / "syslog-ng"
    variant = (d / "syslog-ng-tls.conf").read_text()
    assert 'transport("tls")' in variant
    assert "port(6601)" in variant
    assert "peer-verify(required-trusted)" in variant, (
        "the variant must VERIFY the mesh CA — an unverified TLS hop is "
        "encryption without authentication")
    for opt in ("ca-file(", "cert-file(", "key-file("):
        assert opt in variant, f"variant destination is missing tls {opt})"
    assert "reliable(yes)" in variant and "disk-buffer" in variant, (
        "the TLS variant dropped the F-48 reliable disk-buffer — an aggregator "
        "restart would silently drop device syslog again")
    # Both variants share one body: options/source/parser live in core.conf so
    # the two top-level confs cannot drift apart.
    base = (d / "syslog-ng.conf").read_text()
    core_include = '@include "/etc/syslog-ng/conf.d/core.conf"'
    assert core_include in variant and core_include in base, (
        "both syslog-ng confs must @include the shared core.conf body")
    assert (d / "core.conf").exists()

    # (c) compose.tls.yml wires both ends.
    tlsc = yaml.safe_load(
        (ROOT / "deployment" / "docker" / "compose.tls.yml").read_text())
    sy = tlsc["services"]["syslog-ng"]
    assert any("syslog-ng-tls.conf" in part for part in sy["command"]), (
        "compose.tls.yml must point syslog-ng at the TLS variant conf")
    vols = " ".join(sy.get("volumes", []))
    assert "data/tls/ca.pem" in vols and "data/tls/services/syslog-ng" in vols, (
        "compose.tls.yml must mount the mesh CA and the syslog-ng SVID dir")
    agg_env = tlsc["services"]["vector-aggregator"]["environment"]
    assert str(agg_env.get("SYSLOG_TLS_ENABLED")).lower() == "true", (
        "compose.tls.yml must enable SYSLOG_TLS_ENABLED on vector-aggregator")

    # (d) the inventory row declares the achieved shape (current stays
    # plaintext while the base-compose default listener is plaintext — the
    # api-opensearch precedent; the conversion lives in security_profile).
    inv = {e["id"]: e for e in _load("transport-inventory.yaml")["edges"]}
    prof = inv["syslog-ng-vector"].get("security_profile") or {}
    assert "tls" in (prof.get("transport") or "").lower(), (
        "transport-inventory syslog-ng-vector needs a security_profile "
        "recording the TLS conversion (F-1: declared, never silent)")
