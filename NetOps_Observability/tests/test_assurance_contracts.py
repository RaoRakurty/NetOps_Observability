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


def _compose_yaml(text: str) -> dict:
    """Parse a compose file that may carry compose's merge tags (!override,
    !reset) — yaml.safe_load rejects unknown tags, and the TLS variant uses
    !override to clear profile gating (seal sidecar, nginx ports on the lab)."""
    import yaml

    class _ComposeLoader(yaml.SafeLoader):
        pass

    def _passthrough(loader, node):
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node)
        return loader.construct_scalar(node)

    _ComposeLoader.add_constructor("!override", _passthrough)
    _ComposeLoader.add_constructor("!reset", _passthrough)
    return yaml.load(text, Loader=_ComposeLoader)


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


def test_quarantine_pipeline_wiring():
    """F-11 seal-or-quarantine (owner decision 2026-08-12), slice 1: the
    static halves of the quarantine path. The SEALING half lives in the
    GENERATED processors config (see processors/quarantine_test.go); what the
    tracked configs must provide:

    (a) the registry-MISS discriminator: the attribution lookup sites stamp
        `.tenant_registry` hit/miss — a registry hit that maps a KNOWN
        platform device to the empty tenant is NOT a miss, which is what
        keeps the load-bearing platform untagged bucket (Grafana, self-
        monitoring RCA, device-join visibility) intact;
    (b) the routing: quarantine-enveloped docs (`cx_quarantine == true`) go
        to a dedicated operator-only index — never the per-lane indices,
        never ClickHouse, never the plaintext deadletter;
    (c) the storage contract: an index template that maps ONLY the metadata
        (the sealed payload stays unmapped/unsearchable) and a bounded ISM
        retention policy of its own.
    """
    root = ROOT / "deployment" / "docker"
    agg = (root / "vector" / "vector.yaml").read_text()
    rtr = (root / "vector-router" / "vector.yaml").read_text()

    # (a) discriminator stamps at every device-registry lookup site.
    for name, text, lane in (("aggregator", agg, "syslog"),
                             ("aggregator", agg, "snmptrap"),
                             ("router", rtr, "flows")):
        assert text.count('.tenant_registry = "miss"') >= 1, (
            f"{name}: no registry-miss stamp — the quarantine guard has "
            f"nothing to key on (F-11 {lane})")
    assert agg.count('.tenant_registry = "miss"') >= 2, (
        "aggregator must stamp the miss on BOTH syslog and snmptrap lookups")
    assert '.tenant_registry = "hit"' in agg and '.tenant_registry = "hit"' in rtr, (
        "hit must be stamped explicitly — an absent field is indistinguishable "
        "from a lane that predates the discriminator")

    # (b) routing: route transforms + the dedicated sink.
    assert "opensearch_quarantine" in rtr, "router has no quarantine sink (F-11)"
    assert "netops-quarantine-%Y.%m.%d" in rtr, (
        "quarantine index must be its own dateful index, no tenant segment")
    for lane in ("syslog", "snmptrap", "flows"):
        assert f"{lane}_store_route" in rtr, (
            f"lane {lane}: no store route — quarantine docs would land in the "
            f"normal per-lane index")
        assert f"{lane}_store_route._unmatched" in rtr, (
            f"lane {lane}: normal sink must consume the route's _unmatched output")
    assert "clickhouse_flows" in rtr and "flows_store_route._unmatched" in rtr, (
        "quarantined flows must not reach ClickHouse")
    # The deadletter sink must not consume quarantine routes.
    dl = rtr[rtr.index("opensearch_deadletter"):]
    dl = dl[:dl.index("inputs:") + 200]
    assert "quarantine" not in dl, "deadletter must not consume quarantine outputs"

    # (c) template + retention.
    tpl = json.loads((root / "opensearch" / "index-templates.json").read_text())
    q = tpl["templates"].get("netops-quarantine")
    assert q, "netops-quarantine index template missing"
    props = q["template"]["mappings"]["properties"]
    assert q["template"]["mappings"].get("dynamic") in (False, "false"), (
        "quarantine template must be dynamic:false (field wall)")
    assert "cx_quarantine_payload" not in props, (
        "the sealed payload must stay UNMAPPED — mapping it makes ciphertext "
        "searchable/aggregatable surface for no benefit")
    for field in ("cx_event_id", "identity_sha", "reason", "lane", "received_at"):
        assert field in props, f"quarantine template must map metadata field {field}"

    ism = (root / "opensearch" / "apply-ism.sh").read_text()
    assert "QUARANTINE_RETENTION_DAYS" in ism, (
        "quarantine retention must be its own bounded, configurable window")
    assert "netops-quarantine-*" in ism, (
        "apply-ism.sh never attaches a policy to netops-quarantine-* — "
        "unattributable payloads would be retained forever (INV-F11-09)")


def test_router_lanes_strip_inbound_quarantine_mark():
    """F-11 review fix (2026-08-14): the store routes match
    `to_bool(.cx_quarantine) ?? false`, but the mark is only trustworthy when
    the router's OWN generated stage minted it. Bus producers' JSON passes
    verbatim, so a compromised producer stamping cx_quarantine:true could
    divert its events — full plaintext — into the operator-only
    netops-quarantine-* index, bypassing the tenant indices and ClickHouse
    (and Restore refuses them, so they linger until ISM delete). Pin that
    every router lane's FIRST transform deletes the inbound field before the
    generated quarantine stage (which runs later in the chain) can set it —
    the del(.label) pattern from the applogs mapping fix."""
    import yaml
    cfg = yaml.safe_load(
        (ROOT / "deployment" / "docker" / "vector-router" / "vector.yaml").read_text())
    transforms = cfg["transforms"]

    def first_statement(src: str) -> str:
        for line in src.splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                return s
        return ""

    # Every lane whose events reach an OpenSearch/ClickHouse store — not just
    # the three quarantine-routed ones: an un-stripped mark on any lane is an
    # attacker-controlled field in a trusted routing position.
    for name in ("applogs_tagged", "syslog_tagged", "snmptrap_tagged",
                 "cloudlogs_tagged", "flows_decoded"):
        src = transforms[name]["source"]
        assert "del(.cx_quarantine)" in src, (
            f"{name}: inbound cx_quarantine is not stripped — a producer can "
            f"plant plaintext docs in the quarantine index (F-11)")
        assert first_statement(src) == "del(.cx_quarantine)", (
            f"{name}: del(.cx_quarantine) must be the FIRST statement, before "
            f"any logic can observe or propagate the forged mark")


def test_router_lanes_strip_forgeable_drop_and_event_id_marks():
    """F-11 hardening follow-up (2026-08-14): cx_quarantine is not the only
    producer-controlled field in a trusted position — bus producers' JSON
    passes verbatim into the lane heads, so two more marks must die there:

    (a) .cx_drop — the generated <lane>_rules filter discards any event where
        to_bool(.cx_drop) is true. Only an operator-configured drop_event
        processor (which runs DOWNSTREAM of the lane head, in the generated
        rules chain) may mint it; inbound it is a forged kill-switch — a
        compromised producer pre-marks events and this tier silently discards
        them with no dead-letter and no processor metric attributing the
        drop. Strip must be UNCONDITIONAL.

    (b) .cx_event_id — `id_key` on every OpenSearch sink, i.e. the storage
        document _id: whoever controls it can OVERWRITE the doc bearing that
        id or collapse N events into one (silent suppression). It CANNOT be
        stripped unconditionally: the operator restore path
        (internal/quarantine) re-injects restored events onto the ORIGINAL
        lane topics carrying the envelope's uuid so a re-run UPSERTS instead
        of duplicating (INV-F11-08). The strip must therefore be GUARDED —
        keep only a uuid-shaped id accompanied by the
        cx_restored_from="quarantine" provenance marker, strip everything
        else. (Residual: the marker itself is unauthenticated; the config
        documents why that is accepted and what full closure needs.)
    """
    import yaml
    cfg = yaml.safe_load(
        (ROOT / "deployment" / "docker" / "vector-router" / "vector.yaml").read_text())
    transforms = cfg["transforms"]

    for name in ("applogs_tagged", "syslog_tagged", "snmptrap_tagged",
                 "cloudlogs_tagged", "flows_decoded"):
        src = transforms[name]["source"]

        # (a) cx_drop dies unconditionally at the lane head (own statement,
        # not inside any guard — pinned as a whole line at any indent depth
        # equal to the top-level del(.cx_quarantine)).
        drop_stmts = re.findall(r"^(\s*)del\(\.cx_drop\)\s*$", src, re.M)
        assert drop_stmts, (
            f"{name}: inbound cx_drop is not stripped — a compromised "
            f"producer can pre-mark its events for a silent, unattributed "
            f"drop by the <lane>_rules filter")
        quar = re.search(r"^(\s*)del\(\.cx_quarantine\)\s*$", src, re.M)
        assert quar and drop_stmts[0] == quar.group(1), (
            f"{name}: del(.cx_drop) must sit at the lane head's top level "
            f"(same depth as del(.cx_quarantine)) — a conditional strip is "
            f"a conditional forgery window")

        # (b) cx_event_id strip exists...
        assert "del(.cx_event_id)" in src, (
            f"{name}: inbound cx_event_id is not stripped — a producer-"
            f"chosen id becomes the OpenSearch _id (id_key) and can "
            f"overwrite or dedup-suppress stored documents")
        # ...is guarded by the restore provenance marker + uuid shape
        # (NEVER unconditional — that breaks restore replay idempotency,
        # INV-F11-08)...
        guarded = re.search(
            r"if\s+!\(\(to_string\(\.cx_restored_from\)\s*\?\?\s*\"\"\)\s*==\s*\"quarantine\""
            r"[^\n]*match\(to_string\(\.cx_event_id\)[^\n]*\)\s*\{\s*\n\s*del\(\.cx_event_id\)",
            src)
        assert guarded, (
            f"{name}: del(.cx_event_id) must be guarded on "
            f"cx_restored_from==\"quarantine\" AND a uuid-shaped id — "
            f"unconditional stripping breaks quarantine-restore upserts "
            f"(INV-F11-08), while an unguarded keep re-opens the forgery")
        # ...and is the ONLY cx_event_id strip (no second, unguarded copy).
        assert src.count("del(.cx_event_id)") == 1, (
            f"{name}: exactly one (guarded) del(.cx_event_id) expected")

        # Ordering: the marks die at the head, before any lane logic.
        assert (src.index("del(.cx_quarantine)")
                < src.index("del(.cx_drop)")
                < src.index("del(.cx_event_id)")), (
            f"{name}: strip order must be cx_quarantine, cx_drop, then the "
            f"guarded cx_event_id — all before the lane's own logic")


def test_vector_tiers_reload_enrichment_on_change():
    """F-10 (assurance run 2026-08-09, step-3 e2e): Vector reads enrichment
    tables ONCE at (re)load — --watch-config watches config files only — so a
    device→tenant assignment took effect only at the next restart; until then
    that device's telemetry landed UNTAGGED (and a tenant-guarded seal rule
    silently did not apply). Pin the reload mechanism on BOTH tiers that load
    device_tenant.csv:
    (a) each vector service boots through the reload wrapper (entrypoint) and
        mounts the script — and keeps an explicit `command` (an entrypoint
        override DROPS the image CMD, lesson e);
    (b) the wrapper watches CONTENT (md5, not mtime) and reloads via SIGHUP,
        forwarding lifecycle signals since it runs as PID 1;
    (c) the paths agree: the wrapper's default CSV is exactly where the
        enrichment mount lands in both vector configs."""
    import yaml

    script_path = ROOT / "deployment" / "docker" / "vector" / "cx-enrichment-reload.sh"
    assert script_path.exists(), (
        "cx-enrichment-reload.sh missing — the vector tiers have no way to "
        "notice a device→tenant change without a restart (F-10)")
    script = script_path.read_text()
    for needle, why in [
        ("md5sum", "content hash, not mtime — the export tick used to churn mtime"),
        ("kill -HUP", "SIGHUP is the reload signal"),
        ("set -eu", "§16.3 bash hygiene"),
        ("trap", "PID-1 wrapper must forward lifecycle signals to vector"),
        ("device_tenant.csv", "must default to the mounted enrichment path"),
    ]:
        assert needle in script, f"reload wrapper lost {needle!r} ({why})"

    compose = yaml.safe_load(
        (ROOT / "deployment" / "docker" / "docker-compose.yml").read_text())
    # The wrapper is REACHED through a ./vector DIRECTORY mount (F-51: file
    # mounts pin inodes across edits): the aggregator's own conf mount for the
    # aggregator, a shared mount for the router.
    wrapper_mount = {
        "vector-aggregator": ("/etc/vector/conf/cx-enrichment-reload.sh",
                              "./vector:/etc/vector/conf"),
        "vector-router": ("/etc/vector/shared/cx-enrichment-reload.sh",
                          "./vector:/etc/vector/shared"),
    }
    for svc, (ep_path, mount) in wrapper_mount.items():
        s = compose["services"][svc]
        ep = " ".join(s.get("entrypoint") or [])
        assert ep_path in ep, (
            f"{svc} does not boot through the enrichment reload wrapper (F-10)")
        assert s.get("command"), (
            f"{svc} lost its explicit command — with an entrypoint override the "
            "image CMD is dropped and vector starts with no config (lesson e)")
        vols = " ".join(s.get("volumes") or [])
        assert mount in vols, (
            f"{svc}: the wrapper's directory mount {mount!r} is gone — the "
            "entrypoint path would not resolve (F-51: directory mounts only)")
        assert "/etc/vector/enrichment" in vols, f"{svc} lost the enrichment mount"


def test_ci_runs_the_tls_install_path():
    """F-9 (assurance run 2026-08-09): fresh-install-integrity ran only the two
    preflights — no CI leg ever EXECUTED install.py, so the one-question
    delivery shape and the two-phase mint (phase A mint-before-stores, phase B
    fail-closed recreate) were validated by hand only. Pin that the workflow
    both invokes `install.py --tls=yes` for real and asserts the mesh SERVES
    afterwards (a boot that exits 0 into a crash-loop must not pass)."""
    wf = (ROOT.parent / ".github" / "workflows" /
          "fresh-install-integrity.yml").read_text()
    assert re.search(r"install\.py\s+--tls=yes", wf), (
        "fresh-install-integrity.yml has no leg RUNNING install.py --tls=yes — "
        "the delivery shape is validated only by hand (F-9)")
    assert "--cacert" in wf and "/admin/health" in wf, (
        "the --tls leg must prove the TLS ingress actually SERVES "
        "(CA-verified health probe), not merely that install.py exited 0")
    assert "restarting" in wf, (
        "the --tls leg must fail on crash-looping services — exit 0 from "
        "install.py does not prove the mesh stayed up")


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
    tlsc = _compose_yaml(
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


def test_gotenberg_pdf_sidecar_rides_mesh_tls():
    """api → gotenberg carries TENANT RCA/report document content (full HTML
    bodies) and was the last plaintext app hop on TLS deployments.

    Gotenberg 8 natively serves TLS (--api-tls-cert-file/--api-tls-key-file)
    but performs NO client-certificate verification, so this hop is TLS with
    mesh-CA server verification, not mTLS — the api still PRESENTS its SVID
    via the shared backend transport; gotenberg just doesn't check it.

    The image starts as uid 1001 with no root entrypoint to chown, so the SVID
    (minted uid 65532) is staged by a one-shot init service (kafka-init
    precedent, cross-uid staging like postgres/clickhouse tls-entrypoint).

    Pin the conversion in the TLS variant AND the two-variant doctrine (base
    compose stays plaintext-default for fresh installs).
    """
    import yaml

    dc = ROOT / "deployment" / "docker"
    base = yaml.safe_load((dc / "docker-compose.yml").read_text())
    tlsc = _compose_yaml((dc / "compose.tls.yml").read_text())

    # Two-variant pin: the base gotenberg keeps NO TLS flags and the base api
    # default stays the plaintext URL (fresh installs have no CA or certs).
    base_cmd = base["services"]["gotenberg"]["command"]
    assert not any("--api-tls" in str(c) for c in base_cmd), (
        "base docker-compose.yml gotenberg must stay plaintext-default — "
        "TLS lives ONLY in compose.tls.yml (two-variant doctrine)")
    base_url = base["services"]["api"]["environment"]["REPORT_PDF_SIDECAR_URL"]
    assert "http://gotenberg:3000" in base_url, (
        "base compose must keep the plaintext sidecar default for fresh installs")

    # The cross-uid staging one-shot exists, is pdf-profile-gated, and stages
    # into the dir gotenberg mounts read-only.
    init = tlsc["services"].get("gotenberg-tls-init")
    assert init, "compose.tls.yml is missing the gotenberg-tls-init one-shot"
    assert "pdf" in (init.get("profiles") or []), (
        "gotenberg-tls-init must be pdf-profile-gated like gotenberg itself")
    init_vols = " ".join(str(v) for v in init.get("volumes", []))
    assert "data/tls/services/gotenberg" in init_vols and "gotenberg-staged" in init_vols, (
        "the init one-shot must copy the minted SVID into the staged dir")

    got = tlsc["services"].get("gotenberg")
    assert got, "compose.tls.yml has no gotenberg override"
    cmd = [str(c) for c in got["command"]]
    assert any(c.startswith("--api-tls-cert-file") for c in cmd), (
        "TLS-variant gotenberg command must carry --api-tls-cert-file")
    assert any(c.startswith("--api-tls-key-file") for c in cmd), (
        "TLS-variant gotenberg command must carry --api-tls-key-file")
    # command REPLACES wholesale — every base flag must be restated.
    for flag in base_cmd:
        assert str(flag) in cmd, (
            f"TLS-variant gotenberg command dropped base flag {flag!r} — "
            "compose replaces command lists, it does not merge them")
    got_vols = [str(v) for v in got.get("volumes", [])]
    assert any("gotenberg-staged" in v and v.endswith(":ro") for v in got_vols), (
        "gotenberg must mount the staged cert dir read-only")
    dep = (got.get("depends_on") or {}).get("gotenberg-tls-init") or {}
    assert dep.get("condition") == "service_completed_successfully", (
        "gotenberg must gate on the init one-shot completing — otherwise it "
        "races the staging and crash-loops on missing cert files")

    # The api rides https on the TLS variant (no silent plaintext fallback).
    url = tlsc["services"]["api"]["environment"]["REPORT_PDF_SIDECAR_URL"]
    assert url == "https://gotenberg:3000/forms/chromium/convert/html", (
        "compose.tls.yml must point REPORT_PDF_SIDECAR_URL at the https sidecar")

    # Rotation: the sweep re-stages via the init one-shot and verifies the
    # served cert, both guarded on the optional pdf profile actually running.
    rot = (ROOT / "scripts" / "rotate-tls-services.sh").read_text()
    assert "gotenberg-tls-init" in rot, (
        "rotate-tls-services.sh has no gotenberg re-stage leg — a rotated SVID "
        "would never reach the running sidecar")
    assert re.search(r"verify\s+gotenberg:3000\s+gotenberg", rot), (
        "rotate-tls-services.sh must wire-verify gotenberg:3000 (guarded on "
        "the pdf profile running)")
