# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Helm chart gate — deployment/helm/correlix.

WHAT THIS PROVES, AND WHAT IT DOES NOT.

It proves the chart is RENDERED-AND-VALIDATED: `helm lint` is clean, `helm
template` produces manifests for the default and the lab variant, and every
rendered object validates against the Kubernetes 1.30 schemas. On top of that
it asserts, in pure Python over the rendered YAML, the properties that a schema
validator cannot see — digest pinning against the compose stack, resources and
probes on every container, a default-deny NetworkPolicy, the restricted
PodSecurity shape, and that no credential is baked into the chart.

It does NOT prove the chart INSTALLS. No cluster was available when it was
written and none is used here. A manifest that validates can still fail to
schedule, fail a volume bind, or crash-loop. `docs/audit/INVARIANTS.md` records
that distinction; do not upgrade the claim without a cluster run.

The two binaries are optional: with neither present every tool-backed test
SKIPS with a stated reason and the pure-YAML tests still run against a
pre-rendered manifest only if helm produced one — so a machine without helm
skips loudly rather than passing vacuously.

  HELM_BIN / KUBECONFORM_BIN override the discovered binaries.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

import pytest
import yaml

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
CHART = os.path.join(ROOT, "deployment", "helm", "correlix")
LAB_VALUES = os.path.join(CHART, "values-lab.yaml")
STAGE_SCRIPT = os.path.join(ROOT, "deployment", "helm", "stage-configs.sh")
COMPOSE = os.path.join(ROOT, "deployment", "docker", "docker-compose.yml")
KUBE_VERSION = "1.30.0"

# Correlix builds these itself, per commit. They have no published digest until
# a pipeline pushes them, so they carry a tag and are gated by
# images.requireDigest instead (proved by test_require_digest_gate_is_real).
FIRST_PARTY = {
    "ghcr.io/correlix/netops-api",
    "ghcr.io/correlix/netops-correlation",
    "ghcr.io/correlix/netops-frontend",
    "ghcr.io/correlix/netops-nginx",
    "ghcr.io/correlix/netops-vector-router",
}

# Containers with no probe, and the reason. Configured as the stack configures
# them, neither process opens a TCP or HTTP listener at all: goflow2 listens on
# UDP only, and the shipped gnmic.yaml declares no api-server. A probe against
# an invented endpoint would pass unconditionally, which is worse than none.
PROBELESS = {"goflow2", "gnmic"}

# Pods that cannot meet PodSecurity `restricted`, and why. Both are opt-in and
# default OFF; the chart annotates each with the standard it does need.
CAP_EXEMPT = {
    "prober": "CAP_NET_RAW — raw ICMP construction and per-packet IP TTL",
    "cadvisor": "privileged — reads the container runtime's cgroup state",
}


def _bin(env_name: str, exe: str) -> str | None:
    override = os.environ.get(env_name)
    if override:
        return override if os.path.isfile(override) else None
    return shutil.which(exe)


HELM = _bin("HELM_BIN", "helm")
KUBECONFORM = _bin("KUBECONFORM_BIN", "kubeconform")

needs_helm = pytest.mark.skipif(
    HELM is None,
    reason="helm is not installed (set HELM_BIN, or install helm >= 3.14) — "
           "the chart is unverified on this machine, not verified-as-passing",
)
needs_kubeconform = pytest.mark.skipif(
    KUBECONFORM is None,
    reason="kubeconform is not installed (set KUBECONFORM_BIN) — the rendered "
           "manifests were NOT schema-validated on this machine",
)


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    # check=False on purpose: several of these legs assert on a NON-zero exit
    # (the requireDigest gate, the schema rejections), so a raising helper
    # would turn the property under test into an error.
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=300, check=False)


def _read(*parts: str) -> str:
    with open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def _render(*extra: str) -> str:
    proc = _run([HELM, "template", "correlix", CHART, *extra])
    assert proc.returncode == 0, f"helm template failed:\n{proc.stderr}"
    return proc.stdout


def _docs(text: str) -> list[dict]:
    return [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]


@pytest.fixture(scope="module")
def default_docs() -> list[dict]:
    if HELM is None:
        pytest.skip("helm is not installed")
    return _docs(_render())


@pytest.fixture(scope="module")
def lab_docs() -> list[dict]:
    if HELM is None:
        pytest.skip("helm is not installed")
    return _docs(_render("-f", LAB_VALUES))


def _pod_specs(docs: list[dict]):
    """(kind, name, podspec) for every workload, including the CronJob's."""
    for d in docs:
        kind = d.get("kind")
        meta = d.get("metadata") or {}
        name = meta.get("name", "?")
        spec = d.get("spec") or {}
        if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job"):
            tmpl = (spec.get("template") or {}).get("spec")
            if tmpl:
                yield kind, name, tmpl
        elif kind == "CronJob":
            tmpl = (((spec.get("jobTemplate") or {}).get("spec") or {})
                    .get("template") or {}).get("spec")
            if tmpl:
                yield kind, name, tmpl


def _containers(docs: list[dict]):
    for kind, name, spec in _pod_specs(docs):
        for c in spec.get("containers", []):
            yield kind, name, spec, c


# ── tool-backed legs ────────────────────────────────────────────────────────

@needs_helm
def test_helm_lint_default():
    proc = _run([HELM, "lint", CHART])
    assert proc.returncode == 0, proc.stdout + proc.stderr


@needs_helm
def test_helm_lint_lab_values():
    proc = _run([HELM, "lint", CHART, "-f", LAB_VALUES])
    assert proc.returncode == 0, proc.stdout + proc.stderr


@needs_helm
@needs_kubeconform
@pytest.mark.parametrize("extra", [(), ("-f", LAB_VALUES)],
                         ids=["default", "lab"])
def test_kubeconform_validates_rendered_manifests(tmp_path, extra):
    rendered = tmp_path / "rendered.yaml"
    rendered.write_text(_render(*extra))
    proc = _run([
        KUBECONFORM, "-kubernetes-version", KUBE_VERSION,
        "-strict", "-summary", "-ignore-missing-schemas", str(rendered),
    ])
    if proc.returncode != 0 and "could not" in (proc.stderr or "").lower() \
            and "schema" in (proc.stderr or "").lower():
        pytest.skip(f"kubeconform could not fetch the {KUBE_VERSION} schemas "
                    f"(offline?): {proc.stderr.strip()[:200]}")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # -ignore-missing-schemas turns an unknown kind into a SKIP, and a skipped
    # object is an unvalidated object. Nothing in the default or lab render is
    # a CRD, so the count must be zero.
    skipped = re.search(r"Skipped:\s*(\d+)", proc.stdout)
    assert skipped and skipped.group(1) == "0", \
        f"objects were skipped rather than validated: {proc.stdout}"


@needs_helm
def test_require_digest_gate_is_real():
    """images.requireDigest=true must FAIL, naming the unpinned image.

    Without this the flag could be inert and nobody would notice until a
    production deployment ran from a mutable tag.
    """
    proc = _run([HELM, "template", "correlix", CHART,
                 "--set", "images.requireDigest=true"])
    assert proc.returncode != 0, "requireDigest=true rendered successfully — the gate is inert"
    assert "requireDigest" in proc.stderr
    assert "carries no digest" in proc.stderr


@needs_helm
@pytest.mark.parametrize("bad,expect", [
    ("store.backend=sqlite", "store.backend"),
    ("api.image.digest=sha256:abc", "image.digest"),
    ("secrets.existingSecret=", "existingSecret"),
])
def test_values_schema_rejects_bad_input(bad, expect):
    """values.schema.json must actually constrain something.

    The assertion names the KEY the schema refused, not helm's wording: helm
    3.16 prints `- api.image.digest: Does not match pattern`, helm 3.19 prints
    `- at '/api/image/digest': ... does not match pattern`. Both carry the key.
    """
    proc = _run([HELM, "template", "correlix", CHART, "--set", bad])
    assert proc.returncode != 0, f"schema accepted {bad!r}"
    out = (proc.stdout + proc.stderr).replace("/", ".")
    assert expect in out, f"the refusal does not name {expect!r}: {out[:400]}"


def test_staged_configs_match_canonical_sources():
    """The chart's files/ mirror must not drift from the real configuration.

    Helm cannot read outside the chart root, so the ConfigMaps are rendered
    from checked-in copies. Same shape as scripts/sync-docs-corpus.sh and its
    Go drift test: a mirror plus a gate. Fix a failure by re-running the
    staging script, never by editing files/ by hand.
    """
    proc = _run(["bash", STAGE_SCRIPT, "--check"])
    assert proc.returncode == 0, (
        proc.stdout + proc.stderr
        + "\n\nRe-stage with:  bash deployment/helm/stage-configs.sh"
    )


# Directories the compose stack mounts WHOLE (`./x:/somewhere`), mapped to the
# chart's staged subdirectory, with the files deliberately left out and why.
#
# WHY THIS EXISTS. The chart stages files one by one, and the first pass of it
# missed `syslog-ng/core.conf` — the file `syslog-ng.conf` `@include`s, without
# which the daemon refuses to start. Nothing caught it: helm rendered,
# kubeconform passed, every probe and resource was in place. The generator of
# that bug is "compose mounts a directory, the chart cherry-picks files", so
# the guard is on the directory, not on that one file. A NEW file in one of
# these directories fails here until someone decides whether it belongs in the
# chart.
WHOLE_DIR_MOUNTS = {
    "deployment/docker/syslog-ng": ("syslog-ng", {}),
    "deployment/docker/gnmic": ("gnmic", {}),
    "deployment/docker/vector": ("vector", {
        "tests": "Vector unit-test fixtures; not read at runtime",
        "generated": "spliced INTO vector.yaml at generation time, staged flat "
                     "instead — pinned by the next test",
    }),
    "deployment/docker/vector-router": ("vector-router", {
        "Dockerfile": "build input, not a mounted config",
        "tests": "Vector unit-test fixtures; not read at runtime",
    }),
    "deployment/docker/opensearch": ("opensearch", {
        "Dockerfile": "build input for the slim image, which the chart does not use",
        "opensearch-security.yml": "consumed by the security bootstrap, whose ConfigMap the operator builds",
        "security": "per-identity roles/mappings an operator reviews and creates themselves",
        "SNAPSHOTS-DO-NOT-DELETE-README.txt": "a note to a human on the snapshot volume, not config",
    }),
    "src/config": ("config", {
        "rules-tests": "promtool rule fixtures; run by preflight-configs.sh, never mounted",
        "examples": "documentation samples",
        "devices.lab-clos.yaml": "lab topology fixture, not a shipped default",
        "snmp_profiles.example.json": "an example beside the real snmp_profiles.json",
    }),
}


def test_whole_directory_mounts_are_staged_whole():
    missing: list[str] = []
    for src_rel, (staged_rel, skip) in WHOLE_DIR_MOUNTS.items():
        src_dir = os.path.join(ROOT, src_rel)
        staged_dir = os.path.join(CHART, "files", staged_rel)
        assert os.path.isdir(src_dir), f"{src_rel} no longer exists"
        assert os.path.isdir(staged_dir), f"{staged_rel} is not staged at all"
        staged = set(os.listdir(staged_dir))
        for name in sorted(os.listdir(src_dir)):
            if name in skip:
                continue
            if name not in staged:
                missing.append(f"{src_rel}/{name} -> files/{staged_rel}/")
    assert not missing, (
        "compose mounts these directories WHOLE, so a file present there and "
        "absent from the chart is a config the container will not find:\n  "
        + "\n  ".join(missing)
        + "\n\nAdd it to deployment/helm/stage-configs.sh, or add it to this "
          "test's skip map WITH A REASON."
    )


def test_generated_vrl_is_staged_beside_the_config_it_documents():
    """`vector/generated/syslog-admission.vrl` is spliced INTO vector.yaml by
    scripts/gen-syslog-admission.py rather than loaded at runtime, so it is
    staged flat. Pinned so the flattening stays deliberate."""
    assert os.path.isfile(os.path.join(CHART, "files", "vector", "syslog-admission.vrl"))
    assert os.path.isfile(os.path.join(
        ROOT, "deployment", "docker", "vector", "generated", "syslog-admission.vrl"))


def test_gateway_config_differs_from_compose_only_in_the_resolver():
    """The one deliberate edit, pinned.

    Docker's embedded DNS (127.0.0.11) does not exist in a pod, so the staged
    nginx config swaps that single directive. Any OTHER difference means the
    gateway is serving a routing table that is not the one the compose stack
    was reviewed with — including its auth_request gates.
    """
    canonical = _read(ROOT, "deployment", "docker", "nginx",
                      "default.conf").splitlines()
    staged = _read(CHART, "files", "nginx", "default.conf").splitlines()
    assert len(canonical) == len(staged)
    diffs = [(a, b) for a, b in zip(canonical, staged) if a != b]
    assert len(diffs) == 1, f"expected exactly one differing line, got {diffs}"
    before, after = diffs[0]
    assert "resolver 127.0.0.11" in before
    assert "resolver kube-dns.kube-system.svc.cluster.local" in after


# ── pure-YAML assertions over the rendered manifests ────────────────────────

def _compose_digests() -> dict[str, str]:
    """repository -> digest, from the compose file's pinned images."""
    out: dict[str, str] = {}
    pat = re.compile(r"^\s*image:\s*([^\s@:]+(?::[^\s@]+)?)@(sha256:[a-f0-9]{64})\s*$")
    for line in _read(COMPOSE).splitlines():
        m = pat.match(line)
        if m:
            out[m.group(1).split(":", 1)[0]] = m.group(2)
    # The slim OpenSearch image is built locally; the chart uses the upstream
    # image its Dockerfile derives FROM, so take that digest from the Dockerfile.
    dockerfile = os.path.join(ROOT, "deployment", "docker", "opensearch", "Dockerfile")
    for line in _read(dockerfile).splitlines():
        m = re.match(r"^FROM\s+(opensearchproject/opensearch):[^\s@]+@(sha256:[a-f0-9]{64})", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


@needs_helm
def test_every_third_party_image_is_digest_pinned(lab_docs):
    """Every image the chart CAN pin is pinned, and to the compose digest.

    A repository:tag reference is not a deployment anyone can reproduce, and a
    chart digest that has drifted from the compose digest means Kubernetes and
    Docker users are running different bytes of the same release.
    """
    compose = _compose_digests()
    assert compose, "no digest-pinned images found in docker-compose.yml"
    unpinned: list[str] = []
    mismatched: list[str] = []
    for _kind, name, _spec, c in _containers(lab_docs):
        ref = c["image"]
        if "@" in ref:
            repo, digest = ref.split("@", 1)
            if repo in compose and compose[repo] != digest:
                mismatched.append(f"{name}/{c['name']}: chart {digest} vs compose {compose[repo]}")
            continue
        repo = ref.rsplit(":", 1)[0]
        if repo not in FIRST_PARTY:
            unpinned.append(f"{name}/{c['name']}: {ref}")
    assert not unpinned, f"third-party images without a digest: {unpinned}"
    assert not mismatched, f"chart/compose digest drift: {mismatched}"


@needs_helm
def test_first_party_images_are_exactly_the_documented_set(lab_docs):
    """A new unpinned repository must be a deliberate, reviewed addition."""
    seen = {c["image"].rsplit(":", 1)[0]
            for _k, _n, _s, c in _containers(lab_docs) if "@" not in c["image"]}
    assert seen <= FIRST_PARTY, f"undocumented unpinned image(s): {seen - FIRST_PARTY}"


@needs_helm
def test_every_container_declares_requests_and_limits(lab_docs):
    missing = []
    for _kind, name, _spec, c in _containers(lab_docs):
        res = c.get("resources") or {}
        for side in ("requests", "limits"):
            block = res.get(side) or {}
            for field in ("cpu", "memory"):
                if field not in block:
                    missing.append(f"{name}/{c['name']}: resources.{side}.{field}")
    assert not missing, missing


@needs_helm
def test_every_container_has_probes_or_a_documented_exemption(lab_docs):
    missing = []
    for _kind, name, _spec, c in _containers(lab_docs):
        if c["name"] in PROBELESS:
            continue
        # A Job (and the watchdog CronJob) runs to completion. A readiness
        # probe on a pod that is meant to exit is meaningless, and the exit
        # status IS its liveness signal.
        if _kind in ("Job", "CronJob"):
            continue
        for probe in ("readinessProbe", "livenessProbe"):
            if probe not in c:
                missing.append(f"{name}/{c['name']}: {probe}")
    assert not missing, missing


@needs_helm
def test_probeless_containers_state_their_reason(lab_docs):
    """An exemption without a written reason decays into an oversight."""
    rendered_names = {c["name"] for _k, _n, _s, c in _containers(lab_docs)}
    assert PROBELESS <= rendered_names, \
        f"PROBELESS names no longer render: {PROBELESS - rendered_names}"
    body = _read(CHART, "templates", "pipeline.yaml")
    assert body.count("NO PROBE") == len(PROBELESS), \
        "each probeless container must carry its own NO PROBE rationale"


@needs_helm
def test_default_deny_network_policy_is_present(default_docs):
    policies = [d for d in default_docs if d["kind"] == "NetworkPolicy"]
    assert policies, "networkPolicy.enabled is on but no policy rendered"
    deny = [p for p in policies
            if p["spec"].get("podSelector") == {}
            and set(p["spec"].get("policyTypes", [])) == {"Ingress", "Egress"}
            and not p["spec"].get("ingress")
            and not p["spec"].get("egress")]
    assert len(deny) == 1, \
        f"expected exactly one default-deny policy, found {[p['metadata']['name'] for p in deny]}"


@needs_helm
def test_network_policy_can_be_turned_off_but_is_on_by_default():
    off = _docs(_render("--set", "networkPolicy.enabled=false"))
    assert not [d for d in off if d["kind"] == "NetworkPolicy"]


@needs_helm
def test_pods_are_pod_security_restricted(lab_docs):
    """runAsNonRoot + seccomp at the pod level; drop ALL + no escalation per
    container. The two exemptions are opt-in, default-off, and named."""
    problems = []
    for kind, name, spec, c in _containers(lab_docs):
        sec = spec.get("securityContext") or {}
        if sec.get("runAsNonRoot") is not True and c["name"] not in CAP_EXEMPT:
            problems.append(f"{name}: pod securityContext.runAsNonRoot is not true")
        if (sec.get("seccompProfile") or {}).get("type") != "RuntimeDefault":
            problems.append(f"{name}: pod seccompProfile is not RuntimeDefault")
        csec = c.get("securityContext") or {}
        if c["name"] in CAP_EXEMPT:
            continue
        if csec.get("allowPrivilegeEscalation") is not False:
            problems.append(f"{name}/{c['name']}: allowPrivilegeEscalation is not false")
        drop = (csec.get("capabilities") or {}).get("drop")
        if drop != ["ALL"]:
            problems.append(f"{name}/{c['name']}: capabilities.drop is {drop}, not [ALL]")
        add = (csec.get("capabilities") or {}).get("add") or []
        if not set(add) <= {"NET_BIND_SERVICE"}:
            problems.append(f"{name}/{c['name']}: adds {add}; restricted permits only NET_BIND_SERVICE")
    assert not problems, problems


@needs_helm
def test_no_pod_mounts_a_kubernetes_api_token(lab_docs):
    """Nothing in this stack talks to the Kubernetes API, so nothing holds a
    credential for it."""
    bad = [name for _k, name, spec, _c in _containers(lab_docs)
           if spec.get("automountServiceAccountToken") is not False]
    assert not bad, bad


@needs_helm
def test_chart_creates_no_secret_object(lab_docs):
    """A chart that mints credentials puts them in the release manifest, where
    `helm get manifest` and every backup of the release Secret leak them."""
    assert not [d for d in lab_docs if d["kind"] == "Secret"]


@pytest.mark.parametrize("values_file", ["values.yaml", "values-lab.yaml"])
def test_no_credential_literal_in_values(values_file):
    suspicious = re.compile(r"(password|secret|token|api[_-]?key|credential)", re.IGNORECASE)
    allow_empty = {"", "correlix-secrets", "correlix-mesh-ca",
                   "correlix-ingress-tls"}
    findings = []

    def walk(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{path}.{k}" if path else str(k))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        else:
            leaf = path.rsplit(".", 1)[-1]
            if suspicious.search(leaf) and isinstance(node, str) \
                    and node not in allow_empty:
                findings.append(f"{path} = {node!r}")

    walk(yaml.safe_load(_read(CHART, values_file)) or {}, "")
    assert not findings, f"credential-shaped literal in {values_file}: {findings}"


@needs_helm
def test_service_names_are_literal_not_release_prefixed():
    """The mounted configs address peers by the bare compose service name. A
    release-prefixed Service name breaks the pipeline silently — the request
    just goes nowhere."""
    docs = _docs(_render())
    names = {d["metadata"]["name"] for d in docs if d["kind"] == "Service"}
    for required in ("api", "kafka", "victoria", "opensearch", "clickhouse",
                     "postgres", "redis", "correlation", "frontend", "nginx",
                     "vector-aggregator", "vector-router"):
        assert required in names, f"Service {required!r} missing (got {sorted(names)})"


@needs_helm
def test_kafka_init_creates_exactly_the_compose_topic_set(default_docs):
    """The bootstrap that pre-creates the bus. Broker auto-create is OFF, so a
    topic missing here is a lane that fails loud at its first produce."""
    topic_re = re.compile(r"netops\.[a-z0-9_.]+")
    compose_body = _read(COMPOSE)
    block = compose_body[compose_body.index("  kafka-init:"):]
    block = block[:block.index("--partitions")]
    compose_topics = set(topic_re.findall(block))

    job = next(d for d in default_docs
               if d["kind"] == "Job" and d["metadata"]["name"] == "kafka-init")
    args = "".join(job["spec"]["template"]["spec"]["containers"][0]["args"])
    chart_topics = set(topic_re.findall(args))

    assert chart_topics == compose_topics, (
        f"chart-only: {sorted(chart_topics - compose_topics)}; "
        f"compose-only: {sorted(compose_topics - chart_topics)}"
    )


@needs_helm
def test_store_backend_defaults_to_postgres(default_docs):
    """Tracker 245: PostgreSQL is the default app-state backend for new
    installations. `file` is explicit compatibility mode, never implicit."""
    api = next(d for d in default_docs
               if d["kind"] == "Deployment" and d["metadata"]["name"] == "api")
    env = {e["name"]: e for e in api["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["STORE_BACKEND"].get("value") == "postgres"
    assert "secretKeyRef" in env["DATABASE_URL"]["valueFrom"]


@needs_helm
def test_bootstrap_jobs_are_post_install_and_post_upgrade_hooks(default_docs):
    jobs = [d for d in default_docs if d["kind"] == "Job"]
    assert {j["metadata"]["name"] for j in jobs} >= {"kafka-init", "opensearch-init"}
    for j in jobs:
        ann = j["metadata"]["annotations"]
        assert ann["helm.sh/hook"] == "post-install,post-upgrade", j["metadata"]["name"]
        # A failed bootstrap's pod IS the diagnostic; deleting it on failure
        # throws away the only record of why the install is broken.
        assert "hook-failed" not in ann["helm.sh/hook-delete-policy"]


def test_chart_version_is_pinned_and_semver():
    chart = yaml.safe_load(_read(CHART, "Chart.yaml"))
    assert re.fullmatch(r"\d+\.\d+\.\d+", chart["version"]), chart["version"]
    assert chart["appVersion"]
    assert chart["kubeVersion"]


def test_values_schema_is_valid_json_and_constrains_the_dangerous_settings():
    schema = json.loads(_read(CHART, "values.schema.json"))
    assert schema["properties"]["store"]["properties"]["backend"]["enum"] \
        == ["postgres", "file", "memory"]
    assert schema["definitions"]["resources"]["required"] == ["requests", "limits"]
    assert schema["properties"]["secrets"]["required"] == ["existingSecret"]
