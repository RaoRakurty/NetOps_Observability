"""OpenSearch role privileges are a CONTRACT, not a convenience.

WHY THIS EXISTS. `deployment/docker/opensearch/security/roles.yml` is the only
place the workload identities' authority is declared, and it is applied by a
one-shot container (`opensearch-security-init` → `apply-security.sh` →
`securityadmin.sh -cd`) that nobody watches. Two failure directions, both real
here:

  * TOO LITTLE — the 2026-09-03 `netops-secfindings-*` defect: a lane shipped
    without its write grant, Vector classed the 403 as non-retriable, dropped
    the batch, and the CTEM funnel was silently empty.
    `tests/test_upgrade_bootstraps.py` guards that direction (every pattern a
    writer sinks to is writable, every pattern the api reads is readable).

  * TOO MUCH — the direction THIS file guards. On 2026-09-03 the owner reversed
    the "policy CRUD only" rule so snapshots could be managed from the GUI, and
    `netops_api` gained snapshot create/delete/restore plus
    `cluster:monitor/nodes/stats`. Each grant was argued in the file's comments;
    none of them was pinned by a test. A privilege set that only ever grows,
    one well-argued comment at a time, is how a scoped service identity becomes
    an admin — and the ONE thing that made the widening safe is not the cluster
    grant at all, it is the INDEX scoping (restores confined to disposable
    `restored-*` / `probe-*` namespaces, never `indices_all` on a live lane).
    That scoping is invisible to a reviewer reading a one-line diff, so it is
    asserted here.

The exact-set assertions are deliberate. Adding a privilege must be a decision
someone makes IN THIS FILE, with the reason written down — not something that
rides along in an unrelated change.

Run:  python3 -m pytest tests/test_opensearch_role_privileges.py -v
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLES = ROOT / "deployment" / "docker" / "opensearch" / "security" / "roles.yml"
APPLY = ROOT / "deployment" / "docker" / "opensearch" / "security" / "apply-security.sh"


@pytest.fixture(scope="module")
def roles() -> dict:
    assert ROLES.is_file(), f"missing {ROLES}"
    doc = yaml.safe_load(ROLES.read_text(encoding="utf-8"))
    assert isinstance(doc, dict), "roles.yml must parse to a mapping"
    return doc


# The api's authority, pinned. Every entry is load-bearing; see roles.yml for
# the reason each one is here.
EXPECTED_API_CLUSTER = {
    # baseline read/monitor
    "cluster_composite_ops",
    "cluster:monitor/health",
    "cluster:monitor/state",
    # repository DISK HEADROOM — the Data Protection page reports how much room
    # the snapshot repository has, because disk headroom is the failure class
    # behind the 2026-08-27 unrestorable-repository incident. The api cannot
    # measure it directly (it does not mount data/opensearch-snapshots), so it
    # asks OpenSearch via GET /_nodes/stats/fs. Aggregate node statistics only:
    # no index content, no documents, no tenant data, no write anywhere.
    "cluster:monitor/nodes/stats",
    "indices:data/read/scroll*",
    # snapshot read
    "cluster:admin/repository/get",
    "cluster:admin/repository/verify",
    "cluster:admin/snapshot/get",
    "cluster:admin/snapshot/status",
    # snapshot management from the GUI (owner reversed "policy CRUD only",
    # 2026-09-03) — kept safe by the index scoping asserted further down
    "cluster:admin/snapshot/create",
    "cluster:admin/snapshot/delete",
    "cluster:admin/snapshot/restore",
    # the netops-daily Snapshot Management policy
    "cluster:admin/opensearch/snapshot_management/policy/get",
    "cluster:admin/opensearch/snapshot_management/policy/write",
    "cluster:admin/opensearch/snapshot_management/policy/explain",
    "cluster:admin/opensearch/snapshot_management/policy/start",
    "cluster:admin/opensearch/snapshot_management/policy/stop",
}


def test_api_cluster_privileges_are_exactly_the_agreed_set(roles):
    got = set(roles["netops_api"]["cluster_permissions"])
    added, removed = got - EXPECTED_API_CLUSTER, EXPECTED_API_CLUSTER - got
    assert not added, (
        f"netops_api GAINED cluster privileges not pinned here: {sorted(added)}.\n"
        "A workload identity's authority is a contract. If the grant is right, add it to "
        "EXPECTED_API_CLUSTER with the reason, the same way cluster:monitor/nodes/stats "
        "carries its own. Silent growth is how a scoped identity becomes an admin."
    )
    assert not removed, (
        f"netops_api LOST cluster privileges: {sorted(removed)}.\n"
        "Removing one is fine — but it breaks a live surface, so it must be deliberate. "
        "The DR status panel 403'd for weeks the last time a snapshot read privilege was "
        "missing, and reported a healthy repository as broken."
    )


def test_disk_headroom_privilege_is_present(roles):
    """Pinned on its own: the field must not read null on a shipped install."""
    assert "cluster:monitor/nodes/stats" in roles["netops_api"]["cluster_permissions"], (
        "netops_api cannot call GET /_nodes/stats/fs, so the Data Protection page reports "
        "repository disk headroom as null on every install. Disk headroom is the failure "
        "class behind the 2026-08-27 incident (a filesystem repository sharing a disk with "
        "the data it protects); the page exists partly to warn about it."
    )


@pytest.mark.parametrize(
    "forbidden",
    ["*", "all_access", "cluster_all", "cluster:admin/*", "cluster_manage_index_templates",
     "cluster:admin/settings/update"],
)
def test_api_holds_no_wildcard_or_admin_privilege(roles, forbidden):
    """The api is a read/DR surface. Cluster-shaping authority belongs to the bootstrap."""
    assert forbidden not in roles["netops_api"]["cluster_permissions"], (
        f"netops_api holds {forbidden!r}. The api serves browsers; the bootstrap "
        "(netops_bootstrap, a one-shot) is where cluster-shaping authority belongs. "
        "A wildcard here would also make the exact-set guard above vacuous."
    )


def _api_patterns(roles) -> dict:
    out = {}
    for block in roles["netops_api"]["index_permissions"]:
        for pat in block["index_patterns"]:
            out.setdefault(pat, set()).update(block["allowed_actions"])
    return out


def test_live_lanes_never_get_indices_all(roles):
    """The scoping that makes snapshot restore safe.

    An in-place restore needs close/open/delete on the live lanes and nothing
    more. `indices_all` on netops-* would let the api write or reindex live
    telemetry, which no request path should ever be able to do.
    """
    actions = _api_patterns(roles)["netops-*"]
    assert "indices_all" not in actions, (
        "netops_api holds indices_all on netops-*. That is the grant the 2026-09-03 "
        "widening deliberately avoided: restores are confined to disposable namespaces, "
        "and the live lanes get only the close/open/delete an in-place restore needs."
    )
    assert {"indices:admin/close", "indices:admin/open", "indices:admin/delete"} <= actions, (
        "the in-place restore path needs close, open and delete on netops-*; without all "
        "three the api leaves an index CLOSED after a failed restore — ingest dies silently."
    )
    for write_ish in ("write", "crud", "indices:data/write/bulk"):
        assert write_ish not in actions, (
            f"netops_api holds {write_ish!r} on netops-*. The api must never write a live "
            "telemetry lane; only the router's sink does."
        )


def test_restore_targets_are_confined_to_disposable_namespaces(roles):
    """`indices_all` is acceptable ONLY where no live telemetry can live."""
    patterns = _api_patterns(roles)
    broad = sorted(p for p, a in patterns.items() if "indices_all" in a)
    assert broad == ["probe-*", "restored-*"], (
        f"indices_all is granted on {broad}, expected exactly ['probe-*', 'restored-*'].\n"
        "Those two namespaces hold nothing durable — a renamed restore lands in restored-*, "
        "and the restorability probe restores into probe-* then deletes it. Widening this "
        "set hands the api full authority over indices that DO hold telemetry."
    )


def test_no_other_role_gained_snapshot_write_authority(roles):
    """Only the api (GUI) and the bootstrap (one-shot) may write snapshots."""
    allowed = {"netops_api", "netops_bootstrap"}
    for name, role in roles.items():
        if name == "_meta" or name in allowed:
            continue
        perms = role.get("cluster_permissions") or []
        offenders = [p for p in perms if "snapshot" in p and ("admin" in p or "*" in p)]
        assert not offenders, (
            f"role {name!r} holds snapshot authority {offenders}. Two writers over one "
            "repository is the documented OpenSearch corruption hazard — two independent "
            "deleters over one blob tree."
        )


def test_roles_file_is_the_applied_source_of_truth():
    """A pinned file that the applier does not read would be theatre."""
    body = APPLY.read_text(encoding="utf-8")
    assert "roles.yml" in body, (
        f"{APPLY.name} does not reference roles.yml — these assertions would guard a file "
        "that never reaches the cluster."
    )
    assert "securityadmin.sh" in body and "-cd" in body, (
        "apply-security.sh no longer applies the config directory with securityadmin -cd; "
        "the role contract is not being installed."
    )
