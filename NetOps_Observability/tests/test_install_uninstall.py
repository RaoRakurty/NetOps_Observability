# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""`uninstall` must remove what it says it removes.

FRESH-INSTALL ACCEPTANCE, 2026-09-06 (tracker 265), two filed defects:

  DEFECT-11 (HIGH) — `uninstall --purge` printed "Purging data, configuration,
    and loaded images..." and then ran a plain `rm -rf "$ROOT/data"`. The
    installer runs unprivileged; the store data was written by the containers
    as THEIR uids (postgres 999, clickhouse 101, victoria root). The `rm`
    produced 295 x "Permission denied", the command exited 1, and 6.3 MB of
    data/{postgres,clickhouse,victoria} survived the purge. The fix already
    existed four lines below, in cmd_reset_demo: do the removal from inside a
    container that is root in the mount.

  DEFECT-12 (LOW) — `compose down --remove-orphans` without `-v` orphaned the
    ten anonymous volumes the stack creates. "Purge" has to mean purge.

The rules pinned here:
  * a purge either REMOVES the data or NAMES the refusal — never a silent or
    a half success (§16.1);
  * the privileged path uses an image that is already on the host, because an
    air-gapped appliance cannot pull one (the same lesson install.py's
    _chown_helper_ref() encodes: `docker load` restores by TAG);
  * data is removed BEFORE the images, since removing the images first would
    take away the thing the removal runs in;
  * volumes are removed on `--purge` and kept on a plain `uninstall`, matching
    what each one promises the operator about their data.

Static checks over the shipped script plus a behavioural exercise of
purge_data_dir with docker stubbed out. No docker, no stack.

Run:  python3 -m pytest tests/test_install_uninstall.py -v
"""

from __future__ import annotations

import os
import re
import subprocess
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "install-correlix.sh"


def _src() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _func(name: str) -> str:
    """The body of one top-level function, verbatim from the shipped script."""
    src = _src()
    start = src.index(f"{name}() {{")
    # up to the NEXT top-level function definition (skip this one's own header)
    m = re.compile(r"^[a-z_]+\(\) \{", re.MULTILINE).search(src, start + len(name) + 4)
    body = src[start:m.start() if m else len(src)]
    assert body.strip(), f"could not extract {name}() from {SCRIPT}"
    return body


# ── DEFECT-11: the purge must actually purge, or say why not ────────────────

def test_purge_no_longer_relies_on_a_bare_unprivileged_rm() -> None:
    body = _func("cmd_uninstall")
    assert 'rm -rf "$ROOT/data"' not in body, (
        "cmd_uninstall still removes data/ with a plain rm — on a real "
        "appliance that fails with hundreds of Permission denied and leaves "
        "the stores on disk")
    assert "purge_data_dir" in body


def test_purge_data_dir_uses_a_privileged_helper_container() -> None:
    body = _func("purge_data_dir")
    assert "docker run --rm" in body and '-v "$ROOT/data:/data"' in body, (
        "the removal must run from inside a container that is root in the "
        "mount, the way cmd_reset_demo already does")
    assert "find /data -mindepth 1" in body


def test_the_helper_image_must_already_be_on_the_host() -> None:
    """An air-gapped appliance cannot pull. The helper is chosen from what
    `docker load` actually put on this host, by TAG."""
    body = _func("purge_helper_image")
    assert "docker image inspect" in body, (
        "the helper image must be probed locally, never assumed")
    assert "MANIFEST" in body, (
        "fall back to the bundle's own loaded images when no general-purpose "
        "image is present")
    assert "docker pull" not in _src()


def test_a_purge_that_cannot_remove_the_data_fails_loudly_with_the_fix() -> None:
    body = _func("purge_data_dir")
    assert body.count("die ") >= 2, (
        "both dead ends — the helper failed, and no helper was available — "
        "must be named refusals, not a swallowed error")
    assert "sudo rm -rf" in body, (
        "a refusal has to hand the operator the exact command that finishes "
        "the job; 'it failed' is not an answer")
    assert "|| true" not in body.split("docker run --rm")[1].split("\n")[0], (
        "the helper's exit status must be checked, not discarded")


def test_data_is_removed_before_the_images_it_needs() -> None:
    """The images are the helper. Removing them first strands the removal —
    the exact ordering bug DEFECT-1 was (load_bundle after the chown that
    needed it)."""
    body = _func("cmd_uninstall")
    assert body.index("purge_data_dir") < body.index("docker rmi"), (
        "purge_data_dir must run while the loaded images still exist")


def test_the_success_line_is_only_reached_when_the_data_is_gone() -> None:
    body = _func("cmd_uninstall")
    success = body.index('ok "data, volumes and configuration removed')
    assert body.index("purge_data_dir") < success
    # purge_data_dir dies on failure, so reaching the ok line means it worked.
    assert "die " in _func("purge_data_dir")


# ── DEFECT-12: anonymous volumes ────────────────────────────────────────────

def test_purge_removes_the_anonymous_volumes() -> None:
    body = _func("cmd_uninstall")
    assert "--volumes" in body, (
        "the stack declares no NAMED volumes, so every volume it owns is "
        "anonymous and unreachable by name after the project is gone; a "
        "purge that leaves them is not a purge")
    purge_branch = body[body.index('if [ "$PURGE" = 1 ]'):]
    assert "compose down --remove-orphans --volumes" in purge_branch


def test_a_plain_uninstall_keeps_the_volumes_with_the_rest_of_the_data() -> None:
    body = _func("cmd_uninstall")
    keep = body[body.index("else"):body.index("Remove everything with")]
    assert "--volumes" not in keep
    assert "compose down --remove-orphans\n" in body


def test_the_stack_really_has_no_named_volumes() -> None:
    """The premise behind `--volumes` on a purge: nothing survives that the
    operator could have meant to keep by name."""
    import yaml
    for name in ("docker-compose.yml", "compose.tls.yml"):
        doc = yaml.safe_load(
            (ROOT / "deployment" / "docker" / name).read_text()
            .replace("!override", "").replace("!reset", ""))
        assert not (doc.get("volumes") or {}), (
            f"{name} now declares named volumes — `down --volumes` on a purge "
            "would delete data an operator may have meant to keep")


# ── behavioural: run purge_data_dir for real, with docker stubbed ───────────

def _harness(tmp_path: Path, docker_stub: str, data_owner_root: bool) -> str:
    """Run purge_data_dir + its helpers out of the shipped script."""
    src = _src()
    start = src.index("purge_helper_image() {")
    end = src.index("cmd_uninstall() {")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "docker").write_text("#!/bin/bash\n" + docker_stub)
    (bindir / "docker").chmod(0o755)

    root = tmp_path / "root"
    (root / "data" / "postgres").mkdir(parents=True)
    (root / "data" / "postgres" / "PG_VERSION").write_text("16\n")
    if data_owner_root:
        # Stand in for "written by the container's own uid": the store
        # subdirectory is not writable by this user, so an unprivileged
        # `rm -rf` cannot unlink its contents — the live failure was 295 x
        # "Permission denied" from exactly this shape.
        (root / "data" / "postgres").chmod(0o555)

    script = tmp_path / "harness.sh"
    script.write_text(textwrap.dedent(f"""\
        set -uo pipefail
        ROOT="{root}"
        BUNDLE_DIR=""
        say()  {{ printf '%s\\n' "$*"; }}
        ok()   {{ printf 'OK %s\\n' "$*"; }}
        warn() {{ printf 'WARN %s\\n' "$*"; }}
        die()  {{ printf 'DIE %s\\n%s\\n' "$1" "${{2:-}}"; exit 1; }}
        """) + src[start:end] + "\npurge_data_dir\necho EXIT=$?\n")
    res = subprocess.run(["bash", str(script)], capture_output=True, text=True,
                         timeout=60, check=False, env={**os.environ,
                                          "PATH": f"{bindir}:{os.environ['PATH']}"})
    for d, _sub, _f in os.walk(root):  # let pytest clean tmp_path up
        os.chmod(d, 0o755)
    return res.stdout + res.stderr


DOCKER_WITH_ALPINE = """
case "$1" in
  image) [ "$3" = "alpine:latest" ] && exit 0 || exit 1 ;;
  run)   # wipe the mounted path the way root inside the container would:
         # ownership and mode are no obstacle to uid 0.
         for a in "$@"; do case "$a" in
           *:/data) chmod -R u+w "${a%%:/data}"; rm -rf "${a%%:/data}"/* ;;
         esac; done
         exit 0 ;;
esac
exit 0
"""

DOCKER_NO_IMAGES = """
case "$1" in
  image) exit 1 ;;
  run)   echo "Unable to find image locally" >&2; exit 125 ;;
esac
exit 0
"""

DOCKER_HELPER_FAILS = """
case "$1" in
  image) [ "$3" = "alpine:latest" ] && exit 0 || exit 1 ;;
  run)   echo "rm: /data/postgres: Read-only file system" >&2; exit 1 ;;
esac
exit 0
"""


def test_unprivileged_rm_succeeds_when_the_data_is_ours(tmp_path) -> None:
    out = _harness(tmp_path, DOCKER_NO_IMAGES, data_owner_root=False)
    assert "EXIT=0" in out, out
    assert "DIE" not in out
    assert not (tmp_path / "root" / "data").exists()


def test_container_owned_data_is_removed_through_the_helper(tmp_path) -> None:
    out = _harness(tmp_path, DOCKER_WITH_ALPINE, data_owner_root=True)
    assert "EXIT=0" in out, out
    assert "privileged helper container" in out
    # The helper empties the mount; purge_data_dir then removes the (now
    # empty, ours) directory itself.
    assert not (tmp_path / "root" / "data").exists()


def test_no_helper_available_is_a_named_refusal_not_a_silent_success(
        tmp_path) -> None:
    out = _harness(tmp_path, DOCKER_NO_IMAGES, data_owner_root=True)
    assert "EXIT=0" not in out, "a failed purge must not report success"
    assert "DIE could not remove" in out, out
    assert "sudo rm -rf" in out
    assert (tmp_path / "root" / "data" / "postgres" / "PG_VERSION").exists(), (
        "nothing should have been half-removed")


def test_a_failing_helper_is_a_named_refusal(tmp_path) -> None:
    out = _harness(tmp_path, DOCKER_HELPER_FAILS, data_owner_root=True)
    assert "EXIT=0" not in out, "a failed purge must not report success"
    assert "helper container could not remove" in out, out
    assert "Read-only file system" in out, (
        "the refusal must quote what docker actually said")
    assert "sudo rm -rf" in out
