# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The bundle MANIFEST records the REAL unpacked image size (FMEA row 10).

`install-correlix.sh`'s preflight projects how full the customer's Docker
filesystem will be after the image bundle is loaded. Without a recorded size it
multiplies the compressed archives by 6.2 — a ratio measured on ONE install and
printed as an ESTIMATE — so the gate that is supposed to stop an install before
it fills the disk is a guess on every customer host. `make-installer.sh` knows
the real number: it has just loaded/exported those very images.

Pinned here:
  * make-installer.sh sums `docker image inspect .Size` over every image it
    ships (base + every add-on pack), deduplicated, and never swallows a
    failed or non-numeric inspect (§16.1) — a bundle with a wrong size claim is
    worse than one with none;
  * the MANIFEST line it writes is EXACTLY the shape install-correlix.sh's
    preflight parses, proven by feeding one to the real shell function;
  * with the recorded size the projection stops saying ESTIMATE.

No docker: `docker` is a fake on PATH inside tmp_path, and the harness proves
the fake is the one that answered.

Run:  python3 -m pytest tests/test_install_bundle_manifest.py -v
"""

from __future__ import annotations

import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MAKE = ROOT / "scripts" / "make-installer.sh"
INSTALL = ROOT / "scripts" / "install-correlix.sh"

GB = 2**30
FN = "image_bytes_total()"


def _write_exec(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _make_src() -> str:
    return MAKE.read_text(encoding="utf-8")


def _image_bytes_total() -> str:
    """The shipped image_bytes_total() function, verbatim."""
    src = _make_src()
    assert FN in src, (
        "make-installer.sh no longer defines image_bytes_total() — the bundle "
        "MANIFEST's images_unpacked_bytes would go back to being a 6.2x guess")
    start = src.index(FN)
    end = src.index("\n}\n", start) + len("\n}\n")
    return src[start:end]


# A fake docker whose `image inspect --format {{.Size}} REF` answers from a
# SIZES map; anything else is a hard failure, so the function cannot quietly
# start calling something that is not read-only.
FAKE_DOCKER = r"""#!/bin/bash
printf '%s\n' "$*" >> "$DOCKER_LOG"
if [ "$1" != image ] || [ "$2" != inspect ]; then
  echo "fake docker: unexpected verb: $*" >&2; exit 90
fi
ref="${!#}"
case "$ref" in
  missing/*) echo "Error response from daemon: No such image: $ref" >&2; exit 1 ;;
  weird/*)   printf 'not-a-number\n'; exit 0 ;;
esac
sed -n "s|^$ref |&|p" "$SIZES" >/dev/null
size=$(awk -v r="$ref" '$1 == r { print $2 }' "$SIZES")
[ -n "$size" ] || { echo "fake docker: no size fixture for $ref" >&2; exit 91; }
printf '%s\n' "$size"
"""


def _rig(tmp_path: Path, sizes: dict[str, int]) -> tuple[Path, dict]:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    _write_exec(bindir / "docker", FAKE_DOCKER)
    sizes_file = tmp_path / "sizes.txt"
    sizes_file.write_text("".join(f"{ref} {n}\n" for ref, n in sizes.items()))
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "HOME": str(tmp_path),
           "SIZES": str(sizes_file), "DOCKER_LOG": str(tmp_path / "docker.log")}
    return bindir, env


def _run_total(tmp_path: Path, refs: list[str], sizes: dict[str, int]):
    bindir, env = _rig(tmp_path, sizes)
    script = tmp_path / "total.sh"
    script.write_text("set -euo pipefail\n" + _image_bytes_total()
                      + "\nprintf '%s\\n' " + " ".join(f'"{r}"' for r in refs)
                      + " | image_bytes_total\n")
    r = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=60,
                       env=env, stdin=subprocess.DEVNULL, check=False)
    assert (bindir / "docker").exists()
    return r


# ── the sum itself ──────────────────────────────────────────────────────────

def test_the_total_is_the_sum_of_the_image_sizes(tmp_path: Path) -> None:
    sizes = {"correlix/api:v1": 400 * GB // 1000, "apache/kafka:4.1.1": 700 * GB // 1000,
             "correlix/frontend:v1": 90 * GB // 1000}
    r = _run_total(tmp_path, list(sizes), sizes)
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.strip() == str(sum(sizes.values()))


def test_an_empty_input_is_zero_not_an_error(tmp_path: Path) -> None:
    r = _run_total(tmp_path, [], {})
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.strip() == "0"


def test_an_image_docker_cannot_inspect_fails_the_build_and_is_named(tmp_path: Path) -> None:
    """§16.1: a bundle that ships a size it could not measure is worse than one
    that ships none — the customer's disk gate would trust a wrong number."""
    sizes = {"correlix/api:v1": 1234}
    r = _run_total(tmp_path, ["correlix/api:v1", "missing/thing:v9"], sizes)
    assert r.returncode != 0, r.stdout
    assert "missing/thing:v9" in r.stderr
    assert "No such image" in r.stderr, "the reason docker gave must survive"
    assert r.stdout.strip() in ("", "0"), "no total may be printed for a failed measurement"


def test_a_non_numeric_size_is_refused(tmp_path: Path) -> None:
    r = _run_total(tmp_path, ["weird/thing:v1"], {"weird/thing:v1": 0})
    assert r.returncode != 0, r.stdout
    assert "weird/thing:v1" in r.stderr and "not-a-number" in r.stderr


def test_only_read_only_docker_verbs_are_used(tmp_path: Path) -> None:
    sizes = {"correlix/api:v1": 10}
    r = _run_total(tmp_path, ["correlix/api:v1"], sizes)
    assert r.returncode == 0, r.stdout + r.stderr
    calls = (tmp_path / "docker.log").read_text().splitlines()
    assert calls and all(c.startswith("image inspect") for c in calls), calls


# ── the build writes it into MANIFEST ───────────────────────────────────────

def test_make_installer_writes_the_key_into_the_manifest() -> None:
    src = _make_src()
    manifest_block = src[src.index("# 6. Manifest + checksums"):
                         src.index('} > "$BUNDLE_DIR/MANIFEST"')]
    assert "images_unpacked_bytes:" in manifest_block, (
        "the MANIFEST no longer records images_unpacked_bytes — install-correlix.sh's "
        "disk projection falls back to the 6.2x ESTIMATE on every customer host")


def test_the_recorded_size_covers_the_add_on_packs_too() -> None:
    """A `full` bundle's add-on archives are loaded onto the same filesystem."""
    src = _make_src()
    assert "UNPACKED_BYTES=" in src, "the total is no longer computed"
    computation = src[src.index("UNPACKED_BYTES="):src.index("UNPACKED_BYTES=") + 400]
    assert "$IMAGES" in computation and "PACK_IMAGES" in computation, (
        "the unpacked-size total must cover the base images AND every add-on pack")
    assert "strip_digests" in computation, (
        "refs must be inspected in the same tag form they are saved in, and "
        "deduplicated — an image shared by the base set and a pack is loaded once")
    strip = src[src.index("strip_digests()"):src.index("\n", src.index("strip_digests()"))]
    assert "sort -u" in strip, (
        "strip_digests no longer deduplicates, so a shared image would be counted twice")


# ── what the installer does with it ─────────────────────────────────────────

_PATH_LINE = 'export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"'

FAKE_DF = r"""#!/bin/bash
printf 'df %s\n' "$*" >> "$DOCKER_LOG"
printf 'Filesystem 1-blocks Used Available Capacity Mounted on\n%s\n' \
  "${FAKE_DF_B:-/dev/vda 107374182400 10737418240 96636764160 10% /}"
"""


def _projection(tmp_path: Path, manifest_extra: str) -> subprocess.CompletedProcess:
    """Run the REAL check_image_disk_projection over a bundle whose MANIFEST
    carries `manifest_extra`."""
    src = INSTALL.read_text(encoding="utf-8")
    assert src.count(_PATH_LINE) == 1, "install-correlix.sh PATH line changed — update the harness"
    src = src.replace(_PATH_LINE, 'export PATH="${PATH:?test harness sets PATH}"')
    src = src[:src.rindex('\ncase "$CMD" in\n')] + "\n"

    root = tmp_path / "root"
    (root / "scripts").mkdir(parents=True)
    (root / "deployment" / "docker").mkdir(parents=True)
    # install-correlix.sh locates itself by this file (source-tree mode).
    (root / "deployment" / "docker" / "docker-compose.yml").write_text("services: {}\n")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    with open(bundle / "correlix-images-core-v1.tar.zst", "wb") as fh:
        fh.truncate(2 * GB)
    (bundle / "MANIFEST").write_text("product:  Correlix\n" + manifest_extra + "images:\n  - x\n")

    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    _write_exec(bindir / "docker", "#!/bin/bash\nprintf '%s\\n' \"$*\" >> \"$DOCKER_LOG\"\nexit 0\n")
    _write_exec(bindir / "df", FAKE_DF)
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "HOME": str(tmp_path),
           "DOCKER_LOG": str(tmp_path / "docker.log"), "CORRELIX_NO_SIZING": "1"}
    probe = subprocess.run(["bash", "-c", "command -v docker; command -v df"], env=env,
                           capture_output=True, text=True, timeout=10, check=False)
    assert probe.stdout.split() == [str(bindir / "docker"), str(bindir / "df")], \
        "a test could reach the host's real docker/df — refusing to run"

    harness = root / "scripts" / "harness.sh"
    harness.write_text(src + f'MODE=bundle; BUNDLE_DIR="{bundle}"\n'
                             f'check_image_disk_projection "{tmp_path}"\n')
    return subprocess.run(["bash", str(harness)], capture_output=True, text=True, timeout=120,
                          env=env, stdin=subprocess.DEVNULL, check=False)


def test_without_the_key_the_projection_says_it_is_estimating(tmp_path: Path) -> None:
    r = _projection(tmp_path, "")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ESTIMATE" in r.stdout


@pytest.mark.parametrize("line", [
    "images_unpacked_bytes: {n}\n",          # exactly what make-installer.sh writes
    "images_unpacked_bytes:  {n}\n",         # tolerated spacing
])
def test_the_manifest_line_make_installer_writes_is_the_one_preflight_reads(
        tmp_path: Path, line: str) -> None:
    r = _projection(tmp_path, line.format(n=7 * GB))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "7.0 GB" in r.stdout and "from MANIFEST" in r.stdout
    assert "ESTIMATE" not in r.stdout, \
        "with a recorded size the projection must stop guessing"


def test_the_written_line_is_byte_compatible_with_the_parser(tmp_path: Path) -> None:
    """The build and the installer agree on the shape, not by eye: the exact
    printf from make-installer.sh is rendered and fed to the real parser."""
    src = _make_src()
    idx = src.index("images_unpacked_bytes:")
    rendered = src[src.rindex("echo", 0, idx):src.index("\n", idx)]
    rendered = rendered.replace('echo "', "").rstrip('"')
    rendered = rendered.replace("$UNPACKED_BYTES", str(3 * GB)).replace(
        "${UNPACKED_BYTES}", str(3 * GB))
    r = _projection(tmp_path, rendered + "\n")
    assert "3.0 GB" in r.stdout and "from MANIFEST" in r.stdout, r.stdout
