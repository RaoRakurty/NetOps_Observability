"""The P3 A/B overlays stay ONE-VARIABLE overlays (docs/scale/RUN_PLAN_P3_AB_2026-08-29.md).

THE CONTRACT (amended 2026-08-31, ultra #35). Three defaults exist and they are
NOT the same thing:

  * IMAGE default: OFF — src/correlation/main.py reads CORR_AGGREGATION_PLANE
    with default "0" (a bare `docker run` must not silently aggregate).
  * COMPOSE default: ON — docker-compose.yml sets
    `${CORR_AGGREGATION_PLANE:-1}` (owner-ratified 2026-08-30 after the run
    plan's §7 decision rule); `.env` can override it.
  * The A/B arms: PINNED EXPLICITLY, one one-variable overlay each —
    `compose.agg.yml` (=1, the ON arm) and `compose.agg-off.yml` (=0, the OFF
    arm).

Because the compose default is ON, the OFF arm is NOT "deploy without
compose.agg.yml" any more: the absence of BOTH pin files is the DEPLOYED
DEFAULT (currently ON), which only the end-of-wave restore deploys. The arms'
entire scientific value is unchanged: the two legs differ by exactly one
environment variable on exactly one service — same image, same harness, same
mem limit, same profiler. If either overlay ever grows a second key -- a
buffer size, a mem_limit, a second service -- every leg measured with it
becomes uninterpretable after the fact, and nobody would notice from the run
output. So the constraint is pinned here rather than left to review.

These tests read the files only; they never invoke docker.
"""
from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
OVERLAY_ON = ROOT / "deployment" / "docker" / "compose.agg.yml"
OVERLAY_OFF = ROOT / "deployment" / "docker" / "compose.agg-off.yml"
BASE_COMPOSE = ROOT / "deployment" / "docker" / "docker-compose.yml"

FLAG = "CORR_AGGREGATION_PLANE"
# main.py ~1855: os.environ.get(...).lower() in ("1", "true", "yes") turns the
# plane ON; every other value is OFF.
ON_VALUES = ("1", "true", "yes")
# The overlay set the A/B is layered on top of (docs/design/AGGREGATION_PLANE_P3
# section 7 step 4); the arm's pin overlay is appended LAST so its value wins.
BASE_OVERLAYS = (
    "docker-compose.yml",
    "compose.offline-images.yml",
    "compose.tls.yml",
    "compose.mem125.yml",
    "compose.lab.yml",
    "compose.profile.yml",
)
# Two of the six are PER-HOST files that are deliberately untracked (see
# .gitignore): compose.offline-images.yml is written by `install.py --offline`
# on the target host, and compose.lab.yml is the lab's site-local override
# (Versa CA mount). A fresh checkout — CI — legitimately lacks them; the lab
# deploy host must not. The split below is VERIFIED against the tracked
# .gitignore rather than assumed, so moving a file between the two categories
# without updating the ignore rules still fails here.
PER_HOST_OVERLAYS = frozenset({"compose.offline-images.yml", "compose.lab.yml"})


def _compose_yaml(text: str) -> dict:
    """Parse a compose file that may carry compose's merge tags (!override,
    !reset) -- yaml.safe_load rejects unknown tags. Same loader shape as
    tests/test_assurance_contracts.py."""
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


@pytest.fixture(scope="module", params=[OVERLAY_ON, OVERLAY_OFF],
                ids=["agg-on", "agg-off"])
def overlay_path(request) -> Path:
    path = request.param
    assert path.is_file(), f"{path} is missing -- a P3 arm has no pin overlay"
    return path


@pytest.fixture(scope="module")
def overlay(overlay_path) -> dict:
    return _compose_yaml(overlay_path.read_text())


def _flag_value(path: Path) -> str:
    return _compose_yaml(path.read_text())["services"]["correlation"][
        "environment"][FLAG]


# ── one variable, one service — BOTH pin overlays ───────────────────────────
def test_overlay_parses_and_touches_only_correlation(overlay, overlay_path):
    assert set(overlay) == {"services"}, (
        f"{overlay_path.name} declares top-level keys beyond `services`: "
        f"{sorted(set(overlay) - {'services'})} -- the A/B overlays are "
        f"environment-only (no volumes/networks/x- blocks)")
    assert set(overlay["services"]) == {"correlation"}, (
        f"{overlay_path.name} touches services other than `correlation`: "
        f"{sorted(set(overlay['services']) - {'correlation'})} -- a second "
        f"service is a second variable in the A/B")


def test_overlay_sets_only_the_environment_block(overlay, overlay_path):
    svc = overlay["services"]["correlation"]
    assert set(svc) == {"environment"}, (
        f"{overlay_path.name} sets correlation keys beyond `environment`: "
        f"{sorted(set(svc) - {'environment'})} -- mem_limit/cpus/build/command "
        f"belong to the base or to compose.mem125.yml, never to an A/B arm")


def test_overlay_sets_exactly_the_aggregation_flag_as_a_string(overlay,
                                                               overlay_path):
    env = overlay["services"]["correlation"]["environment"]
    assert isinstance(env, dict), (
        f"{overlay_path.name} must use the mapping form of `environment` so "
        f"the single key is unambiguous (list form permits `KEY` with no "
        f"value, which inherits from the host and is not reproducible)")
    assert set(env) == {FLAG}, (
        f"{overlay_path.name} sets {sorted(env)} -- an A/B pin overlay sets "
        f"exactly {{{FLAG}}} and nothing else")
    assert isinstance(env[FLAG], str), (
        f"{FLAG} must be a QUOTED string in compose (an unquoted 0/1 is "
        f"parsed as an int and compose then rejects or coerces it); got "
        f"{env[FLAG]!r}")


# ── each arm pins its own value ─────────────────────────────────────────────
def test_on_overlay_turns_the_plane_on():
    value = _flag_value(OVERLAY_ON)
    assert value.lower() in ON_VALUES, (
        f"{FLAG}={value!r} does not turn the plane ON -- main.py accepts only "
        f"'1'/'true'/'yes' (case-insensitive). compose.agg.yml IS the ON arm; "
        f"the OFF arm is compose.agg-off.yml, never a 0 here.")


def test_off_overlay_turns_the_plane_off():
    value = _flag_value(OVERLAY_OFF)
    assert value == "0", (
        f"{FLAG}={value!r} in compose.agg-off.yml -- the OFF arm pins exactly "
        f"'0' (main.py treats anything outside {ON_VALUES} as OFF, but the "
        f"pin is the canonical '0' so `env` reads unambiguously). Under the "
        f"default-ON compose (2026-08-30) this PIN is what makes an OFF leg "
        f"OFF; the file's absence is the deployed default (ON), not the OFF "
        f"arm.")


def test_the_two_pins_disagree():
    """A copy-paste that leaves both overlays on the same value would make the
    A/B measure nothing, and no run output would reveal it."""
    on_is_on = _flag_value(OVERLAY_ON).lower() in ON_VALUES
    off_is_on = _flag_value(OVERLAY_OFF).lower() in ON_VALUES
    assert on_is_on and not off_is_on, (
        f"the two pin overlays must pull the flag in OPPOSITE directions "
        f"(agg.yml -> ON, agg-off.yml -> OFF); read "
        f"{_flag_value(OVERLAY_ON)!r} / {_flag_value(OVERLAY_OFF)!r}")


# ── the flag and its two defaults ───────────────────────────────────────────
def test_flag_is_read_by_the_correlation_service():
    """The overlays must name the variable the engine actually reads -- a typo
    here would run an OFF leg that every operator records as ON."""
    main = (ROOT / "src" / "correlation" / "main.py").read_text()
    assert f'os.environ.get(\n    "{FLAG}"' in main or f'"{FLAG}"' in main, (
        f"{FLAG} is not read anywhere in src/correlation/main.py")


def test_flag_default_is_off_in_the_image():
    """The IMAGE default stays OFF (docker-compose.yml's own comment pins
    this): a container run outside the compose set -- unit tests, an ad-hoc
    `docker run` -- must not silently aggregate. Note this is NOT the A/B OFF
    arm any more: under the compose default (ON, 2026-08-30) the OFF arm is
    the compose.agg-off.yml pin, and overlay-absence is the deployed
    default."""
    main = (ROOT / "src" / "correlation" / "main.py").read_text()
    idx = main.index(f'"{FLAG}"')
    tail = main[idx:idx + 200]
    assert '"0"' in tail, (
        f"{FLAG}'s default in src/correlation/main.py is no longer '0' -- "
        f"docker-compose.yml's comment promises the IMAGE default stays OFF. "
        f"Update the comment, docs/scale/RUN_PLAN_P3_AB_2026-08-29.md and "
        f"this suite before running a leg.")


def test_compose_default_is_on():
    """The owner-ratified deployed default (2026-08-30). The driver's restore
    semantics -- `deploy with NEITHER pin overlay` yields ON -- and every doc
    header written since depend on it; flipping it back requires updating
    scripts/scale-ab-driver.py's restore text, both overlay headers and the
    run-plan docs in the same change."""
    text = BASE_COMPOSE.read_text()
    assert "${CORR_AGGREGATION_PLANE:-1}" in text, (
        f"docker-compose.yml no longer defaults {FLAG} ON "
        f"('${{{FLAG}:-1}}' not found) -- the deployed default has changed; "
        f"the A/B restore contract and the overlay headers document ON and "
        f"must be updated with it")


# ── the operator-facing procedure ───────────────────────────────────────────
def test_base_overlay_set_still_exists():
    """The run plan's deploy command names six files; a rename would leave the
    plan pointing at nothing and the operator improvising the A/B.

    The two PER_HOST_OVERLAYS are generated/site-local and gitignored, so a
    fresh checkout (CI) not having them is the expected state, not a rename:
    they are asserted only where they can exist (a deployed host), and their
    absence is excused ONLY if .gitignore still names them — an un-ignored
    missing file fails loudly either way."""
    missing = [n for n in BASE_OVERLAYS
               if not (ROOT / "deployment" / "docker" / n).is_file()]
    tracked_missing = [n for n in missing if n not in PER_HOST_OVERLAYS]
    assert not tracked_missing, (
        f"overlay files named by the P3 run plan are gone: {tracked_missing}")
    per_host_missing = [n for n in missing if n in PER_HOST_OVERLAYS]
    if per_host_missing:
        gitignore = (ROOT / ".gitignore").read_text().split()
        not_ignored = [n for n in per_host_missing
                       if f"deployment/docker/{n}" not in gitignore]
        assert not not_ignored, (
            f"{not_ignored} are missing and NOT gitignored — either the run "
            f"plan's overlay was renamed/deleted (restore it) or it stopped "
            f"being a per-host file (then it must be tracked)")
        pytest.skip("per-host gitignored overlays not present in this "
                    f"checkout (generated at install / lab-local): "
                    f"{per_host_missing}")


def test_overlay_documents_apply_verify_remove(overlay_path):
    """The headers are operator-facing procedure, not decoration: a leg
    deployed to ONE of the two replicas is a mixed arm that no metric
    reveals -- and each header must name its mirror, because under the
    default-ON compose deploying with NEITHER file is a third state (the
    deployed default), not the other arm."""
    text = overlay_path.read_text()
    mirror = (OVERLAY_OFF if overlay_path == OVERLAY_ON else OVERLAY_ON).name
    for needle in ("APPLY", "VERIFY", "REMOVE",
                   "--scale correlation=2",
                   "corr_agg_observed_total",
                   FLAG, mirror):
        assert needle in text, (
            f"{overlay_path.name}'s header no longer documents {needle!r}")
