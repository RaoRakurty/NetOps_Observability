"""The P3 A/B overlay stays a ONE-VARIABLE overlay (docs/scale/RUN_PLAN_P3_AB_2026-08-29.md).

`deployment/docker/compose.agg.yml` is the ON arm of the P3 aggregation-plane
A/B. Its entire scientific value is that the ON leg and the OFF leg differ by
exactly one environment variable on exactly one service: same image, same
harness, same mem limit, same profiler. If this overlay ever grows a second key
-- a buffer size, a mem_limit, a second service -- every leg measured with it
becomes uninterpretable after the fact, and nobody would notice from the run
output. So the constraint is pinned here rather than left to review.

These tests read the file only; they never invoke docker.
"""
from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "deployment" / "docker" / "compose.agg.yml"

FLAG = "CORR_AGGREGATION_PLANE"
# The overlay set the A/B is layered on top of (docs/design/AGGREGATION_PLANE_P3
# section 7 step 4); compose.agg.yml is appended LAST so its value wins.
BASE_OVERLAYS = (
    "docker-compose.yml",
    "compose.offline-images.yml",
    "compose.tls.yml",
    "compose.mem125.yml",
    "compose.lab.yml",
    "compose.profile.yml",
)


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


@pytest.fixture(scope="module")
def overlay() -> dict:
    assert OVERLAY.is_file(), f"{OVERLAY} is missing -- the P3 ON arm has no overlay"
    return _compose_yaml(OVERLAY.read_text())


def test_overlay_parses_and_touches_only_correlation(overlay):
    assert set(overlay) == {"services"}, (
        f"compose.agg.yml declares top-level keys beyond `services`: "
        f"{sorted(set(overlay) - {'services'})} -- the A/B overlay is "
        f"environment-only (no volumes/networks/x- blocks)")
    assert set(overlay["services"]) == {"correlation"}, (
        f"compose.agg.yml touches services other than `correlation`: "
        f"{sorted(set(overlay['services']) - {'correlation'})} -- a second "
        f"service is a second variable in the A/B")


def test_overlay_sets_only_the_environment_block(overlay):
    svc = overlay["services"]["correlation"]
    assert set(svc) == {"environment"}, (
        f"compose.agg.yml sets correlation keys beyond `environment`: "
        f"{sorted(set(svc) - {'environment'})} -- mem_limit/cpus/build/command "
        f"belong to the base or to compose.mem125.yml, never to the A/B arm")


def test_overlay_sets_exactly_the_aggregation_flag_to_on(overlay):
    env = overlay["services"]["correlation"]["environment"]
    assert isinstance(env, dict), (
        "compose.agg.yml must use the mapping form of `environment` so the "
        "single key is unambiguous (list form permits `KEY` with no value, "
        "which inherits from the host and is not reproducible)")
    assert set(env) == {FLAG}, (
        f"compose.agg.yml sets {sorted(env)} -- the A/B ON arm sets exactly "
        f"{{{FLAG}}} and nothing else")
    value = env[FLAG]
    assert isinstance(value, str), (
        f"{FLAG} must be a QUOTED string in compose (an unquoted 1 is parsed "
        f"as an int and compose then rejects or coerces it); got {value!r}")
    # main.py ~1855: os.environ.get(...).lower() in ("1", "true", "yes")
    assert value.lower() in ("1", "true", "yes"), (
        f"{FLAG}={value!r} does not turn the plane ON -- main.py accepts only "
        f"'1'/'true'/'yes' (case-insensitive). This overlay IS the ON arm; the "
        f"OFF arm is deploying WITHOUT this file, never setting it to 0 here.")


def test_flag_is_read_by_the_correlation_service(overlay):
    """The overlay must name the variable the engine actually reads -- a typo
    here would run an OFF leg that every operator records as ON."""
    main = (ROOT / "src" / "correlation" / "main.py").read_text()
    assert f'os.environ.get(\n    "{FLAG}"' in main or f'"{FLAG}"' in main, (
        f"{FLAG} is not read anywhere in src/correlation/main.py")


def test_flag_default_is_off_in_the_image(overlay):
    """The OFF arm is 'deploy without the overlay', which is only true while
    the image default is OFF. If the default ever flips to ON, this run plan's
    OFF legs silently become ON legs."""
    main = (ROOT / "src" / "correlation" / "main.py").read_text()
    idx = main.index(f'"{FLAG}"')
    tail = main[idx:idx + 200]
    assert '"0"' in tail, (
        f"{FLAG}'s default in src/correlation/main.py is no longer '0' -- the "
        f"P3 A/B's OFF arm (deploy without compose.agg.yml) is no longer OFF. "
        f"Update docs/scale/RUN_PLAN_P3_AB_2026-08-29.md before running a leg.")


def test_base_overlay_set_still_exists():
    """The run plan's deploy command names six files; a rename would leave the
    plan pointing at nothing and the operator improvising the A/B."""
    missing = [n for n in BASE_OVERLAYS
               if not (ROOT / "deployment" / "docker" / n).is_file()]
    assert not missing, (
        f"overlay files named by the P3 run plan are gone: {missing}")


def test_overlay_documents_apply_verify_remove():
    """The header is operator-facing procedure, not decoration: a leg deployed
    to ONE of the two replicas is a mixed arm that no metric reveals."""
    text = OVERLAY.read_text()
    for needle in ("APPLY", "VERIFY", "REMOVE",
                   "--scale correlation=2",
                   "corr_agg_observed_total",
                   FLAG):
        assert needle in text, (
            f"compose.agg.yml's header no longer documents {needle!r}")
