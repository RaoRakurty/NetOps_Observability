# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""A generated secret must never start with "-".

The OpenSearch Dashboards image turns OPENSEARCH_PASSWORD into
`--opensearch.password <value>`; a value beginning with "-" is parsed as an
option and the service crash-loops ("must have a value"). With "-" in a
64-character alphabet that was ~1 in 64 fresh installs — the CI two-phase boot
test caught it on run 34911914843 (2026-09-15) while the PR run of the same
commit passed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import install


def _adversarial_choice(seq):
    """Pick "-" whenever the alphabet offers it — the worst case, every time."""
    return "-" if "-" in seq else seq[0]


@pytest.mark.parametrize("gen", ["generate_urlsafe_password", "generate_password"])
def test_first_character_is_never_a_dash_even_in_the_worst_case(gen, monkeypatch):
    monkeypatch.setattr(install.secrets, "choice", _adversarial_choice)
    value = getattr(install, gen)(24)
    assert len(value) == 24
    assert not value.startswith("-"), f"{gen} produced {value[:3]}… — a CLI would read it as an option"
    assert set(value[1:]) == {"-"}, "the rest of the secret keeps the full alphabet"


@pytest.mark.parametrize("gen", ["generate_urlsafe_password", "generate_password"])
def test_real_samples_never_start_with_a_dash(gen):
    samples = [getattr(install, gen)(24) for _ in range(3000)]
    assert not [s for s in samples if s.startswith("-")]
    assert len(set(samples)) == len(samples), "secrets must stay random"


def test_zero_length_is_empty():
    assert install.generate_urlsafe_password(0) == ""


def _write_fresh(tmp_path):
    env_path = tmp_path / ".env"
    install.write_env(env_path, 8000, force=True)
    return env_path


def _set(env_path, key, value):
    lines = env_path.read_text().splitlines(keepends=True)
    out = [f"{key}={value}\n" if line.startswith(f"{key}=") else line for line in lines]
    env_path.write_text("".join(out))


def test_rerun_re_mints_a_dash_leading_dashboards_password(tmp_path):
    env_path = _write_fresh(tmp_path)
    _set(env_path, "OS_DASHBOARDS_PASSWORD", "-legacyBadValue0123456789")
    before = install._parse_env(env_path)

    after = install.write_env(env_path, 8000, force=False)

    healed = after["OS_DASHBOARDS_PASSWORD"]
    assert healed and not healed.startswith("-")
    assert healed != "-legacyBadValue0123456789"
    assert install._parse_env(env_path)["OS_DASHBOARDS_PASSWORD"] == healed
    for key, value in before.items():
        if key != "OS_DASHBOARDS_PASSWORD":
            assert after.get(key) == value, f"{key} must survive the heal unchanged"


def test_rerun_leaves_a_good_dashboards_password_alone(tmp_path):
    env_path = _write_fresh(tmp_path)
    _set(env_path, "OS_DASHBOARDS_PASSWORD", "goodValue-with-dash-inside")
    after = install.write_env(env_path, 8000, force=False)
    assert after["OS_DASHBOARDS_PASSWORD"] == "goodValue-with-dash-inside"
