# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""CX_PLATFORM_ADDRESSES works on a customer install with no manual step
(tracker 387 PR 13; owner rule: no lab-only fixes).

The flows views leave out the flows Correlix's own pollers cause, which needs the
appliance's sender address. The installer writes the default route's source
address on a fresh install and on an upgrade's migration, and never rewrites a
value the operator set. The GUI installer drives install.py, so the same code
writes its .env (scripts/installer-gui only reads .env).
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import install

COMPOSE_DIR = ROOT / "deployment" / "docker"


@pytest.fixture
def compose_dir(tmp_path, monkeypatch):
    for k in ("CORRELIX_STORE_BACKEND", "CORRELIX_ADMIN_USERNAME", "CX_PLATFORM_ADDRESSES"):
        monkeypatch.delenv(k, raising=False)
    cd = tmp_path / "deployment" / "docker"
    cd.mkdir(parents=True)
    for name in ("docker-compose.yml", "compose.tls.yml"):
        shutil.copy2(COMPOSE_DIR / name, cd / name)
    return cd


def test_fresh_install_writes_the_route_source_address(compose_dir, monkeypatch):
    monkeypatch.setattr(install, "_route_source_address", lambda: "10.70.245.122")
    env_path = compose_dir / ".env"
    install.write_env(env_path, 8000, force=True)
    assert install._parse_env(env_path)["CX_PLATFORM_ADDRESSES"] == "10.70.245.122"


def test_an_explicit_value_wins_on_a_fresh_install(compose_dir, monkeypatch):
    monkeypatch.setattr(install, "_route_source_address", lambda: "10.70.245.122")
    monkeypatch.setenv("CX_PLATFORM_ADDRESSES", "198.51.100.7,10.99.0.0/16")
    env_path = compose_dir / ".env"
    install.write_env(env_path, 8000, force=True)
    assert install._parse_env(env_path)["CX_PLATFORM_ADDRESSES"] == "198.51.100.7,10.99.0.0/16"


def test_a_hostile_explicit_value_is_refused(monkeypatch):
    monkeypatch.setenv("CX_PLATFORM_ADDRESSES", "10.0.0.1\nJWT_SECRET=x")
    with pytest.raises(SystemExit):
        install.platform_addresses_default()


def test_no_default_route_leaves_it_empty_for_the_api_fallback(compose_dir, monkeypatch):
    monkeypatch.setattr(install, "_route_source_address", lambda: None)
    env_path = compose_dir / ".env"
    install.write_env(env_path, 8000, force=True)
    assert install._parse_env(env_path)["CX_PLATFORM_ADDRESSES"] == ""


def test_an_upgrade_gains_it_and_never_rewrites_the_operators(compose_dir, monkeypatch):
    monkeypatch.setattr(install, "_route_source_address", lambda: "10.70.245.122")
    env_path = compose_dir / ".env"
    install.write_env(env_path, 8000, force=True)
    # An older .env: no line at all. The migration seeds it.
    text = "".join(line for line in env_path.read_text().splitlines(keepends=True)
                   if not line.startswith("CX_PLATFORM_ADDRESSES="))
    env_path.write_text(text)
    install.write_env(env_path, 8000, force=False)
    assert install._parse_env(env_path)["CX_PLATFORM_ADDRESSES"] == "10.70.245.122"
    # An operator's value, including an explicit empty one, is never touched.
    for operator in ("192.0.2.9", ""):
        text = "".join(line if not line.startswith("CX_PLATFORM_ADDRESSES=")
                       else f"CX_PLATFORM_ADDRESSES={operator}\n"
                       for line in env_path.read_text().splitlines(keepends=True))
        env_path.write_text(text)
        install.write_env(env_path, 8000, force=False)
        assert install._parse_env(env_path)["CX_PLATFORM_ADDRESSES"] == operator


def test_the_key_is_migratable_not_required():
    assert "CX_PLATFORM_ADDRESSES" in install.migrated_env_keys()
    compose = (COMPOSE_DIR / "docker-compose.yml").read_text(encoding="utf-8")
    assert "CX_PLATFORM_ADDRESSES: ${CX_PLATFORM_ADDRESSES:-}" in compose
