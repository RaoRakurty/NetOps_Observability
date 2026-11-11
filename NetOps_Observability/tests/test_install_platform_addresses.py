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

import json
import random
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
    # These tests pin the default-route half of the rule; the host's real
    # interfaces must not leak in (the interface half is tested below).
    monkeypatch.setattr(install, "_ip_addr_json", list)
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


# ── multi-homed hosts (2026-11-11) ───────────────────────────────────────────
#
# The lab host polls 10.70.245.0/24 through its default route and the lab
# network through 192.168.172.1; the default-route address alone left the second
# network's polling counted as customer traffic. The rule: every global address
# on an UP, non-loopback, non-Docker interface, plus the default route's source.

def _iface(name, flags=("BROADCAST", "MULTICAST", "UP", "LOWER_UP"), operstate="UP", addrs=()):
    return {"ifname": name, "flags": list(flags), "operstate": operstate,
            "addr_info": list(addrs)}


def _a(family, local, scope="global", **flags):
    return {"family": family, "local": local, "scope": scope, **flags}


# Canned `ip -j addr show` of a multi-homed appliance (shape taken from the lab
# host, addresses documentation-safe where they are not the lab's own).
CANNED = [
    _iface("lo", flags=("LOOPBACK", "UP", "LOWER_UP"), operstate="UNKNOWN",
           addrs=[_a("inet", "127.0.0.1", "host"), _a("inet6", "::1", "host")]),
    _iface("enp7s0", addrs=[_a("inet", "192.168.172.1"),
                            _a("inet6", "fe80::5054:ff:fe54:b0f", "link")]),
    _iface("enp1s0", addrs=[_a("inet", "10.70.245.122"),
                            _a("inet6", "2001:db8:70::122"),
                            _a("inet6", "2001:db8:70::beef", temporary=True, dynamic=True),
                            _a("inet6", "2001:db8:70::dad", tentative=True),
                            _a("inet6", "fe80::5054:ff:fe47:1f3a", "link")]),
    # Docker's own: never what a device sees.
    _iface("docker0", addrs=[_a("inet", "172.17.0.1")]),
    _iface("br-6831bf9faf2b", addrs=[_a("inet", "172.18.0.1")]),
    _iface("docker_gwbridge", addrs=[_a("inet", "172.19.0.1")]),
    _iface("vethe67efef", addrs=[_a("inet6", "fe80::9884:6dff:fe6a:6241", "link")]),
    # Down: flag missing, or operstate DOWN (a bridge with no carrier).
    _iface("enp9s0", flags=("BROADCAST", "MULTICAST"), operstate="DOWN",
           addrs=[_a("inet", "198.51.100.9")]),
    _iface("virbr1", flags=("NO-CARRIER", "BROADCAST", "MULTICAST", "UP"), operstate="DOWN",
           addrs=[_a("inet", "192.168.200.1")]),
    # A libvirt bridge that is up IS a polling path, and a tunnel reports UNKNOWN.
    _iface("virbr0", addrs=[_a("inet", "192.168.122.1")]),
    _iface("wg0", flags=("POINTOPOINT", "NOARP", "UP", "LOWER_UP"), operstate="UNKNOWN",
           addrs=[_a("inet", "10.200.0.1")]),
    # IPv4 link-local even when mislabelled global; a deprecated address.
    _iface("enp3s0", addrs=[_a("inet", "169.254.10.10"),
                            _a("inet6", "2001:db8:99::1", deprecated=True)]),
]

EXPECTED = ["10.70.245.122", "10.200.0.1", "192.168.122.1", "192.168.172.1",
            "2001:db8:70::122"]


def test_interface_rule_on_a_multi_homed_host():
    assert install.host_interface_addresses(CANNED) == EXPECTED


def test_the_order_is_deterministic_whatever_ip_prints():
    shuffled = list(CANNED)
    random.Random(7).shuffle(shuffled)
    assert install.host_interface_addresses(shuffled) == EXPECTED
    # Duplicates (one address on two interfaces) collapse; IPv6 text is canonical.
    dup = [_iface("a", addrs=[_a("inet6", "2001:DB8:0:0::1"), _a("inet", "10.0.0.5")]),
           _iface("b", addrs=[_a("inet6", "2001:db8::1"), _a("inet", "10.0.0.5")])]
    assert install.host_interface_addresses(dup) == ["10.0.0.5", "2001:db8::1"]


def test_malformed_entries_are_skipped_not_raised_on():
    junk = ["x", None, {"ifname": "eth0"}, {"ifname": "eth1", "flags": "UP", "addr_info": []},
            _iface("eth2", addrs=[{"family": "inet"}, _a("inet", "not-an-ip"),
                                  _a("inet", "10.1.2.3\nJWT_SECRET=x"), "y",
                                  _a("packet", "aa:bb"), _a("inet", "203.0.113.4")])]
    assert install.host_interface_addresses(junk) == ["203.0.113.4"]


def test_default_writes_every_interface_address_plus_the_route(monkeypatch):
    monkeypatch.delenv("CX_PLATFORM_ADDRESSES", raising=False)
    monkeypatch.setattr(install, "_ip_addr_json", lambda: CANNED)
    monkeypatch.setattr(install, "_route_source_address", lambda: "10.70.245.122")
    assert install.platform_addresses_default() == ",".join(EXPECTED)
    # A route source no interface listed (policy routing, a VIP) is still kept.
    monkeypatch.setattr(install, "_route_source_address", lambda: "10.9.9.9")
    assert install.platform_addresses_default() == ",".join(["10.9.9.9", *EXPECTED])


def test_unreadable_interfaces_fall_back_to_the_route_loudly(monkeypatch, capsys):
    monkeypatch.delenv("CX_PLATFORM_ADDRESSES", raising=False)
    monkeypatch.setattr(install, "_ip_addr_json", lambda: None)
    monkeypatch.setattr(install, "_route_source_address", lambda: "10.70.245.122")
    assert install.platform_addresses_default() == "10.70.245.122"
    assert "default route's source address only" in capsys.readouterr().err
    monkeypatch.setattr(install, "_route_source_address", lambda: None)
    assert install.platform_addresses_default() == ""


def test_the_override_wins_over_the_interfaces(monkeypatch):
    monkeypatch.setattr(install, "_ip_addr_json", lambda: CANNED)
    monkeypatch.setattr(install, "_route_source_address", lambda: "10.70.245.122")
    monkeypatch.setenv("CX_PLATFORM_ADDRESSES", "198.51.100.7")
    assert install.platform_addresses_default() == "198.51.100.7"


def test_the_list_is_capped_at_what_the_api_reads(monkeypatch, capsys):
    monkeypatch.delenv("CX_PLATFORM_ADDRESSES", raising=False)
    many = [_iface(f"eth{i}", addrs=[_a("inet", f"10.0.{i}.1")]) for i in range(70)]
    monkeypatch.setattr(install, "_ip_addr_json", lambda: many)
    monkeypatch.setattr(install, "_route_source_address", lambda: None)
    out = install.platform_addresses_default().split(",")
    assert len(out) == install.PLATFORM_ADDRS_MAX == 64
    assert "reads the first 64" in capsys.readouterr().err


def test_an_upgrade_of_a_multi_homed_host_gains_both(compose_dir, monkeypatch):
    monkeypatch.setattr(install, "_ip_addr_json", lambda: CANNED)
    monkeypatch.setattr(install, "_route_source_address", lambda: "10.70.245.122")
    env_path = compose_dir / ".env"
    install.write_env(env_path, 8000, force=True)
    text = "".join(line for line in env_path.read_text().splitlines(keepends=True)
                   if not line.startswith("CX_PLATFORM_ADDRESSES="))
    env_path.write_text(text)
    install.migrate_env_for_upgrade(env_path)
    assert install._parse_env(env_path)["CX_PLATFORM_ADDRESSES"] == ",".join(EXPECTED)
    # The lab's hand-set single address is the operator's and is never widened.
    env_path.write_text(text + "CX_PLATFORM_ADDRESSES=10.70.245.122\n")
    install.migrate_env_for_upgrade(env_path)
    assert install._parse_env(env_path)["CX_PLATFORM_ADDRESSES"] == "10.70.245.122"


# ── reading `ip -j addr` (bounded, never raises) ─────────────────────────────

def _fake_ip(tmp_path, monkeypatch, body: str):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    ip = bindir / "ip"
    ip.write_text("#!/usr/bin/env bash\n" + body)
    ip.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")


def test_ip_json_is_read_from_ip(tmp_path, monkeypatch):
    canned = tmp_path / "canned.json"
    canned.write_text(json.dumps(CANNED))
    _fake_ip(tmp_path, monkeypatch,
             f'[ "$*" = "-j addr show" ] || exit 9\ncat "{canned}"\n')
    assert install.host_interface_addresses(install._ip_addr_json()) == EXPECTED


@pytest.mark.parametrize("body,why", [
    ('echo "Object \\"addr\\" is unknown" >&2\nexit 1\n', "exited 1"),
    ("echo 'not json'\n", "not JSON"),
    ('echo \'{"a": 1}\'\n', "did not print a list"),
    ("exec sleep 5\n", "failed"),
])
def test_ip_failures_are_named_and_return_none(tmp_path, monkeypatch, capsys, body, why):
    _fake_ip(tmp_path, monkeypatch, body)
    assert install._ip_addr_json(timeout=0.5) is None
    assert why in capsys.readouterr().err


def test_ip_missing_is_named(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(install, "_IP_FALLBACK_PATHS", ())
    assert install._ip_addr_json() is None
    assert "not installed" in capsys.readouterr().err
