# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Optional capability ships as add-on packs, and the three files agree on which.

WHY (2026-09-06, the 2.2 GB bundle). Keycloak sat in `make-installer.sh`'s
`BASE_PROFILES` as "SSO is default-on" (owner decision 2026-08-04). It is the
second-largest image in the archive at 235 MB, and the capability it powers is
recorded as DEFERRED by its own design (`docs/design/SSO_SAML_*`), so every
customer paid for it and essentially none used it. It is now the third add-on
pack, alongside `log-search-ui` and `self-monitoring`.

An add-on pack is a contract spread across FOUR files, and a pack is only real
if all of them say the same thing:

  * `scripts/make-installer.sh`   ADDONS — which packs are cut, and from which
                                  compose profile;
  * `scripts/install.py`          ADDON_PACKS — which profile needs which pack
                                  file at install time, and the refusal when it
                                  is not there;
  * `scripts/install-correlix.sh` addon_spec — the post-install enable/disable
                                  registry and the setup console's menu;
  * `.github/workflows/release-bundle.yml` — the smoke step that proves the
                                  pack actually shipped (covered by
                                  tests/test_release_bundle_labels.py).

Drift between them is silent and customer-visible: a pack that is CUT but not
in `addon_spec` cannot be enabled; a profile that is offered but has no pack
reaches for a registry an air-gapped appliance cannot see. So the registries
are compared against each other here rather than each being asserted alone.

The refusal itself is the other half. On an offline install the images are
whatever the archives put in the daemon, and compose runs `--no-build`; asking
for `sso` on a bundle with no sso pack has exactly two possible endings, and
"named refusal now" is the one that tells the customer which file to copy.

No docker, no bundle, no network: source text plus a tmp_path and a captured
SystemExit.

Run:  python3 -m pytest tests/test_install_addon_packs.py -v
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import install  # noqa: E402

MAKE_INSTALLER = (SCRIPTS / "make-installer.sh").read_text()
INSTALL_CORRELIX = (SCRIPTS / "install-correlix.sh").read_text()


# ── the registries agree ────────────────────────────────────────────────────

def make_installer_addons() -> dict[str, str]:
    """make-installer.sh's ADDONS list, as {pack name: compose profile}."""
    m = re.search(r'^ADDONS="([^"]*)"', MAKE_INSTALLER, re.M)
    assert m, "make-installer.sh no longer declares an ADDONS list"
    out = {}
    for entry in m.group(1).split():
        name, _, profile = entry.partition(":")
        out[name] = profile
    return out


def install_correlix_addons() -> dict[str, str]:
    """install-correlix.sh's addon_spec registry, as {pack name: profile}."""
    body = re.search(r"^addon_spec\(\) \{(.*?)^\}", INSTALL_CORRELIX, re.M | re.S)
    assert body, "install-correlix.sh no longer has an addon_spec registry"
    return {name: spec.split("|", 1)[0]
            for name, spec in re.findall(r'^\s*([a-z0-9-]+)\)\s*echo "([^"]+)"',
                                         body.group(1), re.M)}


def test_every_pack_that_is_cut_can_also_be_enabled() -> None:
    """A pack in the bundle that `enable` does not know is a pack nobody can use."""
    assert make_installer_addons() == install_correlix_addons()


def test_install_py_knows_a_pack_for_every_addon_profile() -> None:
    """install.py is keyed by PROFILE (what .env activates), the others by name."""
    by_profile = {prof: name for name, prof in make_installer_addons().items()}
    assert {p: n for p, (n, _) in install.ADDON_PACKS.items()} == by_profile


def test_sso_is_a_pack_and_no_longer_a_base_image() -> None:
    """The whole point: a default bundle must not carry Keycloak.

    Asserted on BASE_PROFILES rather than on an image name, because that array
    is what `docker compose config --images` is asked with — it is the single
    line that decides whether 235 MB enters every customer's download.
    """
    assert make_installer_addons().get("sso") == "sso", (
        "sso is no longer cut as an add-on pack")
    m = re.search(r"^BASE_PROFILES=\((.*)\)$", MAKE_INSTALLER, re.M)
    assert m, "make-installer.sh no longer declares BASE_PROFILES"
    assert "sso" not in m.group(1).split(), (
        "the sso profile is back in BASE_PROFILES — Keycloak (235 MB) would "
        "ship inside the base archive again")


def test_the_sealing_sidecar_is_declared_not_inherited() -> None:
    """`--tls` needs netops-secrets-seal, so the seal profile must be explicit.

    It used to reach the bundle only because this build host's .env chains
    compose.tls.yml (which sets `secrets-seal: profiles: !override []`). A CI
    runner has no .env, so the bundle it cut had no sealing sidecar image and
    its `--tls` install could not start.
    """
    m = re.search(r"^BASE_PROFILES=\((.*)\)$", MAKE_INSTALLER, re.M)
    assert m and "seal" in m.group(1).split()


def test_the_bundle_contents_do_not_depend_on_the_build_host() -> None:
    """Both compose variables are pinned before any `docker compose` call."""
    assert re.search(r'^export COMPOSE_FILE="docker-compose\.yml"$',
                     MAKE_INSTALLER, re.M), (
        "make-installer.sh does not pin COMPOSE_FILE — a developer's .env "
        "COMPOSE_FILE chain (compose.tls.yml, compose.lab.yml, ...) would "
        "decide what a customer receives")
    assert re.search(r'^export COMPOSE_PROFILES=""$', MAKE_INSTALLER, re.M)
    # ...and pinned BEFORE the first real call, not somewhere below it.
    # Comment lines are skipped: this section explains itself at length.
    pin = None
    for n, line in enumerate(MAKE_INSTALLER.splitlines(), 1):
        bare = line.strip()
        if bare.startswith("#"):
            continue
        if bare.startswith("export COMPOSE_FILE="):
            pin = n
        if "docker compose " in bare:
            assert pin is not None, (
                f"line {n} runs `docker compose` before COMPOSE_FILE is pinned")


# ── the refusal ─────────────────────────────────────────────────────────────

@pytest.fixture()
def bundle_dir(tmp_path: Path) -> Path:
    d = tmp_path / "correlix-2026.09.06-gdeadbeef"
    d.mkdir()
    (d / "correlix-images-core-2026.09.06-gdeadbeef.tar.zst").write_bytes(b"\x00")
    return d


def _core(bundle_dir: Path) -> Path:
    return bundle_dir / "correlix-images-core-2026.09.06-gdeadbeef.tar.zst"


def test_a_profile_with_no_pack_refuses_by_name(bundle_dir: Path, capsys) -> None:
    with pytest.raises(SystemExit) as e:
        install.load_addon_packs(_core(bundle_dir), "embedded-bus,prober,sso")
    assert e.value.code == 1
    err = capsys.readouterr().err
    assert "sso" in err, "the refusal must name the profile the customer chose"
    assert "correlix-addon-sso-*.tar.zst" in err, (
        "the refusal must name the FILE to copy — it replaces a `pull access "
        "denied` from a host with no route to a registry")
    assert str(bundle_dir) in err, "the refusal must name where it looked"
    assert "--profiles" in err, "the refusal must offer the way forward"


@pytest.mark.parametrize("profile,pack", [
    ("osd", "log-search-ui"),
    ("self-monitoring", "self-monitoring"),
    ("sso", "sso"),
])
def test_each_pack_refuses_when_absent(bundle_dir: Path, capsys,
                                       profile: str, pack: str) -> None:
    with pytest.raises(SystemExit):
        install.load_addon_packs(_core(bundle_dir), f"embedded-bus,{profile}")
    assert f"correlix-addon-{pack}-*.tar.zst" in capsys.readouterr().err


def test_a_present_pack_is_loaded_and_others_are_not(bundle_dir: Path,
                                                     monkeypatch) -> None:
    for pack in ("log-search-ui", "sso"):
        (bundle_dir / f"correlix-addon-{pack}-2026.09.06-gdeadbeef.tar.zst"
         ).write_bytes(b"\x00")
    loaded: list[str] = []
    monkeypatch.setattr(install, "load_bundle", lambda p: loaded.append(p.name))
    install.load_addon_packs(_core(bundle_dir), "embedded-bus,prober,sso")
    assert loaded == ["correlix-addon-sso-2026.09.06-gdeadbeef.tar.zst"], (
        "only the packs the activated profiles need may be loaded")


def test_a_base_only_install_loads_nothing(bundle_dir: Path, monkeypatch) -> None:
    """The default customer install: base appliance, no packs, no refusal."""
    monkeypatch.setattr(install, "load_bundle",
                        lambda p: pytest.fail(f"loaded {p} for a base install"))
    install.load_addon_packs(_core(bundle_dir), "embedded-bus,prober,seal")


def test_the_newest_pack_wins_when_several_versions_sit_together() -> None:
    """A download folder can accumulate versions; take the highest, not a random one."""
    src = (SCRIPTS / "install.py").read_text()
    assert "packs = sorted(bundle.parent.glob(" in src
    assert "load_bundle(packs[-1])" in src


# ── the enable path (post-install) ──────────────────────────────────────────

def test_enable_refuses_a_missing_pack_instead_of_shrugging() -> None:
    """`enable` used to `if [ -n "$pack" ]` and silently continue to compose up."""
    body = re.search(r"^cmd_enable\(\) \{(.*?)^\}", INSTALL_CORRELIX, re.M | re.S)
    assert body, "install-correlix.sh no longer has cmd_enable"
    body = body.group(1)
    assert 'die "The \'$ADDON_ARG\' add-on pack is not in this bundle."' in body, (
        "a missing pack must be a named refusal, not a skipped load followed "
        "by a docker pull the appliance cannot perform")
    assert "correlix-addon-$ADDON_ARG-<version>.tar.zst" in body, (
        "the refusal must name the file the customer has to copy")


def test_enabling_sso_creates_keycloaks_database() -> None:
    """Keycloak crash-loops on a missing DB, and it cannot create its own.

    install.py owns that at INSTALL time; enabling the pack months later has to
    run the same step or the add-on 'works' by starting a container that never
    comes up (first real SSO bring-up, 2026-08-03).
    """
    body = re.search(r"^cmd_enable\(\) \{(.*?)^\}", INSTALL_CORRELIX, re.M | re.S)
    assert body and "--bootstrap-sso" in body.group(1)
    src = (SCRIPTS / "install.py").read_text()
    assert '"--bootstrap-sso"' in src, "install.py has no --bootstrap-sso flag"
    assert "if args.bootstrap_sso:" in src
    assert "bootstrap_keycloak_db(compose_dir, _parse_env(env_path))" in src


def test_the_setup_console_offers_every_pack() -> None:
    """The terminal menu is one of the two ways a customer chooses add-ons."""
    body = re.search(r"^pick_addon\(\) \{(.*?)^\}", INSTALL_CORRELIX, re.M | re.S)
    assert body, "install-correlix.sh no longer has pick_addon"
    for name in make_installer_addons():
        assert f'PICKED="{name}"' in body.group(1), (
            f"the setup console does not offer the {name!r} add-on")


def test_the_graphical_installer_offers_every_pack() -> None:
    """The other way. The GUI exports `addons: [...]` into the profile config."""
    ui = (SCRIPTS / "installer-gui" / "ui.html").read_text()
    main_go = (SCRIPTS / "installer-gui" / "main.go").read_text()
    for name in make_installer_addons():
        assert f"addons.push('{name}')" in ui, (
            f"the graphical installer's Deployment step does not offer {name!r}")
        assert f'"{name}": true' in main_go, (
            f"the graphical installer would reject {name!r} as an unknown add-on")


def test_one_add_on_list_is_shown_to_humans_not_three_copies() -> None:
    """Three hand-copied 'Available add-ons: ...' strings drifted; now there is one."""
    assert INSTALL_CORRELIX.count("ADDON_HELP=") == 1
    assert "sso (single sign-on via Keycloak)" in INSTALL_CORRELIX
    stale = re.findall(r'"Available add-ons: [^"]*"', INSTALL_CORRELIX)
    assert len(stale) == 1, f"a hand-copied add-on list is back: {stale}"
