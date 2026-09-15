# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Install journal and resume (FMEA §2 #4, §4.1, B1).

A re-run is the documented remedy for a failed install, and it used to redo
everything: on .123 the image loads alone were 716 s of a 1307 s run, and the
phase A→B recreate risk came round again. data/install-timing.json now doubles
as a journal (per stage: status, UTC stamps, pid, sha256 input fingerprints)
and a re-run:

  * skips an image load ONLY when the journal says done from the same archive
    fingerprint AND every image the MANIFEST lists still inspects present;
  * marks a stage left `running` by a dead run as `interrupted`, and runs it;
  * never skips a state-changing stage (up-a, up-b, bootstraps);
  * treats a missing or corrupt journal as "run everything", never a refusal;
  * prints why a stage was skipped or not.

No docker: image presence is injected; files live in temp dirs.
Run:  python3 -m pytest tests/test_install_journal.py -v
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import install

DIGEST = "sha256:" + "a" * 64
MANIFEST = f"""product:  Correlix (NetOps Observability)
version:  2026.09.15-ge8ebc980
git_sha:  e8ebc980
profile:  full
built:    2026-09-15T02:00:00+00:00
images:
  - correlix/api:2026.09.15@{DIGEST}
  - correlix/correlation:2026.09.15@{DIGEST}
  - postgres:16-alpine@{DIGEST}
addon sso (profile sso):
  - quay.io/keycloak/keycloak:26.0@{DIGEST}
addon log-search-ui (profile osd):
  - opensearchproject/opensearch-dashboards:2.16.0@{DIGEST}
source_sha: deadbeef
"""
BASE = ["correlix/api:2026.09.15", "correlix/correlation:2026.09.15", "postgres:16-alpine"]


@pytest.fixture
def state(tmp_path):
    """Isolate the module's per-run timing/journal/progress state."""
    old_t, old_p = dict(install._TIMING), dict(install._PROGRESS)
    install._TIMING.update({"t0": install.time.monotonic(), "open_t": None, "stages": [],
                            "record": True, "report": False,
                            "path": tmp_path / "data" / "install-timing.json",
                            "journal": {}, "open_key": None})
    install._PROGRESS.update({"on": False, "stage": None})
    yield install._TIMING
    install._TIMING.clear()
    install._TIMING.update(old_t)
    install._PROGRESS.clear()
    install._PROGRESS.update(old_p)


@pytest.fixture
def bundle(tmp_path) -> Path:
    d = tmp_path / "bundle"
    d.mkdir()
    (d / "MANIFEST").write_text(MANIFEST)
    archive = d / "correlix-images-core-2026.09.15.tar.zst"
    archive.write_bytes(b"\x28\xb5\x2f\xfd" + b"x" * 1024)
    (d / "correlix-addon-sso-2026.09.15.tar.zst").write_bytes(b"\x28\xb5\x2f\xfd" + b"k" * 512)
    (d / "SHA256SUMS").write_text(f"{'b' * 64}  ./{archive.name}\n")
    return archive


def on_disk(state) -> dict:
    return json.loads(state["path"].read_text())


# ── the journal on disk ──────────────────────────────────────────────────────

def test_a_stage_is_journaled_running_at_start_and_done_at_close(state):
    install._stage_start("bundle", "loading image bundle", inputs={"bundle": "f" * 64})
    entry = on_disk(state)["journal"]["stages"]["bundle"]
    assert entry["status"] == "running" and entry["pid"] == os.getpid()
    assert entry["inputs"] == {"bundle": "f" * 64} and entry["started_utc"].endswith("Z")
    install._stage_start("up-a", "starting stack")          # closes bundle
    doc = on_disk(state)
    assert doc["journal"]["stages"]["bundle"]["status"] == "done"
    assert doc["journal"]["stages"]["bundle"]["ended_utc"].endswith("Z")
    assert doc["journal"]["stages"]["up-a"]["status"] == "running"
    assert doc["version"] == 1 and doc["status"] == "running", "v1 readers keep working"


def test_a_failed_and_an_interrupted_stage_are_told_apart(state):
    install._stage_start("up-b", "phase B")
    with pytest.raises(SystemExit):
        install.fail("compose up failed")
    assert on_disk(state)["journal"]["stages"]["up-b"]["status"] == "failed"
    install._stage_start("mint", "mint")
    with pytest.raises(SystemExit):
        install.fail("interrupted", interrupted=True)
    assert on_disk(state)["journal"]["stages"]["mint"]["status"] == "interrupted"


def test_one_stage_id_run_per_pack_gets_one_entry_per_pack(state):
    install._stage_start("addon-pack", "sso", key="addon-pack:sso")
    install._stage_start("addon-pack", "osd", key="addon-pack:log-search-ui")
    install._stage_close_ok()
    stages = install._TIMING["journal"]
    assert stages["addon-pack:sso"]["status"] == "done"
    assert stages["addon-pack:log-search-ui"]["status"] == "done"


def test_the_journal_carries_fingerprints_never_secret_values(state, tmp_path):
    env_path = tmp_path / ".env"
    install.write_env(env_path, 8000, force=True)
    install._stage_start("up-a", "starting stack", inputs=install.stage_inputs(env_path))
    install._timing_finish("ok")
    text = state["path"].read_text()
    for key, value in install._parse_env(env_path).items():
        if len(value) >= 12 and ("PASSWORD" in key or "TOKEN" in key or "SECRET" in key):
            assert value not in text, f"{key}'s value leaked into the journal"


# ── reading the previous run ─────────────────────────────────────────────────

def test_a_stage_left_running_by_a_dead_run_is_interrupted_and_runs_again(state):
    install._stage_start("bundle", "load", inputs={"bundle": "f" * 64})
    install._stage_start("up-b", "phase B")                  # the run dies here
    stages, notes = install.load_install_journal(state["path"], pid_alive=lambda p: False)
    assert stages["bundle"]["status"] == "done"
    assert stages["up-b"]["status"] == "interrupted"
    assert any("interrupted during stage 'up-b'" in n and "no longer running" in n for n in notes)


@pytest.mark.parametrize("content,needle", [
    (None, "no install journal yet"),
    ("{not json", "corrupt"),
    (json.dumps({"version": 1, "stages": []}), "no usable install journal"),
    (json.dumps({"journal": {"schema": 99, "stages": {}}}), "no usable install journal"),
])
def test_a_missing_or_corrupt_journal_means_run_everything(tmp_path, content, needle):
    path = tmp_path / "install-timing.json"
    if content is not None:
        path.write_text(content)
    stages, notes = install.load_install_journal(path)
    assert stages == {} and needle in notes[0] and "every stage runs" in notes[0]


def test_malformed_entries_are_forgotten_not_trusted(tmp_path):
    path = tmp_path / "install-timing.json"
    path.write_text(json.dumps({"journal": {"schema": 1, "stages": {
        "bundle": {"status": "done", "inputs": {"bundle": "x"}},
        "up-a": {"status": "totally-done"},
        "mint": "done"}}}))
    stages, _ = install.load_install_journal(path)
    assert set(stages) == {"bundle"}


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
def test_an_unreadable_journal_is_not_a_refusal(tmp_path):
    path = tmp_path / "install-timing.json"
    path.write_text("{}")
    path.chmod(0)
    try:
        stages, notes = install.load_install_journal(path)
    finally:
        path.chmod(0o600)
    assert stages == {} and "not readable" in notes[0]


# ── MANIFEST and fingerprints ────────────────────────────────────────────────

def test_manifest_refs_are_split_by_section_with_digests_stripped():
    refs = install.manifest_image_refs(MANIFEST)
    assert refs["base"] == BASE
    assert refs["addon:sso"] == ["quay.io/keycloak/keycloak:26.0"]
    assert refs["addon:log-search-ui"] == ["opensearchproject/opensearch-dashboards:2.16.0"]


def test_a_ref_that_could_be_read_as_an_option_voids_its_section():
    refs = install.manifest_image_refs("images:\n  - good/image:1\n  - --privileged\n")
    assert refs["base"] == [], "an unverifiable section can never justify a skip"


def test_the_fingerprint_follows_the_manifest_and_the_recorded_digest(bundle):
    fp = install.archive_fingerprint(bundle)
    assert fp and len(fp) == 64
    (bundle.parent / "SHA256SUMS").write_text(f"{'c' * 64}  ./{bundle.name}\n")
    fp2 = install.archive_fingerprint(bundle)
    (bundle.parent / "MANIFEST").write_text(MANIFEST.replace("2026.09.15-g", "2026.09.16-g"))
    fp3 = install.archive_fingerprint(bundle)
    assert len({fp, fp2, fp3}) == 3
    (bundle.parent / "MANIFEST").unlink()
    assert install.archive_fingerprint(bundle) is None


# ── the skip decision ────────────────────────────────────────────────────────

def done(fp):
    return {"status": "done", "inputs": {"bundle": fp}}


def test_same_archive_and_every_image_present_skips(bundle):
    asked: list[str] = []
    fp = install.archive_fingerprint(bundle)
    skip, why, got = install.image_load_decision(
        {"bundle": done(fp)}, "bundle", bundle, "base",
        lambda ref: asked.append(ref) or True)
    assert skip is True and got == fp
    assert asked == BASE, "every base ref inspected, and only those"
    assert "all 3 images" in why


def test_one_missing_image_forces_the_load(bundle):
    fp = install.archive_fingerprint(bundle)
    skip, why, _ = install.image_load_decision(
        {"bundle": done(fp)}, "bundle", bundle, "base",
        lambda ref: ref != "correlix/correlation:2026.09.15")
    assert skip is False and "correlix/correlation:2026.09.15" in why


@pytest.mark.parametrize("entry,needle", [
    ({"status": "interrupted", "inputs": {"bundle": "SAME"}}, "interrupted"),
    ({"status": "running", "inputs": {"bundle": "SAME"}}, "running"),
    ({"status": "failed", "inputs": {"bundle": "SAME"}}, "failed"),
    (None, "never run"),
    ({"status": "done", "inputs": {"bundle": "0" * 64}}, "differs"),
])
def test_anything_but_a_matching_completed_load_reloads(bundle, entry, needle):
    fp = install.archive_fingerprint(bundle)
    if entry and entry["inputs"]["bundle"] == "SAME":
        entry["inputs"]["bundle"] = fp
    journal = {"bundle": entry} if entry else {}
    skip, why, _ = install.image_load_decision(journal, "bundle", bundle, "base", lambda r: True)
    assert skip is False and needle in why


def test_a_bundle_without_a_manifest_is_never_skipped(bundle):
    fp = install.archive_fingerprint(bundle)
    (bundle.parent / "MANIFEST").unlink()
    skip, why, _ = install.image_load_decision({"bundle": done(fp)}, "bundle", bundle,
                                               "base", lambda r: True)
    assert skip is False and "MANIFEST" in why


@pytest.mark.parametrize("stage", ["up-a", "mint", "up-b", "kafka-acls", "bootstrap-kc",
                                   "bootstrap-appstate", "data-dirs", "env"])
def test_state_changing_stages_are_never_skipped(bundle, stage):
    fp = install.archive_fingerprint(bundle)
    assert not install.journal_may_skip(stage)
    skip, why, _ = install.image_load_decision({stage: done(fp)}, stage, bundle, "base",
                                               lambda r: True)
    assert skip is False and "never skipped" in why


def test_main_decides_before_the_stage_and_loads_only_when_not_skipping():
    src = (SCRIPTS / "install.py").read_text()
    main_src = src[src.index("def main("):]
    decide = main_src.index('image_load_decision(\n            _TIMING["journal"], "bundle"')
    stage = main_src.index('stage="bundle"')
    load = main_src.index("load_bundle(args.bundle)")
    assert decide < stage < load
    assert "if skip:" in main_src[stage:load] and "else:" in main_src[stage:load]
    assert main_src.index("load_install_journal(") < main_src.index('stage="prereq"')


# ── add-on packs: the same rule, per pack ────────────────────────────────────

def test_a_loaded_pack_is_skipped_on_rerun_and_says_why(state, bundle, monkeypatch, capsys):
    loaded: list[str] = []
    monkeypatch.setattr(install, "load_bundle", lambda p: loaded.append(p.name))
    pack = bundle.parent / "correlix-addon-sso-2026.09.15.tar.zst"
    install._TIMING["journal"] = {"addon-pack:sso": done(install.archive_fingerprint(pack))}
    install.load_addon_packs(bundle, "embedded-bus,sso", image_present=lambda r: True)
    assert loaded == []
    assert "skipping add-on pack sso: already loaded" in capsys.readouterr().out
    install._stage_close_ok()
    assert install._TIMING["journal"]["addon-pack:sso"]["status"] == "done"


def test_a_pack_whose_image_was_removed_is_reloaded(state, bundle, monkeypatch, capsys):
    loaded: list[str] = []
    monkeypatch.setattr(install, "load_bundle", lambda p: loaded.append(p.name))
    pack = bundle.parent / "correlix-addon-sso-2026.09.15.tar.zst"
    install._TIMING["journal"] = {"addon-pack:sso": done(install.archive_fingerprint(pack))}
    install.load_addon_packs(bundle, "sso", image_present=lambda r: False)
    assert loaded == [pack.name]
    assert "not skipped" in capsys.readouterr().out


def test_rerun_after_a_kill_skips_the_finished_load_and_reruns_the_rest(state, bundle):
    """End to end over the file: run 1 loads, then dies in up-a; run 2 reads it."""
    fp = install.archive_fingerprint(bundle)
    install._stage_start("bundle", "loading image bundle", inputs={"bundle": fp})
    install._stage_start("up-a", "starting stack")           # SIGKILL here: no finish
    stages, _notes = install.load_install_journal(state["path"], pid_alive=lambda p: False)
    skip_bundle, _, _ = install.image_load_decision(stages, "bundle", bundle, "base",
                                                    lambda r: True)
    assert skip_bundle is True
    assert stages["up-a"]["status"] == "interrupted"
    assert not install.journal_may_skip("up-a")
