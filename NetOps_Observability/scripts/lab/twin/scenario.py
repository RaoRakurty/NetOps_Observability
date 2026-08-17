"""Scenario DSL loader + validation (tracker 152, design §3.3 / §8.2).

Plain-Python structural validation of the `correlix.twin.scenario.v1` shape —
no jsonschema dependency (stdlib-only contract for the T1 twin, design §4.1).
Every rule from the design is enforced with an ACTIONABLE error message:

  * unknown top-level keys, story keys, or story-param keys are HARD errors
    (zero-trust on our own inputs — a typo'd label must never silently weaken
    ground truth);
  * every story template must be one of the §5.1–§5.10 registry entries below;
  * every referenced device / tenant / seam must exist;
  * seam_type is one of the five FINAL types (DX|VPN|SDWAN|DIA|CLOUD_BACKBONE);
  * the computed steady-state EPS must fit the T1 budget (design §9.1) unless
    the caller forces.

YAML is loaded via PyYAML when available on the host (it is a pre-existing
host package, NOT a new product dependency); a `.json` scenario file works
without it, so the twin never *requires* PyYAML.
"""
from __future__ import annotations

import json
import os
from typing import Any

# T1 budget (design §9.1): refuse scenarios whose computed steady EPS exceeds
# this unless --force. Story bursts are separately capped by review, not here.
T1_STEADY_EPS_BUDGET = 200.0

SEAM_TYPES = ("DX", "VPN", "SDWAN", "DIA", "CLOUD_BACKBONE")
DEVICE_ROLES = ("edge", "core", "spine", "leaf", "wan")

TOP_LEVEL_KEYS = ("twin", "meta", "tenants", "sites", "devices", "links",
                  "seams", "baseline", "stories")
REQUIRED_TOP_LEVEL = ("twin", "meta", "tenants", "devices", "baseline")

STORY_KEYS = ("id", "template", "trigger", "affected", "params", "expect")
REQUIRED_STORY_KEYS = ("id", "template", "trigger", "affected", "expect")

# ── story template registry (design §5.1–§5.10) ─────────────────────────────
# T1-CORE lanes are syslog / probes / cloud / metrics — all bus-direct or via
# the syslog console-producer path, per the task's T1-core scope. Templates
# that REQUIRE the trap lane (out of scope for T1 core: SNMP/snmpsim, traps,
# IPFIX, gNMI are a later wave) are validation-refused with an actionable
# error rather than silently emitting a story the engine cannot detect.
#
# Each entry: allowed param keys (unknown = hard error) and required lanes.
STORY_TEMPLATES: dict[str, dict[str, Any]] = {
    "link_down_cascade": {
        "params": {"probe_loss_pct"},
        "lanes": {"syslog", "probes"},
    },
    "bgp_flap": {
        "params": {"flap_count", "hold_s", "probe_loss_pct"},
        "lanes": {"syslog", "probes"},
    },
    "dx_circuit_flap_cloud_withdrawal": {
        "params": {"flap_count", "hold_s", "final_state", "cloud",
                   "probe_loss_pct"},
        "lanes": {"syslog", "probes", "cloud"},
    },
    "isp_brownout_multi_tenant": {
        "params": {"probe_loss_pct", "duration_s"},
        "lanes": {"probes"},
    },
    "cpu_exhaustion": {
        "params": {"cpu_device", "peak_pct", "with_impact"},
        "lanes": {"metrics"},
    },
    "optics_degradation": {
        "params": {"interface"},
        "lanes": {"syslog"},
    },
    # §5.7 needs a coldStart TRAP to seed the device_restart signal — the trap
    # lane is a later wave (T1-core exclusion), so this template refuses.
    "device_restart": {
        "params": set(),
        "lanes": {"trap"},
    },
    "vpn_tunnel_down": {
        "params": {"cloud", "probe_loss_pct"},
        "lanes": {"syslog", "probes", "cloud"},
    },
    "negative_debug_probe": {
        "params": {"probe_loss_pct", "count"},
        "lanes": {"probes"},
    },
    "negative_unrelated_concurrency": {
        "params": {"cpu_device", "bgp_device", "probe_device"},
        "lanes": {"syslog", "probes", "metrics"},
    },
}

# Lanes the T1-core emitters actually implement.
T1_CORE_LANES = {"syslog", "probes", "cloud", "metrics"}


class ScenarioError(ValueError):
    """A scenario file failed validation. The message is the actionable part —
    it names the offending path and what would fix it."""


def _err(path: str, msg: str) -> ScenarioError:
    return ScenarioError(f"scenario {path}: {msg}")


def _require_type(value: Any, typ: type, path: str, what: str) -> Any:
    if not isinstance(value, typ):
        raise _err(path, f"{what} must be {typ.__name__}, got "
                         f"{type(value).__name__} ({value!r})")
    return value


def load_scenario(path: str) -> dict:
    """Read + parse + validate one scenario file. Returns the validated dict.

    `.yaml`/`.yml` requires PyYAML on the host; `.json` always works.
    """
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError as exc:
        raise ScenarioError(f"cannot read scenario file {path}: {exc}") from exc
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml  # host package (pre-existing); never a product dep
        except ImportError as exc:
            raise ScenarioError(
                f"scenario {path} is YAML but PyYAML is not importable on this "
                f"host — install PyYAML or provide the scenario as .json") from exc
        try:
            raw = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ScenarioError(f"scenario {path}: YAML parse error: {exc}") from exc
    else:
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ScenarioError(f"scenario {path}: JSON parse error: {exc}") from exc
    return validate_scenario(raw, name=os.path.basename(path))


def validate_scenario(raw: Any, name: str = "<scenario>") -> dict:
    """Structural + referential validation (design §8.2 sketch + verify lints)."""
    sc = _require_type(raw, dict, name, "top level")

    unknown = sorted(set(sc) - set(TOP_LEVEL_KEYS))
    if unknown:
        raise _err(name, f"unknown top-level key(s) {unknown} — allowed: "
                         f"{list(TOP_LEVEL_KEYS)} (typos here would silently "
                         f"weaken ground truth, so they are fatal)")
    missing = [k for k in REQUIRED_TOP_LEVEL if k not in sc]
    if missing:
        raise _err(name, f"missing required top-level key(s) {missing}")

    if sc["twin"] != 1:
        raise _err(name, f"'twin' must be the integer 1 (DSL schema version), "
                         f"got {sc['twin']!r}")

    meta = _require_type(sc["meta"], dict, f"{name}.meta", "meta")
    for k in ("name", "seed"):
        if k not in meta:
            raise _err(f"{name}.meta", f"missing required key '{k}'")
    if not isinstance(meta["seed"], int) or isinstance(meta["seed"], bool):
        raise _err(f"{name}.meta.seed", f"seed must be an integer, got "
                                        f"{meta['seed']!r}")

    # tenants
    tenants = _require_type(sc["tenants"], list, f"{name}.tenants", "tenants")
    if not tenants:
        raise _err(f"{name}.tenants", "at least one tenant is required")
    aliases: set[str] = set()
    for i, t in enumerate(tenants):
        p = f"{name}.tenants[{i}]"
        _require_type(t, dict, p, "tenant entry")
        alias = t.get("alias")
        if not alias or not isinstance(alias, str):
            raise _err(p, "tenant requires a non-empty string 'alias'")
        if alias in aliases:
            raise _err(p, f"duplicate tenant alias {alias!r}")
        aliases.add(alias)
        bad = sorted(set(t) - {"alias", "org", "partition_pin"})
        if bad:
            raise _err(p, f"unknown tenant key(s) {bad}")

    # sites (optional, id'd)
    site_ids: set[str] = set()
    for i, s in enumerate(sc.get("sites") or []):
        p = f"{name}.sites[{i}]"
        _require_type(s, dict, p, "site entry")
        sid = s.get("id")
        if not sid or not isinstance(sid, str):
            raise _err(p, "site requires a non-empty string 'id'")
        site_ids.add(sid)

    # devices
    devices = _require_type(sc["devices"], list, f"{name}.devices", "devices")
    if not devices:
        raise _err(f"{name}.devices", "at least one device is required")
    dev_names: set[str] = set()
    dev_by_name: dict[str, dict] = {}
    for i, d in enumerate(devices):
        p = f"{name}.devices[{i}]"
        _require_type(d, dict, p, "device entry")
        for k in ("name", "tenant", "role", "interfaces"):
            if k not in d:
                raise _err(p, f"device missing required key '{k}'")
        dn = d["name"]
        if not dn or not isinstance(dn, str):
            raise _err(p, "device 'name' must be a non-empty string")
        if dn in dev_names:
            raise _err(p, f"duplicate device name {dn!r}")
        dev_names.add(dn)
        dev_by_name[dn] = d
        if d["tenant"] not in aliases:
            raise _err(p, f"device {dn!r} references unknown tenant "
                          f"{d['tenant']!r} — declared: {sorted(aliases)}")
        if d["role"] not in DEVICE_ROLES:
            raise _err(p, f"device {dn!r} role {d['role']!r} invalid — one of "
                          f"{list(DEVICE_ROLES)}")
        if d.get("site") and d["site"] not in site_ids:
            raise _err(p, f"device {dn!r} references unknown site "
                          f"{d['site']!r} — declared: {sorted(site_ids)}")
        ifaces = _require_type(d["interfaces"], list, f"{p}.interfaces",
                               "interfaces")
        for j, itf in enumerate(ifaces):
            _require_type(itf, dict, f"{p}.interfaces[{j}]", "interface")
            if not itf.get("name"):
                raise _err(f"{p}.interfaces[{j}]", "interface requires 'name'")
        for j, nb in enumerate(d.get("bgp_neighbors") or []):
            _require_type(nb, dict, f"{p}.bgp_neighbors[{j}]", "bgp neighbor")
            if not nb.get("peer_ip"):
                raise _err(f"{p}.bgp_neighbors[{j}]",
                           "bgp neighbor requires 'peer_ip'")
            pd = nb.get("peer_device")
            if pd and pd not in dev_names and pd not in {x.get("name")
                                                        for x in devices
                                                        if isinstance(x, dict)}:
                raise _err(f"{p}.bgp_neighbors[{j}]",
                           f"peer_device {pd!r} is not a declared device")

    # links: each end "device:ifname" must resolve
    for i, ln in enumerate(sc.get("links") or []):
        p = f"{name}.links[{i}]"
        _require_type(ln, dict, p, "link entry")
        for end in ("a", "b"):
            ref = ln.get(end)
            if not ref or not isinstance(ref, str) or ":" not in ref:
                raise _err(p, f"link end '{end}' must be 'device:ifname', got "
                              f"{ref!r}")
            dev, ifname = ref.split(":", 1)
            d = dev_by_name.get(dev)
            if d is None:
                raise _err(p, f"link end {ref!r} references unknown device "
                              f"{dev!r}")
            if ifname not in {itf.get("name") for itf in d["interfaces"]}:
                raise _err(p, f"link end {ref!r}: device {dev!r} has no "
                              f"interface {ifname!r}")

    # seams
    seam_ids: set[str] = set()
    seam_by_id: dict[str, dict] = {}
    for i, sm in enumerate(sc.get("seams") or []):
        p = f"{name}.seams[{i}]"
        _require_type(sm, dict, p, "seam entry")
        for k in ("seam_id", "seam_type"):
            if k not in sm:
                raise _err(p, f"seam missing required key '{k}'")
        if sm["seam_type"] not in SEAM_TYPES:
            raise _err(p, f"seam {sm['seam_id']!r} type {sm['seam_type']!r} "
                          f"invalid — the five FINAL types are "
                          f"{list(SEAM_TYPES)} (docs/design/cloud-ingestion.md "
                          f"§4.0; LAN is a domain, not a seam)")
        if sm["seam_id"] in seam_ids:
            raise _err(p, f"duplicate seam_id {sm['seam_id']!r}")
        seam_ids.add(sm["seam_id"])
        seam_by_id[sm["seam_id"]] = sm
        if sm.get("tenant") and sm["tenant"] not in aliases:
            raise _err(p, f"seam {sm['seam_id']!r} references unknown tenant "
                          f"{sm['tenant']!r}")
        for j, mb in enumerate(sm.get("members") or []):
            _require_type(mb, dict, f"{p}.members[{j}]", "seam member")
            if mb.get("member_id") not in dev_names:
                raise _err(f"{p}.members[{j}]",
                           f"seam member {mb.get('member_id')!r} is not a "
                           f"declared device")

    # device seam memberships reference declared seams
    for d in devices:
        for j, ref in enumerate(d.get("seams") or []):
            p = f"{name}.devices[{d['name']}].seams[{j}]"
            _require_type(ref, dict, p, "seam membership")
            if ref.get("seam_id") not in seam_ids:
                raise _err(p, f"device {d['name']!r} references unknown seam "
                              f"{ref.get('seam_id')!r}")

    # baseline
    baseline = _require_type(sc["baseline"], dict, f"{name}.baseline",
                             "baseline")
    bad = sorted(set(baseline) - {"syslog", "flows", "metrics", "probes"})
    if bad:
        raise _err(f"{name}.baseline", f"unknown baseline key(s) {bad}")
    for i, pr in enumerate(baseline.get("probes") or []):
        p = f"{name}.baseline.probes[{i}]"
        _require_type(pr, dict, p, "probe entry")
        if pr.get("target") not in dev_names:
            raise _err(p, f"probe target {pr.get('target')!r} is not a "
                          f"declared device")

    # stories
    stories = sc.get("stories") or []
    _require_type(stories, list, f"{name}.stories", "stories")
    story_ids: set[str] = set()
    for i, st in enumerate(stories):
        p = f"{name}.stories[{i}]"
        _require_type(st, dict, p, "story entry")
        unknown = sorted(set(st) - set(STORY_KEYS))
        if unknown:
            raise _err(p, f"unknown story key(s) {unknown} — allowed: "
                          f"{list(STORY_KEYS)}")
        missing = [k for k in REQUIRED_STORY_KEYS if k not in st]
        if missing:
            raise _err(p, f"story missing required key(s) {missing}")
        sid = st["id"]
        if sid in story_ids:
            raise _err(p, f"duplicate story id {sid!r}")
        story_ids.add(sid)

        tpl = st["template"]
        spec = STORY_TEMPLATES.get(tpl)
        if spec is None:
            raise _err(p, f"story {sid!r} template {tpl!r} unknown — one of "
                          f"{sorted(STORY_TEMPLATES)} (design §5.1–§5.10)")
        needs = spec["lanes"] - T1_CORE_LANES
        if needs:
            raise _err(p, f"story {sid!r} template {tpl!r} requires lane(s) "
                          f"{sorted(needs)} which are OUT of T1-core scope "
                          f"(SNMP/traps/IPFIX/gNMI are a later wave) — remove "
                          f"the story or wait for that wave")

        trig = _require_type(st["trigger"], dict, f"{p}.trigger", "trigger")
        bad = sorted(set(trig) - {"at"})
        if bad:
            raise _err(f"{p}.trigger", f"unknown trigger key(s) {bad} — T1 "
                                       f"supports only 'at' (offset like "
                                       f"'+300s')")
        parse_offset_s(trig.get("at"), f"{p}.trigger.at")

        aff = _require_type(st["affected"], dict, f"{p}.affected", "affected")
        bad = sorted(set(aff) - {"seam", "devices", "tenants"})
        if bad:
            raise _err(f"{p}.affected", f"unknown affected key(s) {bad}")
        for dn in aff.get("devices") or []:
            if dn not in dev_names:
                raise _err(f"{p}.affected", f"story {sid!r} affects unknown "
                                            f"device {dn!r}")
        for tn in aff.get("tenants") or []:
            if tn not in aliases:
                raise _err(f"{p}.affected", f"story {sid!r} affects unknown "
                                            f"tenant {tn!r}")
        if aff.get("seam") and aff["seam"] not in seam_ids:
            raise _err(f"{p}.affected", f"story {sid!r} affects unknown seam "
                                        f"{aff['seam']!r}")

        params = st.get("params") or {}
        _require_type(params, dict, f"{p}.params", "params")
        bad = sorted(set(params) - spec["params"])
        if bad:
            raise _err(f"{p}.params", f"unknown param(s) {bad} for template "
                                      f"{tpl!r} — allowed: "
                                      f"{sorted(spec['params'])}")
        for key in ("cpu_device", "bgp_device", "probe_device"):
            if key in params and params[key] not in dev_names:
                raise _err(f"{p}.params", f"{key} {params[key]!r} is not a "
                                          f"declared device")

        exp = _require_type(st["expect"], dict, f"{p}.expect", "expect")
        bad = sorted(set(exp) - {"rca", "seam", "forbid"})
        if bad:
            raise _err(f"{p}.expect", f"unknown expect key(s) {bad}")
        rca = exp.get("rca") or {}
        bad = sorted(set(rca) - {"verdict_tier_at_least", "hypothesis_matches",
                                 "affected_includes", "single_incident"})
        if bad:
            raise _err(f"{p}.expect.rca", f"unknown rca clause(s) {bad}")
        vt = rca.get("verdict_tier_at_least")
        if vt is not None and vt not in ("suspected", "confirmed"):
            raise _err(f"{p}.expect.rca", f"verdict_tier_at_least must be "
                                          f"'suspected' or 'confirmed', got "
                                          f"{vt!r}")
        for dn in rca.get("affected_includes") or []:
            if dn not in dev_names:
                raise _err(f"{p}.expect.rca", f"affected_includes names "
                                              f"unknown device {dn!r}")
        seam_exp = exp.get("seam") or {}
        bad = sorted(set(seam_exp) - {"seam_id", "seam_type", "owner"})
        if bad:
            raise _err(f"{p}.expect.seam", f"unknown seam clause(s) {bad}")
        if seam_exp:
            sid_ref = seam_exp.get("seam_id")
            if sid_ref not in seam_ids:
                raise _err(f"{p}.expect.seam", f"seam_id {sid_ref!r} is not a "
                                               f"declared seam")
            want_type = seam_exp.get("seam_type")
            have_type = seam_by_id[sid_ref]["seam_type"]
            if want_type and want_type != have_type:
                raise _err(f"{p}.expect.seam",
                           f"expected seam_type {want_type!r} contradicts the "
                           f"declared type {have_type!r} of seam {sid_ref!r}")
        forbid = exp.get("forbid") or {}
        bad = sorted(set(forbid) - {"cross_tenant_merge", "confirmed"})
        if bad:
            raise _err(f"{p}.expect.forbid", f"unknown forbid clause(s) {bad}")

    return sc


def parse_offset_s(raw: Any, path: str) -> float:
    """'+300s' / '+5m' → seconds. Anything else is a hard error."""
    if not isinstance(raw, str) or not raw.startswith("+"):
        raise _err(path, f"trigger offset must look like '+300s' or '+5m', "
                         f"got {raw!r}")
    body = raw[1:]
    try:
        if body.endswith("s"):
            return float(body[:-1])
        if body.endswith("m"):
            return float(body[:-1]) * 60.0
    except ValueError:
        pass
    raise _err(path, f"trigger offset must look like '+300s' or '+5m', got "
                     f"{raw!r}")


def steady_eps(sc: dict) -> float:
    """Computed steady-state EPS of the T1-core lanes (syslog chatter +
    baseline probes). Flow/metric baselines are later-wave lanes and add 0
    here (they are refused at emit time anyway)."""
    base = sc.get("baseline") or {}
    syslog = base.get("syslog") or {}
    eps = float(syslog.get("per_device_eps") or 0.0) * len(sc["devices"])
    for pr in base.get("probes") or []:
        iv = float(pr.get("interval_s") or 30.0)
        if iv > 0:
            eps += 1.0 / iv
    return eps


def check_budget(sc: dict, force: bool = False) -> str:
    """Refuse scenarios whose steady EPS exceeds the T1 budget (design §9.1)
    unless forced. Returns a human summary line either way."""
    eps = steady_eps(sc)
    line = (f"steady-state budget: {eps:.2f} EPS computed vs "
            f"{T1_STEADY_EPS_BUDGET:.0f} EPS T1 budget")
    if eps > T1_STEADY_EPS_BUDGET and not force:
        raise ScenarioError(
            f"{line} — over budget; shrink per_device_eps/devices or pass "
            f"--force (design §9.1: the twin must not squeeze the stack "
            f"it measures)")
    return line
