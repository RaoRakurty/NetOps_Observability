"""Single-contract ownership: the gnmic gate and the SNMP profiles must mirror.

A canonical `device_*` family is served by exactly ONE transport per device.
Two tables decide that, in two languages, in two files:

  * `deployment/docker/gnmic/gnmic.yaml` — the `ownership-gate` processor, a
    GLOBAL delete list: a family named there never leaves the gNMI canonical
    lane, on any device;
  * `src/backend/collectors/profiles.go` — `SNMPMetric.Owner`, applied PER
    DEVICE (`ownedElsewhere` yields only where the device carries the label
    `gnmi: "true"`).

Neither file can see the other, so the two drift silently, and both failure
modes are invisible in review:

  * BOTH yield  → a gNMI-only device gets the family from nobody. This is
    tracker 230 exactly: the gate deleted `device_if_*` / `device_cpu_percent` /
    `device_temp_celsius` unconditionally while SNMP withheld them on
    gNMI-capable devices, so the SR Linux spines — which answer no SNMP at all —
    had no interface, CPU or temperature series from either transport, and the
    stack reported itself healthy the whole time.
  * BOTH emit    → the same canonical series is produced twice, from two
    transports, with different label shapes.

So the invariant is bidirectional, and it is checked here against the real files
rather than against a copy of them:

    family gated by gnmic   <=>  family SNMP-owned in EVERY profile defining it
    family NOT gated        <=>  family Owner "gnmi" in EVERY profile defining it

Run:  python3 -m pytest tests/test_gnmi_ownership_contract.py -v
"""
import os
import re

import yaml

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
GNMIC_DIR = os.path.join(ROOT, "deployment", "docker", "gnmic")
BASE_CFG = os.path.join(GNMIC_DIR, "gnmic.yaml")
CORR_CFG = os.path.join(GNMIC_DIR, "gnmic-correlation.yaml")
PROFILES_GO = os.path.join(ROOT, "src", "backend", "collectors", "profiles.go")

# Families gnmic maps that have no SNMP definition anywhere in the catalog.
# They are gNMI-only by construction (no OID exists / none is in the profiles),
# so "every profile defining it agrees" is vacuously true and the emptiness is
# the point — asserted explicitly below so a new SNMP definition of one of them
# cannot appear without this list being revisited.
GNMI_EXCLUSIVE = {
    "device_bgp_pfx_in",
    "device_isis_adj_state",
    "device_isis_lsp_count",
    "device_isis_spf_runs_total",
    "device_isis_area",
    "device_isis_adj_hold_seconds",
}


def load(path: str) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)


def gnmic_canonical_families(cfg: dict) -> set[str]:
    """Every canonical `device_*` name the canon-names rename table produces.

    This is the set of families the gNMI lane can put on the wire: `drop-unmapped`
    removes anything canon-names did not rename, so a family absent from here is
    one gNMI structurally cannot emit.
    """
    names = set()
    for tf in cfg["processors"]["canon-names"]["event-strings"]["transforms"]:
        new = tf.get("replace", {}).get("new", "")
        if new.startswith("device_"):
            names.add(new)
    assert names, "canon-names produced no canonical families — the table's shape changed"
    return names


def gate_patterns(cfg: dict) -> list[str]:
    gate = cfg["processors"]["ownership-gate"]["event-delete"]
    # An absent key and an empty list both mean "delete nothing"; normalize.
    return list(gate.get("value-names") or [])


def gated_families(cfg: dict) -> set[str]:
    """Which canonical families the ownership gate actually deletes.

    The patterns are regexes (`^device_if_.*$`), so this applies them rather than
    comparing strings — a gate written as a wildcard must be resolved against the
    real family list or the mirror is only checked for the names spelled out.
    """
    pats = [re.compile(p) for p in gate_patterns(cfg)]
    return {f for f in gnmic_canonical_families(cfg)
            if any(p.search(f) for p in pats)}


def snmp_owners() -> dict[str, dict[str, str]]:
    """{metric: {profile: owner}} parsed out of builtinProfiles().

    Reads the Go source, not a transcription of it: the mirror is only worth
    something if it cannot go stale. `owner` is normalized to "snmp" for the
    empty/absent default.
    """
    src = open(PROFILES_GO).read()
    block = re.search(r"func builtinProfiles\(\) \[\]SNMPProfile \{(.*?)\n\}\n",
                      src, re.DOTALL)
    assert block, "builtinProfiles() not found in profiles.go"
    body = block.group(1)

    out: dict[str, dict[str, str]] = {}
    profile = None
    for line in body.split("\n"):
        m = re.search(r'Name:\s+"([a-z0-9]+)",\s*$', line)
        if m:
            profile = m.group(1)
            continue
        m = re.search(r'\{Name: "(device_[a-z0-9_]+)",\s*OID:(.*)$', line)
        if not m:
            continue
        metric, rest = m.group(1), m.group(2)
        owner = re.search(r'Owner:\s*"([a-z]*)"', rest)
        assert profile, f"metric {metric} parsed before any profile name"
        out.setdefault(metric, {})[profile] = (owner.group(1) if owner else "") or "snmp"
    assert out, "no metrics parsed out of builtinProfiles() — the literal's shape changed"
    return out


# ── the invariant ─────────────────────────────────────────────────────────────

def test_gated_families_are_snmp_owned_everywhere():
    """gate deletes it  ⇒  SNMP must actually emit it, on every profile.

    A family withheld on the gNMI side and ALSO carrying Owner "gnmi" on the SNMP
    side is emitted by nobody on a device that has both transports.
    """
    cfg = load(BASE_CFG)
    owners = snmp_owners()
    for fam in sorted(gated_families(cfg)):
        by_profile = owners.get(fam, {})
        assert by_profile, (
            f"{fam} is withheld by the gnmic ownership gate but no SNMP profile "
            "defines it — the family is emitted by NEITHER transport")
        for profile, owner in sorted(by_profile.items()):
            assert owner == "snmp", (
                f"{fam} is withheld by the gnmic ownership gate AND marked "
                f"Owner {owner!r} in the {profile} profile: on a gNMI-capable "
                "device both transports yield and the family is lost (tracker 230)")


def test_ungated_families_are_gnmi_owned_everywhere():
    """gate does NOT delete it  ⇒  every SNMP definition must yield to gNMI.

    Otherwise the same canonical series is produced twice on a dual-transport
    device, from two label shapes.
    """
    cfg = load(BASE_CFG)
    owners = snmp_owners()
    gated = gated_families(cfg)
    for fam in sorted(gnmic_canonical_families(cfg) - gated):
        for profile, owner in sorted(owners.get(fam, {}).items()):
            assert owner == "gnmi", (
                f"{fam} leaves the gNMI canonical lane (not in the ownership "
                f"gate) but the {profile} SNMP profile still owns it "
                f"(Owner {owner!r}) — a device with both transports double-emits it")


def test_gnmi_exclusive_families_have_no_snmp_definition():
    """The list above claims these families have no SNMP source. Prove it.

    If one gains an OID, it stops being vacuously consistent and has to be
    reasoned about like the rest.
    """
    owners = snmp_owners()
    for fam in sorted(GNMI_EXCLUSIVE):
        assert fam not in owners, (
            f"{fam} now has an SNMP definition ({sorted(owners[fam])}) — it is no "
            "longer gNMI-exclusive; remove it from GNMI_EXCLUSIVE and give it an "
            "explicit ownership decision on both sides")


def test_gnmi_exclusive_list_is_exactly_the_families_with_no_snmp_source():
    """And the converse: no family may quietly join the exclusive set."""
    cfg = load(BASE_CFG)
    owners = snmp_owners()
    actual = {f for f in gnmic_canonical_families(cfg) if f not in owners}
    assert actual == GNMI_EXCLUSIVE, (
        "the set of canonical gNMI families with no SNMP counterpart changed.\n"
        f"  newly exclusive: {sorted(actual - GNMI_EXCLUSIVE)}\n"
        f"  no longer exclusive: {sorted(GNMI_EXCLUSIVE - actual)}")


def test_the_two_gnmic_configs_carry_the_same_gate():
    """The correlation overlay runs the same chain; a gate that differed between
    them would put a family on the BUS that the metrics lane withholds."""
    assert gate_patterns(load(BASE_CFG)) == gate_patterns(load(CORR_CFG)), \
        "gnmic.yaml and gnmic-correlation.yaml disagree on the ownership gate"


def test_the_gate_is_still_wired_into_every_canonical_chain():
    """The gate is the ONLY mechanism for handing a family back to SNMP. It is
    empty today, which is exactly when it is most likely to be deleted as dead
    config — and then a future hand-back silently does nothing."""
    for path in (BASE_CFG, CORR_CFG):
        cfg = load(path)
        assert "ownership-gate" in cfg["processors"], \
            f"{os.path.basename(path)}: the ownership-gate processor was removed"
        for name, out in cfg["outputs"].items():
            chain = out.get("event-processors")
            if not chain or "canon-names" not in chain:
                continue  # the raw lane runs no canonical chain
            assert "ownership-gate" in chain, (
                f"{os.path.basename(path)}: output {name!r} runs the canonical "
                "chain without the ownership gate")


# ── tracker 230: the specific families that were lost ─────────────────────────

def test_the_families_tracker_230_lost_are_gnmi_owned():
    """A regression pin, not a restatement of the invariant above.

    These three families were deleted unconditionally by the gate while the SNMP
    side yielded per device, so a gNMI-only device (an SR Linux spine) got them
    from neither transport. The invariant tests would stay green if someone
    "fixed" that by putting them back in the gate AND removing their Owner — a
    consistent state that is nonetheless the bug, because the spines answer no
    SNMP. Pin the direction the decision went.
    """
    cfg = load(BASE_CFG)
    gated = gated_families(cfg)
    owners = snmp_owners()
    for fam in ("device_if_oper_status", "device_if_admin_status",
                "device_if_in_octets", "device_if_out_octets",
                "device_cpu_percent", "device_temp_celsius"):
        assert fam in gnmic_canonical_families(cfg), \
            f"{fam} is no longer mapped by gnmic canon-names"
        assert fam not in gated, (
            f"{fam} is withheld from the gNMI lane again — a gNMI-only device "
            "(SR Linux spine, no SNMP agent) gets it from nobody (tracker 230)")
        assert owners.get(fam), f"{fam} vanished from the SNMP catalog"
        assert set(owners[fam].values()) == {"gnmi"}, \
            f"{fam} is not gNMI-owned in every SNMP profile: {owners[fam]}"


def test_interface_families_gnmi_cannot_supply_stay_snmp_owned():
    """gNMI's interface coverage is a strict SUBSET of SNMP's. The families it
    does not map must keep NO Owner, or a gNMI-capable device loses them
    outright — the same bug as 230, one level down."""
    cfg = load(BASE_CFG)
    mapped = gnmic_canonical_families(cfg)
    owners = snmp_owners()
    for fam in ("device_if_speed", "device_if_last_change", "device_if_fcs_errors",
                "device_sensor_value", "device_sysuptime"):
        assert fam not in mapped, (
            f"{fam} is now mapped by gnmic — it may be flippable; revisit both "
            "sides deliberately instead of leaving this guard stale")
        assert owners.get(fam), f"{fam} vanished from the SNMP catalog"
        assert set(owners[fam].values()) == {"snmp"}, (
            f"{fam} has a non-SNMP Owner ({owners[fam]}) but gNMI has no source "
            "for it — a gNMI-capable device would get it from nobody")


# ── the operator contract: the label asserts subscription coverage ────────────

# gnmic target → the SNMP profiles selectProfiles() would apply to that device
# (the generic floor always, plus the vendor profile matching its sysObjectID
# enterprise). Nokia SR Linux has no vendor profile; Arista's is registered but
# empty. This is what decides what a target LOSES by being labelled gNMI-capable:
# only families some applicable SNMP profile was actually emitting.
VENDOR_SNMP_PROFILES = {"nokia": {"generic"}, "arista": {"generic", "arista"}}

# The vendor each subscription belongs to, taken from the vendor-tag processors
# so the two cannot disagree (a subscription missing from vendor-arista/-nokia
# produces series with no vendor label, which is its own bug).
def subscription_vendors(cfg: dict) -> dict[str, str]:
    out = {}
    for proc, vendor in (("vendor-nokia", "nokia"), ("vendor-arista", "arista")):
        pats = cfg["processors"][proc]["event-add-tag"]["tags"]
        assert cfg["processors"][proc]["event-add-tag"]["add"]["vendor"] == vendor
        for name in cfg["subscriptions"]:
            if any(re.fullmatch(p.strip("^$"), name) for p in pats):
                out[name] = vendor
    return out


def path_covers(path: str, pattern: str) -> bool:
    """Would a subscription on `path` produce a value name matching `pattern`?

    canon-names patterns are `.*<suffix>$`, matched against the FLATTENED value
    name gnmic builds from the update path. A subscription may name a container
    (`/interface[name=*]/statistics`) whose leaves sit below it, or a leaf whose
    ancestors sit above it, so alignment is checked in both directions: some
    tail of the subscribed path must be a prefix of the pattern's suffix.
    """
    suffix = pattern[2:-1] if pattern.startswith(".*") and pattern.endswith("$") else None
    if suffix is None:
        return False
    parts = [seg for seg in re.sub(r"\[[^\]]*\]", "", path).split("/") if seg]
    for k in range(len(parts)):
        tail = "/".join(parts[k:])
        if suffix == tail or suffix.startswith(tail + "/"):
            return True
    return suffix.endswith("/" + "/".join(parts)) or suffix == "/".join(parts)


def test_every_subscription_carries_a_vendor_tag():
    """A subscription absent from vendor-nokia/vendor-arista emits series with
    no `vendor` label — the canonical contract requires one, and the coverage
    check below silently skips whatever it cannot attribute."""
    cfg = load(BASE_CFG)
    vendors = subscription_vendors(cfg)
    missing = sorted(set(cfg["subscriptions"]) - set(vendors))
    assert not missing, (
        f"subscriptions {missing} are tagged by neither vendor-nokia nor "
        "vendor-arista — their series reach VictoriaMetrics with no vendor label")


def test_every_gnmi_owned_family_is_subscribed_on_every_target():
    """Labelling a device `gnmi: "true"` STOPS the SNMP poller emitting the
    gNMI-owned families for it, so every gnmic target must actually subscribe to
    paths that produce them — otherwise the label costs the device a series and
    gives nothing back. That is tracker 230 in the other direction, and it is
    the failure the per-family invariants above cannot see: they compare two
    tables, this compares a table against the paths on the wire.

    Scoped per target to the families the SNMP profiles for THAT vendor were
    actually emitting. An Arista device loses nothing by not streaming
    temperature — no SNMP profile that applies to it defines device_temp_celsius.
    """
    cfg = load(BASE_CFG)
    owners = snmp_owners()
    gated = gated_families(cfg)
    vendors = subscription_vendors(cfg)
    renames = [(tf["replace"]["old"], tf["replace"]["new"])
               for tf in cfg["processors"]["canon-names"]["event-strings"]["transforms"]
               if "replace" in tf and tf["replace"].get("apply-on") == "name"]

    for addr, tgt in sorted(cfg["targets"].items()):
        subs = tgt["subscriptions"]
        tgt_vendors = {vendors[s] for s in subs if s in vendors}
        assert len(tgt_vendors) == 1, (
            f"target {tgt.get('name', addr)} mixes vendors across its "
            f"subscriptions ({sorted(tgt_vendors)}) — the vendor tag is ambiguous")
        vendor = tgt_vendors.pop()
        profiles = VENDOR_SNMP_PROFILES[vendor]

        # What SNMP was emitting for this device and has now stopped emitting.
        must_cover = {
            fam for fam in gnmic_canonical_families(cfg) - gated
            if any(p in profiles for p in owners.get(fam, {}))
        }
        covered = {
            new for pattern, new in renames
            for s in subs for path in cfg["subscriptions"][s]["paths"]
            if path_covers(path, pattern)
        }
        missing = sorted(must_cover - covered)
        assert not missing, (
            f"target {tgt.get('name', addr)} ({vendor}) subscribes to no path "
            f"producing {missing}, but those families are gNMI-owned and the "
            f"{sorted(profiles)} SNMP profile(s) define them: labelling this "
            "device gNMI-capable loses the series outright")
