# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Every vendor's wire frame, through the real edge (tracker 387, PR 10).

Raw bytes go into the shipped syslog-ng config, through the shipped Vector transforms
and into the engine's real classifier, and every assertion is on a VALUE: the fields'
presence is what let a lane sit at 100% `notice` unnoticed.

The frames are the documented literals of `docs/design/research/VENDOR_PACK_SOURCES_2026-11-09.md`
§9 and the 2026-11-09 lab capture (scrubbed). Only Cisco SD-WAN has been seen on the wire;
the rest prove the ENVELOPE of a documented shape, and say nothing about body grammars.

The docker legs skip loudly without docker, as the other Vector suites do.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import syslog_edge_harness as H

ROOT = Path(__file__).resolve().parent.parent
SYSLOG_NG = ROOT / "deployment" / "docker" / "syslog-ng"
VECTOR_YAML = ROOT / "deployment" / "docker" / "vector" / "vector.yaml"
ROUTER_YAML = ROOT / "deployment" / "docker" / "vector-router" / "vector.yaml"
CATALOG = ROOT / "telemetry-catalog"
CORRELATION = ROOT / "src" / "correlation"
LOG_MSG_SIZE = 32768

SENDER = "<the sender's address>"  # the container's own address, known only at run time
_SKIP = ("docker is unavailable, so the edge suite DID NOT RUN against the shipped "
         "syslog-ng config. Run it before shipping.")


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=30,
                              check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@pytest.fixture(scope="module")
def edge() -> Iterator[H.Edge]:
    if not _docker_available():
        pytest.skip(_SKIP)
    with H.running_edge(SYSLOG_NG, VECTOR_YAML,
                        registry=[("vEdge-1", "lab"), ("router1", "lab")]) as running:
        yield running


# ── the engine's real answer, in its own process (its modules import flat) ───────

_ENGINE_PROBE = textwrap.dedent("""\
    import json, sys
    from datetime import datetime, timezone
    import producers as P
    now = datetime(2026, 11, 9, 10, 0, tzinfo=timezone.utc)
    out = []
    for ev in json.load(sys.stdin):
        sig = P.syslog_control_signal(dict(ev), "t1", now) or P.port_event_signal(dict(ev), "t1", now)
        out.append({
            "promotable": P.syslog_promotable(dict(ev)),
            "kind": sig.kind if sig else None,
            "severity": sig.severity.value if sig else None,
            "entity": sig.entity_id if sig else None,
        })
    json.dump(out, sys.stdout)
""")


def engine(docs: list[dict]) -> list[dict]:
    proc = subprocess.run(
        [sys.executable, "-c", _ENGINE_PROBE], input=json.dumps(docs),
        capture_output=True, text=True, check=False, timeout=120,
        env={"PYTHONPATH": str(CORRELATION), "PATH": "/usr/bin:/bin"})
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def opens_alone(answer: dict) -> bool:
    """The stage [5] singleton rule: `severity_open_floor` is `high`."""
    return answer["severity"] in ("high", "crit")


# ── every vendor's frame ─────────────────────────────────────────────────────────

VEDGE_ERR = (b"<187>1 2026-11-09T09:00:00.123Z vEdge-1 FTMD 3875 - - "
             b"%Viptela-vEdge-1-FTMD-3-ERRO-1000002: control connection went away")
VEDGE_CRIT = (b"<186>1 2026-11-09T09:00:00.123-06:00 vEdge-1 SYSMGR 913 - - "
              b"%Viptela-vEdge-1-SYSMGR-2-CRIT-200069: System cpu usage is above 90% (critically high)")
SSHD_KEX = (b"<35>1 2026-11-09T09:00:00.123Z vEdge-1 sshd 27761 - - "
            b"error: kex_exchange_identification: Connection closed by remote host")
CEDGE = (b"<189>25165: Nov  9 09:00:00.123: %DMI-5-AUTH_PASSED: R0/0: dmiauthd: "
         b"User svc-user authenticated successfully from 192.0.2.1:50000")
JUNOS_SD = (b'<165>1 2007-02-15T09:17:15.719Z router1 mgd 3046 UI_DBASE_LOGOUT_EVENT '
            b'[junos@2636.1.1.1.2.18 username="regress"] User \'regress\' exiting configuration mode')
JUNOS_STD = (b"<28>Apr  7 07:32:34 Branch1 rpd[2310]: RPD_BGP_NEIGHBOR_STATE_CHANGED: "
             b"BGP peer 10.1.1.1 (External AS 1111) changed state from Established to Idle")
ASA = (b"<166>:2018-06-27T12:17:46Z: %ASA-6-110002: Failed to locate egress interface")
ASA_PLAIN = (b"<166>2018-06-27T12:17:46Z asa : %ASA-6-110002: Failed to locate egress interface")
NXOS = (b"<190>sw01.pdx01: 2017 Jul 28 14:42:46 UTC: %AUTHPRIV-6-SYSTEM_MSG: "
        b"pam_unix(dcos_sshd:session): session opened for user luke by (uid=0) - dcos_sshd[12977]")
IOSXR = (b"<187>94307: gw2.acy1 LC/0/2/CPU0:Jul  7 20:16:14.834 : ifmgr[214]: "
         b"%PKT_INFRA-LINK-3-UPDOWN : Interface TenGigE0/2/0/4, changed state to Down")
EOS = (b"<149>Apr 16 11:04:17 edge01 Rib: %BGP-3-NOTIFICATION: received from neighbor "
       b"194.53.172.97 (AS 2611) 6/1 (Cease/maximum number of prefixes reached) 0 bytes")
SROS = (b"<188>Jan  2 18:43:23 10.221.38.108 TMNX: 17 Base "
        b"SYSTEM-WARNING-tmnxStateChange-2009 [subject]: Status of Card 1 changed")
SONIC = (b"<30>2026-11-09T09:00:00.123456+00:00 sonic-1 INFO bgp#bgpd[123]: neighbor 10.0.0.1 Down")
SONIC_ERR = (b"<27>2026-11-09T09:00:00.123456+00:00 sonic-1 ERR syncd#syncd: SAI_API_PORT failed")
FORTI = (b"<189>date=2026-11-09 time=09:00:00 devname=fw01 devid=FGT60E logid=0000000013 "
         b"type=traffic subtype=forward level=notice srcip=10.0.0.1 dstip=10.0.0.2 action=accept")

#: name, frame, the fields it must arrive with.
FRAMES = [
    ("vEdge err", VEDGE_ERR, {
        "frame_format": "rfc5424", "hostname": "vEdge-1", "appname": "FTMD", "procid": 3875,
        "severity": "err", "syslog_facility": "local7", "timestamp": "2026-11-09T09:00:00.123Z",
        "message": "%Viptela-vEdge-1-FTMD-3-ERRO-1000002: control connection went away",
        "parser_id": "cisco_sdwan.v1", "facility": "FTMD", "event_type": "ftmd_1000002",
        "tenant_id": "lab"}),
    ("vEdge crit, zone offset kept", VEDGE_CRIT, {
        "frame_format": "rfc5424", "hostname": "vEdge-1", "appname": "SYSMGR", "procid": 913,
        "severity": "crit", "syslog_facility": "local7", "timestamp": "2026-11-09T15:00:00.123Z",
        "normalized_severity": "critical", "parser_id": "cisco_sdwan.v1"}),
    ("vEdge sshd", SSHD_KEX, {
        "frame_format": "rfc5424", "hostname": "vEdge-1", "appname": "sshd", "procid": 27761,
        "severity": "err", "syslog_facility": "auth",
        "message": "error: kex_exchange_identification: Connection closed by remote host",
        "event_type": "ssh_banner_probe", "event_category": "management_audit"}),
    ("cEdge, no hostname and the mnemonic survives", CEDGE, {
        "frame_format": "rfc3164", "hostname": SENDER, "appname": "unknown",
        "severity": "notice", "syslog_facility": "local7",
        "timestamp": "2026-11-09T09:00:00.123Z",
        "message": "%DMI-5-AUTH_PASSED: R0/0: dmiauthd: User svc-user authenticated "
                   "successfully from 192.0.2.1:50000",
        "structured_data": '[meta sequenceId="25165"]',
        "vendor": "cisco", "parser_id": "cisco_mgmt_audit.v1", "event_type": "dmi_auth_passed"}),
    ("Junos structured data", JUNOS_SD, {
        "frame_format": "rfc5424", "hostname": "router1", "appname": "mgd", "procid": 3046,
        "msgid": "UI_DBASE_LOGOUT_EVENT", "severity": "notice", "syslog_facility": "local4",
        "timestamp": "2007-02-15T09:17:15.719Z",
        "message": "User 'regress' exiting configuration mode",
        "structured_data": '[junos@2636.1.1.1.2.18 username="regress"]',
        "event_type": "ui_dbase_logout_event", "vendor": "juniper", "tenant_id": "lab"}),
    ("Junos standard", JUNOS_STD, {
        "frame_format": "rfc3164", "hostname": "Branch1", "appname": "rpd", "procid": 2310,
        "severity": "warning", "syslog_facility": "daemon",
        "message": "RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.1.1.1 (External AS 1111) "
                   "changed state from Established to Idle",
        "vendor": "juniper"}),
    ("ASA EMBLEM", ASA, {
        "frame_format": "rfc3164", "hostname": SENDER, "appname": "unknown",
        "severity": "info", "syslog_facility": "local4", "timestamp": "2018-06-27T12:17:46Z",
        "message": "%ASA-6-110002: Failed to locate egress interface",
        "parser_id": "ios_style.v1", "facility": "ASA", "event_type": "110002"}),
    ("ASA with a device id", ASA_PLAIN, {
        "frame_format": "rfc3164", "hostname": "asa", "appname": "unknown", "severity": "info",
        "message": "%ASA-6-110002: Failed to locate egress interface", "parser_id": "ios_style.v1"}),
    ("NX-OS", NXOS, {
        "frame_format": "rfc3164", "hostname": "sw01.pdx01", "appname": "unknown",
        "severity": "info", "syslog_facility": "local7",
        "message": "%AUTHPRIV-6-SYSTEM_MSG: pam_unix(dcos_sshd:session): session opened for "
                   "user luke by (uid=0) - dcos_sshd[12977]",
        "parser_id": "ios_style.v1", "facility": "AUTHPRIV", "event_type": "system_msg"}),
    ("IOS-XR", IOSXR, {
        "frame_format": "rfc3164", "hostname": "gw2.acy1", "appname": "ifmgr", "procid": 214,
        "severity": "err", "syslog_facility": "local7",
        "message": "%PKT_INFRA-LINK-3-UPDOWN : Interface TenGigE0/2/0/4, changed state to Down",
        # Still unparsed, and the body grammar is a later stream's (plan §6a).
        "parser_status": "unparsed"}),
    ("EOS", EOS, {
        "frame_format": "rfc3164", "hostname": "edge01", "appname": "Rib", "severity": "notice",
        "syslog_facility": "local2",
        "message": "%BGP-3-NOTIFICATION: received from neighbor 194.53.172.97 (AS 2611) 6/1 "
                   "(Cease/maximum number of prefixes reached) 0 bytes",
        "normalized_severity": "error", "parser_id": "ios_style.v1", "facility": "BGP",
        "event_type": "notification"}),
    ("SR OS", SROS, {
        "frame_format": "rfc3164", "hostname": "10.221.38.108", "appname": "TMNX",
        "severity": "warning", "syslog_facility": "local7",
        "message": "17 Base SYSTEM-WARNING-tmnxStateChange-2009 [subject]: Status of Card 1 changed",
        "parser_status": "unparsed"}),
    ("SONiC, the severity word is not the program", SONIC, {
        "frame_format": "rfc3164", "hostname": "sonic-1", "appname": "bgp#bgpd", "procid": 123,
        "severity": "info", "syslog_facility": "daemon", "timestamp": "2026-11-09T09:00:00.123Z",
        "message": "neighbor 10.0.0.1 Down"}),
    ("SONiC err, no pid", SONIC_ERR, {
        "frame_format": "rfc3164", "hostname": "sonic-1", "appname": "syncd#syncd",
        "severity": "err", "message": "SAI_API_PORT failed"}),
    # Our own senders. internal/pipedebug's probe must keep its marker in the message, and
    # the cloud lane's filter (`cloud=<provider> {`) reads the same field.
    ("the pipeline debugger's probe",
     b"<134>1 2026-11-09T09:00:00.000000Z spine1 correlix-debug - - - cx_debug=01HZZZZZZZZZZZZZZZZZZZZZZZ probe", {
         "frame_format": "rfc5424", "hostname": "spine1", "appname": "correlix-debug",
         "severity": "info", "syslog_facility": "local0",
         "message": "cx_debug=01HZZZZZZZZZZZZZZZZZZZZZZZ probe"}),
    ("a cloud lane line", b'<134>1 2026-11-09T09:00:00Z fw1 cloudd - - - cloud=aws {"event":"x"}', {
        "frame_format": "rfc5424", "hostname": "fw1", "appname": "cloudd",
        "message": 'cloud=aws {"event":"x"}'}),
    ("FortiGate key-value, no header", FORTI, {
        "frame_format": "no_header", "hostname": SENDER, "appname": "traffic/forward",
        "severity": "notice", "syslog_facility": "local7", "vendor": "fortinet",
        "message": "date=2026-11-09 time=09:00:00 devname=fw01 devid=FGT60E logid=0000000013 "
                   "type=traffic subtype=forward level=notice srcip=10.0.0.1 dstip=10.0.0.2 "
                   "action=accept"}),
]


@pytest.mark.parametrize("name,frame,want", FRAMES, ids=[f[0] for f in FRAMES])
def test_a_wire_frame_arrives_with_these_values(edge: H.Edge, name: str, frame: bytes, want: dict) -> None:
    doc = edge.send(frame)
    for key, value in want.items():
        expected = edge.sender_ip if value == SENDER else value
        assert doc.get(key) == expected, f"{name}: {key}={doc.get(key)!r}, wanted {expected!r}\n{doc}"
    # What every frame owes, whatever its vendor.
    assert doc["source_ip"] == edge.sender_ip, doc
    assert doc["message_original"] == frame.decode(), doc
    assert "frame_problem" not in doc, doc
    assert not doc["message"].startswith("﻿"), "the BOM is framing, not message text"


# ── what the engine makes of them ────────────────────────────────────────────────

#: frame, kind, severity. `None` is "no signal": the line stays a searchable log.
ENGINE_CASES = [
    ("vEdge crit opens through its typed row", VEDGE_CRIT, "device_resource_anomaly", "crit"),
    ("the SSH banner probe emits nothing at err", SSHD_KEX, None, None),
    ("a vEdge err stays below the floor", VEDGE_ERR, "device_alarm", "warn"),
    ("cEdge audit is not an alarm", CEDGE, None, None),
    ("EOS BGP notification types as it always did", EOS, "bgp_adjacency_change", "high"),
    ("IOS-XR link fault: no body grammar yet, so generic and below the floor",
     IOSXR, "device_alarm", "warn"),
    ("Junos warning is kept below the floor", JUNOS_STD, "device_alarm", "warn"),
    ("SONiC err is kept below the floor", SONIC_ERR, "device_alarm", "warn"),
    ("SONiC info is a log", SONIC, None, None),
    ("SR OS warning is kept below the floor", SROS, "device_alarm", "warn"),
    ("ASA info is a log", ASA, None, None),
    ("FortiGate notice is a log", FORTI, None, None),
]


@pytest.mark.parametrize("name,frame,kind,severity", ENGINE_CASES, ids=[c[0] for c in ENGINE_CASES])
def test_the_engine_reads_the_framed_line(edge: H.Edge, name: str, frame: bytes, kind: str | None,
                                          severity: str | None) -> None:
    got = engine([edge.send(frame)])[0]
    assert (got["kind"], got["severity"]) == (kind, severity), got


def test_a_tag_carried_only_in_msgid_reaches_the_field_the_rules_read(edge: H.Edge) -> None:
    """Junos structured data carries the tag in MSGID and nowhere else."""
    doc = edge.send(b'<189>1 2026-11-09T09:00:00.000Z router1 mgd 3046 UI_COMMIT '
                    b'[junos@2636.1.1.1.2.18 username="regress"] '
                    b"User 'regress' requested 'commit' operation")
    # The rule that reads it is a shadow row today (events.yaml, syslog.config.change),
    # so the event_type is the fact to pin: its guard reads this field or the message.
    assert doc["event_type"] == "ui_commit"
    assert "UI_COMMIT" not in doc["message"]


def test_the_prefilter_keeps_rejecting_what_it_rejected(edge: H.Edge) -> None:
    """`local` is a screen literal. If the PRI facility stayed in .facility, every line
    from a fleet on local7, Cisco's default, would pass the screen."""
    doc = edge.send(b"<190>Nov  9 09:00:01 r1 ntpd[1]: an ordinary informational line")
    assert doc["syslog_facility"] == "local7"
    assert "facility" not in doc, doc
    got = engine([doc])[0]
    assert got["promotable"] is False, got
    assert got["kind"] is None
    assert "cx_admission" not in doc, "the generated screen must agree with the engine's"


def test_the_other_pri_facility_words_would_not_widen_the_screen() -> None:
    """The engine's screen reads .facility, and of the PRI facility words only local* is
    a literal. Pinned so moving them out of .facility stays a fix for a known cause."""
    words = ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
             "authpriv", "ftp", "ntp", "security", "console", "solaris-cron"]
    docs = [{"hostname": "r1", "appname": "x", "severity": "info", "message": "m", "facility": w,
             "timestamp": "2026-11-09T10:00:00Z"} for w in words]
    assert [a["promotable"] for a in engine(docs)] == [False] * len(words)


# ── link state, in both directions (tracker 385, stage [5]) ─────────────────────
#
# Stage [5] opens on peak severity, and `_admin_change_only` (#155) filters on the same
# floor, so what moves a link line's severity moves what can open an object.

LINK_UP = "Interface GigabitEthernet1, changed state to up"
LINK_DOWN = "Interface GigabitEthernet1, changed state to down"
PROTO_DOWN = "Line protocol on Interface GigabitEthernet1, changed state to down"
ADMIN_DOWN = "Interface GigabitEthernet1, changed state to administratively down"
LINK_FRAMES = [
    # A real link fault: must open, as it did where the line was readable.
    ("fault, IOS no hostname", f"<187>25166: Nov  9 09:00:01.123: %LINK-3-UPDOWN: {LINK_DOWN}", "high"),
    ("fault, IOS zone word", f"<187>25166: Nov  9 09:00:01.123 UTC: %LINK-3-UPDOWN: {LINK_DOWN}", "high"),
    ("fault, IOS hostname", f"<187>Nov  9 09:00:01 r1 %LINK-3-UPDOWN: {LINK_DOWN}", "high"),
    ("fault, IOS logging origin-id", f"<187>34: r1: *Nov  9 09:00:01.123: %LINK-3-UPDOWN: {LINK_DOWN}", "high"),
    ("fault, tagged", f"<187>Nov  9 09:00:01 edge01 Ebra: %LINK-3-UPDOWN: {LINK_DOWN}", "high"),
    # EOS logs only the protocol line, so that line is the fault.
    ("fault, protocol line, EOS", f"<149>Nov  9 09:00:01 edge01 Ebra: %LINEPROTO-5-UPDOWN: {PROTO_DOWN}", "high"),
    # On IOS the same line follows both a fault and a shutdown, so alone it cannot open.
    ("protocol line, IOS no hostname", f"<189>25167: Nov  9 09:00:02.123: %LINEPROTO-5-UPDOWN: {PROTO_DOWN}", "warn"),
    ("protocol line, IOS hostname", f"<189>Nov  9 09:00:02 r1 %LINEPROTO-5-UPDOWN: {PROTO_DOWN}", "warn"),
    # Recovery: never opens.
    ("recovery, IOS no hostname", f"<189>25168: Nov  9 09:00:03.123: %LINK-3-UPDOWN: {LINK_UP}", "warn"),
    # An operator's shutdown: the line that says so must not open.
    ("admin, IOS no hostname", f"<189>25169: Nov  9 09:00:03.123: %LINK-5-CHANGED: {ADMIN_DOWN}", None),
    ("admin, IOS hostname", f"<189>Nov  9 09:00:03 r1 %LINK-5-CHANGED: {ADMIN_DOWN}", None),
    ("admin, IOS-XR", ("<189>94308: gw2.acy1 LC/0/2/CPU0:Jul  7 20:16:14.834 : ifmgr[214]: "
                       "%PKT_INFRA-LINK-5-CHANGED : Interface TenGigE0/2/0/4, changed state to Administratively Down"), None),
    ("admin, NX-OS", ("<189>sw01.pdx01: 2017 Jul 28 14:42:46 UTC: %ETHPORT-5-IF_DOWN_ADMIN_DOWN: "
                      "Interface Ethernet1/1 is down (Administratively down)"), None),
]


@pytest.mark.parametrize("name,line,severity", LINK_FRAMES, ids=[f[0] for f in LINK_FRAMES])
def test_a_link_line_opens_exactly_what_it_should(edge: H.Edge, name: str, line: str, severity: str | None) -> None:
    got = engine([edge.send(line.encode())])[0]
    assert got["severity"] == severity, f"{name}: {got}"
    if severity is not None:
        assert got["kind"] == "link_state_change", got


def test_a_junos_admin_link_down_cannot_open_an_object(edge: H.Edge) -> None:
    doc = edge.send(b"<28>Nov  9 09:00:01 r1 mib2d[1]: SNMP_TRAP_LINK_DOWN: ifIndex 1, "
                    b"ifAdminStatus down(2), ifOperStatus down(2), ifName ge-0/0/0")
    got = engine([doc])[0]
    assert (got["kind"], got["severity"]) == ("device_alarm", "warn"), got
    assert not opens_alone(got)


_STAGE5_PROBE = textwrap.dedent("""\
    import json, sys
    from datetime import datetime, timezone
    import catalog, engine, producers as P
    now = datetime(2026, 11, 9, 10, 0, tzinfo=timezone.utc)
    sigs = [s for s in (P.syslog_control_signal({**d, "timestamp": "2026-11-09T09:59:00Z"}, "t1", now)
                        for d in json.load(sys.stdin)) if s]
    sigs.sort(key=lambda s: (s.ts, s.signal_id))
    print(len(engine.run_window(tuple(sigs), catalog.builtin_catalog(), ())))
""")


def _objects_opened(docs: list[dict]) -> int:
    """The engine's real stage [5] over what the real edge delivered."""
    proc = subprocess.run(
        [sys.executable, "-c", _STAGE5_PROBE], input=json.dumps(docs), capture_output=True,
        text=True, check=False, timeout=120,
        env={"PYTHONPATH": str(CORRELATION), "PATH": "/usr/bin:/bin"})
    assert proc.returncode == 0, proc.stderr
    return int(proc.stdout.strip())


IOS_FAULT = (b"<187>25170: Nov  9 09:00:01.123: %LINK-3-UPDOWN: Interface Gi1, changed state to down",
             b"<189>25171: Nov  9 09:00:02.123: %LINEPROTO-5-UPDOWN: Line protocol on Interface Gi1, changed state to down")
IOS_SHUTDOWN = (b"<189>25172: Nov  9 09:00:01.123: %LINK-5-CHANGED: Interface Gi1, changed state to administratively down",
                b"<189>25173: Nov  9 09:00:02.123: %LINEPROTO-5-UPDOWN: Line protocol on Interface Gi1, changed state to down")


def test_a_real_ios_link_fault_opens_one_object(edge: H.Edge) -> None:
    assert _objects_opened([edge.send(f) for f in IOS_FAULT]) == 1


def test_an_ios_shutdown_opens_nothing(edge: H.Edge) -> None:
    """Both of its lines, as the box logs them, through stage [5]."""
    assert _objects_opened([edge.send(f) for f in IOS_SHUTDOWN]) == 0


def test_an_eos_link_fault_still_opens(edge: H.Edge) -> None:
    doc = edge.send(b"<149>Nov  9 09:00:01 edge01 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on "
                    b"Interface Ethernet1, changed state to down")
    assert _objects_opened([doc]) == 1


@pytest.mark.parametrize("pri", range(8))
def test_true_pri_cannot_move_a_typed_link_rows_severity(pri: int) -> None:
    """The rows state severity by link STATE (`by_state: {down: high}`). Whatever PRI a
    device sends, a down line is high and an up line is warn: PRI cannot widen or narrow
    what stage [5] opens on these rows, nor what #155's filter sees as opening."""
    word = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"][pri]
    base = {"hostname": "r1", "severity": word, "timestamp": "2026-11-09T10:00:00Z",
            "facility": "LINK", "event_type": "updown", "appname": "unknown"}
    down, up = engine([
        {**base, "message": f"%LINK-3-UPDOWN: {LINK_DOWN}"},
        {**base, "message": f"%LINK-3-UPDOWN: {LINK_UP}"},
    ])
    assert (down["kind"], down["severity"]) == ("link_state_change", "high")
    assert (up["kind"], up["severity"]) == ("link_state_change", "warn")


# ── the generic net: real PRI, no pack (owner D3) ────────────────────────────────

GENERIC_LADDER = [("emerg", "crit"), ("alert", "crit"), ("crit", "crit"), ("err", "warn"),
                  ("warning", "warn"), ("notice", None), ("info", None), ("debug", None)]


@pytest.mark.parametrize("word,severity", GENERIC_LADDER)
def test_the_generic_net_opens_only_on_a_critical_line(word: str, severity: str | None) -> None:
    got = engine([{"hostname": "r1", "appname": "otherd", "severity": word,
                   "message": "a line no rule and no pack knows", "timestamp": "2026-11-09T10:00:00Z"}])[0]
    assert got["severity"] == severity, got
    assert opens_alone(got) is (severity == "crit"), got


def test_an_err_mnemonic_at_the_start_of_a_tagged_line_is_read() -> None:
    """It used to reach the engine in the tag, by accident of the double parse. Lost,
    `Rib: %FOO-3-BAR` under a notice PRI would be nothing at all."""
    got = engine([{"hostname": "r1", "appname": "Rib", "severity": "notice",
                   "message": "%FOO-3-BAR: no rule knows this", "timestamp": "2026-11-09T10:00:00Z"}])[0]
    assert (got["kind"], got["severity"]) == ("device_alarm", "warn"), got


def test_a_mnemonic_later_in_the_line_sets_no_severity() -> None:
    """A sender writes its own message text; it cannot talk its way to critical."""
    got = engine([{"hostname": "r1", "appname": "otherd", "severity": "notice",
                   "message": "user typed %FOO-1-BAR into a field", "timestamp": "2026-11-09T10:00:00Z"}])[0]
    assert got["kind"] is None, got


# ── malformed and oversized frames: counted, and the lane lives ──────────────────

MALFORMED = [
    ("empty PRI, which the legacy parser reads as kern.emerg", b"<>nothing", "malformed_pri"),
    ("PRI out of range", b"<999>Nov  9 09:00:01 r1 app: out of range", "malformed_pri"),
    ("PRI 192, one past the last valid", b"<192>Nov  9 09:00:01 r1 app: one past", "malformed_pri"),
    ("PRI not a number", b"<abc>Nov  9 09:00:01 r1 app: bad pri", "malformed_pri"),
    ("RFC 5424 cut in the timestamp", b"<187>1 2026-11-09T09:00", "malformed_5424"),
    ("RFC 5424 with nothing after the version", b"<186>1 ", "malformed_5424"),
    ("RFC 5424 with a bad timestamp", b"<186>1 notatime vEdge-1 FTMD 3875 - - message", "malformed_5424"),
]


@pytest.mark.parametrize("name,frame,problem", MALFORMED, ids=[m[0] for m in MALFORMED])
def test_a_malformed_frame_is_kept_counted_and_harmless(edge: H.Edge, name: str, frame: bytes, problem: str) -> None:
    doc = edge.send(frame)
    assert doc["frame_problem"] == problem, doc
    assert doc["frame_format"] == problem, doc
    assert doc["severity"] == "notice", f"an unreadable frame states no severity: {doc}"
    assert doc["hostname"] == edge.sender_ip, doc
    assert doc["message_original"] == frame.decode(), doc
    assert doc["message"].strip() == frame.decode().strip(), "nothing of it is lost"
    got = engine([doc])[0]
    assert got["kind"] is None and not opens_alone(got), got
    # The next frame is on time: the lane did not stall.
    assert edge.send(VEDGE_ERR)["hostname"] == "vEdge-1"


def test_a_frame_with_no_pri_gets_the_default_and_is_counted(edge: H.Edge) -> None:
    doc = edge.send(b"just some text with no pri at all")
    assert doc["frame_problem"] == "no_pri", doc
    assert doc["severity"] == "notice" and doc["syslog_facility"] == "user", doc
    assert doc["message_original"] == "just some text with no pri at all", doc


def test_a_bad_byte_does_not_stall_the_lane(edge: H.Edge) -> None:
    """Vector's octet decoder treats one non-UTF-8 byte as a broken stream, and syslog-ng
    then waits time-reopen (60 s), with every device's syslog behind it. RECORD_TIMEOUT_S
    is well under that, so a stall fails here."""
    before = edge.vector_log().count("Failed framing bytes")
    doc = edge.send(b"<187>Nov  9 09:00:01 r1 app: bin\x00ary\xff\xfe\xc3\x28 end")
    assert doc["message"] == "bin\\x00ary\\xff\\xfe\\xc3( end", doc
    assert doc["severity"] == "err" and doc["hostname"] == "r1", doc
    assert doc["message_original"] == "<187>Nov  9 09:00:01 r1 app: bin\\x00ary\\xff\\xfe\\xc3( end", doc
    assert edge.send(VEDGE_ERR)["hostname"] == "vEdge-1"
    assert edge.vector_log().count("Failed framing bytes") == before


def test_valid_utf8_is_left_alone(edge: H.Edge) -> None:
    frame = "<189>Nov  9 09:00:01 r1 app: café 日本語 ok".encode()
    doc = edge.send(frame)
    assert doc["message"] == "café 日本語 ok", doc
    assert doc["message_original"] == frame.decode(), doc


def test_an_oversized_udp_datagram_is_trimmed_and_counted(edge: H.Edge) -> None:
    frame = b"<187>Nov  9 09:00:01 r1 app: " + b"x" * 40000
    doc = edge.send(frame)
    assert doc["frame_problem"] == "oversized", {k: v for k, v in doc.items() if k != "message_original"}
    assert len(doc["message_original"]) == LOG_MSG_SIZE
    assert doc["hostname"] == "r1" and doc["severity"] == "err"
    assert edge.settle() == [], "the rest of the datagram is not another frame"


def test_the_tail_of_an_oversized_tcp_line_is_counted_and_cannot_alarm(edge: H.Edge) -> None:
    """syslog-ng reads a long line in 32 KiB pieces. Each is bounded, stored and counted,
    and the pieces after the first have no header, so they state no severity."""
    frame = b"<186>Nov  9 09:00:01 r1 app: " + b"x" * (LOG_MSG_SIZE + 100) + b"\n"
    edge.send_raw(frame, "tcp")
    first, tail = edge.collect(2)
    assert first["frame_problem"] == "oversized", first["frame_format"]
    assert first["hostname"] == "r1"
    assert tail["frame_problem"] == "no_pri", tail
    assert tail["severity"] == "notice" and tail["hostname"] == edge.sender_ip, tail
    assert engine([tail])[0]["kind"] is None
    assert edge.settle() == []
    assert edge.send(VEDGE_ERR)["hostname"] == "vEdge-1"


def test_the_worst_case_relay_frame_fits_the_aggregator(edge: H.Edge) -> None:
    """Every byte of a maximal frame escaped, in the field escaped twice. Past
    syslog_in.max_length Vector drops the frame, and a device could silence itself."""
    pad = b'"' * (LOG_MSG_SIZE - 80)
    frame = b'<165>1 2026-11-09T09:00:00Z r9 app 1 ID [a@1 q="' + pad.replace(b'"', b'\\"')[:LOG_MSG_SIZE - 80] + b'"] m'
    doc = edge.send(frame[:LOG_MSG_SIZE])
    assert doc["source_ip"] == edge.sender_ip
    assert edge.send(VEDGE_ERR)["hostname"] == "vEdge-1"


def test_the_bound_is_stated_in_step_at_both_ends() -> None:
    core = (SYSLOG_NG / "core.conf").read_text(encoding="utf-8")
    assert f"log-msg-size({LOG_MSG_SIZE});" in core
    shipped = yaml.safe_load(VECTOR_YAML.read_text(encoding="utf-8"))
    assert shipped["sources"]["syslog_in"]["max_length"] >= 7 * LOG_MSG_SIZE
    assert f"strlen(cx_raw) >= {LOG_MSG_SIZE}" in shipped["transforms"]["syslog_sender"]["source"]


def test_the_router_counts_every_bad_frame() -> None:
    router = yaml.safe_load(ROUTER_YAML.read_text(encoding="utf-8"))
    t = router["transforms"]
    assert t["syslog_bad_frame_events"]["inputs"] == ["syslog_tagged"]
    assert t["syslog_bad_frame_events"]["condition"] == "exists(.frame_problem)"
    metric = t["syslog_bad_frame_metric"]["metrics"][0]
    assert metric["name"] == "netops_ingest_syslog_bad_frames"
    assert metric["tags"] == {"reason": "{{ frame_problem }}"}
    exporter = [s for s in router["sinks"].values() if s.get("type") == "prometheus_exporter"]
    assert any("syslog_bad_frame_metric" in s["inputs"] for s in exporter)


# ── structured data: a sender cannot write the event's fields (§3) ───────────────

def test_structured_data_cannot_land_on_a_field(edge: H.Edge) -> None:
    """Vector writes each SD element onto the top of the event. Forwarded as elements,
    `[hostname y="evil"]` would replace the hostname: it did, in the evaluation."""
    doc = edge.send(b'<165>1 2026-11-09T09:00:00Z r9 app 1 ID '
                    b'[tenant_id x="evil"][hostname y="evil"][origin ip="6.6.6.6" software="z"]'
                    b'[__key a="b"][frame_format f="rfc5424"][frame_problem p="q"] hello')
    assert doc["hostname"] == "r9", doc
    assert doc["tenant_id"] == "", doc
    assert doc["__key"] == "global", doc
    assert doc["frame_format"] == "rfc5424", doc
    assert "frame_problem" not in doc, doc
    assert doc["source_ip"] == edge.sender_ip, "the network fact wins over the claim"
    assert doc["origin"] == {"ip": edge.sender_ip}, doc
    assert doc["message"] == "hello"
    assert doc["structured_data"].startswith('[tenant_id x="evil"]'), "kept, as text"


def test_the_sender_structured_data_keeps_its_escapes_and_no_dotted_key_appears(edge: H.Edge) -> None:
    frame = b'<165>1 2026-11-09T09:00:00Z r9 app 1 ID [a@1.2.3 q="he said \\"x\\" \\] \\\\ end"] hello'
    doc = edge.send(frame)
    assert doc["structured_data"] == '[a@1.2.3 q="he said \\"x\\" \\] \\\\ end"]', doc
    assert doc["message_original"] == frame.decode(), doc

    def dotted(node: object) -> list[str]:
        if not isinstance(node, dict):
            return []
        out = [k for k in node if "." in k]
        for value in node.values():
            out += dotted(value)
        return out

    # The CLAUDE.md gotcha: OpenSearch reads a dotted key as an object path.
    assert dotted(doc) == [], doc


# ── framing the catalogue, and its own guards ────────────────────────────────────

def test_the_stop_gap_is_gone_and_a_genuine_line_is_left_alone(edge: H.Edge) -> None:
    doc = edge.send(b"<189>Nov  9 09:00:01 r1 app: 12 - - a genuine message")
    assert doc["message"] == "12 - - a genuine message", doc
    assert "procid" not in doc, doc
    packs = (CATALOG / "vendor-packs" / "standard.yaml").read_text(encoding="utf-8")
    assert "rfc5424_remnant" not in packs


def test_tcp_carries_several_frames_on_one_connection(edge: H.Edge) -> None:
    edge.send_raw(VEDGE_ERR + b"\n" + EOS + b"\n", "tcp")
    docs = edge.collect(2)
    assert {d["hostname"] for d in docs} == {"vEdge-1", "edge01"}, docs


def test_a_nil_hostname_falls_back_to_the_sender(edge: H.Edge) -> None:
    doc = edge.send(b"<187>1 2026-11-09T09:00:00Z - - - - - message")
    assert doc["hostname"] == edge.sender_ip, doc
    assert doc["appname"] == "unknown" and doc["message"] == "message", doc
    assert doc["frame_format"] == "rfc5424"


def _load_bake():
    sys.path.insert(0, str(CATALOG))
    import bake_rules
    return bake_rules


@pytest.mark.parametrize("row,why", [
    ({"id": "x", "match": "abc", "replace": "$1", "fidelity": "lab_validated"}, "anchored"),
    ({"id": "x", "match": "^<a'b", "replace": "$1", "fidelity": "lab_validated"}, "soundly"),
    ({"id": "x", "match": "^<a", "replace": "$1`x`", "fidelity": "lab_validated"}, "soundly"),
    ({"id": "x", "match": "^<(", "replace": "$1", "fidelity": "lab_validated"}, "compile"),
    ({"id": "x", "match": "^<a", "fidelity": "lab_validated"}, "exactly one"),
    ({"id": "x", "match": "^<a", "replace": "$1", "no_header": True, "fidelity": "lab_validated"}, "exactly one"),
    ({"id": "x", "match": "^<a", "replace": "$1", "fidelity": "doc_claimed"}, "source"),
    ({"id": "x", "match": "^<a", "replace": "$1", "fidelity": "lab_validated", "typo": 1}, "unknown"),
])
def test_a_bad_edge_shape_does_not_bake(row: dict, why: str) -> None:
    bake = _load_bake()
    with pytest.raises(bake.BakeError, match=why):
        bake.edge_shapes([{"pack": "p", "edge_shapes": [row]}])


def test_the_mechanism_names_no_vendor() -> None:
    """Vendors live in pack comments and `source`; the edge's own config names shapes."""
    core = (SYSLOG_NG / "core.conf").read_text(encoding="utf-8")
    start = core.index("# >>> BEGIN GENERATED-EDGE-SHAPES")
    end = core.index("# <<< END GENERATED-EDGE-SHAPES")
    shapes = core[start:end]
    words = re.compile(r"viptela|vedge|cedge|juniper|junos|nokia|arista|sonic|fortinet|fortigate", re.IGNORECASE)
    assert not words.findall(shapes), shapes


@pytest.mark.parametrize("variant", ["syslog-ng.conf", "syslog-ng-tls.conf"])
def test_both_variants_frame_the_same_way(variant: str) -> None:
    conf = (SYSLOG_NG / variant).read_text(encoding="utf-8")
    log = re.search(r"log\s*\{(.*?)\};", conf, re.DOTALL)
    assert log, variant
    steps = re.findall(r"(\w+)\((\w+)\);", log.group(1))
    assert steps == [("source", "s_network"), ("parser", "p_frame"), ("rewrite", "r_frame_facts"),
                     ("rewrite", "r_sender_address"), ("destination", "d_vector")], steps


# ── the mesh-TLS variant, end to end ─────────────────────────────────────────────

def _make_certs(dest: Path) -> None:
    def openssl(*args: str) -> None:
        proc = subprocess.run(["openssl", *args], capture_output=True, text=True, timeout=60, check=False)
        assert proc.returncode == 0, proc.stderr
    (dest / "svid").mkdir()
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(dest / "ca.key"),
            "-out", str(dest / "ca.pem"), "-subj", "/CN=test-ca", "-days", "2")
    for stem, cn in ((dest / "aggregator", "vector-aggregator"), (dest / "svid" / "syslog-ng", "syslog-ng")):
        ext = dest / f"{cn}.ext"
        ext.write_text(f"subjectAltName=DNS:{cn}\n", encoding="utf-8")
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{stem}.key", "-out", f"{stem}.csr",
                "-subj", f"/CN={cn}")
        openssl("x509", "-req", "-in", f"{stem}.csr", "-CA", str(dest / "ca.pem"), "-CAkey", str(dest / "ca.key"),
                "-CAcreateserial", "-out", f"{stem}.crt", "-days", "2", "-extfile", str(ext))
    for path in dest.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    dest.chmod(0o755)


def test_the_tls_variant_frames_identically(tmp_path: Path) -> None:
    if not _docker_available():
        pytest.skip(_SKIP)
    if shutil.which("openssl") is None:
        pytest.skip("openssl is unavailable, so the TLS variant DID NOT RUN")
    _make_certs(tmp_path)
    with H.running_edge(SYSLOG_NG, VECTOR_YAML, variant="syslog-ng-tls.conf", tls_dir=tmp_path) as tls_edge:
        for name, frame, want in FRAMES:
            if name not in ("vEdge err", "cEdge, no hostname and the mnemonic survives", "Junos structured data"):
                continue
            doc = tls_edge.send(frame)
            for key, value in want.items():
                if key == "tenant_id":
                    continue  # this edge's registry is empty
                expected = tls_edge.sender_ip if value == SENDER else value
                assert doc.get(key) == expected, f"{name}: {key}={doc.get(key)!r}"
            assert doc["source_ip"] == tls_edge.sender_ip
