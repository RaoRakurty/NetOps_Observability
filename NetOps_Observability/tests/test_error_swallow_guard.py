"""§16.1 regression guard — no swallowed errors in operational scripts.

The 2026-08 scale test's defect class #3: `ensure_data_dirs` caught the chown
failure, printed `[info] Fix: sudo chown -R ...` and CONTINUED — shipping two
broken deployments in one week (238k dead-letter payloads lost; a TLS
bootstrap deadlock). The fix (`chown_tree`, tests/test_install_data_dirs.py)
escalates. THIS suite makes the class structurally hard to reintroduce in ANY
script:

  1. Literal swallow patterns — `except OSError: pass|continue` and bare
     `except Exception: pass` — are banned in scripts/*.py AND scripts/*.sh
     (the .sh scan catches Python heredocs embedded in shell).
  2. AST rule over scripts/*.py: an `except` handler that catches OSError /
     PermissionError and contains NO escalation (`raise`, `fail(`, `die(`,
     `abort(`, `refuse(`, `exit`/`sys.exit`/`os._exit`) is a violation.
  3. Chown-remedy rule: a `warn`/`info`/`print` call whose literal text offers
     a `chown` remedy may only live in a function that ALSO escalates — the
     remedy must accompany a hard failure, never a warn-and-continue.

Every currently-shipping site that trips rule 2 was reviewed on 2026-08-16 and
is pinned in ALLOWLIST below with its justification. Adding a NEW swallow
means consciously adding an allowlist entry in this file — which is the point:
the pattern becomes a reviewed decision, never a default.

Run:  python3 -m pytest tests/test_error_swallow_guard.py -v
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"

TARGET_EXC = {"OSError", "PermissionError"}
ESCALATION_CALLS = {"fail", "die", "abort", "refuse", "exit"}  # + attr .exit (sys.exit / os._exit)

# (filename, lineno) -> why this reviewed site is allowed to stay. Line numbers
# are load-bearing: moving the handler invalidates the entry, forcing re-review.
ALLOWLIST: dict[tuple[str, int], str] = {
    # -- probes / capability checks: the False/None IS the reported outcome --
    ("install.py", 216): "docker-availability probe; returns False, caller reports/blocks",
    ("install.py", 934): "sandboxed exec shim; returns ExecResult(126, stderr=exc) — error propagated",
    ("install.py", 1175): "chown_tree direct-attempt probe; returns (False, err) to the fallback chain",
    ("install.py", 1208): "chown_tree child walk; failures collected in `failed`, caller escalates",
    ("install.py", 1214): "chown_tree direct attempt; err captured, docker fallback runs, both-fail => fail()",
    ("vrl-harness.py", 68): "vector-binary availability probe; returns False => harness skips loudly",
    # -- optional-input reads with a sane, visible default --
    ("install.py", 173): "git rev-parse for build provenance; falls back to 'unknown', which drift check FAILS on",
    ("install.py", 1146): "uid/gid from a .env that may not exist yet (--no-start dry paths); compose default",
    ("refresh_provider_ranges.py", 111): "first-run bootstrap: no previous snapshot file => empty baseline",
    # Re-pinned 2026-08-17: shifted by the BUS_PARTITIONS planner work
    # (constants + derive_bus_partitions inserted above it). Handler re-read,
    # unchanged, justification holds.
    ("resource_planner.py", 311): "optional cgroup limit file; absent => host os.cpu_count/meminfo defaults",
    ("regression_correlation_smoke.py", 70): "optional .env read; returns '' and the caller reports missing config",
    ("smoke-test.py", 291): "optional .env admin-credential read; falls back to prompting defaults",
    ("snmp_fidelity_harness.py", 170): "optional .env read; returns None, caller handles absence",
    ("snmp_fidelity_harness.py", 220): "partial walk returned on socket error; harness compares what it got",
    ("snmp_fidelity_harness.py", 383): "optional ifName probe (noqa S110 on site); empty names still yields a recorded verdict",
    # -- reporting-and-continue in operator-facing lab/demo tooling --
    ("demo_lab.py", 539): "lab inventory listing prints '<unreadable>' per file — reported, not swallowed",
    ("seed-test-traffic.py", 109): "test-traffic generator prints each send failure to stderr and keeps seeding",
    ("seed-test-traffic.py", 183): "test-traffic generator prints each send failure to stderr and keeps seeding",
    ("secret_rotation.py", 251): "service-owned marker unreadable from operator uid; commented, rotation proceeds",
    ("secret_rotation.py", 266): "service-owned marker dir unreadable from operator uid; commented fallback",
    ("install.py", 2308): "external-broker reachability preflight; warn states services retry from inside the network",
    # Re-pinned 2026-08-17 (same four reviewed sites, shifted twice in one day:
    # first by the group_lag/preflight consumer-membership fix, then by the
    # RUF012 move of _MEM_UNITS to module scope + the ruff I001 import re-sort.
    # All four handlers re-read at the new lines and unchanged — the line-keyed
    # design forcing this re-read is working as intended).
    #
    # Re-pinned again 2026-08-22 (tracker 170): the correlation-completion gate
    # inserted `corr_replicas` / `corr_completion_state` (~100 lines) above the
    # preflight probes and the completion phase (~110 lines) above the twin
    # read, shifting all four. The `resource_planner.py` cgroup entry had also
    # drifted 304 -> 311 in an earlier wave and was red on the clean tree before
    # this one. ALL FIVE handlers were re-read at their new lines and are
    # behaviourally UNCHANGED:
    #   scale-miniladder.py:197  `env_get` — still `except OSError: pass` with the
    #                            documented "callers decide whether empty is fatal"
    #                            contract; every caller checks the empty string.
    #   scale-miniladder.py:894  ingress probe — still `problems.append(...)`, and
    #                            preflight fails on any non-empty `problems`.
    #   scale-miniladder.py:901  API-login probe — same escalation path.
    #   scale-miniladder.py:1162 twin artifact read — still returns an explicit
    #                            `self.phase("burst", "FAIL", ...)`.
    #   resource_planner.py:311  optional cgroup file — absent is the normal v1/v2
    #                            case; host defaults are used and reported.
    # This is a RE-PIN of reviewed sites after line drift, which is the workflow
    # this line-keyed allowlist exists to force. It is NOT a new exemption: no
    # handler's behaviour was weakened and no new site was added.
    #
    # Re-pinned again 2026-08-22 (tracker 167 live selectivity): the internal
    # load generator gained `--event-mix realistic`, which inserted +4 lines in
    # the module docstring, +2 in `__init__` and +83 for the mix table and the
    # generator itself, shifting all four sites by exactly those amounts
    # (197->201, 894->900, 901->907, 1162->1252). ALL FOUR were re-read at their
    # new lines and are behaviourally UNCHANGED — no handler body was touched by
    # that change, only lines above them:
    #   scale-miniladder.py:201  `env_get` — still `except OSError: pass`
    #                            returning "", callers-decide contract intact.
    #   scale-miniladder.py:900  ingress probe — still `problems.append(...)`.
    #   scale-miniladder.py:907  API-login probe — still `problems.append(...)`.
    #   scale-miniladder.py:1252 twin artifact read — still returns an explicit
    #                            `self.phase("burst", "FAIL", ...)`.
    # RE-PIN of reviewed sites after line drift, per the workflow this
    # line-keyed allowlist exists to force. No behaviour weakened, no new site.
    #
    # Re-pinned 2026-08-22 (tenant-keyed injection): Stack.produce gained key
    # support + registry_tenant (+47 lines above the three lower sites; env_get
    # at 201 is above the insertion and did not move). All three re-read at
    # their new lines, behaviourally unchanged: ingress/login probes still
    # `problems.append(...)`, twin read still returns an explicit burst FAIL.
    #
    # Re-pinned 2026-08-22 (ratified workload profiles): WORKLOAD_PROFILES +
    # noise/composed mix tables + the multi-lane burst path added ~140 lines
    # above the three lower sites (947->1020, 954->1027, 1299->1420); env_get
    # at 201 is above every insertion. All three re-read at their new lines,
    # behaviourally unchanged.
    #
    # Re-pinned 2026-08-28 (interrupt-cleanup fix): the InterruptGuard /
    # residue-purge section and the drain-ETA helper added lines above all four
    # sites, and the 2026-08-28 async OpenSearch purge (curl exit-code
    # reporting + os_purge_syslog) shifted them again
    # (201->242, 1073->1566, 1080->1573, 1473->2031). ALL FOUR re-read at
    # their new lines and behaviourally UNCHANGED — no handler body was
    # touched:
    #   scale-miniladder.py:242  `env_get` — still `except OSError: pass`
    #                            returning "", callers-decide contract intact.
    #   scale-miniladder.py:1566 ingress probe — still `problems.append(...)`.
    #   scale-miniladder.py:1573 API-login probe — still `problems.append(...)`.
    #   scale-miniladder.py:2031 twin artifact read — still an explicit burst
    #                            FAIL.
    # The new `--cleanup-only` ingress/login probes are NOT allowlisted: both
    # call die(), which is a real escalation.
    #
    # Re-pinned 2026-08-29 (cross-run collision guards): the RunLock class,
    # the residue helpers and the preflight foreign-residue gate added lines
    # above all four sites (242->260, 1596->1857, 1603->1864, 2061->2375), and
    # the onboard stop-reason work shifted them again in the same wave
    # (260->266, 1857->1867, 1864->1874, 2375->2417) together with the nine new
    # RunLock sites below (+6 each, +42 for the twin read). EVERY site was
    # re-read at its final line and is behaviourally UNCHANGED — the shifts are
    # module-docstring and phase-body edits ABOVE the handlers, no handler body
    # was touched.
    # ALL FOUR re-read at their new lines and behaviourally UNCHANGED — no
    # handler body was touched:
    #   scale-miniladder.py:260  `env_get` — still `except OSError: pass`
    #                            returning "", callers-decide contract intact.
    #   scale-miniladder.py:1857 ingress probe — still `problems.append(...)`.
    #   scale-miniladder.py:1864 API-login probe — still `problems.append(...)`.
    #   scale-miniladder.py:2375 twin artifact read — still an explicit
    #                            `self.phase("burst", "FAIL", ...)`.
    # Re-pinned 2026-08-29 for the combined scale-miniladder wave of that day
    # (three changes, one file): the PRODUCER_* injection-integrity block and
    # the hardened `Stack.produce`, the burst work-boxing block (BURST_*
    # constants + `_lane_schedule`/`_burst_single_lane`), and the memflat
    # instrument split (cgroup-anon sampling + the ClickHouse clause-2/3
    # probes). Every site moved because code was inserted ABOVE it —
    # 413->549, 622->819, 1460..1576 -> 1752..1868, 2166->2468, 2173->2475,
    # 2716->3028. ALL FOURTEEN handlers were re-read at their new lines and are
    # behaviourally UNCHANGED: no handler body was touched by any of the three.
    # This is the re-pin workflow the line-keyed allowlist exists to force, not
    # a new exemption.
    ("scale-miniladder.py", 682): "optional .env read; returns '' with a documented callers-decide contract",
    # (+10-line drift 2026-08-22: the lanes-routing comment block in
    # WORKLOAD_PROFILES; all three re-read, unchanged.)
    # (+15-line drift 2026-08-22: soak-72h profile; +17 more 2026-08-23: the
    # 2.5K rung profiles — all three handlers re-read at each pin, unchanged.)
    #
    # Re-pinned 2026-08-27 (tracker #169): the ACTIVE-consumer membership
    # preflight block (group-lag settle loop + ClickHouse/healthz probes) and
    # the correlation-completion evidence added lines above these three sites,
    # shifting them 1062->1073, 1069->1080, 1462->1473. ALL THREE re-read at
    # their new lines and are behaviourally UNCHANGED — no handler body touched:
    #   scale-miniladder.py:1073 ingress probe — still `problems.append(...)`;
    #                            preflight returns FAIL on any non-empty
    #                            `problems` (status line: PASS iff not problems).
    #   scale-miniladder.py:1080 API-login probe — same `problems.append(...)`
    #                            escalation path through the preflight verdict.
    #   scale-miniladder.py:1473 twin artifact read — still returns an explicit
    #                            `self.phase("burst", "FAIL", ...)` (hard FAIL).
    # RE-PIN of reviewed sites after line drift, per the workflow this
    # line-keyed allowlist exists to force. No behaviour weakened, no new site.
    #
    # Re-pinned 2026-08-29 (hollow-completion gate): the `parse_prom_metrics`
    # helper plus the per-replica completion facts added ~30 lines above the
    # three lower sites (1566->1596, 1573->1603, 2031->2061); env_get at 242 is
    # above the insertion and did not move. ALL THREE re-read at their new
    # lines and behaviourally UNCHANGED — no handler body was touched:
    #   scale-miniladder.py:1596 ingress probe — still `problems.append(...)`.
    #   scale-miniladder.py:1603 API-login probe — still `problems.append(...)`.
    #   scale-miniladder.py:2061 twin artifact read — still an explicit
    #                            `self.phase("burst", "FAIL", ...)`.
    #
    # Re-pinned 2026-08-29 (transient-failure retry + adaptive OS purge budget):
    # the one bounded HTTP retry policy (`_http_transient_reason`,
    # `_annotate_exc`, `http_retry`, `http_ingress_status`), the
    # `cleanup_step`/`empty_purge_ev` teardown guards and the OpenSearch
    # re-estimation block added lines above every scale-miniladder site
    # (266->413, 1257..1373 -> 1460..1576 uniformly +203, 1867->2166,
    # 1874->2173, 2417->2716). EVERY site was re-read at its new line and is
    # behaviourally UNCHANGED — no handler body was touched, only code above
    # them. RE-PIN of reviewed sites after line drift, which is the workflow
    # this line-keyed allowlist exists to force.
    # RE-PIN 2026-08-29 (memflat wave: the ClickHouse metric_log plausibility
    # filter + correlation's pending-zero anchor + --rescore-memflat). Pure
    # line drift from code added ABOVE these sites — the CH_PLAUSIBLE_SAMPLE /
    # CORR_MEM_SETTLE constants and the module-level ch_number/ch_memory_cap
    # helpers (549->638, 819->908 uniformly +89), corr_replicas' name/RSS
    # fields (+21 more: 1752..1868 -> 1862..1978), the Harness.__init__ state
    # (+10 more: 2468/2475/3028 -> 2588/2595/3148). EVERY site was re-read at
    # its new line and is behaviourally UNCHANGED — no handler body was
    # touched. RE-PIN of reviewed sites after line drift, which is the workflow
    # this line-keyed allowlist exists to force.
    ("scale-miniladder.py", 2671): "preflight ingress probe; failure appended to `problems`, preflight fails on any problem",
    ("scale-miniladder.py", 2678): "preflight API-login probe; failure appended to `problems`, preflight fails on any problem",
    ("scale-miniladder.py", 3249): "twin-mode burst artifact read; failure returns an explicit burst-phase FAIL (tracker 152 §8.3)",
    # -- NEW 2026-08-29: Stack.api's post-retry transport handler -------------
    # THE ONE NEW ENTRY IN THIS WAVE, and a deliberate one. `Stack.api` used to
    # let a socket read timeout escape as a raw `TimeoutError`; on the live run
    # p2-s012d-08290411 that unwound cleanup() and ended the run
    # `RESIDUE LEFT: UNKNOWN (never verified)` with the fleet still standing.
    # The call is now retried under the shared bounded policy (5 attempts,
    # exponential backoff + full jitter) and only reaches this handler when the
    # whole budget is spent. It is NOT a swallow: the failure is counted
    # (`http_transport_failures`, reported in the cleanup evidence), warned by
    # name, and returned as `(0, "transport: <exc!r>")` — a status every caller
    # in the file already treats as "this answer is not evidence"
    # (`devices_with_prefix` -> list ERROR -> residue UNKNOWN, never zero;
    # `delete_devices` -> a named failure string). Escalating here instead is
    # exactly the defect: one unreachable call must not cost the teardown.
    ("scale-miniladder.py", 983): "post-retry API transport failure; counted + warned + returned as HTTP 0 so every caller reports it as 'not evidence' (residue UNKNOWN, never zero)",
    # -- RunLock (NEW 2026-08-29, cross-run collision guard) -----------------
    # Reviewed as a group. The lock's contract is that EVERY failure becomes a
    # refusal the caller escalates: `acquire()` returns (False, message) and
    # both call sites (`main`, `cleanup_only`) immediately `die(message)` —
    # exit 2, nothing touched. A `raise`/`die()` inside these handlers would
    # make the lock untestable and would abort a run for a lock problem the
    # caller may legitimately decide about; the escalation is one frame up, and
    # tests/test_miniladder_cross_run_collision.py pins that both callers do it.
    # The two `release()` handlers and the pid probe cannot escalate at all —
    # they run on the way out (or answer a question), and each REPORTS by name.
    ("scale-miniladder.py", 1945): "pid liveness probe: PermissionError means a LIVE process owned by another user; the True is the answer, and it refuses rather than steals",
    ("scale-miniladder.py", 1947): "pid liveness probe fallback: warns by name and answers ALIVE (never steals a lock on an unknown error)",
    ("scale-miniladder.py", 1959): "lock-file read: warns that the file is unreadable and returns an owner-less holder, which the caller treats as stale — reported, not silent",
    ("scale-miniladder.py", 1988): "lock dir creation: returns (False, reason); main()/cleanup_only() die() on it — refusing to run unlocked",
    ("scale-miniladder.py", 2019): "stale-lock unlink: returns (False, reason); caller die()s rather than racing a lock it could not clear",
    ("scale-miniladder.py", 2026): "lock O_EXCL create: returns (False, reason); caller die()s",
    ("scale-miniladder.py", 2031): "lock stamp write: returns (False, reason) after removing the half-written lock; caller die()s",
    ("scale-miniladder.py", 2034): "removal of a half-written lock: warns by name; the outer handler still refuses the run",
    ("scale-miniladder.py", 2061): "lock release on the way out: warns by name and says the next run reclaims it as stale (this pid will be dead) — nothing left to escalate to",
    # -- NEW 2026-08-29: --rescore-memflat's saved-curve read ---------------
    # The offline re-score reads a FINISHED run's correlation-completion.json.
    # An unreadable/corrupt curve is not fatal and must not be: the handler
    # appends "correlation cannot be re-scored" to `problems`, which makes the
    # re-scored verdict FAIL/UNKNOWN, is printed in memflat-rescore.md, and
    # exits non-zero. Escalating instead would throw away the ClickHouse half
    # of the re-score, which is readable and is the half being asked about.
    ("scale-miniladder.py", 5998): "--rescore-memflat curve read; failure becomes a `problems` entry -> the re-scored verdict is FAIL/UNKNOWN and the tool exits non-zero",
    # -- NEW 2026-08-29 (tracker 175: the device-store tombstone debt) -------
    # Both handlers answer a DIAGNOSTIC question — how many suppression
    # tombstones the device store carries, and how the onboard rate has moved
    # across runs — and neither is a teardown or a verdict. Each warns by name
    # and records the reason as evidence (UNKNOWN, never 0), and cleanup's
    # tombstone step deliberately routes its failures to its own list so a
    # device store this harness cannot count never turns a clean teardown red.
    # Escalating either one would fail a run over a directory listing.
    ("scale-miniladder.py", 4926): "tombstone-count scandir; warns by name and returns reachable=False with the reason — the debt reads UNKNOWN, never 0",
    ("scale-miniladder.py", 5432): "previous last-run.json read for the onboard-rate trend; warns by name and restarts the history at this run rather than costing the run its report",
    # The four 2026-08-16 chown-swallow findings (enrichment seed, processors
    # seed, appid/cloud fixtures, vuln SUDO_UID dir) were RESOLVED the same
    # day: all now route through chown_tree (repair-or-refuse), and the vuln
    # site validates SUDO_UID/SUDO_GID explicitly with a loud warn on a
    # mangled environment. See tests/test_install_data_dirs.py.
}

# Rule 1: literal swallows, any text file (catches heredoc Python in .sh too).
LITERAL_SWALLOWS = [
    re.compile(r"except\s+OSError\s*:\s*(?:#[^\n]*)?\n\s*(?:pass|continue)\b"),
    re.compile(r"except\s+OSError\s*:\s*(?:pass|continue)\b"),
    re.compile(r"except\s+Exception\s*:\s*(?:#[^\n]*)?\n\s*pass\b"),
    re.compile(r"except\s+Exception\s*:\s*pass\b"),
]


def script_files(suffix: str) -> list[Path]:
    files = sorted(SCRIPTS.glob(f"*{suffix}"))
    assert files, f"no {suffix} scripts found — the guard is scanning the wrong tree"
    return files


def caught_names(node: ast.expr | None) -> set[str]:
    if node is None:
        return set()  # bare `except:` — covered by the Exception literal rule
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Attribute):
        return {node.attr}
    if isinstance(node, ast.Tuple):
        out: set[str] = set()
        for elt in node.elts:
            out |= caught_names(elt)
        return out
    return set()


def escalates(node: ast.AST) -> bool:
    """True when the subtree re-raises, exits, or calls a hard-fail helper."""
    for n in ast.walk(node):
        if isinstance(n, ast.Raise):
            return True
        if isinstance(n, ast.Call):
            f = n.func
            name = f.id if isinstance(f, ast.Name) else (
                f.attr if isinstance(f, ast.Attribute) else "")
            if name in ESCALATION_CALLS:
                return True
    return False


def violation_key(path: Path, lineno: int) -> tuple[str, int]:
    return (path.name, lineno)


def literal_swallow_sites() -> dict[tuple[str, int], str]:
    """All rule-1 matches, allowlisted or not: key -> offending first line."""
    out: dict[tuple[str, int], str] = {}
    for path in script_files(".py") + script_files(".sh"):
        text = path.read_text(errors="replace")
        for rx in LITERAL_SWALLOWS:
            for m in rx.finditer(text):
                lineno = text.count("\n", 0, m.start()) + 1
                out[violation_key(path, lineno)] = (
                    f"{path.relative_to(ROOT)}:{lineno}: {m.group(0).splitlines()[0]}")
    return out


def test_no_literal_swallow_patterns_in_scripts():
    """Rule 1: `except OSError: pass|continue` / bare `except Exception: pass`
    never appear in scripts — not in .py, and not in Python heredocs inside .sh."""
    hits = [line for key, line in sorted(literal_swallow_sites().items())
            if key not in ALLOWLIST]
    assert not hits, (
        "§16.1: banned error-swallow literals in scripts (report the failure "
        "or escalate — never pass/continue):\n  " + "\n  ".join(hits)
    )


def test_oserror_handlers_escalate_or_are_reviewed():
    """Rule 2 (the chown-defect class): every handler catching OSError /
    PermissionError in scripts/*.py must escalate (raise / fail( / die( /
    abort( / refuse( / sys.exit) or carry a reviewed ALLOWLIST entry here."""
    violations: list[str] = []
    seen_allowlisted: set[tuple[str, int]] = set()
    for path in script_files(".py"):
        src = path.read_text(errors="replace")
        tree = ast.parse(src, str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if not (caught_names(node.type) & TARGET_EXC):
                continue
            if escalates(node):
                continue
            key = violation_key(path, node.lineno)
            if key in ALLOWLIST:
                seen_allowlisted.add(key)
                continue
            first = (ast.get_source_segment(src, node) or "").splitlines()
            head = first[0] if first else ""
            violations.append(f"{path.relative_to(ROOT)}:{node.lineno}: {head}")
    assert not violations, (
        "§16.1: OSError/PermissionError caught without escalation (the "
        "warn-and-continue class that lost 238k dead-letter payloads). Either "
        "escalate, or add a REVIEWED allowlist entry in this file:\n  "
        + "\n  ".join(violations)
    )
    # The allowlist must not rot: every entry still matches a live site (a
    # rule-2 handler or a rule-1 literal), so a fixed/moved handler forces the
    # entry's removal — and line drift is loud.
    stale = sorted(set(ALLOWLIST) - seen_allowlisted - set(literal_swallow_sites()))
    assert not stale, f"stale ALLOWLIST entries (site fixed or moved — update this file): {stale}"


def test_chown_remedy_never_ships_as_warn_and_continue():
    """Rule 3: the exact 2026-08 defect shape — a warn/info/print offering a
    `chown` remedy in a function that then continues. A chown remedy may only
    appear in a function that also hard-fails (chown_tree's both-attempts-failed
    path). String literals only; docstrings/comments don't count."""
    violations: list[str] = []
    for path in script_files(".py"):
        src = path.read_text(errors="replace")
        tree = ast.parse(src, str(path))
        # Map every node to its enclosing function for the escalation check.
        for fn in [n for n in ast.walk(tree)
                   if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            for n in ast.walk(fn):
                if not isinstance(n, ast.Call):
                    continue
                f = n.func
                name = f.id if isinstance(f, ast.Name) else (
                    f.attr if isinstance(f, ast.Attribute) else "")
                if name not in {"warn", "info", "print", "warning"}:
                    continue
                texts = [a.value for a in ast.walk(n)
                         if isinstance(a, ast.Constant) and isinstance(a.value, str)]
                if not any("chown" in t for t in texts):
                    continue
                if not escalates(fn):
                    violations.append(
                        f"{path.relative_to(ROOT)}:{n.lineno}: {name}(...'chown'...) "
                        f"in {fn.name}() which never escalates")
    assert not violations, (
        "§16.1: a chown remedy is being delivered as warn-and-continue — the "
        "install must FAIL when it cannot hand the service its directory "
        "ownership (see chown_tree / tests/test_install_data_dirs.py):\n  "
        + "\n  ".join(violations)
    )
