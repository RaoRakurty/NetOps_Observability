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
    ("resource_planner.py", 285): "optional cgroup limit file; absent => host os.cpu_count/meminfo defaults",
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
    # Re-pinned 2026-08-17 (same four reviewed sites, shifted by the
    # group_lag/preflight consumer-membership fix — the line-keyed design
    # forcing this re-read is working as intended).
    ("scale-miniladder.py", 188): "optional .env read; returns '' with a documented callers-decide contract",
    ("scale-miniladder.py", 651): "preflight ingress probe; failure appended to `problems`, preflight fails on any problem",
    ("scale-miniladder.py", 658): "preflight API-login probe; failure appended to `problems`, preflight fails on any problem",
    ("scale-miniladder.py", 878): "twin-mode burst artifact read; failure returns an explicit burst-phase FAIL (tracker 152 §8.3)",
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
