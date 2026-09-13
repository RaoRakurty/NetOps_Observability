# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Guard: no test may leave the engine RECONFIGURED for the tests after it.

`main`'s configuration knobs are module-level globals read straight out of the
environment at import (`CORR_QUIESCE_S`, `CORR_PRUNE_CHUNK`, `CLOUD_LOGS_DIR`,
...). A test that rebinds one by DIRECT ASSIGNMENT — `main.CORR_QUIESCE_S =
300.0` instead of `monkeypatch.setattr(main, "CORR_QUIESCE_S", 300.0)` — leaks
that value into every later test in the same process, and the failure surfaces
somewhere that has nothing to do with it.

That is not hypothetical. `test_sync_stretch_bound_p1`'s storm helpers set
CORR_QUIESCE_S to 300 s and 10,000,000 s directly; run in the same process as
`test_ownership_seed_155`, two of its tests failed on a quiesce horizon the
engine was never configured with, while each file passed alone.

The rule this file enforces, per file, for every env-derived tunable in
`main.py`: a test module that assigns one directly must ALSO either

  * register it with monkeypatch (`monkeypatch.setattr(main, "NAME", ...)`, or
    the register-at-current-value loop `_stack`/`_isolated` use), or
  * snapshot it (`saved = main.NAME`, a tuple/dict of them, ...) so a
    finally/tearDown/addCleanup can put it back.

…and the restore has to reach the assignment: a fixture's covers the whole
module and a `setUp`'s covers its class, but one test's `monkeypatch.setattr`
does NOT excuse the same global being assigned from a different test. That is
how `test_loop_yield_resilience` leaked CORR_LOOP_YIELD_MS behind a single
monkeypatched test for as long as the file existed.

Limit of a static scan, stated plainly: it proves a module *took a snapshot or
registered the name*, not that the restore actually runs on every path. It
catches the class that bit us — reconfigure and walk away — and cannot catch a
snapshot whose `finally` is missing. A second, RUNTIME check is possible (diff
`main`'s scalars around every test) and is how the 14 original sites were
cross-checked; it is not in the PR gate because it costs a full-suite run.

Scope, deliberately: env-derived CONFIGURATION only. Counters and gauges
(`TRAPS_RECEIVED`, `PRUNE_CALLS`, ...) are observables that tests zero before
measuring, not knobs that change what the engine does, and the conftest autouse
fixtures already reset the module STRUCTURES (window, watermarks, consumer
supervision). Leaked configuration is the class that makes an unrelated test
lie.
"""
from __future__ import annotations

import ast
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
MAIN = os.path.join(HERE, "main.py")

# `main.py` builds its knobs from the environment at module scope. Anything
# whose top-level assignment reads the environment is configuration.
_ENV_READ = re.compile(r"os\.environ|getenv")


def _tunables() -> set[str]:
    """Every UPPER_CASE module-level global in main.py derived from the env.

    Line-sliced rather than `ast.get_source_segment`, which re-splits all 15k
    lines of main.py once per statement.
    """
    with open(MAIN, encoding="utf-8") as fh:
        src = fh.read()
    lines = src.splitlines()
    names: set[str] = set()
    for node in ast.parse(src).body:
        if isinstance(node, ast.Assign):
            targets = [t for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets = [node.target]
        else:
            continue
        if not any(t.id.isupper() and t.id[0].isalpha() for t in targets):
            continue
        end = node.end_lineno or node.lineno
        seg = "\n".join(lines[node.lineno - 1:end])
        if not _ENV_READ.search(seg):
            continue
        for t in targets:
            if t.id.isupper() and t.id[0].isalpha():
                names.add(t.id)
    return names


def _main_attr(node: ast.AST) -> str:
    """`main.NAME` → "NAME"; anything else → ""."""
    if (isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "main"):
        return node.attr
    return ""


# Restoration recorded in one of these applies to EVERY test in the module (a
# fixture runs around each) or to every test in the class (`setUp` runs before
# each). Anywhere else it only covers the function it is written in — a single
# test's `monkeypatch.setattr` must NOT excuse the same global being assigned
# from a different test, which is how the CORR_LOOP_YIELD_MS leak in
# test_loop_yield_resilience.py hid behind one monkeypatched test.
_SETUP_METHODS = frozenset({"setUp", "setUpClass", "asyncSetUp", "setup_method"})


def _is_fixture(node: ast.AST) -> bool:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    for dec in node.decorator_list:
        for sub in ast.walk(dec):
            if isinstance(sub, ast.Attribute) and sub.attr == "fixture":
                return True
            if isinstance(sub, ast.Name) and sub.id == "fixture":
                return True
    return False


class _Scan(ast.NodeVisitor):
    """Per-module: what is assigned to `main.X`, and — per SCOPE — what is
    registered with monkeypatch or snapshotted for a later restore.

    A scope is `("module",)` for a fixture or module-level statement,
    `("class", C)` for a `setUp`-family method of class C, and
    `("func", C_or_None, F)` for anything else, where F is the outermost def
    inside the module or class (helpers nested in a test belong to that test).
    """

    def __init__(self) -> None:
        self.assigned: list[tuple[int, str, tuple]] = []   # (lineno, name, scope)
        self.restored: dict[tuple, set[str]] = {}
        self._class: str | None = None
        self._func: str | None = None
        self._module_scope = True

    # ---- scope tracking ---------------------------------------------------
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        prev_class, prev_func, prev_mod = self._class, self._func, self._module_scope
        self._class, self._func, self._module_scope = node.name, None, False
        self.generic_visit(node)
        self._class, self._func, self._module_scope = prev_class, prev_func, prev_mod

    def _visit_func(self, node) -> None:
        prev_func, prev_mod = self._func, self._module_scope
        if self._func is None:
            # An outermost def: it opens a new scope. A fixture's restorations
            # apply module-wide, a setUp's class-wide, everything else only to
            # itself (nested defs inherit it).
            self._func = node.name
            self._module_scope = _is_fixture(node)
        self.generic_visit(node)
        self._func, self._module_scope = prev_func, prev_mod

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func

    def _scope(self) -> tuple:
        if self._module_scope or self._func is None:
            return ("module",)
        if self._func in _SETUP_METHODS and self._class is not None:
            return ("class", self._class)
        return ("func", self._class, self._func)

    def _restore(self, name: str) -> None:
        self.restored.setdefault(self._scope(), set()).add(name)

    def covers(self, scope: tuple, name: str) -> bool:
        """Is `name` restored by a scope that encloses `scope`?"""
        if name in self.restored.get(("module",), ()):
            return True
        if (scope[0] in ("class", "func") and len(scope) > 1 and scope[1]
                and name in self.restored.get(("class", scope[1]), ())):
            return True
        return name in self.restored.get(scope, ())

    # ---- assignment / snapshot -------------------------------------------
    def visit_Assign(self, node: ast.Assign) -> None:
        for tgt in node.targets:
            self._record_target(tgt)
        # Everything READ off `main` on the right-hand side of an assignment
        # whose target is not `main.X` is a snapshot: `saved = main.X`,
        # `saved = (main.A, main.B)`, `saved = {"A": main.A}`, ...
        self._record_snapshot(node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._record_target(node.target)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._record_target(node.target)
        if node.value is not None:
            self._record_snapshot(node.value)
        self.generic_visit(node)

    def _record_target(self, tgt: ast.AST) -> None:
        if isinstance(tgt, (ast.Tuple, ast.List)):
            for el in tgt.elts:
                self._record_target(el)
            return
        name = _main_attr(tgt)
        if name:
            self.assigned.append((tgt.lineno, name, self._scope()))

    def _record_snapshot(self, value: ast.AST) -> None:
        for sub in ast.walk(value):
            name = _main_attr(sub)
            if name:
                self._restore(name)

    # ---- monkeypatch registration ----------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        fn = node.func
        if (isinstance(fn, ast.Attribute) and fn.attr == "setattr"
                and len(node.args) >= 2
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "main"):
            target = node.args[1]
            if isinstance(target, ast.Constant) and isinstance(target.value, str):
                self._restore(target.value)
            # A non-literal name (the register-at-current-value loop
            # `for _name in ("A", "B"): monkeypatch.setattr(main, _name, ...)`)
            # is picked up from the loop's tuple by visit_For below.
        self.generic_visit(node)

    # ---- the loop form's tuple of names ----------------------------------
    def visit_For(self, node: ast.For) -> None:
        if isinstance(node.target, ast.Name):
            body = ast.dump(ast.Module(body=node.body, type_ignores=[]))
            if "setattr" in body and node.target.id in body:
                for sub in ast.walk(node.iter):
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                        self._restore(sub.value)
        self.generic_visit(node)


def _test_modules(where: str) -> list[str]:
    return sorted(fn for fn in os.listdir(where)
                  if (fn.startswith("test_") or fn == "conftest.py")
                  and fn.endswith(".py"))


def _leaks(where: str = HERE) -> list[str]:
    tunables = _tunables()
    assert "CORR_QUIESCE_S" in tunables, (
        "the tunable inventory did not find CORR_QUIESCE_S — main.py's config "
        "shape changed and this guard is no longer reading it")
    bad: list[str] = []
    for fn in _test_modules(where):
        path = os.path.join(where, fn)
        scan = _Scan()
        with open(path, encoding="utf-8") as fh:
            scan.visit(ast.parse(fh.read()))
        for lineno, name, scope in scan.assigned:
            if name not in tunables:
                continue            # counters/gauges/structures: out of scope
            if scan.covers(scope, name):
                continue
            bad.append(f"{fn}:{lineno}: main.{name}")
    return bad


def test_no_test_leaks_an_engine_tunable_into_the_next_test():
    """Each site below must become `monkeypatch.setattr(main, "NAME", value)`,
    or be registered at its current value so teardown restores it, or be
    snapshotted for an explicit finally/tearDown restore."""
    bad = _leaks()
    assert not bad, (
        "these tests reconfigure the engine and never put it back — the value "
        "leaks into every later test in the process:\n  "
        + "\n  ".join(bad)
        + "\n\nFix: monkeypatch.setattr(main, \"NAME\", value), or register the "
          "name at its current value in an autouse fixture (see `_isolated` in "
          "test_sync_stretch_bound_p1.py), or snapshot it and restore it in a "
          "finally/tearDown.")


def test_the_guard_detects_a_planted_leak(tmp_path):
    """Teeth: the scan must fail on the exact shape that caused the regression,
    and pass once it is monkeypatched. Without this, an inventory that silently
    matched nothing would report a clean suite forever."""
    leaky = tmp_path / "test_planted_leak.py"
    leaky.write_text(
        "import main\n"
        "def test_x():\n"
        "    main.CORR_QUIESCE_S = 300.0\n", encoding="utf-8")
    bad = _leaks(str(tmp_path))
    assert bad == ["test_planted_leak.py:3: main.CORR_QUIESCE_S"], bad

    leaky.write_text(
        "import main\n"
        "def test_x(monkeypatch):\n"
        "    monkeypatch.setattr(main, \"CORR_QUIESCE_S\", 300.0)\n",
        encoding="utf-8")
    assert _leaks(str(tmp_path)) == []

    # …and the snapshot/restore form is accepted too.
    leaky.write_text(
        "import main\n"
        "def test_x():\n"
        "    saved = main.CORR_QUIESCE_S\n"
        "    main.CORR_QUIESCE_S = 300.0\n"
        "    main.CORR_QUIESCE_S = saved\n", encoding="utf-8")
    assert _leaks(str(tmp_path)) == []
