# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""scripts/spdx-headers.py — the per-file SPDX header sweep.

A sweep that touches every source file in the repository is only as trustworthy
as its edit rule. The failure modes that matter are all silent ones: a header
stacked twice because the second run did not recognise the first, a shebang
pushed off line 1 so a script stops being executable, a Go package doc comment
turned into a licence comment, a `//go:build` constraint separated from the
package clause, a stylesheet commented out by an unbalanced `*/`. Each of those
would pass a naive "does the file contain the string" check and break something
real.

So the fixtures below are one per file type plus one per prologue rule, and the
idempotence assertion is applied to every one of them: apply(apply(x)) == apply(x).

The exemption list is asserted to live in licensing-policy.json and to be read
from there, because an exemption that migrates into the script stops being a
reviewed decision.

Run:  python3 -m pytest tests/test_spdx_headers.py -q
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

PROJ = Path(__file__).resolve().parents[1]
SCRIPT = PROJ / "scripts" / "spdx-headers.py"
POLICY_PATH = PROJ / "licensing-policy.json"

CORE = "Apache-2.0"
COMMERCIAL = "LicenseRef-Correlix-Enterprise"
COPYRIGHT = "Copyright 2026 Correlix"
TAG = "SPDX-License-Identifier:"


def _load():
    spec = importlib.util.spec_from_file_location("_spdx_headers", SCRIPT)
    assert spec is not None and spec.loader is not None, f"cannot load {SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


spdx = _load()


@pytest.fixture(scope="module")
def policy() -> dict:
    with open(POLICY_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def apply(text: str, ext: str, identifier: str = CORE) -> str:
    return spdx.apply_header(text, ext, identifier, COPYRIGHT)


def assert_idempotent(text: str, ext: str, identifier: str = CORE) -> str:
    once = apply(text, ext, identifier)
    assert apply(once, ext, identifier) == once, (
        f"a second sweep of a {ext} file changed it again:\n{once!r}")
    assert spdx.is_compliant(once, identifier, COPYRIGHT)
    return once


# ── one fixture per file type ────────────────────────────────────────────────

def test_go_file_keeps_its_package_doc_as_a_package_doc():
    """Inserting the header without a blank line beneath it would glue the
    licence text onto `package`, turning it into the package's doc comment —
    which is what `go doc` prints."""
    src = "// Package hardening evaluates device configuration.\npackage hardening\n"
    out = assert_idempotent(src, ".go")
    assert out.startswith(f"// {TAG} {CORE}\n// {COPYRIGHT}\n\n")
    assert "\n\n// Package hardening evaluates" in out
    assert out.endswith("package hardening\n")


def test_go_build_constraint_stays_ahead_of_the_package_clause():
    """A `//go:build` line may be preceded by line comments and blank lines, so
    the header goes above it — but the constraint must keep a blank line between
    itself and `package`, or the go tool ignores it."""
    src = "//go:build integration\n\npackage backend\n"
    out = assert_idempotent(src, ".go")
    lines = out.split("\n")
    assert lines[0] == f"// {TAG} {CORE}"
    assert lines[1] == f"// {COPYRIGHT}"
    assert lines[2] == ""
    assert lines[3] == "//go:build integration"
    assert lines[4] == ""
    assert lines[5] == "package backend"


def test_python_module_docstring_is_still_the_docstring():
    src = '"""What this module does."""\nimport os\n'
    out = assert_idempotent(src, ".py")
    assert out.startswith(f"# {TAG} {CORE}\n# {COPYRIGHT}\n\n\"\"\"What this")


def test_python_shebang_stays_on_line_one():
    src = '#!/usr/bin/env python3\n"""Doc."""\n'
    out = assert_idempotent(src, ".py")
    assert out.split("\n")[0] == "#!/usr/bin/env python3"
    assert out.split("\n")[1] == f"# {TAG} {CORE}"


def test_python_encoding_cookie_stays_where_the_interpreter_looks():
    """PEP 263: the cookie must be on line 1 or 2. A header above it would push
    it to line 3 and change how the file decodes."""
    src = "#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\nx = 1\n"
    out = assert_idempotent(src, ".py")
    lines = out.split("\n")
    assert lines[0] == "#!/usr/bin/env python3"
    assert lines[1] == "# -*- coding: utf-8 -*-"
    assert lines[2] == f"# {TAG} {CORE}"


def test_shell_shebang_stays_on_line_one():
    src = "#!/usr/bin/env bash\nset -euo pipefail\n"
    out = assert_idempotent(src, ".sh")
    lines = out.split("\n")
    assert lines[0] == "#!/usr/bin/env bash"
    assert lines[1] == f"# {TAG} {CORE}"
    assert lines[2] == f"# {COPYRIGHT}"
    assert lines[3] == ""
    assert lines[4] == "set -euo pipefail"


def test_typescript_file():
    src = 'import { useState } from "react";\n'
    out = assert_idempotent(src, ".ts")
    assert out.startswith(f"// {TAG} {CORE}\n// {COPYRIGHT}\n\nimport")


def test_tsx_file():
    src = "export function Panel() {\n  return null;\n}\n"
    out = assert_idempotent(src, ".tsx")
    assert out.startswith(f"// {TAG} {CORE}\n// {COPYRIGHT}\n\nexport function")


def test_ts_directive_and_use_strict_stay_first():
    src = '// @ts-check\n"use strict";\nconst a = 1;\n'
    out = assert_idempotent(src, ".js")
    lines = out.split("\n")
    assert lines[0] == "// @ts-check"
    assert lines[1] == '"use strict";'
    assert lines[2] == f"// {TAG} {CORE}"


def test_css_uses_a_balanced_block_comment():
    src = ":root {\n  --bg: #fff;\n}\n"
    out = assert_idempotent(src, ".css")
    assert out.startswith(f"/* {TAG} {CORE}\n   {COPYRIGHT} */\n\n:root")
    assert out.count("/*") == out.count("*/") == 1


def test_yaml_file():
    src = "groups:\n  - name: licence\n"
    out = assert_idempotent(src, ".yaml")
    assert out.startswith(f"# {TAG} {CORE}\n# {COPYRIGHT}\n\ngroups:")


def test_yaml_document_marker_is_not_disturbed():
    """A comment before `---` is legal YAML and the document still starts at the
    marker."""
    yaml = pytest.importorskip("yaml")
    src = "---\n_meta:\n  type: roles\n"
    out = assert_idempotent(src, ".yml")
    assert yaml.safe_load(out) == yaml.safe_load(src)


def test_a_utf8_bom_stays_a_bom():
    src = "﻿package backend\n"
    out = assert_idempotent(src, ".go")
    assert out.startswith("﻿// " + TAG)


def test_an_empty_file_gets_only_the_header():
    out = apply("", ".go")
    assert out == f"// {TAG} {CORE}\n// {COPYRIGHT}\n"
    assert apply(out, ".go") == out


def test_a_file_that_is_only_a_blank_line_gains_no_second_blank():
    out = apply("\n", ".py")
    assert out == f"# {TAG} {CORE}\n# {COPYRIGHT}\n\n"
    assert apply(out, ".py") == out


# ── repair, not restamp ──────────────────────────────────────────────────────

def test_an_existing_header_gains_the_copyright_line_in_place():
    """The commercial files were stamped before the copyright line existed.
    They must gain it beneath the identifier, not gain a second header."""
    src = (f"// {TAG} {COMMERCIAL}\n//\n// COMMERCIAL ADD-ON MODULE.\n\n"
           "package dialects\n")
    out = assert_idempotent(src, ".go", COMMERCIAL)
    assert out.count(TAG) == 1
    lines = out.split("\n")
    assert lines[0] == f"// {TAG} {COMMERCIAL}"
    assert lines[1] == f"// {COPYRIGHT}"
    assert lines[2] == "//"
    assert lines[3] == "// COMMERCIAL ADD-ON MODULE."


def test_a_wrong_identifier_is_corrected_in_place():
    src = f"// {TAG} MIT\n// {COPYRIGHT}\n\npackage backend\n"
    out = assert_idempotent(src, ".go")
    assert out.count(TAG) == 1
    assert f"{TAG} {CORE}" in out
    assert "MIT" not in out


def test_a_css_header_buried_in_a_multiline_block_is_reported_not_guessed():
    """An unbalanced `*/` would comment out the stylesheet. The rewrite refuses
    the case it cannot do safely and returns the file unchanged, which the
    caller reports as a violation."""
    src = f"/**\n * {TAG} MIT\n */\n:root {{ }}\n"
    out = apply(src, ".css")
    assert out == src, "the sweep must not attempt an unbalanced block-comment repair"


def test_running_the_sweep_twice_over_every_fixture_is_a_no_op():
    fixtures = [
        (".go", "package backend\n"),
        (".py", "import os\n"),
        (".sh", "#!/bin/sh\necho hi\n"),
        (".ts", "export const a = 1;\n"),
        (".tsx", "export const A = () => null;\n"),
        (".js", '"use strict";\nvar a = 1;\n'),
        (".mjs", "export default 1;\n"),
        (".css", "a { color: red; }\n"),
        (".yaml", "a: 1\n"),
        (".yml", "a: 1\n"),
    ]
    for ext, src in fixtures:
        assert_idempotent(src, ext)


# ── scope, exemptions and the licence a path maps to ─────────────────────────

def test_the_identifier_comes_from_the_policy_not_from_the_script(policy):
    for entry in policy["commercial_paths"]["entries"]:
        inside = entry["path"] + "/whatever.go"
        assert spdx.expected_identifier(inside, policy) == COMMERCIAL
    assert spdx.expected_identifier("src/backend/main.go", policy) == CORE
    assert spdx.expected_identifier("scripts/install.py", policy) == CORE


def test_the_exemption_list_lives_in_the_policy(policy):
    """If an exemption ever migrates into the script it stops being a reviewed
    decision, so the script must carry none of its own."""
    entries = policy["header_enforcement"]["exempt"]["entries"]
    assert entries, "the exemption list is empty; state the generated files"
    for entry in entries:
        assert entry["why"].strip(), f"{entry['path']} is exempt with no reason"
    source = SCRIPT.read_text(encoding="utf-8")
    for entry in entries:
        assert entry["path"] not in source, (
            f"{entry['path']} is hard-coded in spdx-headers.py; exemptions belong "
            f"in licensing-policy.json")


@pytest.mark.parametrize(
    "path,exempt",
    [
        ("src/correlation/parser_rules.py", True),
        ("src/correlation/producers.py", False),
        ("src/backend/internal/tac/testdata/candidate-export.yaml", True),
        ("src/backend/internal/tac/tac.go", False),
        ("deployment/docker/vector-router/processors-default.yaml", True),
        ("deployment/docker/vector-router/vector.yaml", False),
    ],
)
def test_exemption_matching(policy, path, exempt):
    assert spdx.is_exempt(path, spdx.exempt_patterns(policy)) is exempt


def test_a_directory_prefix_exemption_matches_segments_not_substrings(policy):
    assert spdx.is_exempt("a/b/c.go", ["a/b/"])
    assert not spdx.is_exempt("a/bc/d.go", ["a/b/"])


def test_every_exemption_and_sweep_root_still_exists(policy):
    """A stale exemption means the sweep covers less than the policy claims."""
    stale = [str(v) for v in spdx.check_roots(policy)]
    assert not stale, stale


def test_scope_is_non_trivial_and_excludes_vendored_trees(policy):
    scope = spdx.in_scope(policy)
    assert len(scope) > 1000, "the sweep covers implausibly little of the tree"
    assert not [p for p in scope if "/vendor/" in p or "/node_modules/" in p]
    assert "src/backend/main.go" in scope
    assert "scripts/install.py" in scope
    for entry in policy["header_enforcement"]["exempt"]["entries"]:
        assert entry["path"] not in scope


def test_the_tree_actually_carries_its_headers(policy):
    """The sweep is the fix; this is the assertion that it was run."""
    violations, changed = spdx.scan(policy, write=False)
    assert changed == []
    assert not violations, (
        "these files do not carry the header licensing-policy.json assigns them.\n"
        "Run: python3 scripts/spdx-headers.py --write\n  "
        + "\n  ".join(str(v) for v in violations[:40]))


def test_check_mode_exits_nonzero_on_a_violation():
    """The gate's exit code is what CI reads, so it is asserted directly rather
    than inferred from the violation list.

    The probe is planted in a SUBPACKAGE, not in src/backend itself: the root
    package carries a file-count ratchet, and a probe there would race it."""
    plant = PROJ / "src" / "backend" / "internal" / "hardening" / "zz_spdx_probe.go"
    assert not plant.exists(), "a previous run left its probe behind"
    plant.write_text("package hardening\n", encoding="utf-8")
    try:
        rc = spdx.main(["--check"])
    finally:
        plant.unlink()
    assert rc == 1, "a source file with no header did not fail --check"


def test_the_gate_delegates_to_this_sweep():
    """One scope, one exemption list. If the gate grew its own copy the two
    would drift and a file could pass one and fail the other."""
    gate = (PROJ / "scripts" / "licensing-gate.py").read_text(encoding="utf-8")
    assert "spdx-headers.py" in gate
    assert "check_headers" in gate
