# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""`printf "$x" | grep -q …` is wrong under `set -o pipefail`.

grep -q exits at its first match. When $x is larger than the pipe buffer
(64 KiB) the writer is still writing, takes SIGPIPE, and pipefail turns the
pipeline's status into a failure: a FOUND match reads as "not found". The
fresh-install self-heal gate died this way on 2026-10-25 (PR #93,
assert-postgres-sso.sh): postgres had run crash recovery, grep found it, and
the job reported "no crash recovery" with `printf: write error: Broken pipe`.

Feed grep from a here-string (`grep -q PAT <<<"$x"`): no pipe, no SIGPIPE.
"""

import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
# The writer, then `| grep` whose own leading option words include q (-q, -qE,
# -iqx, …). Options are matched on the same line only, so a later `-eq` is not
# mistaken for grep's.
PIPE_INTO_GREP_Q = re.compile(
    r"""(?:printf\s+'[^'\n]*'|echo)\s+"\$[^"\n]*"\s*\|[ \t]*grep(?:[ \t]+-[A-Za-z]+)*?[ \t]+-[A-Za-z]*q[A-Za-z]*(?=[ \t]|$)""",
    re.M)


def _shell_scripts():
    out = subprocess.run(["git", "ls-files", "*.sh"], cwd=ROOT, check=True,
                         capture_output=True, text=True, timeout=30).stdout.split()
    return [ROOT / p for p in out if "node_modules" not in p]


def test_no_script_pipes_a_variable_into_grep_q_under_pipefail():
    bad = []
    for path in _shell_scripts():
        text = path.read_text(encoding="utf-8", errors="replace")
        if "pipefail" not in text:
            continue
        joined = re.sub(r"\|\s*\n\s*", "| ", text)  # a pipeline split across lines
        for m in PIPE_INTO_GREP_Q.finditer(joined):
            line = joined.count("\n", 0, m.start()) + 1
            bad.append(f"{path.relative_to(ROOT)}:~{line}: {m.group(0)[:100]}")
    assert not bad, ("variable piped into grep -q under pipefail (a match can read as "
                     "a miss via SIGPIPE) — use `grep -q PAT <<<\"$var\"`:\n  " + "\n  ".join(bad))


def test_the_here_string_form_survives_a_large_input(tmp_path):
    # The failure mode itself, reproduced: 1 MiB of text with the match first.
    script = tmp_path / "t.sh"
    script.write_text(
        "set -euo pipefail\n"
        "big=$(printf 'MATCH\\n'; head -c 1048576 /dev/zero | tr '\\0' 'x')\n"
        "if printf '%s\\n' \"$big\" | grep -q MATCH; then echo pipe=found; else echo pipe=missed; fi\n"
        "if grep -q MATCH <<<\"$big\"; then echo here=found; else echo here=missed; fi\n")
    out = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=60).stdout
    assert "here=found" in out, out
    # Documents why the rule exists; on this kernel the pipe form loses the match.
    assert "pipe=" in out
