# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The generated .env never gives a key an inline comment as its value.

Found on the lab (2026-11-13): the api logged
`region "# e.g. us-east-1" is not a valid AWS region`. The template wrote

    AWS_REGION=                    # e.g. us-east-1

and an env-file reader trims the blank before the `#`, so an EMPTY value
followed by a comment becomes the comment itself. A key with a real value
(`JIRA_MIN_SEVERITY=critical   # …`) is unaffected, because its `#` follows
a space inside the value. So the rule pinned here is narrow: no line may
assign a key whose value, once trimmed, starts with `#`.

It reads the .env `write_env` actually renders (the customer path), not the
template source, and checks it with both readers that matter: the
installer's own parser and the "trim, then take the rest" reading that
produced the lab error.

No docker. Run: python3 -m pytest tests/test_install_env_inline_comments.py -v
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

ASSIGN = re.compile(r"^\s*([A-Z][A-Z0-9_]*)=(.*)$")


def _render(tmp_path: Path) -> str:
    sys.path.insert(0, str(SCRIPTS))
    import install  # noqa: PLC0415 — the installer is a script, imported by path
    env_path = tmp_path / ".env"
    install.write_env(env_path, 8000, force=True)
    return env_path.read_text()


def test_no_key_takes_a_comment_as_its_value(tmp_path):
    text = _render(tmp_path)
    offenders = []
    for n, line in enumerate(text.splitlines(), start=1):
        m = ASSIGN.match(line)
        if m and m.group(2).strip().startswith("#"):
            offenders.append(f"line {n}: {m.group(1)}")
    assert offenders == [], (
        "these keys would read a comment as their value — put the comment on "
        "its own line above the key: " + ", ".join(offenders)
    )


def test_installer_parser_agrees(tmp_path):
    sys.path.insert(0, str(SCRIPTS))
    import install  # noqa: PLC0415
    parsed = install._parse_env_text(_render(tmp_path))
    bad = sorted(k for k, v in parsed.items() if v.startswith("#"))
    assert bad == [], f"keys whose parsed value is a comment: {bad}"


def test_the_formerly_broken_keys_are_present_and_empty(tmp_path):
    sys.path.insert(0, str(SCRIPTS))
    import install  # noqa: PLC0415
    parsed = install._parse_env_text(_render(tmp_path))
    for key in ("AWS_REGION", "SNS_PHONE_NUMBERS", "SMTP_HOST", "JIRA_BASE_URL",
                "SERVICENOW_INSTANCE_URL", "OIDC_ISSUER"):
        assert key in parsed, f"{key} disappeared from the rendered .env"
        assert parsed[key] == "", f"{key} should render empty, got a value"
