# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""tracker 367 — the Python credential backstop, against the SHARED corpus."""

from __future__ import annotations

import io
import json
import logging
import os

import pytest

import log_redact as R

CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "contracts",
                      "log_redaction_corpus.json")


@pytest.fixture(scope="module")
def corpus() -> dict:
    with open(CORPUS, encoding="utf-8") as fh:
        c = json.load(fh)
    assert c["cases"] and c["secrets"] and c["negatives"], "empty corpus proves nothing"
    return c


def test_matches_the_shared_corpus(corpus: dict) -> None:
    for case in corpus["cases"]:
        assert R.redact(case["in"]) == case["out"], case["in"]


def test_negatives_pass_through(corpus: dict) -> None:
    for s in corpus["negatives"]:
        assert R.redact(s) == s


def test_no_seeded_secret_survives_and_idempotent(corpus: dict) -> None:
    for case in corpus["cases"]:
        out = R.redact(case["in"])
        assert not any(sec in out for sec in corpus["secrets"]), out
        assert R.redact(out) == out


def test_formatter_redacts_message_args_and_traceback(corpus: dict) -> None:
    stream = io.StringIO()
    logger = logging.getLogger("test_log_redact_isolated")
    logger.propagate = False
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger.addHandler(handler)
    try:
        # A dedicated logger: install() is exercised on the named loggers below.
        handler.setFormatter(R.RedactingFormatter(handler.formatter))
        logger.warning("push to %s failed", "https://svc:Sup3rS3cretPw@vmauth:8427")
        try:
            raise RuntimeError("password=s3cr3tvalue rejected")
        except RuntimeError:
            logger.exception("boom")
    finally:
        logger.removeHandler(handler)
    out = stream.getvalue()
    assert "Sup3rS3cretPw" not in out and "s3cr3tvalue" not in out, out
    assert "Traceback" in out and "vmauth:8427" in out


def test_install_wraps_root_and_uvicorn_handlers_once() -> None:
    added = []
    for name in ("", "uvicorn", "uvicorn.access"):
        h = logging.StreamHandler(io.StringIO())
        logging.getLogger(name).addHandler(h)
        added.append((name, h))
    try:
        assert R.install() >= len(added)
        assert R.install() == 0, "install() must be idempotent"
        for _name, h in added:
            assert isinstance(h.formatter, R.RedactingFormatter)
    finally:
        for name, h in added:
            logging.getLogger(name).removeHandler(h)
