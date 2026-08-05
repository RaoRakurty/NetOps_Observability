"""test_kafka_security.py — SEC-006.2 regression guards for the consumer's
bus TLS seam. The property under test: plaintext baseline unchanged when
unconfigured, full config yields SSL + the SVID, and a PARTIAL config is a
loud boot failure — never a silent plaintext downgrade (the failure mode
that presents as "the bus is quiet today")."""

import shutil
import ssl
import subprocess

import pytest

from main import kafka_security_kwargs


def test_unconfigured_is_plaintext_baseline():
    assert kafka_security_kwargs(env={}) == {}


@pytest.mark.parametrize("present", [
    {"KAFKA_SSL_CA": "/x/ca.pem"},
    {"KAFKA_SSL_CERT": "/x/c.crt", "KAFKA_SSL_KEY": "/x/c.key"},
    {"KAFKA_SSL_CA": "/x/ca.pem", "KAFKA_SSL_KEY": "/x/c.key"},
])
def test_partial_config_refuses_to_start(present):
    with pytest.raises(RuntimeError, match="refusing a partial TLS config"):
        kafka_security_kwargs(env=present)


def test_full_config_builds_ssl_context(tmp_path):
    if shutil.which("openssl") is None:
        pytest.skip("openssl binary not available to mint a test certificate")
    ca = tmp_path / "ca.pem"
    key = tmp_path / "c.key"
    crt = tmp_path / "c.crt"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(crt), "-days", "1",
         "-subj", "/CN=test"],
        check=True, capture_output=True)
    ca.write_bytes(crt.read_bytes())
    kwargs = kafka_security_kwargs(env={
        "KAFKA_SSL_CA": str(ca),
        "KAFKA_SSL_CERT": str(crt),
        "KAFKA_SSL_KEY": str(key),
    })
    assert kwargs["security_protocol"] == "SSL"
    assert isinstance(kwargs["ssl_context"], ssl.SSLContext)
    # Server verification stays ON — encrypting to an unverified peer would
    # be TLS theatre.
    assert kwargs["ssl_context"].verify_mode == ssl.CERT_REQUIRED
