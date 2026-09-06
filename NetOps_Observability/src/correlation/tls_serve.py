# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""tls_serve.py — mTLS entrypoint for the correlation service (APP-001).

The base compose CMD stays `uvicorn main:app --port 8000` (the documented
plaintext baseline); a TLS deployment's override switches the command to
`python tls_serve.py`. A separate entrypoint, not flags on the base CMD,
because two things the CLI cannot do are required here:

  * `--http` only accepts the literal names auto|h11|httptools
    (uvicorn.config.HTTP_PROTOCOLS) — a custom protocol class, which is the
    only way uvicorn 0.30 can expose the peer certificate, must be passed
    programmatically;
  * the certificate paths and client-CA requirement must FAIL LOUD when
    misconfigured (a KeyError below crashes the container and the
    healthcheck says so) — a silent fallback to plaintext would be exactly
    the downgrade §3 forbids.

CERT_REQUIRED does the transport half (only mesh-CA client certificates can
even complete the handshake); tls_ident.PeerIdentityMiddleware does the
authorization half (which identities may call which paths).
"""

import os
import ssl

import uvicorn

from tls_ident import IdentityH11Protocol


def main() -> None:
    config = uvicorn.Config(
        "main:app",
        host="0.0.0.0",  # nosec B104 — container listener behind the compose network, same bind as the base CMD
        port=int(os.environ.get("CORR_TLS_PORT", "8443")),
        http=IdentityH11Protocol,
        ssl_certfile=os.environ["CORR_TLS_CERT"],
        ssl_keyfile=os.environ["CORR_TLS_KEY"],
        ssl_ca_certs=os.environ["CORR_TLS_CLIENT_CA"],
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        log_level=os.environ.get("LOG_LEVEL", "info").lower(),
    )
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
