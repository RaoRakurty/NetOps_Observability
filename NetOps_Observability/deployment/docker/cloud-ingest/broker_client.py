"""Connector-registry / token-broker client (cloud platform backlog Wave 1 #2).

Per-tenant ingestion: the poller never holds long-lived per-tenant cloud
credentials. It authenticates to the platform API with ONE dedicated service
credential — a platform-realm API key carrying the `ingest:cloud` scope — and,
per cycle, asks the backend:

  GET  /api/cloud/ingest/connectors                   which connectors to poll
  POST /api/cloud/ingest/connectors/{id}/credentials  a SHORT-LIVED provider
                                                      credential minted by the
                                                      backend identity broker
  PUT  /api/cloud/ingest/connectors/{id}/inventory    discovered inventory
                                                      (tenant stamped SERVER-side
                                                      from the connector row)

Security posture (zero-trust §3):
  - the API key and every provider credential live in MEMORY ONLY — never
    written to disk, never logged, never placed in an error message;
  - error strings carry only method/path/status/exception-type;
  - all calls are bounded (connect+read timeouts) and retried with
    backoff + jitter (§9); 4xx is terminal (an auth/validation failure will
    not fix itself by retrying).

Config (all env):
  BROKER_API_URL        e.g. http://api:8080 — empty ⇒ connector mode OFF
                        (the ambient-credential lanes keep running unchanged)
  BROKER_API_KEY        the ntk_ service key, or
  BROKER_API_KEY_FILE   path to a file holding it (preferred: keeps the secret
                        out of `docker inspect`)
"""
from __future__ import annotations

import os
import random
import time

import requests

API_URL = os.environ.get("BROKER_API_URL", "").rstrip("/")
KEY_FILE = os.environ.get("BROKER_API_KEY_FILE", "")
CONNECT_TIMEOUT_S = float(os.environ.get("BROKER_CONNECT_TIMEOUT_S", "5"))
READ_TIMEOUT_S = float(os.environ.get("BROKER_READ_TIMEOUT_S", "30"))
RETRIES = int(os.environ.get("BROKER_RETRIES", "3"))
BACKOFF_CAP_S = 8.0


class BrokerError(RuntimeError):
    """A broker call failed. The message NEVER contains credentials or bodies."""


def _api_key() -> str:
    """The service API key — read fresh each call so a rotated key file takes
    effect without a restart. Never logged."""
    if KEY_FILE:
        try:
            with open(KEY_FILE, encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            return ""
    return os.environ.get("BROKER_API_KEY", "").strip()


def configured() -> bool:
    """Connector mode is ON only when both the URL and the key are present."""
    return bool(API_URL and _api_key())


def _request(method: str, path: str, body: dict | None = None) -> dict:
    """One bounded, retried JSON call. 5xx / transport errors are retried with
    exponential backoff + jitter; 4xx is terminal. Raises BrokerError with a
    SANITIZED message (method/path/status only) on final failure."""
    url = API_URL + path
    last: BrokerError | None = None
    for attempt in range(max(1, RETRIES)):
        if attempt:
            time.sleep(min(BACKOFF_CAP_S, 2.0 ** attempt) * (0.5 + random.random()))
        try:
            resp = requests.request(
                method, url, json=body if body is not None else None,
                headers={"Authorization": "Bearer " + _api_key()},
                timeout=(CONNECT_TIMEOUT_S, READ_TIMEOUT_S))
        except requests.RequestException as exc:
            last = BrokerError(f"{method} {path}: {type(exc).__name__}")
            continue
        if resp.status_code < 400:
            try:
                return resp.json() or {}
            except ValueError as exc:
                raise BrokerError(f"{method} {path}: bad JSON ({type(exc).__name__})") from None
        if resp.status_code < 500:
            # Terminal: 401/403 (credential), 404 (connector gone), 4xx contract.
            raise BrokerError(f"{method} {path} -> {resp.status_code}")
        last = BrokerError(f"{method} {path} -> {resp.status_code}")
    raise last if last is not None else BrokerError(f"{method} {path}: no attempt ran")


def list_connectors() -> list[dict]:
    """The enabled (ACTIVE) connectors the poller should poll — id, tenant,
    provider, scopes. NO secrets, no trust metadata."""
    return (_request("GET", "/api/cloud/ingest/connectors")).get("connectors") or []


def credentials(connector_id: str) -> dict:
    """A short-lived provider credential for ONE connector, minted server-side
    by the identity broker. Held in memory only; never persisted or logged."""
    return _request("POST", f"/api/cloud/ingest/connectors/{connector_id}/credentials", body={})


def put_inventory(connector_id: str, doc: dict) -> dict:
    """Deliver one inventory snapshot. The backend stamps the TENANT from the
    connector row — nothing this client sends can change the owner."""
    return _request("PUT", f"/api/cloud/ingest/connectors/{connector_id}/inventory", body=doc)


def put_source_status(records: list[dict]) -> dict:
    """Report the poller's CURRENT per-source error set (permission_denied /
    misconfigured), full-set replace semantics (Wave 2 #4). Records naming a
    connector_id get tenant+provider stamped from the connector row server-side."""
    return _request("PUT", "/api/cloud/ingest/source-status", body={"records": records})
