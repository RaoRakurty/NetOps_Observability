"""Structured per-source error reporting (cloud platform backlog Wave 2 #4).

The poller has always LOGGED provider failures ("connector poll error",
"azure cycle error", ...) — but a log line never reaches the product's
Ingestion Status page, so an operator saw "Not configured" when the truth was
"IAM denied flow logs since Tuesday". This module closes that loop:

  classify(exc)  -> "permission_denied" | "misconfigured" | None
                    (403/401-class vs 400/404-class provider errors)
  note(...)      -> record one lane's CURRENT failure (first-seen preserved)
  clear(...)     -> the lane succeeded again; drop its record
  flush()        -> PUT the full current error set to the platform API
                    (/api/cloud/ingest/source-status, full-set replace)

Honesty contract: a poller may only ever report WHY a lane is failing —
never that it is healthy (the backend measures flowing/stale/off itself from
what actually landed). Everything here is best-effort: a reporting hiccup
must never take a poll lane down, and no credential or token ever appears in
a record (provider exception strings carry operation/role names only).

No new dependencies: stdlib + the existing broker_client (requests).
"""
from __future__ import annotations

import json
import time

import broker_client

# Providers' "you may not" error codes (AWS botocore Error.Code values; the
# HTTP-status fallback below covers Azure/GCP urllib errors and anything else).
PERMISSION_CODES = {
    "AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
    "UnauthorizedAccess", "AuthFailure", "ExpiredToken", "ExpiredTokenException",
    "InvalidClientTokenId", "UnrecognizedClientException", "Forbidden",
    "AuthorizationError",
}
# "You asked for something that isn't set up" — a configuration problem, not a
# permission one. NOT retry-fixable; the operator must change the config.
MISCONFIG_CODES = {
    "ResourceNotFoundException", "NoSuchBucket", "NoSuchKey",
    "ValidationError", "ValidationException", "InvalidParameterValue",
    "InvalidParameterException", "NotFound", "BadRequest",
}

FLUSH_EVERY_S = 60.0
MAX_RECORDS = 200
DETAIL_MAX = 200

_active: dict[tuple, dict] = {}
_dirty = False
_last_flush = 0.0


def _log(msg: str, **kw) -> None:
    print(json.dumps({"ts": time.time(), "service": "cloud-ingest",
                      "component": "source-status", "msg": msg, **kw}), flush=True)


def classify(exc: BaseException) -> str | None:
    """Map a provider exception to a reportable source status, or None when it
    is not a permission/configuration failure (timeouts, 5xx, bugs — those keep
    today's log-and-retry handling)."""
    # botocore ClientError: .response is a dict with Error.Code + HTTP status.
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        code = str((resp.get("Error") or {}).get("Code") or "")
        status = (resp.get("ResponseMetadata") or {}).get("HTTPStatusCode") or 0
        if code in PERMISSION_CODES or status in (401, 403):
            return "permission_denied"
        if code in MISCONFIG_CODES or status in (400, 404):
            return "misconfigured"
        return None
    # urllib.error.HTTPError (Azure/GCP lanes): .code is the HTTP status.
    # requests.HTTPError: .response.status_code.
    status = getattr(exc, "code", None)
    if not isinstance(status, int):
        status = getattr(exc, "status_code", None)
    if not isinstance(status, int) and resp is not None:
        status = getattr(resp, "status_code", None)
    if isinstance(status, int):
        if status in (401, 403):
            return "permission_denied"
        if status in (400, 404):
            return "misconfigured"
    return None


def _iso(ts: float) -> str:
    import datetime as _dt
    return (_dt.datetime.fromtimestamp(ts, _dt.timezone.utc)
            .replace(microsecond=0).isoformat().replace("+00:00", "Z"))


def note(provider: str, source_type: str, exc: BaseException, *, tenant: str = "",
         account: str = "", region: str = "", connector_id: str = "") -> str | None:
    """Record one lane's current failure IF it classifies. Returns the status
    ("permission_denied"/"misconfigured") or None when the error is not ours to
    report. First-seen is preserved across repeats so "since Tuesday" holds."""
    global _dirty
    status = classify(exc)
    if status is None:
        return None
    key = (tenant, provider, account, region, source_type)
    prev = _active.get(key)
    _active[key] = {
        "tenant": tenant,
        "connector_id": connector_id,
        "provider": provider,
        "account_id": account,
        "region": region,
        "source_type": source_type,
        "status": status,
        "detail": str(exc)[:DETAIL_MAX],
        "since_iso": prev["since_iso"] if prev else _iso(time.time()),
    }
    if prev != _active[key]:
        _dirty = True
    return status


def clear(provider: str, source_type: str, *, tenant: str = "",
          account: str = "", region: str = "") -> None:
    """The lane succeeded again — drop its record (the next flush clears it
    server-side; full-set replace semantics)."""
    global _dirty
    if _active.pop((tenant, provider, account, region, source_type), None) is not None:
        _dirty = True


def flush(now: float | None = None) -> bool:
    """PUT the full current error set to the platform API. Called once per main
    loop; sends when something changed, and re-sends an unchanged non-empty set
    every FLUSH_EVERY_S so records never expire server-side while the failure
    persists. Never raises. Returns True when a report was sent."""
    global _dirty, _last_flush
    if not broker_client.configured():
        return False
    now = time.time() if now is None else now
    if not _dirty and not (_active and now - _last_flush >= FLUSH_EVERY_S):
        return False
    records = list(_active.values())[:MAX_RECORDS]
    try:
        broker_client.put_source_status(records)
    except Exception as exc:  # noqa: BLE001 — reporting must never hurt polling
        _log("source-status report failed", error=str(exc)[:200])
        return False
    _dirty = False
    _last_flush = now
    if records:
        _log("source-status reported", records=len(records))
    return True


def reset() -> None:
    """Test hook: forget all local state."""
    global _dirty, _last_flush
    _active.clear()
    _dirty = False
    _last_flush = 0.0
