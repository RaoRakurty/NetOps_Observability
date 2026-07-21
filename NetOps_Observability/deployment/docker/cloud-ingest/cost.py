"""Cloud cost ingestion (cloud platform backlog Wave 5 #18, slice 1).

Daily provider-billed cost per (tenant, provider, account, service, day) →
normalized cloud_cost records on the Kafka cost topic (netops.cloudcosts). The
vector-router lands them in ClickHouse netops.cloud_costs (slice 2); the API
serves them tenant-scoped as /api/cloud/costs.

Lanes (each polls only where the credential actually allows):
  aws    Cost Explorer GetCostAndUsage — DAILY granularity, grouped by
         SERVICE + LINKED_ACCOUNT. NOTE: AWS METERS this API ($0.01/request),
         which is why the lane is daily-cadence (COST_EVERY_S, default 6h ⇒
         ~4 requests/day) and toggleable (CLOUD_COST_LANES=off), mirroring the
         AWS_METERED_METRICS cost-tier policy.
  azure  Cost Management query API (plain ARM token, Cost Management Reader) —
         Daily granularity grouped by ServiceName. Free, rate-limited.
  gcp    HONEST GAP: GCP exposes actual daily spend ONLY via the BigQuery
         billing export (infra-heavy, out of scope here). The plain-token
         Cloud Billing API surface confirms billing LINKAGE
         (projects.getBillingInfo) but carries no spend, and the Budgets API
         carries limits, not spend. This lane therefore emits NO cost records
         — a fabricated number would violate the honesty contract — and
         reports the gap as a structured source-status note ("cost: not
         enabled — requires BigQuery billing export") instead of silent zeros.

Discipline (mirrors the poller's other lanes):
  * checkpointed like trail_state: the per-lane state dict carries the last
    complete day fetched; each cycle re-reads a small RESTATE window because
    providers restate recent days (AWS documents up to ~72 h), and the
    ClickHouse ReplacingMergeTree dedupes the re-emits. Never regresses.
  * bounded everything: backfill days, records per lane per cycle, pages per
    request, connector count and wall-clock budget.
  * per-connector isolation: one failing connector/lane never kills the cycle
    (the connector_cycle pattern).
  * honesty: a permission/misconfiguration failure becomes a structured
    source_status record ("cost: permission denied since <t>") the Ingestion
    page can render — never a silent 0.

Dependencies: boto3 (already a poller dep, connector lane only, deferred
import) + stdlib urllib for the Azure/GCP REST lanes (the azure.py posture).
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import time
import urllib.request

import broker_client
import ingest_metrics
import source_status

COST_TOPIC = os.environ.get("COST_TOPIC", "netops.cloudcosts")
# Daily-granularity data: polling faster than a few hours only re-reads the
# same figures (and, on AWS, bills another metered request).
COST_EVERY_S = int(os.environ.get("COST_EVERY_S", str(6 * 3600)))
# Cost-tier policy toggle (same model as AWS_METERED_METRICS): off = the lane
# is honestly disabled, never silently missing.
COST_LANES = os.environ.get("CLOUD_COST_LANES", "on").lower() != "off"
# Providers restate recent days; re-read this many trailing days each cycle.
COST_RESTATE_DAYS = int(os.environ.get("COST_RESTATE_DAYS", "3"))
# First run backfills at most this much history.
COST_BACKFILL_DAYS = int(os.environ.get("COST_BACKFILL_DAYS", "30"))
# Emission cap per lane per cycle — a runaway grouping can never flood the bus.
COST_MAX_RECORDS = int(os.environ.get("COST_MAX_RECORDS", "5000"))
COST_MAX_PAGES = int(os.environ.get("COST_MAX_PAGES", "20"))
# Connector pass bounds (the connector_cycle pattern).
COST_CONNECTOR_MAX = int(os.environ.get("COST_CONNECTOR_MAX", "25"))
COST_CONNECTOR_BUDGET_S = int(os.environ.get("COST_CONNECTOR_BUDGET_S", "240"))
# How long a lane waits for the broker to acknowledge its records before it
# declares the flush failed and HOLDS the day checkpoint (see flush_verified).
COST_FLUSH_TIMEOUT_S = int(os.environ.get("COST_FLUSH_TIMEOUT_S", "30"))

TENANT = os.environ.get("CLOUD_TENANT", "global")
ACCOUNT = os.environ.get("CLOUD_ACCOUNT", "")
# Cost Explorer is a global endpoint homed in us-east-1.
CE_REGION = "us-east-1"

ARM_BASE = "https://management.azure.com"
COSTMGMT_API_VERSION = "2023-03-01"
GCP_BILLING_BASE = "https://cloudbilling.googleapis.com/v1"

# ── the normalized cost record (the ONE shape all lanes emit) ────────────────

COST_RECORD_FIELDS: tuple[str, ...] = (
    "kind", "tenant_id", "provider", "account", "service", "day",
    "amount", "currency", "granularity", "collection_path", "ts",
)

COLLECTION_PATHS: dict[str, str] = {
    "aws": "aws_cost_explorer",
    "azure": "azure_cost_management",
    "gcp": "gcp_billing_bq_export",  # what WOULD produce it — lane dormant (honest gap)
}

_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def cost_record(*, provider: str, tenant: str, account: str, service: str,
                day: str, amount: float, currency: str, ts: str,
                collection_path: str = "") -> dict:
    """Build one normalized cloud_cost record. Every identifying field is
    required and validated loudly (the cloud_events.py discipline): a blank
    field would silently mis-route or vanish downstream. `amount` may be
    negative (credits/refunds are real cost records) but must be numeric."""
    cp = collection_path or COLLECTION_PATHS.get(provider, "")
    required = {
        "provider": provider, "tenant_id": tenant, "account": account,
        "service": service, "currency": currency, "ts": ts,
        "collection_path": cp,
    }
    for name, val in required.items():
        if not isinstance(val, str) or not val.strip():
            raise ValueError(f"cost_record: missing/blank {name!r}")
    if not isinstance(day, str) or not _DAY_RE.match(day):
        raise ValueError(f"cost_record: bad day {day!r} (want YYYY-MM-DD)")
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        raise ValueError("cost_record: amount must be numeric")
    return {
        "kind": "cloud_cost",
        "tenant_id": tenant,
        "provider": provider,
        "account": account,
        "service": service,
        "day": day,
        "amount": float(amount),
        "currency": currency,
        "granularity": "daily",
        "collection_path": cp,
        "ts": ts,
    }


# ── checkpoint core (pure — the trail_state discipline for a day-keyed lane) ──

def poll_window(last_day: str, today: str) -> tuple[str, str] | None:
    """[start, end) day window to fetch, complete days only (end = today,
    exclusive — the in-flight day is never read, the cloudmetrics P0-2 rule).

    * no checkpoint → backfill COST_BACKFILL_DAYS;
    * checkpoint → resume after it, minus the RESTATE overlap (providers
      restate recent days; ReplacingMergeTree dedupes the re-emit);
    * never regresses past the backfill horizon; None when nothing to fetch.
    """
    end = dt.date.fromisoformat(today)
    horizon = end - dt.timedelta(days=max(1, COST_BACKFILL_DAYS))
    if last_day and _DAY_RE.match(last_day):
        start = dt.date.fromisoformat(last_day) - dt.timedelta(days=max(0, COST_RESTATE_DAYS - 1))
        start = max(start, horizon)
    else:
        start = horizon
    if start >= end:
        return None
    return start.isoformat(), end.isoformat()


def advance_day_checkpoint(last_day: str, today: str) -> str:
    """Checkpoint after a successful poll: the newest COMPLETE day (yesterday).
    Never regresses (the trail_state rule)."""
    newest = (dt.date.fromisoformat(today) - dt.timedelta(days=1)).isoformat()
    if last_day and _DAY_RE.match(last_day) and last_day > newest:
        return last_day
    return newest


def _today() -> str:
    return dt.datetime.now(dt.timezone.utc).date().isoformat()


def _now_iso() -> str:
    return (dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
            .isoformat().replace("+00:00", "Z"))


def _log(msg: str, **kw) -> None:
    print(json.dumps({"ts": time.time(), "service": "cloud-ingest",
                      "component": "cost", "msg": msg, **kw}), flush=True)


def _emit(producer, records: list[dict]) -> int:
    for rec in records:
        producer.send(COST_TOPIC, rec)
    return len(records)


def _delivery_failures(producer) -> int:
    """Records the producer KNOWS it failed to deliver (GuardedProducer).
    0 when the producer does not track them (tests, plain KafkaProducer) — the
    flush result is then the only evidence, which is still strictly better than
    advancing blind."""
    n = getattr(producer, "failed_count", None)
    return n if isinstance(n, int) else 0


def flush_verified(producer, lane: str, mark: int) -> bool:
    """Block until this lane's records are acknowledged, and report whether ALL
    of them made it (`mark` = the delivery-failure count taken BEFORE emitting).

    The cost checkpoint is the only record that a billing day was fetched, and
    the lane is on a 6-hour cadence with a short restate window: advancing it
    over records that were never delivered loses a full day of a customer's
    billing data permanently, because the next poll window starts after the
    checkpoint and never looks back. So the order is flush → verify → advance,
    and a failure is LOUD and holds the checkpoint (the next cycle re-reads the
    same window; ClickHouse's ReplacingMergeTree dedupes the re-emit, so a
    retry is free and idempotent).
    """
    try:
        producer.flush(COST_FLUSH_TIMEOUT_S)
    except Exception as exc:  # noqa: BLE001 — classified into the return value
        ingest_metrics.record_flush_failure(f"cost_{lane}")
        _log("cost flush FAILED — day checkpoint HELD BACK (window will be re-read)",
             lane=lane, error=str(exc)[:200])
        return False
    lost = _delivery_failures(producer) - mark
    if lost > 0:
        ingest_metrics.record_flush_failure(f"cost_{lane}")
        _log("cost records LOST in delivery — day checkpoint HELD BACK",
             lane=lane, lost_records=lost)
        return False
    return True


# ── AWS: Cost Explorer GetCostAndUsage ───────────────────────────────────────

def poll_aws(ce, producer, tenant: str, account: str, st: dict,
             today: str | None = None) -> int:
    """One AWS cost poll: daily UnblendedCost grouped by SERVICE +
    LINKED_ACCOUNT over the checkpointed window. Returns records emitted.
    Raises provider errors to the caller (which classifies them into a
    structured source-status record)."""
    today = today or _today()
    win = poll_window(st.get("cost_day", ""), today)
    if win is None:
        return 0
    start, end = win
    ts = _now_iso()
    sent = 0
    token = None
    truncated = False
    mark = _delivery_failures(producer)
    for _ in range(max(1, COST_MAX_PAGES)):
        kw = {
            "TimePeriod": {"Start": start, "End": end},
            "Granularity": "DAILY",
            "Metrics": ["UnblendedCost"],
            "GroupBy": [{"Type": "DIMENSION", "Key": "SERVICE"},
                        {"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"}],
        }
        if token:
            kw["NextPageToken"] = token
        resp = ce.get_cost_and_usage(**kw)
        batch: list[dict] = []
        for day_bucket in resp.get("ResultsByTime", []):
            day = (day_bucket.get("TimePeriod") or {}).get("Start", "")
            for g in day_bucket.get("Groups", []):
                keys = g.get("Keys") or []
                service = (keys[0] if len(keys) > 0 else "") or "unattributed"
                acct = (keys[1] if len(keys) > 1 else "") or account or "unknown"
                m = (g.get("Metrics") or {}).get("UnblendedCost") or {}
                try:
                    amount = float(m.get("Amount", ""))
                except (TypeError, ValueError):
                    continue  # a non-numeric provider row is dropped, not guessed
                if sent + len(batch) >= COST_MAX_RECORDS:
                    truncated = True
                    break
                batch.append(cost_record(
                    provider="aws", tenant=tenant, account=acct, service=service,
                    day=day, amount=amount, currency=m.get("Unit") or "USD", ts=ts))
            if truncated:
                break
        sent += _emit(producer, batch)
        token = resp.get("NextPageToken")
        if not token or truncated:
            break
    if truncated:
        _log("aws cost emission capped", cap=COST_MAX_RECORDS, window=[start, end])
    # flush → verify → THEN advance. The checkpoint must never move past
    # records the broker has not acknowledged (flush_verified explains why).
    if sent and not flush_verified(producer, "aws", mark):
        return sent
    st["cost_day"] = advance_day_checkpoint(st.get("cost_day", ""), today)
    return sent


# ── Azure: Cost Management query (plain ARM token, urllib — azure.py posture) ─

def _azure_cost_query(tok: str, subscription: str, start: str, end_incl: str) -> dict:
    url = (f"{ARM_BASE}/subscriptions/{subscription}/providers/"
           f"Microsoft.CostManagement/query?api-version={COSTMGMT_API_VERSION}")
    body = json.dumps({
        "type": "ActualCost",
        "timeframe": "Custom",
        "timePeriod": {"from": f"{start}T00:00:00Z", "to": f"{end_incl}T23:59:59Z"},
        "dataset": {
            "granularity": "Daily",
            "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"}},
            "grouping": [{"type": "Dimension", "name": "ServiceName"}],
        },
    }).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Authorization": "Bearer " + tok, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 - fixed ARM host
        return json.loads(r.read().decode())


def _usage_day(v) -> str:
    """Azure UsageDate (20260711 int or '2026-07-11T...' string) → YYYY-MM-DD."""
    s = str(v)
    if _DAY_RE.match(s[:10]):
        return s[:10]
    if re.match(r"^\d{8}$", s):
        return f"{s[0:4]}-{s[4:6]}-{s[6:8]}"
    return ""


def poll_azure(tok: str, producer, tenant: str, subscription: str, st: dict,
               today: str | None = None) -> int:
    """One Azure cost poll: Daily ActualCost grouped by ServiceName over the
    checkpointed window. Column order is discovered from the response's own
    columns list — never assumed. Raises provider errors to the caller."""
    today = today or _today()
    win = poll_window(st.get("cost_day", ""), today)
    if win is None:
        return 0
    start, end = win
    end_incl = (dt.date.fromisoformat(end) - dt.timedelta(days=1)).isoformat()
    mark = _delivery_failures(producer)
    resp = _azure_cost_query(tok, subscription, start, end_incl)
    props = resp.get("properties") or {}
    cols = [str(c.get("name", "")).lower() for c in (props.get("columns") or [])]
    try:
        i_cost = cols.index("cost")
        i_day = cols.index("usagedate")
        i_svc = cols.index("servicename")
    except ValueError:
        _log("azure cost response missing expected columns", columns=cols)
        return 0
    i_cur = cols.index("currency") if "currency" in cols else -1
    ts = _now_iso()
    batch: list[dict] = []
    truncated = False
    for row in props.get("rows") or []:
        if len(batch) >= COST_MAX_RECORDS:
            truncated = True
            break
        try:
            amount = float(row[i_cost])
        except (TypeError, ValueError, IndexError):
            continue
        day = _usage_day(row[i_day]) if i_day < len(row) else ""
        if not day:
            continue
        service = (str(row[i_svc]) if i_svc < len(row) and row[i_svc] else "unattributed")
        currency = (str(row[i_cur]) if 0 <= i_cur < len(row) and row[i_cur] else "USD")
        batch.append(cost_record(
            provider="azure", tenant=tenant, account=subscription, service=service,
            day=day, amount=amount, currency=currency, ts=ts))
    sent = _emit(producer, batch)
    if truncated:
        _log("azure cost emission capped", cap=COST_MAX_RECORDS, window=[start, end])
    # flush → verify → THEN advance (see flush_verified).
    if sent and not flush_verified(producer, "azure", mark):
        return sent
    st["cost_day"] = advance_day_checkpoint(st.get("cost_day", ""), today)
    return sent


# ── GCP: honest gap (no spend without the BigQuery billing export) ───────────

GCP_COST_GAP_DETAIL = ("cost API not enabled: GCP daily spend requires the BigQuery "
                       "billing export; the plain-token Cloud Billing API exposes "
                       "billing linkage and budgets, not spend")


def poll_gcp(tok: str, tenant: str, project: str, *,
             connector_id: str = "") -> dict:
    """GCP cost lane: confirm billing linkage with the plain token, then report
    the honest gap — NO records are emitted (there is no spend surface without
    the BigQuery export, and we never fabricate). A 401/403 on the linkage read
    raises to the caller (classified there like every other lane)."""
    url = f"{GCP_BILLING_BASE}/projects/{project}/billingInfo"
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + tok})
    with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 - fixed Google host
        info = json.loads(r.read().decode())
    billing_enabled = bool(info.get("billingEnabled"))
    detail = GCP_COST_GAP_DETAIL if billing_enabled else \
        "cost API not enabled: project has no active billing account"
    # Structured, renderable state — never a silent zero (Wave 2 #4 discipline).
    source_status.note_status(
        "gcp", "cost", "misconfigured", detail,
        tenant=tenant, account=project, connector_id=connector_id)
    return {"records": 0, "billing_enabled": billing_enabled,
            "status": "no_spend_api"}


# ── cycle orchestration (the connector_cycle pattern) ────────────────────────

def _connector_scope(conn: dict) -> tuple[str, str]:
    """(account_ref, region) from the connector's declared scopes — same
    precedence as poller._connector_scope (kept local: cost.py must stay
    importable without pulling the poller's boto3/kafka module graph)."""
    account, region = "", ""
    for sc in conn.get("scopes") or []:
        if sc.get("type") == "region" and not region:
            region = sc.get("ref", "")
            continue
        if not account:
            account = sc.get("ref", "")
            if sc.get("regions") and not region:
                region = sc["regions"][0]
    return account, region


def _poll_connector_cost(conn: dict, creds: dict, producer, cst: dict) -> int:
    """Cost poll for ONE connector with ITS short-lived credential; everything
    emitted is owned by the CONNECTOR's tenant (server truth, never local env)."""
    provider = str(conn.get("provider", ""))
    account, _region = _connector_scope(conn)
    if provider == "aws":
        import boto3  # deferred: poller dep, not needed for the pure/test paths
        session = boto3.Session(
            aws_access_key_id=creds.get("aws_access_key_id", ""),
            aws_secret_access_key=creds.get("aws_secret_access_key", ""),
            aws_session_token=creds.get("aws_session_token", ""),
            region_name=CE_REGION)
        return poll_aws(session.client("ce"), producer, conn["tenant"],
                        account, cst)
    if provider == "azure":
        return poll_azure(creds.get("token", ""), producer, conn["tenant"],
                          account, cst)
    if provider == "gcp":
        poll_gcp(creds.get("token", ""), conn["tenant"], account,
                 connector_id=str(conn.get("id", "")))
        return 0
    return 0


def connector_pass(producer, st: dict) -> dict:
    """Per-connector cost polling: list enabled connectors, mint a short-lived
    credential per connector, poll ITS provider's cost surface. FAILURE
    ISOLATION per connector; bounded count + wall clock (connector_cycle)."""
    started = time.time()
    counts = {"connectors": 0, "failed": 0, "skipped": 0}
    if not broker_client.configured():
        return counts
    try:
        conns = broker_client.list_connectors()
    except Exception as exc:  # noqa: BLE001 — broker outage never kills the cycle
        _log("cost connector list failed", error=str(exc)[:200])
        return counts
    if len(conns) > COST_CONNECTOR_MAX:
        _log("cost connector list truncated", total=len(conns), cap=COST_CONNECTOR_MAX)
        conns = conns[:COST_CONNECTOR_MAX]
    for conn in conns:
        cid = str(conn.get("id", ""))
        provider = str(conn.get("provider", ""))
        if time.time() - started > COST_CONNECTOR_BUDGET_S:
            counts["skipped"] += 1
            continue
        if provider not in ("aws", "azure", "gcp") or not cid or not conn.get("tenant"):
            counts["skipped"] += 1
            continue
        acct, reg = _connector_scope(conn)
        cst = st.setdefault("connectors", {}).setdefault(cid, {})
        try:
            creds = broker_client.credentials(cid)  # short-lived; memory only
            n = _poll_connector_cost(conn, creds, producer, cst)
            counts["connectors"] += 1
            if provider != "gcp":  # gcp writes its own honest-gap status inside
                source_status.clear(provider, "cost", tenant=conn["tenant"],
                                    account=acct, region=reg)
            _log("connector cost polled", connector=cid, provider=provider,
                 tenant=conn["tenant"], records=n)
        except Exception as exc:  # noqa: BLE001 — per-connector isolation
            counts["failed"] += 1
            status = source_status.note(provider, "cost", exc,
                                        tenant=conn["tenant"], account=acct,
                                        region=reg, connector_id=cid)
            _log("connector cost error", connector=cid, provider=provider,
                 classified=status or "", error=str(exc)[:200])
    if counts["skipped"]:
        _log("cost connector budget/skip", **counts)
    return counts


def run(producer, st: dict, *, session=None, azure_mod=None, gcp_mod=None) -> dict:
    """One full cost cycle: ambient lanes (poller-local credentials, TENANT-
    owned) + the per-connector pass. Every lane is its own failure domain.
    `azure_mod` / `gcp_mod` are the provider modules (injected for tests);
    None ⇒ import the real ones."""
    if not COST_LANES:
        return {"disabled": True}
    if azure_mod is None:
        import azure as azure_mod  # noqa: PLC0415
    if gcp_mod is None:
        import gcp as gcp_mod  # noqa: PLC0415
    cst = st.setdefault("cost", {})
    counts = {"aws": 0, "azure": 0, "gcp": 0}
    produced = False

    if session is not None:
        try:
            ce = session.client("ce", region_name=CE_REGION)
            counts["aws"] = poll_aws(ce, producer, TENANT, ACCOUNT,
                                     cst.setdefault("aws", {}))
            produced = produced or counts["aws"] > 0
            source_status.clear("aws", "cost", tenant=TENANT, account=ACCOUNT)
        except Exception as exc:  # noqa: BLE001 — lane isolation
            status = source_status.note("aws", "cost", exc, tenant=TENANT, account=ACCOUNT)
            _log("aws cost lane error", classified=status or "", error=str(exc)[:200])

    if azure_mod.configured():
        try:
            tok = azure_mod.token()
            counts["azure"] = poll_azure(tok, producer, TENANT,
                                         azure_mod.SUBSCRIPTION,
                                         cst.setdefault("azure", {}))
            produced = produced or counts["azure"] > 0
            source_status.clear("azure", "cost", tenant=TENANT,
                                account=azure_mod.SUBSCRIPTION)
        except Exception as exc:  # noqa: BLE001 — lane isolation
            status = source_status.note("azure", "cost", exc, tenant=TENANT,
                                        account=azure_mod.SUBSCRIPTION)
            _log("azure cost lane error", classified=status or "", error=str(exc)[:200])

    if gcp_mod.configured():
        try:
            poll_gcp(gcp_mod.token(), TENANT, gcp_mod.PROJECT)
        except Exception as exc:  # noqa: BLE001 — lane isolation
            status = source_status.note("gcp", "cost", exc, tenant=TENANT,
                                        account=gcp_mod.PROJECT)
            _log("gcp cost lane error", classified=status or "", error=str(exc)[:200])

    conn_counts = connector_pass(producer, cst)
    counts.update({f"connector_{k}": v for k, v in conn_counts.items()})
    # Cycle-closing flush. Each lane already flushed + verified before it moved
    # its own checkpoint; this catches anything a lane emitted without one (and
    # the failure is REPORTED, not swallowed — a silently discarded flush error
    # is how a day of billing records used to disappear).
    if produced or conn_counts.get("connectors"):
        try:
            producer.flush(COST_FLUSH_TIMEOUT_S)
        except Exception as exc:  # noqa: BLE001 — observable, never fails the cycle
            ingest_metrics.record_flush_failure("cost_cycle")
            counts["flush_failed"] = 1
            _log("cost cycle flush FAILED — records may be undelivered",
                 error=str(exc)[:200])
    return counts
