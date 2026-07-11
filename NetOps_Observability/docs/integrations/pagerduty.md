# PagerDuty Integration — Setup Guide

Correlix pages PagerDuty through **Events API v2**: alerts that clear the
severity gate trigger PD incidents with stable dedup keys, and **auto-resolve
them when the alert clears** (resolution propagation, 2026-07-11). One alert =
one PD incident for its whole lifecycle — re-fires update, they never
duplicate.

## 1. PagerDuty side (get the Integration Key)

1. Log in to your PagerDuty account → **Services** → **Service Directory**.
2. Either open an existing service or **+ New Service**
   (name: e.g. `Correlix NetOps`; assign the escalation policy that should
   receive network pages).
3. On the service → **Integrations** tab → **+ Add an integration** →
   choose **Events API V2** → **Add**.
4. Copy the 32-character **Integration Key** (a.k.a. routing key). This is
   the only PagerDuty credential Correlix needs.

Treat the key as a secret — it authorizes event submission to your service.

## 2. Correlix side

### UI (preferred)

1. Administrator login → **Administration → Notification channels →
   PagerDuty**.
2. Paste the **Integration Key** (write-only; stored encrypted, shown only as
   `routing key set`).
3. **Minimum severity**: default `critical` — recommended. PD is for waking
   humans; leave `warning`-class chatter to Slack/email.
4. Toggle **Enabled** → **Save** → **Test**. A test event must appear as a
   triggered incident on the PD service (resolve it in PD afterwards).

### API (equivalent)

```bash
curl -X PUT https://<host>/api/notify/pagerduty \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"enabled":true,"routing_key":"<32-char-key>","min_severity":"critical"}'
curl -X POST https://<host>/api/notify/pagerduty/test -H "Authorization: Bearer $TOKEN"
```

Config persists in the encrypted notify store; the legacy `PAGERDUTY_KEY` env
var only seeds it on first boot — the UI/API value is authoritative.

## 3. Behavior details (what to expect)

- **Trigger**: each qualifying alert sends `event_action: trigger` with a
  dedup key derived from the alert identity; PD severity is normalized to the
  Events v2 enum (a 2026-07-11 fix — earlier 400-rejections came from empty
  `source`/non-enum severities).
- **Resolve**: when the alert leaves the engine's active set, Correlix sends
  `event_action: resolve` with the SAME dedup key — the PD incident closes
  itself. No payload needed; gate-suppressed resolves are harmless no-ops.
- **History note**: resolution only fires on clears that happen *after* the
  feature shipped. If your service accumulated a backlog before then,
  bulk-resolve once in the PD UI; the count tracks reality from that point.
- **Severity gate**: applies to triggers only; resolutions always pass
  (closing an incident is never noise).

## 4. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Test button fails, PD shows nothing | Wrong/revoked integration key, or the service uses a different integration type — must be **Events API V2**, not email/API-token integrations. |
| HTTP 400 from PD in api logs | Malformed event — normalized since 2026-07-11; if seen on newer builds, capture the log line and file it. |
| Incidents pile up and never close | Pre-propagation backlog (bulk-resolve once), or the alert never actually clears in Correlix — check the alert's state in the UI before blaming PD. |
| Duplicate incidents for one alert | Should be impossible (dedup key). If observed, compare the `dedup_key` on both PD incidents — differing keys means the alert identity changed (e.g. rule renamed mid-flight). |
| Too many pages | Raise `min_severity` to `critical`, and remember alert-quality work belongs in `rules.yaml`, not in gating everything out at the channel. |
| TLS error on test (lab only) | Versa egress interception — host CA bundle mount in the compose override handles it; restart api if the override was just added. |

## 5. Current limits & roadmap

Today PD is a **platform-global channel driven by raw alerts** with a
severity gate — deliberately simple and engine-independent. The planned
evolution (tracker: PD incident-policy lane) brings it to parity with the
ServiceNow RCA ticketing control plane: per-tenant routing keys, verdict/
severity policy gates on *correlated RCA objects* rather than raw alerts, PD
urgency mapping, and simulator coverage — while keeping a thin policy-free
lane for platform self-health so pages still fire if the correlation engine
itself is down.
