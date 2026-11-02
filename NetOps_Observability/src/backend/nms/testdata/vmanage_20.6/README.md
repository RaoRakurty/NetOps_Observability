# vManage 20.6.1 — recorded payloads

Captured read-only from the lab Catalyst SD-WAN Manager (20.6.1) on 2026-11-01
for tracker 371 / the source-equivalence programme (E2a):

- `alarms.json` — `POST /dataservice/alarms` (last 168 h), all 20 alarms, fields
  trimmed to those the connector reads. Note the real shape: the device is in
  `devices[].system-ip` and context in `values[]`, not top-level fields.
- `events.json` — `POST /dataservice/event` (last 168 h), two examples of each
  event name / BGP state seen (bgp-peer-state-change, cpu-usage,
  tunnel-ipsec-rekey, system-login/logout-change).
- `alarm_rules.json` — `GET /dataservice/alarms/rulenamedisplay/keyvalue`: the
  release's full alarm-rule vocabulary (99 distinct keys; the endpoint returns 106 entries including blanks and a duplicate). Every key must be mapped or
  explicitly unclassified in vmanage.go (vmanageAlarmKinds /
  vmanageUnclassifiedAlarms); a new release's new rule fails the test.
- `auditlog.json` — `GET /dataservice/auditlog?count=500` (2026-11-02, E5b):
  the release's real AuditLogEntry field set (`logid, entry_time,
  statcycletime, logmodule, logfeature, loguser, logusersrcip, logmessage,
  logdeviceid, auditdetails[], tenant, id`), one example of each of the two
  entry kinds the lab held (all 119 were module `user`: logins and session
  timeouts — no change had been made in the window). Note the payload's own
  `tenant` field ("default", vManage's tenancy): the transform must never read
  it; the tenant is the integration's (§3a).
