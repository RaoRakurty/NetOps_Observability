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
- `events_control_connection.json` — the 4 `control-connection-state-change`
  events of the tracker-399 drill (2026-11-25 23:23:32Z, `clear sdwan control
  connections` on cEDGE-80). Recovered READ-ONLY from the connector's own
  `netops.controller_events` messages on the lab bus (the connector keeps
  `event_id`, `event_time`, the reporting `system_ip` / `host_name`, the
  component and `eventname + " " + details` verbatim); `severity_level` is not
  preserved downstream, so it is omitted (a down is high by kind; an up is the
  clear). The real shape: the CONTROLLER reports it (vSmart / vManage,
  `personality=vsmart|vmanage`, `peer-type=vedge` even for a cEdge) and names the
  edge as `peer-system-ip`; the edge reported nothing itself.
