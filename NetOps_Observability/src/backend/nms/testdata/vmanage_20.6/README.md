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
