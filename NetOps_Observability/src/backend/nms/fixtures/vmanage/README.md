# vManage recorded fixtures

| file | captured | source | notes |
|---|---|---|---|
| `bfd_sessions_vedge20.json`, `bfd_sessions_vedge51.json`, `bfd_sessions_cedge81.json` | 2026-10-25 | lab Catalyst SD-WAN Manager 20.6.1, `GET /dataservice/device/bfd/sessions?deviceId=<system-ip>` (read-only) | Real responses, trimmed to the sessions between vEdge-20 (vEdge 20.6.1) and vEdge-51 (vEdge 20.6.1) / cEDGE-81 (IOS XE 17.03.02). Fields kept as returned; only unrelated rows removed. They prove the two ends of one BFD session report MIRRORED fields (`vdevice-name`/`system-ip`, `local-color`/`color`), which `CanonicalTunnelID` relies on. Lab addresses only (RFC 1918 / lab ranges). |
| `tunnel_down.json`, `approute_stats.json` | earlier | — | provenance not recorded at the time |
