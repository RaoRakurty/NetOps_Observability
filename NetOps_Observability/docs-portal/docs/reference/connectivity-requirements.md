---
title: Connectivity requirements
sidebar_label: Connectivity requirements
description: Every listening port, outbound port and internet dependency Correlix uses, with the component that owns each one.
page_type: reference
sidebar_position: 10
---

# Connectivity requirements

Correlix monitors agentlessly, so the requirement is network reachability on a small set of standard ports. Hand the tables below to whoever writes the firewall rules. Open the rows for the telemetry planes you actually use.

Direction is stated from the deployment host's point of view. **Inbound** means something connects to Correlix. **Outbound** means Correlix opens the connection.

## Inbound, published on the host

Every row below is a port the compose stack publishes on the host. Docker binds them on all addresses unless the row says otherwise.

| Port | Protocol | Owner | Purpose | Configured by |
| --- | --- | --- | --- | --- |
| 8000 | TCP | nginx | The console and the REST API. The single front door. | `BASE_PORT`, default 8000 |
| 443 | TCP | nginx | HTTPS front door. Published only when the deployment is installed with TLS. 8000 stays published as well. | `install.py --tls` |
| 514 | UDP | syslog-ng | Syslog. Published unconditionally and additionally to the configurable port. | Not configurable |
| 514 | TCP | syslog-ng | Syslog over TCP, same listener. | Not configurable |
| 5514 | UDP | syslog-ng | Syslog. This is the shipped default port. | `SYSLOG_PORT`, default 5514 |
| 5514 | TCP | syslog-ng | Syslog over TCP. | `SYSLOG_PORT`, default 5514 |
| 162 | UDP | api | SNMP traps. The host mapping is published whether or not the receiver is enabled. | `SNMP_TRAP_PORT`, default 162, mapped to `SNMP_TRAP_LISTEN` `:1162` inside the container |
| 2055 | UDP | goflow2 | NetFlow v5 and v9. | `NETFLOW_PORT`, default 2055 |
| 4739 | UDP | goflow2 | IPFIX. | `IPFIX_PORT`, default 4739 |
| 6343 | UDP | goflow2 | sFlow. | `SFLOW_PORT`, default 6343 |
| 11019 | TCP | api | BMP. The host mapping is published whether or not the receiver is enabled. | `BMP_PORT`, default 11019 |
| 8099 | TCP | mock-servicenow | Test double. Bound to `127.0.0.1` and only under the `mock-snow` compose profile. | `MOCK_SNOW_HOST_PORT` |
| 8098 | TCP | mock-nms | Test double. Bound to `127.0.0.1` and only under the `mock-nms` compose profile. | `MOCK_NMS_HOST_PORT` |

Two of these need saying plainly.

**UDP 162 and TCP 11019 are published even when their features are off.** `FEATURE_SNMP_TRAPS` and `FEATURE_BMP` both default to off, and with the flag off nothing binds inside the container and the routes answer `404`. The host socket is still published by Docker, so a port scan sees it. Nothing is listening behind it.

**Syslog port 514 cannot be turned off from the environment.** The compose file publishes 514 on UDP and TCP in addition to `SYSLOG_PORT`. Setting `SYSLOG_PORT=514` maps the same pair twice.

Nothing else is published. Kafka, PostgreSQL, OpenSearch, VictoriaMetrics, ClickHouse, the correlation engine, Vector, Grafana, Keycloak and NetBox are reachable only inside the compose network. An appliance install exposes the console port and the telemetry receivers, and nothing else.

## Inbound, and unauthenticated

Syslog ingest is unauthenticated at the transport. There is no ACL and no credential on the listener: anything that can route to the port can send a message asserting any hostname. Restrict UDP and TCP 514 and 5514 to your device management ranges at the firewall. That restriction is the access control for this plane.

## Outbound, to your devices

| Port | Protocol | Owner | Purpose | Gate and default |
| --- | --- | --- | --- | --- |
| 161 | UDP | api collectors | SNMP polling, metrics, discovery, LLDP, CDP, tunnel discovery, verification | `ENABLE_SNMP_COLLECTION` and `ENABLE_SNMP_METRICS`, both on. Per-device port override available. |
| ICMP echo | ICMP | api and prober | Reachability, WAN echo, traceroute, ICMP synthetics | Requires `CAP_NET_RAW`. Allow echo request out and echo reply plus time-exceeded and destination-unreachable back. |
| 830 | TCP | api collector | NETCONF | `ENABLE_NETCONF_COLLECTION`, off. When on, it probes every device. |
| 57400 | TCP | gnmic sidecar | gNMI streaming telemetry, TLS. The shipped Nokia SR Linux target. | `ENABLE_GNMI_COLLECTION`, off. The port is set on the device. |
| 6030 | TCP | gnmic sidecar | gNMI streaming telemetry, plaintext. The shipped Arista target. | `ENABLE_GNMI_COLLECTION`, off. |
| 22 | TCP | api SSH gateway | Interactive device SSH from the console | `FEATURE_DEVICE_SSH`, off. |
| 22 | TCP | api | Configuration backup | `FEATURE_CONFIG_BACKUP`, off. Port from `CONFIG_BACKUP_SSH_PORT`, default 22. |
| 22 | TCP | api | Packet capture | `FEATURE_PACKET_CAPTURE`, off. Port from `PCAP_SSH_PORT`, default 22. |
| 22 | TCP | api | Protocol-diagnostics collection | `FEATURE_PROTOCOL_DIAG_COLLECT`, off. Port from `PROTOCOL_DIAG_SSH_PORT`, default 22. |
| 22 | TCP | api | Active verification, read-only SSH | `FEATURE_ACTIVE_VERIFICATION`, off, plus a per-tenant opt-in. |
| 179 | TCP | api collector | BGP-LS session to a route reflector | `ENABLE_BGPLS_DISCOVERY`, off. Peers from `BGPLS_PEERS`. |
| 862 | UDP | prober | STAMP and TWAMP-Light probes | `FEATURE_ACTIVE_PROBE`, off. Per-target port from `STAMP_TARGETS`. |
| 443 | TCP | prober | Traceroute TCP-SYN method, WAN echo TCP fallback, TCP synthetics | `TRACEROUTE_TCP_PORT`, `WAN_ECHO_TCP_PORT` and the synthetics target list, all default 443. |
| Vendor-set | TCP | api | UniFi controller API over HTTPS | `FEATURE_UNIFI`, off. The URL is `UNIFI_URL`. |

## Outbound, to the internet

Every destination below is HTTPS on TCP 443 unless stated. All of them are optional, and all of them are off until the matching feature is configured.

| Destination | Used for | Gate |
| --- | --- | --- |
| Your identity provider | OIDC sign-in | `OIDC_ENABLED`, off. The bundled Keycloak broker is internal. |
| `stat.ripe.net`, `rdap.arin.net` | BGP live feed, RPKI validation, AS-path and registry lookups | `FEATURE_BGP_LIVE_FEED`, `FEATURE_BGP_ALERTS`, both off |
| Geofeed URLs found in registry records | Geofeed resolution. These are arbitrary third-party hosts, fetched through an SSRF-guarded client. | The BGP depth views |
| `team-cymru.org` bogon feed | Full bogon list | `FEATURE_BGP_BOGON_FEED`, off. With it off Correlix uses the embedded IANA set and makes no request. |
| An ASPA provider you host | ASPA validation | `BGP_ASPA_PROVIDER_URL`. There is no default, because no public per-ASN ASPA API exists. |
| `ntfy.sh` | Push notifications | `FEATURE_NTFY_NOTIFICATIONS`. Server overridable. |
| `hooks.slack.com` | Slack notifications | `FEATURE_SLACK_NOTIFICATIONS` |
| `events.pagerduty.com` | PagerDuty events | `FEATURE_PAGERDUTY_NOTIFICATIONS` |
| `api.twilio.com` | SMS | `FEATURE_TWILIO_NOTIFICATIONS` |
| AWS SNS | SNS notifications | `FEATURE_SNS_NOTIFICATIONS` |
| Your SMTP relay | Email notifications | `FEATURE_EMAIL_NOTIFICATIONS`. The port is part of `SMTP_HOST`, for example `smtp.example.com:587`. There is no separate port variable. |
| Your ServiceNow, Jira or Teams endpoint | Ticketing and chat | `SERVICENOW_INSTANCE_URL`, `JIRA_BASE_URL`, `TEAMS_WEBHOOK_URL` |
| `api.anthropic.com`, `api.openai.com`, `generativelanguage.googleapis.com` | The Iris assistant's model provider | `FEATURE_AI`, `FEATURE_COPILOT` |
| AWS, Azure and Google identity and resource endpoints | Cloud connectors | The `cloud-ingest` compose profile plus per-tenant connector configuration |
| DNS, UDP 53 | Every name the platform resolves | Always. Resolvers are set in [System settings](/administration/system-settings) |
| NTP, UDP 123 | Clock-offset measurement | The NTP card in [System settings](/administration/system-settings#ntp-time-sources) |

The vulnerability advisory feed makes no outbound request at runtime. The feed is prepared offline and mounted read only, and the vulnerabilities view reports itself as not enabled until the file exists.

`HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` are honoured for outbound HTTP. `SSRF_ALLOWED_HOSTS` allowlists a private-address destination, which you need when your ticketing system or NetBox is self-hosted on RFC 1918 space.

## Corporate TLS inspection

`OUTBOUND_HTTPS_CA_FILE` names a PEM file holding your inspection proxy's certificate authority. Correlix starts from the system trust pool and **appends** the certificates in that file to it. It never replaces the system pool, and it never disables verification. There is no option that turns certificate verification off.

The failure modes are quiet and safe rather than silent:

- If the file cannot be read, Correlix logs `OUTBOUND_HTTPS_CA_FILE unreadable — outbound TLS uses the system pool only` and continues with the system trust pool.
- If the file holds no usable certificate, it logs `OUTBOUND_HTTPS_CA_FILE held no usable certificates` and continues the same way.
- When the file is used, the transport also pins a TLS 1.2 minimum.

The variable's scope is the outbound fetcher used by the BGP operations views, which is what reaches RIPEstat, RDAP and third-party geofeed hosts. It does not cover notification, ticketing, model-provider or cloud-connector egress. For those, mount your certificate authority into the container's trust directory. The shipped TLS compose variant does this additively with `SSL_CERT_DIR`, deliberately rather than with `SSL_CERT_FILE`, because the latter replaces the root store instead of adding to it.

## Firewall guidance

Work the path in three segments.

1. **Operators to Correlix.** Allow TCP 8000, or 443 on a TLS deployment, from operator networks. Nothing else needs to be reachable by a person.
2. **Correlix to the management network.** Allow UDP 161 and ICMP from the deployment host to your management subnets. Add the gNMI port only for devices you stream from, and TCP 22 only if you enable a device-SSH feature. This direction unblocks discovery and metric polling, so start here.
3. **Devices to Correlix.** Allow the syslog, trap and flow ports from device management addresses. These are push planes: nothing arrives until the devices are also configured to send. See [Send data](/send-data/overview).

:::tip Source addresses decide attribution
For syslog and traps, Correlix attributes a message to a device by its source address. A device must send from an address Correlix knows for it, normally the management address it polls. A message sourced from a loopback, or one whose path applies NAT, arrives and attaches to no device. Fix that with the device's source-interface setting rather than at the firewall.
:::

:::caution UDP does not retransmit
Syslog over UDP, SNMP traps and flow export are fire and forget. A firewall dropping one of these ports produces exactly the symptom of a device that is green for SNMP metrics and stuck on no data for syslog, traps or flows. See [Troubleshooting](/reference/troubleshooting#no-syslog-or-traps). Where the device supports it, syslog over TCP gives reliable delivery.
:::

## What Correlix does not need

- No inbound access to your devices beyond the ports above. There is no agent, and SNMP is read only.
- No connectivity between your devices and the internet. All telemetry terminates at your deployment.
- No egress at all for a deployment with every optional integration off. The vulnerability feed, the bogon feed and the model providers are the dependencies people expect and each one is opt-in.

## Credentials

Reachability gets packets through. These get them answered.

- **SNMP v2c** community or **SNMP v3** user with authentication and privacy, read-only. Managed in [SNMP profiles](/onboard-devices/snmp-profiles).
- **gNMI**: an account the device authorises for telemetry subscriptions.
- **SSH**: a read-only account, needed only for the device-SSH, configuration backup, packet capture, protocol diagnostics and verification features.

## Browser requirements

- A current version of Chrome, Edge, Firefox or Safari.
- JavaScript enabled.
- WebSocket connections permitted to the Correlix host. Live-updating views and the device terminal stream over WebSocket, so a proxy that strips the upgrade header breaks live panels while leaving static pages working.
- No plugins or extensions.

## Related

- [Deployment requirements](/deploy/requirements) for the full prerequisite list.
- [Send data](/send-data/overview) for per-plane device configuration.
- [Troubleshooting](/reference/troubleshooting) for what to check when a plane stays empty.
- [Feature flags](/reference/feature-flags) for every gate named above and its shipped default.
