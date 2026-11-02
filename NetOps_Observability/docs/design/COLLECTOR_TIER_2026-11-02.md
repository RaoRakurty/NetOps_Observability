# Collector tier and cloud ingestion — plan of record (2026-11-02)

**Status:** APPROVED by the owner 2026-11-02 ("I like it and let's go ahead").
**Implementation:** tracker 372 — **starts only after the Iris work is complete**
(owner 2026-11-02). Nothing below is built yet.

Supersedes §3 (channels) and P1/P2 of `NMS_DEVICE_IDENTITY_2026-11-01.md`; the
tenancy principle there (§2, truest multitenancy) is unchanged and binding.
Inputs: owner's competitor research (Datadog Agent/NDM, New Relic ktranslate,
Dynatrace ActiveGate + OTel Collector) and Correlix research (Fable, 2026-11-02).

## 1. What runs where — two packages

| Package | Contains | Runs | Operated by |
|---|---|---|---|
| **Correlix platform** (today's `install.py` stack + Helm chart) | api, UI, Iris, event bus, stores, correlation engine, **Ingest Gateway (new)** | SaaS: Correlix region · self-hosted: the customer's Correlix server | SaaS: Correlix · self-hosted: customer with our installer |
| **Correlix Collector (new)** | collector (SNMP/gNMI polling, trap/syslog/flow receivers, disk queue, redaction) + goflow2 + gnmic sidecars | at each customer site, close to the devices | always the customer, on their VM / container platform |

The collector is a software appliance (the Datadog Agent / ktranslate /
ActiveGate equivalent), not an agent on each network device: devices run
nothing new; they answer SNMP and send traps / syslog / flows to the collector.
Shipped as OVA / qcow2 (VMware, KVM, Hyper-V) and as a container image.

## 2. Transport topology

```
 devices (DC, campus, branches over SD-WAN/MPLS)
        │  SNMP 161 · gNMI 57400 (collector → device)
        │  traps 162 · syslog 514/6514 · flows 2055/4739/6343 (device → collector)
        ▼
 Collector(s) in the customer's management zone ──outbound TCP 443 only──►  customer firewall / NAT / proxy
                                                                                  │ Internet, or VPN / Direct Connect + PrivateLink
                                                                                  ▼
                                               ingest.<region>.correlix.com → L4 load balancer (TCP passthrough)
                                                                                  ▼
                                               Ingest Gateway  ◄── TLS TERMINATES HERE (verifies collector identity)
                                                                                  ▼  separate internal mesh-mTLS hop
                                               event bus → router → stores · correlation engine · api
```

- **One FQDN per region** (`ingest.<region>.correlix.com`) for enrolment,
  telemetry, config, shard leases and sealed credentials. No inbound rules ever:
  every session starts from the collector.
- The load balancer never decrypts. The gateway terminates TLS itself because
  the collector's client identity decides the tenant and is checked against live
  revocation on every connection; terminating at an LB / nginx would move that
  identity into a forgeable header.
- Appliance mode: the gateway runs on the Correlix host (own port, or nginx
  TLS passthrough by SNI on 443); a built-in local collector is the Provider's
  stream (G0). Same code in every deployment.

**Customer firewall sheet:** collector→devices UDP 161, TCP 57400/9339 (opt.);
devices→collectors UDP 162, UDP/TCP 514, TCP 6514, UDP 2055/4739/6343;
collector→on-prem controller TCP 443 (opt.); collector↔collector one TCP port
(HA only, e.g. 9443); collector→Correlix TCP 443 to one FQDN; collector→NTP/DNS
UDP 123/53; optional HTTP CONNECT proxy.

**Customer provides:** collector VM(s) (start ~4 vCPU / 8 GB / 100 GB; sizing
floor ~1 vCPU per 1,000 SNMP devices or 2,000 flows/s or 2,000 syslog/s, then
measured Correlix figures), management-zone IPs reachable to/from devices,
firewall rules, device destinations (or controller templates), NTP/DNS,
optional flow VIP. **Correlix provides:** images, per-collector one-time
enrolment token (UI), regional FQDN + server-cert fingerprint, firewall sheet,
sizing guide, per-vendor device snippets (Cisco, Juniper, Arista, Nokia, SONiC,
vManage templates), signed updates, collector health in the UI. Device and
controller credentials are entered in the Correlix UI and delivered sealed to
that site's collectors only.

## 3. Standalone and HA — both first-class (owner requirement)

A **collector group** is the unit of configuration, dedup and leasing. A
standalone collector is a group of one; HA is a group of two or more. The same
binary, the same enrolment, the same wire; only the group size differs.

| | Standalone (group of 1) | HA (group of ≥2) |
|---|---|---|
| Polling (SNMP, gNMI, controllers) | holds every shard lease | shards leased across members (~30 s TTL); a peer takes over a lost member's shards; peers keep the split over an authenticated heartbeat if the WAN drops, both poll if they cannot reach each other (dedup absorbs it) |
| Traps / syslog | devices send to the one collector | devices send to both; gateway dedups exactly per (tenant, group, record id) |
| Flows | devices export to the collector | one destination: a VIP from the customer's LB/anycast (collector 2 standby), or dual export with exact sequence dedup |
| Loss of the collector | site visible as **collection lost** (a competing hypothesis in RCA), disk queue survives a restart | peer continues; the lost member is a warning, not an outage |
| Upgrades | brief gap, queue covers it | rolling, one member at a time, no gap |
| Firewall | no peer port | one peer TCP port |

Promotion from standalone to HA = enrol a second collector into the same group;
demotion = revoke a member. No re-configuration of devices beyond adding the
second trap/syslog destination.

## 4. Transport security across the internet — the standard

| Control | Requirement |
|---|---|
| Protocol | **TLS 1.3 only** on the collector→gateway hop (TLS 1.2 refused); AEAD suites only (AES-GCM / ChaCha20-Poly1305), ephemeral key exchange (forward secrecy) |
| Server authentication | gateway certificate from a public CA for `ingest.<region>.correlix.com`; the collector also **pins** the Correlix channel-CA / gateway key set delivered at enrolment, so a mis-issued public cert cannot impersonate Correlix |
| Client authentication | **mutual TLS by default**; per-collector key **generated on the collector and never exported** (P-256; TPM / OS keystore where available); 24 h certificate from a dedicated **channel CA** that is never in the internal mesh trust; auto-renew at half-life |
| Tenant binding | tenant = the certificate's identity only, cross-checked against Postgres (row-level isolated); never anything in the payload. Region carried in the certificate; a gateway refuses a foreign-region collector (data residency) |
| TLS-intercepting proxies | preferred: customer exempts the one FQDN from inspection (pure mTLS). Otherwise **signed-request mode**: every request signed with the same collector key (method, path, body hash, timestamp, batch id; ±300 s window, replay cache) **and the payload encrypted end to end to the gateway's key** (ECDH P-256 + HKDF + AES-GCM, stdlib) so the proxy sees only ciphertext. Signed mode is per-collector, opt-in, audited and visible in the UI |
| Revocation | collector or tenant status in Postgres; gateway cache ~10 s; live connections closed; 24 h expiry as backstop. Enrolment tokens single-use, short-lived, hash-stored |
| Integrity and replay | per-collector monotonic sequence + batch id (gaps detectable, duplicates refused); record ids are content hashes; the gateway signs a channel stamp on every record that the router and engine verify (closes the bus-claim path) |
| Payload hygiene | redaction runs at the edge before egress (same rule engine as central; a rule may never remove a field the classifier reads); size bounds (≈4 MiB compressed / 32 MiB decompressed / 64 KiB per record), decompression-bomb guard |
| Abuse limits | per-tenant and per-collector quotas, 429 + Retry-After; a stolen credential can only write into its own tenant until revoked (~10 s) or expired (24 h), never read |
| Credentials at the edge | device / controller credentials sealed to one collector's key; held in memory only (re-fetched after a restart once the WAN is back); tenant DEKs and sealing keys never leave Correlix |
| Crypto module | Go standard library only (§6); FIPS 140-3 mode available via the Go FIPS module for customers who require it |
| Audit and monitoring | every enrolment, renewal, revocation and signed-mode use audited; collector health (queue depth/age, UDP drops, rejects, cert expiry, clock offset) on the gateway; promtool-tested rules for collector silent / gateway rejecting / fleet silent |
| Private paths | HTTP CONNECT proxy, VPN / Direct Connect + PrivateLink: the same L4 passthrough, same end-to-end TLS |

## 5. Wire, data flow and engine — summary

- **Wire (CEP/1):** `POST /edge/v1/batch`, NDJSON + gzip; batch header
  (collector, group, sequence, spool age, replay flag, config/bundle/redaction
  versions, clock offset); records carry lane, receive time, sender, ODID,
  content-hash id and today's lane body. 200 partial-success / 409 duplicate /
  429-503 Retry-After / 413 split / 401-403 re-enrol / 426 version skew.
  At-least-once; ack only after a durable hand-off. **OTLP/HTTP-JSON accepted**
  from stock OTel Collectors (mTLS only, declared lower fidelity).
- **Edge vs central:** edge decodes, redacts, summarises flows (per-interface
  volume, top talkers, critical-prefix flows; raw flows kept on site N days),
  queues to disk (10 GiB / 72 h default). Classification, device identity and
  tenant stay central (one rule table; replay determinism).
- **After an outage:** live data drains first; backlog drains in parallel and a
  retrospective engine pass may rank it but never confirm it.
- **Engine gains:** channel-verified tenant and per-tenant identity at stage
  [1]; sender + ODID for identity tiers; receive-time-based ages and skew;
  collector fate stamped only on collector-originated observations; a new
  "collection lost" competing hypothesis at stage [6].

## 6. Phases (tracker 372; ★ = full gate + pgintegration + §3a isolation test)

C0 close the bus forgery paths · C1★ collector groups / collectors schema
(FORCE-RLS), channel CA, `internalca.IssueFromCSR`, enrolment API · C2★ Ingest
Gateway (TLS 1.3 mTLS + signed mode with payload encryption, credential→tenant,
group dedup, quotas, channel stamp, edge lane) · C2b★ engine accepts the channel
stamp, receive-time ages · C3★ collector binary (enrol, disk queue, syslog,
traps, heartbeat, standalone + HA groups) + lab RETAIL collector(s) · C4★ sealed
credentials + edge polling + shard leases · C5 flows (goflow2 sequence dedup,
summaries, local raw) · C6 edge redaction · C7★ collector fate + collection-lost
hypothesis · C8★ retrospective backlog pass · C9 on-prem controller polling at
the edge · C10 appliance convergence + parity harness · C11 OTLP-JSON adapter ·
C12 VM appliance, signed updates, regional endpoints.

Owner questions deferred to C3 (memory): where the lab collector runs (separate
VM vs container on the Correlix host) and who adds the edges' second
destinations.

## 7. Decisions (adopted with the owner's approval, 2026-11-02)

1. Auth: per-collector key, mTLS default, signed-request mode (with end-to-end
   payload encryption) behind intercepting proxies; no bearer keys.
2. Collector runtime: one Go binary with role flags + goflow2 / gnmic sidecars.
3. Wire: CEP/1 primary, OTLP/HTTP-JSON accepted.
4. Edge processing: decode, redact, summarise; classification/identity/tenant central.
5. HA push: dual destination + exact dedup for traps/syslog; single VIP for flows.
6. Backlog: live-first + retrospective rank-only pass.
7. Flow egress: aggregates + top talkers + critical prefixes; raw kept on site.
8. Collector fate: collector-originated observations only, plus "collection lost".
9. Standalone and HA collectors both first-class (owner requirement).
10. Transport security per §4 (owner requirement: highest standards over the internet).
11. Residency: region pinned per tenant, carried in the certificate.
