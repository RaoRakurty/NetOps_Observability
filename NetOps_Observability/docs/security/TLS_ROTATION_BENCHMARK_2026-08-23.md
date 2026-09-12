# TLS rotation — vendor benchmark & hardening wave (2026-08-23)

**Trigger:** owner directive during the 72h soak: "if there is any enhancement
we can make to tls cert rotations, do it now… make sure our process is on par
with today's best vendors' methods."
**Method:** web research against primary vendor sources (SPIFFE/SPIRE, Istio,
HashiCorp Vault, cert-manager, smallstep step-ca, Let's Encrypt/ACME, Google
ALTS), then close every delta that can be closed without disturbing the
running soak; stage the rest for the post-soak restart window.

## 1. Where we stood (verified, not assumed)

| Layer | Mechanism | Status before this wave |
|---|---|---|
| Issuance | Embedded CA in the api (`tls_ca.go`): 10-year root, per-service SPIFFE SVIDs, `TLS_SVID_TTL` (deployed 168h, code default 24h), re-issue loop at TTL/2, re-issue on boot | Automatic, no jitter |
| Propagation | `rotate-tls-services.sh`: kafka dynamic keystore / `pg_reload_conf` / CH `SYSTEM RELOAD CONFIG` / nginx reload / health-gated restarts, then **served-vs-mint verification** of every mesh endpoint | Built + verified, **never scheduled** (comment said "weekly cron" — no cron existed); compose-path bug made repo-root runs fail all legs |
| Alerting | vmalert on `netops_tls_peer_cert_expiry_seconds` (WIRE truth from the api's prober): warn <24h, crit <6h, probe-failed | Live |

## 2. Vendor benchmark (headline numbers)

| Vendor | Leaf TTL | Renewal point | Jitter | Propagation |
|---|---|---|---|---|
| SPIFFE/SPIRE | 1h default | 1/2 lifetime | agent sync backoff | Workload API push |
| Istio | 24h (`SECRET_TTL`) | 0.5 ratio | ±1% ratio jitter | Envoy SDS hot-swap |
| Vault Agent | 30–90d leafs | 90% of TTL (non-renewable) | ± jitter | template + reload hook |
| cert-manager | 90d | 2/3 of duration | — | writes Secret; reload is user's problem |
| step-ca | 24h | ~2/3 elapsed | built-in ([0, d/20] with --expires-in) | renew hooks |
| Let's Encrypt | 90d / 45d / **160h shortlived (GA 2025)** | ARI, else 1/3 remaining; <10d certs: at halfway | retry backoff ladder | client-side |
| Google ALTS | handshake certs: hours; workload masters ~2d | push-based | — | central push + **CRL push** (they do NOT trust expiry alone) |

**Verdict on our fundamentals:** TTL (24h default / 7d deployed ≈ LE's new
160h short-lived direction), TTL/2 renewal (= SPIRE/Istio), 10-year root
(= step-ca/Istio, inside Vault's 2–10y band), short-TTL-as-revocation
(= smallstep "passive revocation"), and hot-reload mechanisms (kafka KIP-226,
PG reload semantics, CH reload, nginx) are **all on par with 2025-26 practice**.
Post-rotation served-vs-minted verification and wire-truth alerting are
**ahead of shipped vendor tooling** (Postgres silently ignores bad cert files
on reload — our wire verification is the only thing that catches exactly that).

## 3. Deltas found → what was done (all proven live against the running soak)

1. **Cadence arithmetic was latently unsafe (worst gap, found by the review
   math, not the vendors).** A weekly restart sweep with TTL=7d/reissue at
   TTL/2 can pick up a mint with only 3.5d left and not return until after it
   expires — the 2026-08-05 outage class surviving *with* a cron installed.
   → **Sweep v2:** cron runs **daily**; hot-reload legs always propagate
   (zero-downtime); the restart class is **need-based** — a service restarts
   only when the cert its process actually holds drops under
   `RESTART_WHEN_LEFT_H` (72h), which is the Istio/step-ca "renew at ~2/3
   elapsed" semantics applied to the wire. Held-cert truth comes from the wire
   for probeable endpoints and from a recorded loaded-mint expiry
   (`scripts/.rotate-tls.loaded`) for client-only services. Verification is
   strict mint-match for services restarted this run, expiry-floor
   (`WIRE_MIN_LEFT_H` 48h) otherwise.
2. **No scheduling + path bug.** `--project-directory` does not discover
   compose files from a foreign CWD → `dc()` now subshell-`cd`s into the
   compose dir (picking up `COMPOSE_FILE`/`COMPOSE_PROFILES` from `.env`
   exactly like an operator invocation); daily cron installed (05:07).
3. **Qualification guard.** A live `scale-miniladder.py` run owns the stack:
   act mode still runs hot-reload legs (each proven zero-downtime against the
   live 72h soak on 2026-08-23) but defers the restart class; deferred
   endpoints are judged by the 48h floor — planned deferral quiet, imminent
   expiry loud. Deferral-vs-expiry collision is a flagged, non-zero-exit event.
4. **No jitter on the re-issue loop** (every vendor staggers renewals).
   → `jitteredInterval()` in `tls_ca.go`: each cycle waits TTL/2 ± 10%
   uniform (crypto/rand), unit-tested (bounds, variance, degenerate inputs).
   Takes effect at the api's next restart (post-soak deploy batch).
5. **No renewal-loop dead-man** (cert-manager-mixin's key idea: an expiry
   threshold placed PAST the renewal point can only mean "the loop is dead").
   → new vmalert rule `TLSReissueLoopSuspect`: the api's own served cert
   (in-process hot-swap, zero propagation dependency) under 72h — below the
   84h floor the TTL/2 loop maintains at TTL=168h — fires days before the
   generic expiry alerts would. Validated with `vmalert -dryRun` before
   promoting into the hot-reloaded rules file.
6. **Watchdog integration.** Three transition-only checks added to
   `stack-watchdog.sh`: last sweep DEGRADED; heartbeat older than 26h (daily
   cron dead); act-heartbeat older than 10 days (rotations perpetually
   deferred/failing). Same idiom as the hygiene-cron checks.
7. **OpenSearch restart-class exit, staged (SEC-019.1 part 4).** Security plugin's
   on-demand reload API (`plugins.security.ssl_cert_reload_enabled: true`)
   staged in `opensearch-security.yml`; inert until the post-soak restart.
   The 2.19 file-watcher hot reload is the successor when the image moves
   past 2.16. After adoption, the sweep's reload leg replaces the restart.

## 4. Deltas deliberately NOT closed (with reasons)

- **CA root rotation ceremony stays manual.** `rotate-workload-ca.md` already
  encodes the dual-root/dual-bundle overlap procedure (the SPIRE-style
  pattern the research recommends for flat hierarchies). SPIRE automates
  prepare-at-½ / activate-at-⅚; with a 10-year root minted 2026, automation
  buys nothing for years. Revisit at SaaS.
- **No CRL/OCSP.** Deliberate (short-TTL passive revocation, per smallstep);
  honesty note: Google pushes CRLs *in addition* — if instant kill of a
  stolen identity ever becomes a requirement, `revoke-compromised-identity.md`
  already documents the gap and the compensating controls.
- **Vault-style 90% renewal point.** We keep TTL/2 (the mesh-vendor default);
  with need-based wire rotation + dead-man alerting, later renewal buys
  nothing and halves the margin.
- **nginx per-handshake variable certs (1.15.9+).** Would remove the one
  reload; not worth config churn while the reload is proven zero-downtime.

## 5. Operating envelope after this wave

```
disk mint:   always ≥ TTL/2 left        (api loop, jittered ±10%)
hot class:   ≤ 24h behind disk mint     (daily sweep, zero-downtime reloads)
restart class: ≥ 48h wire validity always; restarted in [72h..48h] window
alerts:      loop-dead @<72h(api) → sweep-degraded/stale (watchdog)
             → served <24h warn → served <6h crit   (defense in depth, 4 layers)
```

Files: `scripts/rotate-tls-services.sh` (v2), `scripts/stack-watchdog.sh`,
`src/backend/tls_ca.go` (+`tls_ca_jitter_test.go`), `src/config/rules.yaml`,
`deployment/docker/opensearch/opensearch-security.yml` (staged), crontab
(daily 05:07). Research agent's full report with URLs: session transcript
2026-08-23; headline numbers reproduced in §2.
