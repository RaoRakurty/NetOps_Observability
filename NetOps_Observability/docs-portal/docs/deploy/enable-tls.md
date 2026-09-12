---
title: Enable TLS and mTLS
description: Turn on the Correlix transport mesh - ingress TLS on 443, mutual TLS between nginx and the API, per-store certificates, and Kafka mTLS with ACLs.
page_type: task
sidebar_position: 7
---

# Enable TLS and mTLS

Correlix ships a complete transport-security mesh behind one installer question. Enabling it moves the console to HTTPS on 443 and puts mutual TLS between nginx and the API. It also wraps every store in a fail-closed TLS configuration, switches Kafka to mTLS listeners with an ACL matrix, secures the Vector lanes, and places the internal certificate authority's key under sealed custody.

The default install serves plaintext HTTP on 8000 and expects a TLS terminator in front of it. Enable the mesh when Correlix is the terminator, or when the traffic between its own services must be authenticated.

## Before you begin

- Decide before the first install. Enabling on an existing deployment works, and it recreates every container.
- An interactive `install.py` run asks the question and defaults to yes. An unattended run without `--tls` keeps the plaintext baseline, because an install script must not surprise an unattended run with a mesh it did not ask for.
- A real certificate for the ingress, if this deployment is reachable by operators. The installer generates a self-signed one so nginx can start; browsers warn on it.
- Enough time for two full stack starts. Enablement is a two-phase operation.

## Steps

1. Run the installer with the flag. The flag wins over the prompt.

   ```bash
   python3 scripts/install.py --tls yes
   ```

2. Let phase A finish. The baseline stack boots with the minting variables set, and the API's internal certificate authority writes a certificate for every issuance surface into `data/tls`. The installer blocks until each one exists, with a 300-second bound.

   | Path | Identity |
   |---|---|
   | `data/tls/ca.pem` | The internal certificate authority. |
   | `data/tls/api.crt` | The API. |
   | `data/tls/nginx/nginx.crt` | The ingress. |
   | `data/tls/admin/admin.crt` | The OpenSearch admin certificate. |
   | `data/tls/services/kafka/kafka.crt` | The bus. |
   | `data/tls/services/postgres/postgres.crt` | The relational store. |
   | `data/tls/services/opensearch/opensearch.crt` | The search store. |

   A timeout here is a loud install failure. Activating fail-closed wrappers on a half-minted tree would take the whole stack down, so a partial mint stops the install instead.

3. Let phase B finish. The installer appends `compose.tls.yml` to the `COMPOSE_FILE` chain and recreates the stack with the fail-closed store wrappers and the mTLS listeners active.

4. Let the Kafka authorization matrix apply. With default-deny enforced on the broker, an empty ACL store is a silently authorization-dead ingest tier, so the installer applies and verifies the matrix before reporting success. On a plaintext baseline and on an external broker this step is a deliberate no-op.

5. Replace the self-signed ingress certificate with a real one. Keep the filenames.

   ```bash
   cp fullchain.pem privkey.pem deployment/docker/nginx/certs/
   cd deployment/docker && docker compose restart nginx
   ```

6. Verify the mesh before you announce the URL.

   ```bash
   curl -fs https://localhost/admin/health
   bash scripts/bootstrap-opensearch.sh --verify
   bash scripts/deploy-qualify.sh
   ```

## Result

The installer prints the new addresses:

```
  Dashboard: https://localhost/   (TLS ingress, port 443)
  API:       https://localhost/api/
  Health:    https://localhost/admin/health
```

The plaintext port stays published alongside 443 during the migration window, so an existing integration does not break the moment TLS goes on. Close it deliberately once every client has moved.

Three things changed in `deployment/docker/.env`, all by line surgery, so your other edits survive:

| Change | Value |
|---|---|
| A TLS variable block | `TLS_INTERNAL_CA=true`, `TLS_TRUST_DOMAIN=netops`, `TLS_SVID_TTL=168h`, the certificate and key paths, and `SEAL_PROVIDER=swtpm`. |
| `COMPOSE_PROFILES` | Gains `seal`, `security` and `vmauth`. |
| `COMPOSE_FILE` | Gains `compose.tls.yml` at the end of the chain, so its merges win. |

The `seal` profile is required, not optional: the certificate authority's seal gate refuses a plaintext CA key.

## Why enablement is two-phase

The certificate authority's own state lives in the relational store, and with the mesh active that store is fail-closed. A fail-closed PostgreSQL cannot start without certificates that only a running API can mint. Phase A therefore boots the plaintext baseline purely so the CA can issue, and phase B switches the mesh on once every identity exists. Running the installer again on an already-minted tree converges in a single pass.

## Verifying without changing anything

`bootstrap-opensearch.sh --verify` reads the live cluster and writes nothing. On a healthy stack it prints one `role: COVERED` line per router lane and one `template: PRESENT` line per template, ending with:

```
VERIFY OK — every router sink lane is writable and every template is installed.
```

`role: UNCOVERED <pattern>` means a lane the router writes to is not covered by the writer role, and that lane is silently write-dead. `template: MISSING <name>` means the index-template bootstrap never landed.

:::danger Never add `-k` or `--insecure` to a store health check
The OpenSearch certificate carries `DNS:opensearch` plus a SPIFFE URI and nothing else, so the host name in the URL must be `opensearch`. Using `localhost` fails hostname verification, and silencing that with `-k` turns a real interception or a misissued certificate into a silent pass.
:::

## Related

- [Verify a deployment is doing work](/deploy/verify-deployment) - the post-deploy gate, which audits the router lanes too.
- [Install Correlix on a Linux host](/deploy/install-linux) - where the TLS question is asked.
- [Security](/security/overview) - what the mesh protects and what it does not.
