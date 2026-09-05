# Device SSH Credentials — Operator Runbook

The read-only account Correlix uses to **log into network devices**: where it
lives, how to set it, and how to prove it still works.

This is the credential behind **configuration backup / drift**, the
**protocol-diagnostics collector**, and the **TAC escalation** collector. It is
supplied by the operator; Correlix never generates, discovers or guesses it, and
no Correlix document, script, fixture or commit ever contains its value.

## TL;DR

```bash
cd /path/to/NetOps_Observability

# Is it configured, and does it still authenticate to this device?
scripts/check-device-ssh.sh --device leaf1 --address 172.40.40.21
```

`configured: yes` + `verdict: AUTH OK` is the whole answer. Anything else prints
an error **class** (`auth-failed`, `unreachable`, `host-key`, …) and exits
non-zero. The credential is never printed.

---

## 1. Which credential does what

There are **three** device-SSH identities in the platform. They are not
interchangeable, and only two of them share a store.

| Identity | Who uses it | Where it is configured | Scope |
|---|---|---|---|
| `CONFIG_BACKUP_SSH_*` | configuration backup + drift; and, by documented fallback, the protocol-diagnostics and TAC collectors | `deployment/docker/.env` | platform-global |
| `PROTOCOL_DIAG_SSH_*` | protocol-diagnostics collect + TAC collect — a dedicated diagnostics identity | `deployment/docker/.env` | platform-global |
| Active Verification SSH credential | the active-verification engine only | **UI**: Settings → Verification (`GET/PUT /api/settings/verification`) | per tenant, sealed under the tenant DEK |

**The product path today covers only the third row.** Active Verification has a
real sealed-credential UI (write-only, never echoed back, sealed under the
tenant's vault DEK). Configuration backup and the diagnostics/TAC collectors do
**not** read it — they read the environment. So for capture and TAC collection
the supported path is the environment file below, and that is a deliberate
statement of today's state, not an aspiration: there is no "test credential"
button and no credential-store row for these two identities.

*(For completeness: the SNMP credential/profile UI under Administration → SNMP
Credentials manages SNMP v2c/v3 material only. It has no SSH fields.)*

---

## 2. Setting it (the environment path)

`deployment/docker/.env` is generated at install and **gitignored**. Edit it in
place on the host; never commit it, never paste its values into a ticket, a chat
message or a document.

### 2.1 Configuration backup / drift (and the default for collectors)

```
FEATURE_CONFIG_BACKUP=true
CONFIG_BACKUP_SSH_USER=<least-privilege read-only account>
CONFIG_BACKUP_SSH_PASSWORD=<the account's password>   # or CONFIG_BACKUP_SSH_KEY
CONFIG_BACKUP_SSH_PORT=22                             # optional, default 22
```

Set **`CONFIG_BACKUP_SSH_USER` and exactly one of** `CONFIG_BACKUP_SSH_PASSWORD`
or `CONFIG_BACKUP_SSH_KEY`. With the user set and neither secret set, the api
refuses with *"no config-capture credential configured"* — it never guesses.
Source of truth: `configGateway()` in `src/backend/main.go`; the variable names
are constants in `src/backend/internal/configstore/`.

### 2.2 Protocol diagnostics / TAC collect

```
FEATURE_PROTOCOL_DIAG_COLLECT=true
PROTOCOL_DIAG_SSH_USER=<least-privilege read-only account>
PROTOCOL_DIAG_SSH_PASSWORD=…      # or PROTOCOL_DIAG_SSH_KEY
PROTOCOL_DIAG_SSH_PORT=22         # optional, default 22
```

**Precedence, exactly as `protocolDiagCredential()` implements it**
(`src/backend/protocol_diag_gateway.go`):

1. the dedicated identity (`PROTOCOL_DIAG_SSH_USER` **+** `_PASSWORD` or `_KEY`);
2. only when **none** of those three is set, the `CONFIG_BACKUP_SSH_*` capture
   account;
3. a **partially** set dedicated identity — a user with no secret, or a secret
   with no user — is a hard error. Falling back there would silently
   authenticate as a *different* account than the operator named.

`PROTOCOL_DIAG_SSH_KEY_FILE` exists for the env-gated lab-proof harness
(`src/backend/internal/tac/labproof_test.go`) only; it is not a server variable.

### 2.3 The account itself

* **Read-only.** Three independent guards stand between a plan file and a device,
  but the account is the one that matters if all three are ever wrong.
* **Privilege matters on some platforms.** Arista EOS answers
  `show running-config` and `show environment all` only at privilege 15; below
  that they exit non-zero, and capture/collect record the failure against those
  commands and continue. Raise the privilege deliberately or accept the gap —
  do not work around it by handing the platform an enable-capable account.
* **Sealing.** These values may be stored as vault ciphertext (`v1:…`) rather
  than plaintext; the api opens them under the platform DEK. Plaintext is
  accepted (encrypt-on-next-write compatibility) unless `VAULT_STRICT=true`.

### 2.4 Applying a change

```bash
cd deployment/docker && docker compose up -d --force-recreate api
```

The api reads these at start. Editing `.env` alone changes nothing.

---

## 3. Validating it

### 3.1 From the host — `scripts/check-device-ssh.sh`

Does not need the stack to be up. It resolves the identity with the **same**
precedence the server uses, reports `configured: yes|no` and the *shape* of what
is set, then runs **one** read-only `show version` against one named device under
a hard timeout.

```bash
scripts/check-device-ssh.sh --device leaf1 --address 172.40.40.21
scripts/check-device-ssh.sh --device leaf1 --identity config-backup --show-error
scripts/check-device-ssh.sh --help
```

| Exit | Meaning |
|---|---|
| 0 | configured, and the account authenticated |
| 1 | configured, but the test failed — the class is on the verdict line |
| 2 | usage error, or a required tool is missing |
| 3 | not configured (no user, or no password and no key) |
| 4 | configured but the secret is **sealed** (`v1:`) — only the api can open it; use §3.2 |

| Class | What it means | What to do |
|---|---|---|
| `auth-failed` | the device rejected the account | rotate the value in `.env` to the device's current read-only account, then recreate the api |
| `unreachable` / `timeout` / `dns` | the device did not answer | reachability, not the credential — check routing and the device's mgmt interface |
| `host-key` | the device's key differs from the one this tool recorded | treat as possible MITM until the device is confirmed rebuilt |
| `crypto-mismatch` | no common host key / kex / cipher | an ssh client-policy issue, not the credential |
| `command-refused` | the session opened and the device exited non-zero | the account authenticated; check its privilege level |
| `sealed-secret` | the value is `v1:` ciphertext | validate through the api (§3.2) |

What it will never do: print, log or echo the credential; print the device's
pre-auth banner or the command output (byte counts only); write to the
platform's own pinned host-key store; touch a device's configuration. It keeps
its **own** trust-on-first-use file (`~/.correlix/device-ssh-known-hosts`) for
exactly that reason — a probe must not be able to pin a fingerprint the api will
later trust.

A **password** identity needs `sshpass` on the host; a **key** identity does not.
The tool says so by name rather than failing obscurely.

### 3.2 Through the api — the in-product confirmation

`POST /api/devices/{id}/config/backup` then `GET /api/devices/{id}/config/status`.
This is the only way to validate a **sealed** value, and the only way to prove
the credential works *from inside the container*, which is what actually matters:

```bash
# 1. trigger a capture (202 + job id; the capture runs detached)
curl -s -X POST "$API/api/devices/leaf1/config/backup" -H "Authorization: Bearer $TOKEN"

# 2. read the outcome
curl -s "$API/api/devices/leaf1/config/status" -H "Authorization: Bearer $TOKEN"
```

`config/status` returns `last_capture_at`, `last_sha`, `golden_sha` and — when
the last attempt failed — `last_error`. **A 202 from step 1 is not evidence of
anything**: the capture is detached, so a dead credential shows up only as a
`last_error` here (and a scrubbed api log line), never as an HTTP error.

---

## 4. Rotating it

1. Rotate the account **on the devices** first (or have the network owner do it).
2. Edit `deployment/docker/.env` on the host — the variable from §2, nothing else.
3. `cd deployment/docker && docker compose up -d --force-recreate api`
4. Prove it: `scripts/check-device-ssh.sh --device <device>` on a device of each
   vendor in the fabric, then §3.2 for one device.

Never put the value in a commit, a fixture, a runbook, a scenario write-up, a
tracker row, or a chat message. `deployment/docker/.env` is gitignored; keep it
that way.

---

## 5. Known lab state (2026-09-05)

Validated with `scripts/check-device-ssh.sh` against the clos lab, using the
`CONFIG_BACKUP_SSH_*` identity from `deployment/docker/.env`
(`PROTOCOL_DIAG_SSH_*` is unset, so the documented fallback applies):

| Device | Platform | Result |
|---|---|---|
| spine1 `172.40.40.11` | Nokia SR Linux | **AUTH OK** |
| spine2 `172.40.40.12` | Nokia SR Linux | **AUTH OK** |
| leaf1 `172.40.40.21` | Arista cEOS | `auth-failed` |
| leaf2 `172.40.40.22` | Arista cEOS | `auth-failed` |
| leaf3 `172.40.40.23` | Arista cEOS | `auth-failed` |
| leaf4 `172.40.40.24` | Arista cEOS | `auth-failed` |
| wan-r2 `172.40.40.32` | Arista cEOS | `auth-failed` |

So configuration capture and TAC/diagnostics collection work on the SR Linux
spines and are dead on every Arista device. Correcting the record: the spines do
**not** refuse this credential — only the cEOS devices do.

Closing this needs a working read-only account on the cEOS devices, set by the
owner in `deployment/docker/.env` per §2.1. Nothing in the platform can be
changed to fix it.

---

## Related

* `docs/runbooks/tac-escalation.md` — the TAC collector that shares this identity
* `docs/runbooks/secret-rotation.md` — rotating the rest of `.env`
* `docs-portal/docs/security/config-backup.md` — the configuration-backup module
* `docs-portal/docs/investigate/collect-from-a-device.md` — the collect path
