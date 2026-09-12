# Runbook (OUTLINE) — Restore an encrypted backup

> **Status: OUTLINE. Partially executable today — with a significant caveat.**
> Backup and restore tooling exists and is documented
> (`scripts/backup.sh`, `scripts/restore.sh`, `scripts/restore-drill.sh`,
> `scripts/ch-cold-restore.sh`; operator guide:
> [`docs/runbooks/backup-restore.md`](../backup-restore.md)). **A backup
> *encryption* domain does not** — HLD threat **T20 (backup theft) is scored HIGH
> with no target control**, and ADR-SEC-002 domain 5 is designed but not built.
> Everything about *encrypted* backups below is **[PENDING — ADR-SEC-002 domain
> 5 / HLD §11.6]**. What *is* live today is the interaction between restore and
> **sealed secrets**, which is a real hazard right now.
> **Do not restore over a live system from this document alone.**

**Decision record:** ADR-SEC-002 (domain 5 — backup authority), ADR-SEC-007
(sealing custody and its restore implications).
**Complements:** `docs/runbooks/backup-restore.md` is the **operational
authority** for what is backed up and how — this runbook covers only the
*security* dimensions (key custody, cross-host restore, evidence). Do not
duplicate it; follow it. Also `secret-unseal-failure.md` and
`opensearch-security-bootstrap.md` (security-plugin interaction with snapshots).

---

## 1. Purpose

Restore Correlix data when the backup — or the data inside it — is protected by
keys, covering the two questions the existing backup runbook does not answer:

1. **Where is the key, and is it available at restore time?**
2. **What is recoverable when restoring onto a *different host* than the one that
   sealed the data?**

## 2. The hazard that exists today (read this first)

Sealed secrets are encrypted under a KEK sealed to **this host's** custodian
(swtpm today — `docs/design/secret-custody.md` §2–§3). The design goal is stated
as *"unrecoverable without the TPM."* That is excellent for confidentiality and
it means:

> **A backup restored onto a different host cannot decrypt any sealed secret**
> unless the sealing state is restored with it.

Affected on restore: SNMP credentials, webhook secrets, notification tokens
(SMTP/Twilio/ntfy/Slack/PagerDuty), the OIDC client secret, the LDAP bind
password, the TACACS+ shared secret (`secret-custody.md` §7 phase 1c) — **and the
internal CA private key** (`tls.ca.key`, `src/backend/tls_ca.go:31`).

This is precisely why ADR-SEC-002 keeps the **backup authority separate from the
sealing root**: a backup must be restorable *exactly when the original host is
gone*, which is the one condition under which host-bound sealing fails.

## 3. Prerequisites

- [ ] Know **which** restore this is: same-host rollback, different-host DR, or a
      partial/single-store restore. The answers below differ sharply.
- [ ] The backup artifact, its integrity checksum, and its provenance.
- [ ] **[PENDING]** The backup encryption key, from a custody path independent of
      the platform being restored.
- [ ] For sealed data: the sealing state, or acceptance that sealed secrets will
      be re-entered.
- [ ] Target host prepared per `docs/runbooks/backup-restore.md`.
- [ ] Authority — a restore overwrites data.

## 4. SAFETY WARNINGS

| Risk | Detail |
|---|---|
| 🔴 **Restore is destructive and largely irreversible** | It overwrites live data. Take a fresh backup of the *current* state before restoring, even when the current state is broken. |
| 🔴 **Sealed secrets will NOT decrypt on a different host** | See §2. Plan for re-entry of every reversible secret, or restore the sealing state alongside — and understand that restoring the sealing state onto a new host reduces the "bound to this host" guarantee to "bound to whoever holds the state file". Both choices are defensible; making neither choice consciously is not. |
| 🔴 **A restored internal CA key may be stale or exposed** | If the CA key is restored, verify it is still the current root, and if the backup predates any rotation, do **not** resurrect a retired root. If the backup was taken while the CA was unsealed, the key is in the clear in that backup — treat per `ca-compromise-response.md`. |
| 🔴 **Restoring can destroy ClickHouse row policies** | Policies live in ClickHouse access storage. A restore that replaces it removes them until the API's convergence runs (`src/backend/clickhouse_policies.go`). **Verify policies exist before allowing tenant traffic** — a restored cluster with no row policies is a cross-tenant leak, not just a config gap. |
| 🔴 **Restoring can resurrect OpenSearch security config** | Roles/mappings restored from an older snapshot may re-grant access that was deliberately removed. Reconcile after restore. |
| 🟠 **Backups are secrets** | An unencrypted backup contains every tenant's data. Until domain 5 exists, backup files must be treated as the most sensitive artifact the platform produces — access-controlled, transported securely, and never left on shared storage. |
| 🟠 **Telemetry gap is inherent** | Data between the backup point and now is lost unless upstream buffers cover it. Quantify it and state it, per tenant. |
| 🟠 **Do not restore into a running stack** | Follow `docs/runbooks/backup-restore.md`'s stop/restore/start sequence. |
| ⚪ **Drills are safe; production restores are not** | `scripts/restore-drill.sh` exists — use it, on a scratch target. |

## 5. Pre-validation

1. Verify the artifact's integrity and provenance (checksum, expected size,
   creation timestamp, which host produced it).
2. Confirm the backup's contents match the intended scope (which stores).
3. **[PENDING]** Confirm the decryption key is available **and tested** — a key
   you have not tested is not a key you have.
4. Determine whether the sealing state is available for this target host.
5. Take a fresh backup of the current state.
6. Record what will be lost (time window) and which tenants are affected.
7. Rehearse on a scratch target first whenever the situation permits.

## 6. Procedure

### Phase A — decide and prepare
1. Classify the restore (same-host / different-host / partial).
2. **[PENDING]** Retrieve and verify the backup decryption key from its
   independent custody path. If the only copy of the key is inside the platform
   being restored, the backup is not restorable — record that as a finding.
3. Decide the sealed-secret strategy: restore sealing state, or re-enter
   secrets. Record the decision.

### Phase B — restore
4. Stop the stack per `docs/runbooks/backup-restore.md`.
5. **[PENDING]** Decrypt the backup artifact into a secured working location
   (never a shared path; never world-readable).
6. Restore per `docs/runbooks/backup-restore.md` / `scripts/restore.sh` (and
   `scripts/ch-cold-restore.sh` for ClickHouse cold data).
7. If restoring sealing state, place it before starting the API.
8. Start the stack.

### Phase C — security reconciliation (the part unique to this runbook)
9. Verify the API unsealed successfully; if not, `secret-unseal-failure.md`.
10. **Verify ClickHouse row policies exist** before permitting tenant traffic —
    restart the API to force convergence if needed, then confirm.
11. Verify Postgres RLS is intact and the app role is still non-superuser /
    non-BYPASSRLS (`assertRLSCapable` must pass).
12. Verify OpenSearch roles and mappings match current intent, not the snapshot's
    history.
13. Re-enter any sealed secret that did not survive; verify each dependent
    feature works (SNMP polling, notifications, SSO, LDAP).
14. Verify the internal CA: is the restored root the current one? If in doubt,
    rotate (`rotate-workload-ca.md`) rather than trust it.
15. Securely destroy the decrypted working copy.

## 7. Rollback

| Stage | Action |
|---|---|
| Phase A | Nothing changed; abort freely. |
| Phase B before start | Restore the pre-restore backup taken in pre-validation §5. |
| After the stack is running on restored data | **No rollback except restoring the pre-restore backup** — which is why taking it is mandatory, not advisory. |
| Sealed-secret loss | Not recoverable; re-entry is the only path. |

## 8. Audit evidence to capture

- Ticket, authorization, operator, and the reason for the restore.
- Backup artifact identity: source host, creation time, checksum, scope.
- **[PENDING]** Key custody path used, and confirmation it was independent of
  the restored platform.
- The classification (same-host/different-host/partial) and the sealed-secret
  decision with its reasoning.
- Data-loss window, per tenant.
- Post-restore verification results for: row policies, RLS, OpenSearch roles,
  unseal, CA validity.
- List of secrets re-entered and by whom.
- Destruction record for the decrypted working copy.

## 9. Post-checks

1. Stack healthy; API starts sealed and clean.
2. **Tenant isolation re-proven** — row policies present, RLS enforcing,
   OpenSearch roles correct. Run the negative tests; do not infer.
3. Data spot-checked per tenant against expectations; the loss window matches
   what was predicted.
4. Every dependent feature that uses a sealed secret verified working.
5. Certificates valid and monitored; CA confirmed current.
6. Decrypted artifacts destroyed; backup artifact returned to secure storage.
7. **[PENDING]** File the gap if it appeared: an unencrypted backup, or a key
   whose only copy lived inside the platform, is a T20 finding and belongs in the
   backlog with domain 5.
