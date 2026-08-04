# Transport inventory — companion (SEC-001.1)

`transport-inventory.yaml` is the **machine-readable as-built statement** of
every network hop in the stack: what it does *today* on a fresh install, what
the security profile changes, and the agreed v1 target. It is the executable
input to the SEC-002 validator's rule set and the data source for the SEC-021
posture UI. `docs/TRACKER.md` #151 is the programme it belongs to.

## Reading it

- **File format:** the content is JSON, which is valid YAML 1.2 — chosen so the
  stdlib-only static gate (`scripts/preflight-install.py`) can parse it without
  adding a YAML dependency. Edit it as JSON.
- **`current`** = what the BASE `docker-compose.yml` ships on a fresh install.
  This is the honest baseline — several rows say `plaintext` + `none` because
  that is verifiably true (the acceptance criterion of SEC-001.1).
- **`security_profile`** = the state once the TLS override/profile is enabled.
  The lab runs this today for `nginx→api` and `victoria→api`.
- **`target`** = the agreed v1 end state per the owner steer (backlog §0a):
  intra-stack + ingress in v1; device lanes Phase 2+ (their rows say
  `deferred-phase2`).
- **`transport` vocabulary** follows
  `docs/design/transport-encryption-2026-08-04.md` §4: `plaintext`, `tls`,
  `mtls`, `protocol_native` (SNMPv3 USM, SSH — protocols that carry their own
  scheme), plus `plaintext-DECLARED` for lanes that *cannot* encrypt
  (NetFlow/sFlow) and are recorded risk acceptances, never accidents (P4).
- **`evidence`** — every row carries `path[:line]` proving the claim. The gate
  fails if a path stops existing; line drift is tolerated.

## Non-network channels (deliberately not rows)

- `api ↔ secrets-seal` is a **Unix socket** (`/run/secrets-seal/seal.sock`,
  host-private bind mount) carrying only the sealed root KEK — no network
  transit; covered by `docs/design/secret-custody.md` and SEC-018.
- In-process collectors (SNMP/gNMI pollers inside the api) appear as their
  *device-facing* hops only.

## Keeping it honest (enforced)

`scripts/preflight-install.py` (wired into `fresh-install-integrity.yml`)
asserts: every compose service that **publishes a port** appears in at least
one edge; every service named in an edge exists in compose; every evidence path
exists. `tests/test_architecture_contract.py` re-asserts coverage from the test
suite. Add a service with a published port and no inventory row → the gate
fails, which is the point.
