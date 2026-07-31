# Sealed Fields — reversible masking

**Status:** shipped (backend + UI). Key custody, cipher, edge execution, reveal
API, RBAC, audit and metrics are in place. See TRACKER #129 for what remains.

Every other processor action **destroys**. `mask` overwrites, `hash` digests,
`redact_*` replaces — once ingested, the original is gone and no amount of
authority brings it back. That is the right default and it is what most
sensitive data should get.

Some data cannot work that way. A card number in a payment gateway log is
needed months later for a chargeback dispute; a customer identifier in an
application log is needed to answer a subject-access request. Destroying it
protects privacy and destroys the business record. Keeping it in the clear does
the reverse.

**Sealed Fields is the third option: encrypt at ingest, recover under audit.**
The value is unreadable to everyone who looks at the log, and recoverable by a
named person, for a stated reason, on a record that cannot be quietly deleted.

---

## 1. What an operator sees

A sealed value appears wherever the field appears, as a token:

```
<enc:v1:YWNtZQ:1:loPguJ021iYZ6aQWWLg-dA:QCp4G5U34ILAD_VOzfGWkQ:auVyLnpx3do76…>
```

It is deliberately recognisable: an operator scanning a log knows immediately
that this is protected data and not corruption. Holders of
`sensitive_data:admin` get a **Reveal** control, which requires a written
justification before it will send the request.

The reveal is not remembered. Closing and reopening asks the server again — and
audits again — so the trail counts how many times a secret was actually looked
at, not how many times a page rendered.

---

## 2. Configuring a seal processor

Pipeline Processors → new processor → action **Seal (reversible)**.

| Field | Meaning |
|---|---|
| **Field** | The exact field to seal. `*` (the whole-event sweep) is **refused** — see §6. |
| **Data type** | Semantic type (`card`, `email`, `ssn`). Bound into the token. |
| **Keep last N** | Length of the readable tail in the masked display form. |

> **Changing the data type on an existing processor makes values already sealed
> under the old type unreadable.** This is intended, not a bug: a token minted
> as a card number must not later become readable as something else. Create a
> new processor instead of re-typing a live one.

Sealing is **off unless enabled**: it needs `FEATURE_SEALED_FIELDS=true` *and*
real key custody (`SEAL_PROVIDER=swtpm`). With the flag on and custody missing,
the backend **aborts at boot** rather than starting a deployment whose
sensitive-data rules silently do nothing.

---

## 3. Key model — envelope, never a master key

```
root KEK  (TPM-sealed, internal/vault)
  └─ per-tenant DEK  (wrapped at rest, unwrapped in memory, VERSIONED)
       └─ per-tenant SEAL key  (HKDF-separated from the DEK)
            └─ sealed value
```

Sealed Fields reuses the vault's existing envelope hierarchy rather than
standing up a second key system.

**Deliberately rejected: `HKDF(master_secret, tenant_id)`.** It is simpler and
it is wrong — one compromised master would expose every tenant, including
tenants created *after* the compromise. Per-tenant DEKs under a sealed root
bound a compromise to the keys actually taken.

**Why the seal key is derived rather than the DEK used directly:** domain
separation. Field sealing is a high-volume path touching attacker-influenced
data. A weakness there must not become recovery of the stored credentials
(SMTP, OIDC, LDAP, TACACS, SNMP) that chain to the same DEK.

---

## 4. Rotation

`RotateTenantKey` mints the next version and makes it active. Existing values
are **not** re-encrypted and do not need to be: each token names the version
that sealed it, and old versions stay readable until an operator deliberately
retires them.

This is the only workable model at log scale — sealed values live in immutable
OpenSearch and ClickHouse data across the whole retention window, so
"re-encrypt everything" is not an operation that can succeed.

**Retiring a version** (deleting its custody entry) takes effect immediately:
the next reveal of a value naming it fails closed with `410 Gone`. Derived keys
are cached only for the *active* version — the reveal path always re-derives, so
a withdrawn key stops working at once rather than at the next process restart.

---

## 5. The cipher, and why it is what it is

**AES-256-CTR with encrypt-then-MAC (HMAC-SHA256), not AES-GCM.**

This is a constraint of the runtime, not a preference. Sealing happens at the
**edge** — a value that reaches storage in the clear has already leaked, so
encryption must precede indexing — and the edge is Vector's VRL, which offers
AES-CTR and no AEAD mode. Verified against the pinned binary, not assumed.

So the construction is composed by hand, correctly: separate MAC key, MAC over
the full authenticated context, verified in **constant time before any
decryption is attempted**. A tampered token is an error, never plaintext.

When VRL gains AES-GCM this becomes one provider swap with no caller changes;
existing `v1` tokens keep opening through the current path, which is why the
token carries its own version.

### 5.1 The counter-mode trap

> **Vector's `AES-256-CTR` is not Go's.** Rust's `ctr::Ctr64LE` uses the first
> eight IV bytes as a **little-endian** block counter; Go's
> `crypto/cipher.NewCTR` treats the whole IV as one big-endian counter.

They agree on block 0 and diverge from block 1 onward. A 16-byte card number
round-trips perfectly; an email address comes back as `jsmith@example.o`
followed by garbage. **Every round-trip test written entirely in Go passes**,
and every sealed value longer than one AES block is permanently unreadable in
production — discovered when a customer first tries to reveal one.

Go therefore implements the edge's counter mode exactly, pinned by a golden
vector captured from Vector 0.40.0 that runs without Docker. `vrl_parity_test.go`
additionally drives the real pinned binary and unseals its output through the
production Go path.

---

## 6. Context binding

The MAC covers **tenant, processor id, field name, data type and key version**
alongside the ciphertext. A token cannot be replayed into another tenant,
another field or another processor: moving a sealed value anywhere it did not
originate makes it undecryptable rather than silently portable.

This is why the whole-event sweep (`field = "*"`) is refused for `seal`. The
sweep rewrites every string it finds, but a token is bound to *one* field — a
swept value could never be unsealed again.

---

## 7. Revealing a value

```
POST /api/pipeline/processors/unseal
{ "value": "<enc:v1:…>", "reason": "PCI dispute #4471" }
```

Requires **`sensitive_data:admin`**. That is its own RBAC module, not a level of
`administration`, on purpose: revealing a card number is a different capability
from configuring the platform, and an infrastructure or alerting admin must not
acquire it by being an admin of something else.

| Level | Capability |
|---|---|
| `sensitive_data:read` | see that a field is sealed, and its masked display form |
| `sensitive_data:write` | create and edit `seal` processors |
| `sensitive_data:admin` | **reveal plaintext** |

Built-in roles: super-admin and org-admin hold reveal; operator, read-only,
api-client and **auditor** do not. An auditor reads the *trail*, never the
secrets — and a test pins that, so a future grid edit that widens it fails the
build rather than production.

**The caller does not name the processor.** Only the tenant and key version
travel inside a token; the rest is covered by the MAC and unrecoverable from the
token alone. Requiring an operator staring at a log line to know which processor
produced a value written weeks ago would make the feature unusable, so the
server tries the caller's **own** seal processors until one verifies. That is
not a weakening — the binding exists to stop replay into a context its owner
does not hold, and every context tried is one this tenant legitimately owns.

### Responses, and why they differ

| Status | Meaning |
|---|---|
| `200` | Revealed. Response names the field, data type, processor and key version. |
| `403` | You do not hold `sensitive_data:admin`. |
| `404` | The value belongs to **another tenant**. Not 403 — confirming it exists is itself a disclosure. |
| `400` | The token is malformed or fails integrity. It may have been altered. |
| `410` | The key that sealed it is **gone**. Nobody can read it, ever. |
| `501` | Sealing is not enabled on this deployment. |

`410` versus `403` matters operationally: an operator needs to tell "I may not"
from "nobody can, ever again."

---

## 8. Audit and metrics

Every attempt is recorded — **including the refusals, which are the interesting
ones**. The record carries actor, tenant, outcome, field, data type, key
version, the stated reason, and a **fingerprint** of the token (a hash of the
ciphertext) so repeated reveals of the same value can be correlated.

**The plaintext is never recorded.** Nor is the raw token: storing it would be
defensible — it is ciphertext — but it would hand anyone who later obtains a key
a ready-made list of exactly the values worth decrypting, concentrated in one
admin-readable place. A test asserts the plaintext never appears in the trail.

```
netops_unmask_requests_total{outcome="granted"}
netops_unmask_requests_total{outcome="forbidden"}
netops_unmask_requests_total{outcome="unreadable"}
netops_unmask_requests_total{outcome="key_unavailable"}
```

Deliberately **no per-field or per-value label**: a metric series named after
the data it protects is a disclosure channel that outlives the audit entry.

---

## 9. Key delivery to the edge

VRL has no HKDF, so the edge cannot derive anything. It receives the
**already-derived** seal key and MAC key through Vector's `exec` secret backend
(`SECRET[cxseal.<tenant>]` / `SECRET[cxmac.<tenant>]`), resolved at config load
and held in memory only — never written to disk. The tenant DEK never leaves the
API process.

A router compromise therefore exposes the seal keys of tenants that **enabled
sealing**, not a master capable of deriving every tenant's key, and not the DEK
that protects stored credentials.

A tenant id that is unsafe as a Vector secret key is **refused, never
sanitised**: `SECRET[backend.key]` has no escaping, so an id containing `.`
would reference the wrong secret — at the edge that means sealing with another
tenant's key. Mapping two tenants onto one key is the same failure wearing a
friendlier face.

---

## 10. What this deliberately does not do

- **No searchable encryption.** Sealed values are not greppable, by design.
  Equal plaintexts produce different tokens (random IV), so an observer cannot
  link records by ciphertext without decrypting. When you need to *join* on a
  sensitive value without reading it, use the `hash` action — that is what it is
  for. Weakening the cipher to make search work would give away exactly the
  property sealing exists to provide.
- **No bulk reveal.** One value per request, each audited. A bulk endpoint would
  turn a compromised admin session into a data export.
- **No client-side decryption.** Keys never reach the browser.
