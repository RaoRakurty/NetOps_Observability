---
title: Review sensitive-data access
sidebar_label: Sensitive Data Access
description: Read every attempt to reveal a sealed value, successful or refused, and rotate the tenant's sealing key.
page_type: task
sidebar_position: 11
---

# Review sensitive-data access

Sealed Fields is reversible masking. A `seal` processor encrypts a value at the edge under the tenant's own key, so what lands in storage is a token rather than the value, and an operator who genuinely needs the value asks for it through an audited reveal. **Administration → Data Collection → Sensitive Data Access** is the read-back: who asked, for what, why, and what happened.

## Before you begin

- **Permission:** `sensitive_data:admin`. Reading who revealed data is itself sensitive, because it names the values that were interesting enough to look at, so the read is behind the same gate as the reveal. The trail is per-tenant data.
- `sensitive_data` is its own module rather than a level of `administration`, so an infrastructure or alerting administrator does not acquire the reveal capability by being an administrator of something else. On the ladder, `read` sees that a field is sealed and its masked form, `write` creates and edits `seal` processors, and `admin` reveals plaintext.
- **Flag:** `FEATURE_SEALED_FIELDS`, default off.
- **Key custody is also required.** Sealing needs real key material, from `SEAL_PROVIDER`. With the flag on and no custody, the API refuses to start rather than running with sealing silently inert. There is no state in which the feature reports itself on while values pass through in plaintext.
- With sealing off, `POST /api/pipeline/processors/unseal` and `POST /api/pipeline/processors/seal/rotate` answer `501 sealed fields are not enabled on this deployment`. The access trail still reads, and it is empty because nothing was ever sealed.

## How sealing works

- A sealed value is encrypted with AES-256 in counter mode and authenticated with HMAC-SHA256, encrypt-then-MAC. The MAC is verified in constant time before anything is decrypted, so a tampered token is rejected rather than decrypted into garbage.
- The stored token names its own parameters: a version, the owning tenant, the key version, the initialisation vector, the ciphertext and the MAC. The version leads and is covered by the MAC.
- Keys are per tenant and versioned. The tenant's data-encryption key never leaves the API process. Only derived seal and MAC keys reach the edge, delivered over an internal route that exists only when sealing is on and is gated on the ingest router's own workload identity under TLS.
- The ingest cipher and the application cipher are the same construction, generated from one package, and their agreement is proved against the real pinned edge binary rather than asserted in a comment.

## Steps

### Read the access trail

1. Open **Administration → Data Collection → Sensitive Data Access**.
2. Read the columns:

   | Column | What it holds |
   | --- | --- |
   | **When** | The time of the attempt. |
   | **Who** | The operator who asked. |
   | **Outcome** | **Revealed**, **Failed integrity**, **Key retired**, or **Refused — other tenant**. |
   | **What** | The data type and the field, as context, never the value. |
   | **Stated reason** | The reason the operator gave, or "none given". |
   | **Value** | A short fingerprint of the ciphertext token, so repeated reveals of the same value correlate. |
   | **Key** | The key version that sealed the value. |

3. To read the same trail from the API, call `GET /api/pipeline/processors/unseal/audit`. It carries the standard pagination headers, and the total in `X-Total-Count` is the true total under the same filter.

The filter is applied on the server, on the recorded route, and not by filtering a page in the browser. A client-side filter over a capped page would render an empty list whenever reveals sat below the newest rows, and a compliance surface that silently reports "nobody read anything" is the one failure this page must never have.

### Rotate the tenant's sealing key

1. Call `POST /api/pipeline/processors/seal/rotate` as a principal holding `sensitive_data:admin` and scoped to one tenant.
2. Read the response. It states that new values seal under the new version once the router reloads its configuration, and that values sealed under earlier versions remain readable.

Rotation advances the version and orphans nothing. Values already written are not re-encrypted, and each one names the version that sealed it, so it keeps opening. That is the only model that works at log scale, where sealed values sit in immutable search and analytics data across the whole retention window. Retiring a key version takes effect immediately rather than at the next restart, because historical key versions are derived on demand and never cached.

## What the trail records, and what it never records

Each attempt records the outcome, the tenant that owns the value, the data type, the field, the processor, the operator's stated reason, the operator's own tenant and whether they were acting cross-tenant, the key version, and a fingerprint of the ciphertext token.

**It never records the plaintext, and nothing derived from it.** An audit trail that leaked what it audits would concentrate every revealed secret in one administrator-readable place. This page therefore cannot display a revealed value, and no filter or export will produce one, because the server never wrote one down.

The record is written before the plaintext is returned. If the trail cannot durably record who read what and why, the reveal is refused with `503` and nothing is disclosed. A reveal that cannot be witnessed does not happen.

## The outcomes

| Outcome | Status | Meaning |
| --- | --- | --- |
| Revealed | `200` | The value was returned to the caller, and the reveal is recorded. |
| Refused, other tenant | `404` | The token belongs to another tenant. It is refused before any key material is touched, and as a `404` rather than a `403`, because confirming that another tenant's token exists is itself a disclosure. |
| Key retired | `410` | The key version that sealed this value is gone. Nobody can open it, now or later. |
| Failed integrity | `400` | The token is tampered, malformed, or belongs to a context this tenant does not have. |

Refusals are recorded as well as successes. A caller refused by the permission gate has nothing extra recorded, so they cannot learn from the trail whether the token they presented was valid.

The same outcomes are counted as `netops_unmask_requests_total`, labelled `granted`, `forbidden`, `unreadable` and `key_unavailable`, with no per-field or per-value label. A metric that carried the field name would be a disclosure channel outliving the audit entry.

## Result

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/pipeline/processors/unseal/audit
```

```json
[]
```

An empty array on a deployment with sealing off means exactly what it says: no reveal has ever been attempted. That is different from a failure to read. If the trail cannot be read, the route answers `502 audit trail unavailable` and the page says so in words: this is a load failure, not an empty access trail. The page never renders one as the other.

## Related

- [Create a pipeline processor](/administration/processors) for the `seal` action and the rest of the shaping catalog.
- [Read the audit log](/administration/audit-log) for the wider trail this one is a filtered view of.
- [Add users and grant access](/administration/identity-access) for the `sensitive_data` module and its ladder.
- [Honest states](/reference/honest-states) for the same distinction on other surfaces.
