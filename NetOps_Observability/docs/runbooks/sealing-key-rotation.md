# Sealing Key Rotation — Operator Runbook

How to rotate a tenant's **sealed-fields** key, what stays readable afterwards,
and the one delay that catches people out.

This is not the same thing as `docs/runbooks/secret-rotation.md`, which rotates
the stack's own service credentials. The key here encrypts *customer data
inside events* — the `<enc:v1:…>` tokens the `seal` processor writes at the edge.
Design: `docs/design/sealed-fields.md`.

## TL;DR

**Sensitive Data Access → Sealing key → Rotate → Confirm rotate.**
The page reports the version it landed on. Then reload the edge router so new
values start sealing under it:

```bash
cd /path/to/NetOps_Observability/deployment/docker
docker compose restart vector-router
```

Nothing already stored becomes unreadable. Nothing needs re-encrypting.

---

## 1. The model in one paragraph

Each tenant holds a **versioned** data-encryption key. Every sealed token names
the version that sealed it, so a rotation is *additive*: version N+1 becomes the
one new values seal under, and versions 1…N are **retained**, which is what keeps
every value already in OpenSearch and ClickHouse openable for the rest of its
retention window. `v1` IS the legacy key — installs that predate versioning need
no migration.

Re-encryption is deliberately not offered. Sealed values live in immutable log
storage across the whole retention window; a scheme that required rewriting them
would fail the first time it was actually needed.

## 2. When to rotate

* A key may have been exposed (host compromise, a leaked backup, an accidental
  copy of the vault material).
* Someone holding `sensitive_data:admin` has left.
* Your own policy sets a schedule. Quarterly is a common choice; there is no
  platform-enforced cadence, because an unnecessary rotation carries the config
  reload below and nothing else.

Rotating is cheap and safe. Not rotating after an exposure is not.

## 3. Procedure

1. **Rotate.** Sensitive Data Access → *Sealing key* → **Rotate** →
   **Confirm rotate**. The control is two-step on purpose: the first click only
   arms it. The result names the new version.

   The same act over the API, for an automated policy:

   ```bash
   curl -sS -X POST https://<host>:8000/api/pipeline/processors/seal/rotate \
        -H "Authorization: Bearer $TOKEN" -d '{}'
   # → {"key_version":2,"note":"New values seal under this version once the router reloads…"}
   ```

   Requires `sensitive_data:admin` on a **tenant-scoped** principal. A
   cross-tenant platform principal is refused (400): there is no such thing as
   rotating "everyone's" key in one call.

2. **Reload the edge router.** Vector resolves its secrets when it loads its
   config, so until it reloads it is still sealing under the previous version.
   This is the step that is easy to skip and easy to misread as a failed
   rotation.

   ```bash
   docker compose restart vector-router
   ```

3. **Verify.** Seal a value through the pipeline (or wait for live traffic) and
   open the new token on **Sensitive Data Access**: the *Key* column shows the
   new version. Rows from before rotation still show theirs, and still reveal.

## 4. What can go wrong

| Symptom | Cause | What to do |
|---|---|---|
| `sealed fields are not enabled on this deployment` (501) | No seal provider is configured on this install. | Nothing to rotate. See `docs/design/sealed-fields.md` for enabling it. |
| `a tenant-scoped principal is required` (400) | You are on the platform/Global scope. | Switch to the tenant whose key you are rotating. |
| New rows still show the old version | The router has not reloaded. | Step 2. |
| A reveal returns **Key retired** | The token names a version the provider can no longer resolve. | Rotation never retires a version by itself — restore the key material, or accept that those values are unreadable. |
| The router will not start after a rotation | It could not fetch a key (`/internal/sealing/edge-keys`). | Fail-closed by design: exit 78, no key, no start. Check the router's identity and the endpoint, not the rotation. |

## 5. What rotation does **not** do

* It does not re-encrypt stored values.
* It does not retire or delete any earlier key version.
* It does not touch another tenant.
* It does not change what a reveal is audited as — every unseal, granted or
  refused, still lands on Sensitive Data Access with the key version it used.
