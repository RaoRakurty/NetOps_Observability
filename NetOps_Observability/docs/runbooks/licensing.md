# Runbook — licensing (issue · install · verify · rotate)

**Who this is for:** whoever issues a Correlix licence, and whoever has to
explain to a customer why the one they were sent will not install.

**Alerts that route here:** `LicenceExpiringSoon`, `LicenceInGrace`,
`LicenceExpired` (group `licence` in `src/config/rules.yaml`), plus the
soft-overage group `licence-ceilings` (`LicenceCeilingApproaching`,
`LicenceCeilingReached`, `LicenceOverage`). None of them is
a page.

**Design of record:** `docs/design/LICENSING_MODEL_2026-09-04.md` §3 (the file)
and §4 (the enforcement points).

---

## 1. What the mechanism is

A licence is **one signed JSON file**. Nothing else.

* **ed25519** (Go stdlib `crypto/ed25519`), detached signature carried in the
  same file, over a canonical payload.
* **Verified entirely offline**, against public keys embedded in the binary.
* **No licence file = Community.** That is a normal, supported, un-alarming
  state: the boot line is INFO, not a warning.
* Tiers are **data, not builds**. One binary, one image set. A customer upgrades
  by installing a file, never by pulling a different image.

### What it deliberately is **not**

| Not this | Why |
|---|---|
| an activation server | there is none, and there will not be one. Everything below works on a host with no route to the internet. |
| a phone-home | the product never reports usage anywhere by itself. Metering (design §5) is a signed report the customer downloads and sends if they want to. |
| a kill switch | a lapsed licence lowers commercial ceilings. It cannot stop the platform, delete anything, or hide anything. |
| obfuscation | the commercial code is readable in the tree. Enforcement is the gate plus the contract, not hiding source. |
| a per-tenant thing | one licence covers the whole deployment. The route behind it is `requirePlatformAdmin`, not `requireAdmin`. |

### What it gates, exactly

**Two ENFORCED ceilings**, and no others:

| Ceiling | Community | Enforced at |
|---|---|---|
| `devices` — the unit is a **MONITORED** device | **25** | the monitoring transition, in ONE place: the device registry's `SetMonitorGate` (`internal/discovery/monitoring.go`, wired in `main.go`). It is asked by `PUT /api/devices/{id}/monitoring`, by `POST /api/devices` (a manually created device is monitored), and by a discovery SOURCE reporting a device that would default to monitored. **Discovery is never refused** — an over-ceiling device enters the inventory and its COLLECTION is withheld and listed |
| `watched_prefixes` | **5** | the BGP watchlist `Add` path (`bgp_ops.go`) |

The other five ceilings in the file — `tenants`, `orgs`, `retention_days`,
`skills`, `provider_tokens_per_day` — are **carried but not enforced**. They are
in the document so an issued file is forward-compatible and complete, and the
admin page and the CLI both label them `(carried, not enforced)`. Nothing in the
product gates on them, because the tiering plan's numbers for them are proposals
the owner has not decided. `entitlement.Enforced(name)` is the machine-readable
statement of which is which, and `TestOnlyDecidedCeilingsAreEnforced` fails if
that ever drifts.

**The LOCKED commercial feature set**, exactly seven names and nothing else:

| Feature | Lowest tier | Gate today |
|---|---|---|
| `security_findings` | **Team** | `/api/security/findings*` |
| `security_dialects` | Enterprise | hardening dialect registry (`licenceDialectAllowed`); core dialect `cisco-iosxe` is never gated |
| `msp_management` | Enterprise | org create, cross-tenant fleet listing |
| `saml` | Enterprise | `oidc_config.go` SAML provider path |
| `ldap` | Enterprise | `/api/auth/ldap/config`, `/api/auth/ldap/test` |
| `siem_export` | Enterprise | **no route yet — the capability does not exist.** The gate is ready; see `TestLicenceGatesReadyForAbsentFeatures` |
| `scim` | Enterprise | **no route yet — same** |

Adding an eighth name gates a capability for every customer, so it is an owner
decision, not a diff.

### Expiry, grace and overage — DECIDED 2026-09-05

Owner decision, recorded in `docs/design/TIERING_PLAN_2026-09-03.md` §9 and
written up in `docs/design/LICENSING_MODEL_2026-09-04.md` §8. This is what you
may tell a customer.

**Three phases.** The evaluated state carries `phase`, and every 402 carries the
same value as `licence_state`:

| phase | when | what they experience |
|---|---|---|
| `valid` | before `expires_at` — and always on Community, which has no expiry | everything the licence grants |
| `in_grace` | inside `expires_at + grace_days` | **nothing changes at all.** The Licence page shows the days left; `LicenceInGrace` warns |
| `post_grace` | after that | creation and configuration of paid capability is refused; everything else keeps working |

**What stops after grace, and what does not.** Refused: a monitoring activation
beyond the Community 25, a second tenant or organisation, and any non-GET on a
feature-gated route (SAML config, LDAP config/test, a new dialect, a SIEM
export). Kept working: every GET/list/export of a licensed feature — findings,
their facets and trend, the LDAP configuration as it stands, the tenant and org
lists. Every device already monitored stays monitored. **Nothing is disabled,
hidden or deleted, and Correlix never chooses which devices "lose"** — the
over-ceiling devices are listed newest-first so the shape of the overage is
visible, and the API says exactly that beside the list.

**Grace defaults are the ISSUER's, not the format's.** `correlix-licence sign`
writes an explicit number: 30 days for team/enterprise, 7 with `--trial`, 0 for
community, and whatever `--grace-days N` says when given (including 0). A file
that omits `grace_days` still means **zero** — a licence already in a customer's
hands is never re-termed by a later policy.

**Trials.** `--trial` issues a 30-day Team/Enterprise evaluation licence: expiry
30 days from issue, `trial: true` in the document, 7 days of grace. It grants
exactly what its tier, ceilings and features say; the flag changes the words
(`show`, `verify`, and "Evaluation licence · N days left" on the page), never the
enforcement. Because `trial` is omitted from the canonical payload when false,
every licence issued before the field existed still verifies.

**Soft overage (Team and Enterprise).** The monitored-device allowance does not
block: activation beyond it succeeds and is recorded. Never a kill switch during
an incident. Community keeps the **hard** block at the 26th activation — a
published free ceiling. The register beside the licence
(`licence-overage.json`) keeps `overage_since` and the peak across restarts and
fails soft. **Do not quote a window**: how long an overage may run and what it
costs are order-form terms and appear nowhere in the product. The word the
product uses is *true-up*.

Alerts: `LicenceCeilingApproaching` (80–90 %), `LicenceCeilingReached`
(90–100 %), `LicenceOverage` (over) — all `tier: warning`, all joined on
`netops_licence_ceiling_soft == 1`, so a Community deployment fires none of them.
The post-grace rule is `LicenceExpired` (renamed from `LicenceDegraded` on
2026-09-05; the expression is unchanged).

---

## 2. The safety invariant (read this before answering any customer question)

A licence problem — **expired, invalid, tampered, missing, deliberately
removed** — is *technically incapable* of weakening:

* tenant isolation and RLS / data separation,
* authorization (`requirePerm` / `requirePlatformAdmin` / `requireCrossTenant`),
* integrity controls (sealing, audit, signature verification),
* core authentication. **OIDC is core and is always available**, at every tier,
  with no licence at all.

This is structural, not a promise: the isolation and authentication paths do not
import `internal/entitlement` at all, and
`src/backend/internal/entitlement/safety_invariant_test.go` asserts they do not
(`TestSafetyPackagesDoNotDependOnEntitlement`,
`TestSafetyFunctionsDoNotConsultEntitlement`, `TestOIDCStaysCore`).

The worst case of a bug anywhere in the licence subsystem is a customer who paid
for SAML not getting SAML. That is a support ticket, not a breach.

Fail-closed is the other half: every gate is nil-safe and answers **Community**
when unwired. Deleting the whole mechanism (the two packages plus every
`LICENCE-BEGIN`/`LICENCE-END` marker block: ten in `main.go`, one each in
`bgp_ops.go`, `oidc_config.go`, `org_handlers.go` and `identity_handlers.go`) is
a supported state in which every gate answers Community. Nothing breaks and
nothing opens up.

---

## 3. Issue a licence

Signing happens on the **signing host**, never on a customer's deployment and
never in CI. Build the tool from a clean checkout:

```bash
cd src/backend
go build -o /usr/local/bin/correlix-licence ./cmd/correlix-licence
```

### 3.1 Today: the LAB key

The key currently embedded in `keys.go` is a **LAB/dev key generated 2026-09-04
on the owner's lab host**. It issues **lab and trial licences only**. No
production customer licence will ever be signed with it. Its private half lives
at `data/licence-signer/lab-signing-key.ed25519`, mode `0600`, gitignored
(`.gitignore` excludes `data/licence-signer/` and re-includes only `*.pub`).

* key id: `0edbb619f9b318e0`
* public key (publishable, and published in `keys.go`):
  `Q+PMj3/TNIjbRvopQwXLM5tJfgjzPTsoHIWwiM0apR8=`

The **production** key does not exist yet — see §6.

### 3.2 Sign

```bash
correlix-licence sign \
  --key      data/licence-signer/lab-signing-key.ed25519 \
  --customer "Acme Networks" \
  --tier     team \
  --issued   2026-09-04 \
  --expires  2026-12-31 \
  --features security_findings \
  --grace-days 14 \
  --support-level business-hours \
  --support-contact support@example.com \
  --out      acme-networks.json
```

```
wrote acme-networks.json (licence_id=acme-networks-20260904, tier=team, key=0edbb619f9b318e0)
```

An Enterprise example, with an explicit ceiling override and the full locked
Enterprise feature set:

```bash
correlix-licence sign \
  --key      data/licence-signer/lab-signing-key.ed25519 \
  --customer "Acme Networks" \
  --tier     enterprise \
  --expires  2027-09-04 \
  --ceilings devices=-1,watched_prefixes=-1,retention_days=90 \
  --features security_findings,security_dialects,siem_export,msp_management,saml,scim,ldap \
  --grace-days 30 \
  --out      acme-networks-enterprise.json
```

Flag notes that matter:

| Flag | Behaviour |
|---|---|
| `--tier` | `community`, `team` or `enterprise`. Anything else is refused. |
| `--expires` / `--issued` | RFC3339 or bare `YYYY-MM-DD` (midnight UTC). `--issued` defaults to now. |
| `--ceilings` | starts from the **tier's reference values**, so state only what differs. `-1` means unlimited. An unknown ceiling name is refused, never silently ignored. |
| `--features` | must be inside the closed vocabulary. A typo is refused **at signing time**, so our mistake never leaves the signing host. |
| `--grace-days` | **issuer-set, no product default.** Omitting it issues zero days of grace. State it deliberately. |
| `--licence-id` | defaults to `<customer-slug>-<YYYYMMDD>`. |
| `--support-level` / `--support-contact` | informational only. Nothing gates on support. |

The signed file (signature elided here; it is 88 base64 characters):

```json
{
  "licence_id": "acme-networks-20260904",
  "customer": "Acme Networks",
  "tier": "team",
  "issued_at": "2026-09-04T00:00:00Z",
  "expires_at": "2026-12-31T00:00:00Z",
  "ceilings": {
    "devices": 250,
    "tenants": 5,
    "orgs": 1,
    "retention_days": 30,
    "watched_prefixes": 100,
    "skills": 10,
    "provider_tokens_per_day": 0
  },
  "features": [ "security_findings" ],
  "support": { "level": "business-hours", "contact": "support@example.com" },
  "grace_days": 14,
  "key_id": "0edbb619f9b318e0",
  "signature": "…"
}
```

**Always verify before sending** (§5). A file that verifies on the signing host
verifies on the customer's host, because the same code does both.

---

## 4. Install a licence

Two paths. Both end in the same file, and both take effect without a restart.

### 4.1 The admin page

**Administration → Platform → Licence → Install a licence.** Choose the file or
paste the document, then select **Install licence**.

* The route is `PUT /api/system/licence`, gated by `requirePlatformAdmin`. A
  tenant or organization administrator holds full `administration:admin` and
  **must not** reach it; for them the page renders read-only.
* The body is bounded at 64 KiB (`MaxDocumentBytes`).
* **The signature is verified before anything is written.** A refused document
  never touches the disk, so a bad upload cannot displace a working licence, and
  the operator keeps the tier they had.
* Both outcomes are audited: an allow records `licence_id`, `customer`, `tier`,
  `expires_at`, `key_id`; a deny records the verbatim refusal reason.
* `DELETE /api/system/licence` removes it and returns to Community. The page
  requires typing a confirmation token first.

### 4.2 Drop the file

```bash
# host path (the api's data volume), mode 0600 is what the api writes itself
install -m 0600 acme-networks.json data/api/licence.json
```

In the container that path is `/data/api/licence.json` (`licence.DefaultPath`),
overridable with `LICENCE_FILE`.

The store re-stats the file at most every 5 s (`DefaultPollInterval`), so a
hand-dropped file takes effect within about five seconds. It is also
re-evaluated on that schedule **without** the bytes changing, so a licence that
crosses its expiry or the end of its grace reports the new state on its own.

Confirm from the boot log or by re-reading the page:

```bash
docker compose -f deployment/docker/docker-compose.yml logs api | grep -i licence
```

The line is the `State.Summary()` string: licence id, tier, customer, expiry,
the two enforced ceilings, the granted features, and `IN GRACE` / `DEGRADED`
when either applies.

---

## 5. Verify a licence offline

`correlix-licence verify` is the same verification code the product runs, so a
customer checking a file we sent them exercises exactly the install path.

```bash
correlix-licence verify acme-networks.json
```

```
VERIFIED  acme-networks.json
  acme-networks-20260904, tier=team, customer="Acme Networks", expires=2026-12-31T00:00:00Z, ceilings=250 devices/100 watched prefixes, features=security_findings
  ceilings:
    devices                  250
    watched_prefixes         100
    tenants                  5  (carried, not enforced)
    orgs                     1  (carried, not enforced)
    retention_days           30  (carried, not enforced)
    skills                   10  (carried, not enforced)
    provider_tokens_per_day  0  (carried, not enforced)
  features:
    security_findings        security findings
```

Exit status is 0 only when the file authenticated.

### A customer verifying with the published key

A customer who does not want to trust our binary's embedded key list supplies
the published public key explicitly:

```bash
correlix-licence verify \
  --pubkey Q+PMj3/TNIjbRvopQwXLM5tJfgjzPTsoHIWwiM0apR8= \
  acme-networks.json
```

**Flags come before the file.** The command uses the stdlib `flag` package,
which stops parsing at the first non-flag argument, so
`verify acme-networks.json --pubkey …` is refused with
`verify: exactly one licence file is required`.

The same key is on the Licence page under **Verification** (with a copy button
and the `verify_hint` line the API returns), so the value can be read from the
running product rather than taken from an email.

### Evaluating expiry at another time

`--at` evaluates the file as at a chosen instant, which is how to show a
customer what their licence will do before it does it:

```bash
correlix-licence verify --at 2027-01-05T00:00:00Z acme-networks.json | tail -1
```

```
  IN GRACE:  licence expired on 2026-12-31; running at Team under the issuer's 14-day grace until 2027-01-14
```

```bash
correlix-licence verify --at 2027-02-01T00:00:00Z acme-networks.json | head -2
```

```
VERIFIED  acme-networks.json
  acme-networks-20260904, tier=team, customer="Acme Networks", expires=2026-12-31T00:00:00Z, ceilings=25 devices/5 watched prefixes, features=none — DEGRADED: licence expired on 2026-12-31 and the 14-day grace ended on 2027-01-14; running at Community ceilings — nothing has been deleted and everything over a ceiling is listed
```

### Inspecting a file that will **not** verify

That is usually why you are looking at it. `show` parses and prints without
authenticating, and says so on the first line:

```bash
correlix-licence show acme-networks.json
```

```
NOT VERIFIED (use `verify` to authenticate this file)

  licence_id:  acme-networks-20260904
  …
```

### Cosmetic edits are safe

The signature covers a canonical payload: fixed field order, RFC3339 UTC
timestamps, features sorted and de-duplicated. Whitespace, key order in the
outer file and trailing newlines are outside it, so an operator can pretty-print
an issued licence and it still verifies
(`TestVerifyIgnoresCosmeticReserialisation`).

---

## 6. Keys — custody, rotation, and the ceremony that has not happened

### 6.1 Custody

* The **private key never enters this repository, any build, or any container
  image.** That is checkable, not merely stated: nothing in the api's import
  graph reaches `internal/licence/signer`.
* `signer.LoadPrivateKey` **refuses** any key file more permissive than `0600`.
* `signer.WritePrivateKey` opens with `O_EXCL` and refuses to overwrite an
  existing key. Silently clobbering a signing key would strand every licence
  already issued under it.
* `correlix-licence keygen` prints the **public** key and the *path* of the
  private one. It never prints private key material. Reading the private key is
  a deliberate `cat`, not a side effect of running a tool.

### 6.2 Rotation

The procedure is the one at the top of `src/backend/internal/licence/keys.go`,
and it is the authority. **Never more than two trusted keys** — a build that
trusts a long tail of retired keys has no rotation story, it has an accumulation
story.

1. Generate the new key on the signing host:

   ```bash
   correlix-licence keygen --dir /secure/correlix-signing --name prod-signing-key
   ```

   It prints the key id, the public key, and the two paths. Move the private key
   to its custody location.

2. In `keys.go`, change the entry that is currently `RoleCurrent` to
   `RolePrevious`.

3. Add the new key as `RoleCurrent`, with a `note` that records the ceremony it
   came from. `keygen` prints the exact line to paste.

4. Ship. **Both keys verify**, so every licence already in the field keeps
   working while new ones are issued under the new key.

5. After every outstanding licence has been reissued — that is, after the
   longest term expires — delete the previous entry.

A document names the key it was signed with (`key_id`), and lookup is by that
id: there is no "try every key until one works", so a rotation mistake is
diagnosable rather than invisible. `TestKeyRotation` covers the two-key window
and `TestEmbeddedKeysAreUsable` covers the shipped set.

### 6.3 Key ceremony for the PRODUCTION key — **PENDING, HAS NOT HAPPENED**

**No production signing key exists.** The only key any build trusts today is the
lab/dev key of §3.1, and it issues lab and trial licences only.

The ceremony is a prerequisite for issuing any commercial licence. What it owes,
per design §3:

* generation on an **offline** signer (HSM or air-gapped host), witnessed;
* a recorded custody chain: who holds the key, where the backup is, who may
  invoke it, and how a compromise is declared;
* the public key added to `keys.go` as `RoleCurrent`, demoting the lab key to
  `RolePrevious` and then dropping it per §6.2;
* the same public key published here and on the Licence page, so a customer can
  verify without contacting us.

**Also pending, and blocking commercial issue:** the **Correlix Enterprise
licence TEXT and the CLA are awaiting legal approval, and no terms are written
anywhere in this repository.** `LICENSES/Correlix-Enterprise.txt` is a slot, not
a document. Do not draft, paraphrase, or generate licence or CLA text — the
design's build order (§7 step 1) records both as blockers precisely so that
nobody does.

---

## 7. What degradation actually looks like

Three states, and the product distinguishes all three on the page, in the log
line, and in the metrics.

| State | When | Tier in force | Features | What the operator sees |
|---|---|---|---|---|
| **live** | `now <= expires_at` | the licensed tier | as granted | nothing unusual |
| **in grace** | `expires_at < now <= expires_at + grace_days` | still the licensed tier | still granted | a banner and `LicenceInGrace`. **Nothing has changed yet.** This is the last quiet window to install a renewal |
| **post_grace** | `now > expires_at + grace_days` | **Community** | **none granted; the lapsed set stays READABLE** | `LicenceExpired`, the licensed tier remembered ("your Team licence expired"), every over-ceiling item and device listed, and every GET/list/export of a licensed feature still served |

`grace_days` is issuer-set with **no default**: a file that omits it goes from
live to degraded at expiry with no grace at all.

### Over-ceiling items are LISTED, never hidden and never deleted

When usage exceeds an **enforced** ceiling, `State.Overages` produces a row per
ceiling saying how many are over, that nothing has been removed, and which tier
covers them. The Licence page renders that list.

The device count is the **monitored** count: an inventory of five hundred
discovered devices with twelve enabled reads 12 of 25, because discovery costs
no allowance (owner C4, 2026-09-05). An over-ceiling number therefore only
appears where monitoring was already in force — a Team deployment whose licence
lapsed to Community, say — and in that case NOTHING is switched off: the
existing monitoring keeps running, new activations are refused, and the page
lists the excess. Devices whose default-on monitoring the ceiling withheld are
counted separately and named in a note beside the bar
(`netops_monitoring_withheld_devices_total`), so "25 of 25" is never the whole
story on a network that has more.

Only enforced ceilings can produce an overage. Reporting one against a limit
nothing gates would be theatre.

### What refusals look like

A gate that refuses returns **402 Payment Required** — deliberately not 403,
because the caller's authorization is fine and the SPA keys its upgrade card off
that exact status. The body names the ceiling or feature, the current value, the
limit, the tier in force and the tier that lifts it, so the UI renders an upgrade
card rather than a broken page.

### What does **not** change, in any state

* tenant isolation, RLS and data separation;
* permissions and every authorization check;
* sign-in, including OIDC;
* integrity controls: sealing, the audit trail, signature verification;
* **the data.** Nothing is deleted, nothing is hidden, no device is removed from
  the inventory, no history is truncated.

The page carries this statement itself (`ExpirySemanticsNote`), because a policy
that is still open is a fact about the product and belongs in the product.

---

## 8. Alerts and metrics

Two gauges, emitted on **every** scrape including on a Community deployment, so
"no licence" is a value and not a gap in the series.

| Metric | Meaning |
|---|---|
| `netops_licence_days_to_expiry` | whole days to expiry, negative once expired. **`36500` is the sentinel for "no licence installed, nothing to expire"** |
| `netops_licence_state{tier,degraded,in_grace}` | `1` on the combination in force, `0` on every other. Every combination is emitted every scrape |

Group `licence` in `src/config/rules.yaml`, unit-tested in
`src/config/rules-tests/licence.test.yaml`:

| Alert | Expression | For | Tier |
|---|---|---|---|
| `LicenceExpiringSoon` | `netops_licence_days_to_expiry >= 0 and … < 14` | 1h | `warning` |
| `LicenceInGrace` | `netops_licence_state{in_grace="true"} == 1` | 15m | `warning` |
| `LicenceExpired` | `netops_licence_state{degraded="true"} == 1` | 15m | `warning` |
| `LicenceCeilingApproaching` | `(usage / ceiling >= 0.8 < 0.9) and on(ceiling) ceiling_soft == 1 and on(ceiling) ceiling > 0` | 1h | `warning` |
| `LicenceCeilingReached` | `(usage / ceiling >= 0.9 <= 1) and on(ceiling) ceiling_soft == 1 and on(ceiling) ceiling > 0` | 1h | `warning` |
| `LicenceOverage` | `netops_licence_overage_devices > 0 and on() ceiling_soft{ceiling="devices"} == 1` | 1h | `warning` |

**None of these is a page, and that is deliberate.** The four page conditions are
the ones in `docs/runbooks/engine-liveness-matrix.md`, and a licence is none of
them: a lapsed licence lowers commercial ceilings, and that is an office-hours
commercial problem, not a 3 a.m. phone call.

Two guards worth knowing before editing the rules:

* **The Community guard is structural.** A deployment with no licence reports the
  `36500` sentinel, and `36500 < 14` is false, so it never enters
  `LicenceExpiringSoon`'s range. That holds only while the threshold stays far
  below the sentinel: check any widening against it first. The two state rules
  match on the **value** (`== 1`), not the presence of the series, because a
  Community install does publish `in_grace="true"` — as `0`.
* **The `tier` label collides on purpose.** `netops_licence_state` carries its own
  `tier` label (the licence tier) and the routing label is also `tier`. Rule
  labels win over sample labels, so the explicit `tier: warning` overwrites
  `community|team|enterprise` on the fired alert. The consequence is that
  `{{ $labels.tier }}` in one of these annotations would print `warning`, which
  is why the summaries never name the tier.

---

## 9. Troubleshooting — every refusal the verifier can produce

The install route returns the refusal **verbatim**, and the page shows it
unchanged. An operator holding a file we will not accept needs the exact reason,
not "invalid".

| Message | Sentinel | What it actually means | What to do |
|---|---|---|---|
| `licence: unknown signing key: key_id "…" (this build trusts … (current))` | `ErrUnknownKey` | The file is signed by a key this build does not carry. The signature was never even checked. Usually: signed with a **retired** key that has already been dropped, signed with a key from a **different** ceremony, or the customer is running a build older than the rotation. | Compare the `key_id` in the file (`correlix-licence show`) with the ids the message lists. Reissue under the current key, or ship a build that still carries the previous one (§6.2 step 4 exists so this does not happen). |
| `licence: signature does not verify (key …): the file was modified after it was issued, or it was not issued by Correlix` | `ErrSignature` | The key is trusted and the signature over the canonical payload does not match. **The file was edited after signing** — the ceilings, tier, dates or customer were changed — or it was forged. Cosmetic reformatting cannot cause this; only payload content can. | Do not attempt to repair it. Reissue from the signing host. If the customer did not edit it, treat it as a tampering report. |
| `licence: malformed document: json: unknown field "…"` | `ErrMalformed` | The document carries a field the schema does not have. The parser sets `DisallowUnknownFields` on purpose: a misspelled ceiling must fail loudly rather than silently leave the default in place. | Look at the named field. It is a typo in a hand-edited file, or a file from a newer schema than this build. |
| `licence: malformed document: invalid character 'h' looking for beginning of value` | `ErrMalformed` | Not JSON at all. Usually a truncated download, an HTML error page saved as `.json`, or a PGP-wrapped copy. | Re-send the file. Check the byte count. |
| `licence: malformed document: signature is not 64 base64 bytes` | `ErrMalformed` | The `signature` field is missing, empty, not base64, or the wrong length. An **unsigned** document lands here, which is the point: unsigned is an error, never a quiet downgrade. | Reissue. Never hand-assemble a licence document. |
| `licence: malformed document: expires_at (…) is not after issued_at (…)`, `… licence_id is empty`, `… grace_days is negative`, `… ceiling X is -N (only -1 means unlimited)` | `ErrMalformed` | Shape validation, run **after** the signature checks out. Reaching this means something signed a document that `correlix-licence sign` would have refused, because the signer validates before signing. | Reissue with the CLI. If it came from the CLI, that is a bug — capture the file. |
| `licence: value outside the closed vocabulary: tier "…"` / `: feature "…"` | `ErrVocabulary` | The document names a tier or feature that is not in the closed vocabulary. A typo in an issued licence must be a loud refusal, never a capability the customer paid for and silently did not receive. Like the row above, the signer refuses these **before** signing, so seeing one at install time means the file was signed by something other than `correlix-licence sign`. | Reissue. If the customer genuinely needs the named capability, it is an owner decision to add it to the vocabulary, not a document edit. |
| `licence: verified but could not be stored at …` | — | The document is valid; the write failed. Disk full, a read-only volume, or wrong ownership on `data/api/`. | Fix the volume. The previous licence, if any, is untouched: the write is atomic (temp file in the same directory, then rename). |
| `cannot read /data/api/licence.json: …` in `State.LoadError` | — | A licence file **exists** but cannot be read. The state is Community plus a loud reason, and the boot log says so at WARN. It is never a boot failure. | Check permissions and ownership on the file and its directory. |

Two shapes that are **not** errors:

* **no file at all** — Community, INFO boot line, `netops_licence_days_to_expiry`
  at the `36500` sentinel. The free tier is the funnel, not a fault.
* **expired but authentic** — an expired file still verifies. Expiry is evaluated,
  not rejected, which is what lets the page say "your Team licence expired"
  instead of "invalid licence".

---

## 10. Where the code is

| Thing | Path |
|---|---|
| Central entitlement service (vocabulary, gates, the 402) | `src/backend/internal/entitlement/entitlement.go` |
| Safety invariant test | `src/backend/internal/entitlement/safety_invariant_test.go` |
| Document, canonical payload, keys, errors | `src/backend/internal/licence/document.go`, `keys.go` |
| Verification and expiry evaluation | `src/backend/internal/licence/verify.go`, `state.go` |
| File store (atomic write, poll, install/remove) | `src/backend/internal/licence/store.go` |
| `entitlement.Service` implementation + metrics | `src/backend/internal/licence/service.go` |
| Platform-admin route `GET\|PUT\|DELETE /api/system/licence` | `src/backend/internal/licence/api.go`, wired at `main.go` (`licenceDeps`, `licenceGate`, `licenceUsage`) |
| Signing (never imported by the api) | `src/backend/internal/licence/signer/signer.go` |
| CLI | `src/backend/cmd/correlix-licence/main.go` |
| Admin page | `src/frontend/src/pages/Licence.tsx`, `licence.model.ts` |
| Alert rules and their tests | `src/config/rules.yaml` (group `licence`), `src/config/rules-tests/licence.test.yaml` |
| Operator-facing page | `docs-portal/docs/administration/licence.md` |
