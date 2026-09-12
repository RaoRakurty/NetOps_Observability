# Runbook — production licence signing key (ceremony · custody · rotation · DR)

> ## STATUS: BLOCKED ON CUSTODIANS
>
> **custodians: TO BE NAMED BY THE OWNER**
>
> **The ceremony has NOT happened. No production signing key exists.** Nothing in
> this runbook has been executed, rehearsed or proven — it is the procedure to
> follow, written before the fact, not a record of something done. At least two
> named human custodians must exist before step §3 is run, and naming them is an
> owner action that no engineer and no agent may perform. Until then the only key
> any build trusts is the **LAB** key, and the release guard (§9) refuses.

**What this is.** The procedure that turns "we need to sign customer licences"
into a production ed25519 signing key that exists in exactly one place, is
controlled by two people, and can be rotated, recovered and retired without
invalidating a single licence already in a customer's hands.

**Owner decision of record:** 2026-09-05, tracker 259 — *HSM/OFFLINE, TWO-PERSON
CONTROL.* Production signing private keys must never live in this repository, in
CI secrets, on a developer machine, in a production container, or in the Correlix
API.

**Related:**

| Document | What it owns |
|---|---|
| `docs/runbooks/licensing.md` | the everyday mechanism — issue, install, verify, degrade, troubleshoot. §6 is custody + rotation for the key that exists today |
| `docs/design/LICENSING_MODEL_2026-09-04.md` §3, §9 | the design of record: signed file, embedded public keys, GA prerequisite |
| `src/backend/internal/licence/keys.go` | the trusted public-key set and the rotation procedure, in code |
| `src/backend/internal/licence/signer/` | key generation, private-key file handling, signing. **The api never imports it** |

This runbook does **not** repeat how a licence is issued or installed. That is
`licensing.md` §3 and §4, and it is the same command with a different key.

---

## 1. The rule that has no exceptions

**The LAB key must never be promoted to production.**

The key embedded in `keys.go` today (`0edbb619f9b318e0`, purpose `lab`) was
generated on 2026-09-04 on the owner's lab host, with an ordinary `keygen` run,
on a machine that has a network, a shell history and no custody chain. Its
private half sits at `data/licence-signer/lab-signing-key.ed25519` (gitignored).
It is fit for exactly what its note says: lab and trial licences.

Promotion is forbidden in every form, and all four of these are the same act:

* copying `lab-signing-key.ed25519` to a signing host;
* signing a customer licence with it;
* relabelling its `keys.go` entry `purpose: PurposeProduction`;
* declaring it "the production key for now, we will rotate later".

There is no later. A key that has been on a networked general-purpose host
cannot be un-exposed by a decision taken afterwards, and every licence signed
under it inherits that. The production key comes from §3 or it does not exist.

`TestLabKeyIsLabelledLab` fails if the lab entry is relabelled, and `ReleaseReady`
(§9) refuses while it is the only key embedded.

---

## 2. Operating model — the two supported shapes

Either shape satisfies the owner decision. **Pick one before the ceremony**; do
not start §3 and decide halfway.

### 2a. HSM (preferred) — **NOT SUPPORTED BY THE TOOLING TODAY**

An HSM (or a hardware token exposing PKCS#11) holds the private key in hardware
that cannot export it; signing is a call, never a file read.

**Honest blocker:** `correlix-licence sign --key <path>` reads an ed25519 private
key from a **file** (`signer.LoadPrivateKey`). There is no PKCS#11 path, no
external-signer seam, and adding one means either a new third-party module —
which requires amending the CLAUDE.md §6 allowlist first — or an out-of-band
signing step that produces the detached signature and a small "attach signature"
mode in the tool. **Neither exists.** Choosing HSM therefore means scheduling
that work *before* the ceremony, not discovering it during one.

### 2b. Sealed dedicated offline signing machine (supported today)

A dedicated machine that:

* has **never** been on a network after the OS install, and has its wireless and
  wired interfaces physically disabled or removed;
* holds **only** the signing key, a checked-out copy of the repo at a known tag,
  and a Go toolchain;
* has full-disk encryption whose passphrase is split between the custodians
  (§4);
* lives in a locked container/safe when not in use, with a tamper-evident seal
  whose serial is recorded in the ceremony log;
* is never used for anything else. Not builds, not email, not "just this once".

This is the shape the tooling supports unchanged, and unless the HSM work in §2a
has landed, **this is the shape the ceremony uses.**

---

## 3. The ceremony — generation

**Preconditions, all of them, checked out loud before anything is generated:**

| # | Precondition | State today |
|---|---|---|
| 1 | Two named custodians, both present | ❌ **TO BE NAMED BY THE OWNER** |
| 2 | A witness/scribe who is not a custodian (may be the owner) | ❌ pending (1) |
| 3 | The shape from §2 chosen, and if HSM, the tooling gap closed | ❌ pending |
| 4 | The signing host built per §2b (or the HSM initialised), sealed and logged | ❌ pending |
| 5 | Two backup media prepared (§5) | ❌ pending |
| 6 | The ceremony log started (§7) | ❌ pending |

**No precondition may be waived to "unblock a release".** A release blocked on
this is the guard working.

### 3.1 Generate

On the signing host, offline, with both custodians present:

```bash
cd /path/to/NetOps_Observability/src/backend
go build -o /usr/local/bin/correlix-licence ./cmd/correlix-licence

correlix-licence keygen --dir /secure/correlix-signing --name prod-signing-key
```

`keygen` prints the key id, the **public** key, the two paths and the `keys.go`
line to paste. It never prints private key material — reading the private key is
a deliberate `cat`, not a side effect of running a tool. The private key is
written mode `0600` with `O_EXCL`: an existing key file is never overwritten,
because doing so would strand every licence issued under it.

Both custodians read the **key id** aloud and the scribe records it. That id is
what every licence, every log line and every later rotation refers to.

### 3.2 Trust it in the product

Add the public key to `src/backend/internal/licence/keys.go`, following the
rotation procedure at the top of that file:

```go
{
    base64:  "<the public key keygen printed>",
    role:    RoleCurrent,
    purpose: PurposeProduction,
    note:    "PRODUCTION key, ceremony <date>, custodians <A>/<B>, media <serials>",
},
```

and demote the lab entry to `RolePrevious`. **Never more than two entries.**

`purpose: PurposeProduction` is not decoration: `keys.go` panics at first use on
an unknown purpose, and `ReleaseReady()` (§9) reads it. Do not write it for a key
that did not come from this ceremony.

Publish the same public key in `docs/runbooks/licensing.md` §3.1 and on the
customer-facing licence page, so a customer can verify a file without contacting
us.

### 3.3 Prove it before anyone relies on it

On the signing host, sign a throwaway licence and verify it against the
**published base64**, not against the embedded set:

```bash
correlix-licence sign --key /secure/correlix-signing/prod-signing-key.ed25519 \
  --customer "Ceremony Proof" --tier team --expires 2026-12-31 --grace-days 0 \
  --out /tmp/proof.json
correlix-licence verify --pubkey "<the published base64>" /tmp/proof.json
```

Then, on a normal machine with the new build, `correlix-licence verify
/tmp/proof.json` (no `--pubkey`) must also pass — that is the proof the embedded
set and the key agree. Destroy `/tmp/proof.json`; it is a valid licence.

Record both outcomes in the log. **A ceremony that did not verify did not
happen.**

---

## 4. Custodianship

**custodians: TO BE NAMED BY THE OWNER.** Two, minimum. Named individuals, not
roles and not a team alias — "whoever is on call" is not custody.

| Control | Rule |
|---|---|
| Two-person integrity | No single person can produce a signature. Split the FDE passphrase (or the HSM PIN) between the custodians, or hold the token and its PIN separately. Neither half is useful alone |
| Presence | Both custodians present for generation, for every rotation, for every backup-medium access, and for disaster recovery. Routine signing may be single-custodian **only if** the second half of the secret is required to unseal — otherwise it is two-person too |
| Separation | A custodian is not the same person as the release manager who cuts the tag, where the organisation is large enough to make that distinction real. Where it is not, say so in the log rather than pretending |
| Succession | A custodian leaving is a **rotation trigger** (§8), not a handover of the same key material |
| Compromise declaration | Either custodian may declare a suspected compromise alone. Declaring is never penalised; the response is §8.3 |

Record for each custodian: name, role, the date they took custody, what they
physically hold, and the date they gave it up.

---

## 5. Backup and recovery

The private key exists in **at most three places**: the signing host (or HSM),
and two backup media. Never more, never in a password manager, never in cloud
storage, never in a repository, never in a chat message or a paste bin.

* **Two media, two locations.** Two encrypted USB devices, or two sealed paper
  copies of the base64 in tamper-evident envelopes, in two separate safes. One
  medium in the same room as the signing host is one incident away from being
  zero media.
* **Encrypted at rest**, with a passphrase that is itself split between
  custodians. An unencrypted backup makes the two-person control fiction.
* **Sealed and serialised.** Record every serial in the ceremony log. Opening a
  seal is a logged event (§7), whatever the reason.
* **Verified at creation, then never read casually.** After writing a medium,
  restore it on the signing host and re-derive the key id; it must match. From
  then on, an access is either a disaster recovery (§10) or a scheduled
  verification.
* **Verify annually.** Both custodians, both media, re-derive both key ids,
  reseal, log. Media rot is discovered on a schedule or during an outage.
* **HSM shape:** the backup is the HSM's own wrapped-key backup to a second
  device of the same model, with the wrapping key under the same split control.
  If the HSM cannot export a wrapped backup, then a single device failure is
  total key loss — read §10 before accepting that.

---

## 6. Signing procedure (offline), and how the file travels

Everything below happens on the signing host. **Nothing about this step is
online.** There is no activation server, no key escrow, and no path by which a
customer's deployment ever contacts us.

1. **Unseal** the signing host with both custodians present. Log it (§7).
2. **Sign** exactly as `licensing.md` §3.2 documents, with `--key` pointing at
   the production key:

   ```bash
   correlix-licence sign \
     --key      /secure/correlix-signing/prod-signing-key.ed25519 \
     --customer "Acme Networks" --tier team \
     --expires  2027-09-05 --grace-days 30 \
     --features security_findings \
     --out      acme-networks.json
   ```

   The tool validates the document **before** signing: a tier, ceiling or
   feature outside the closed vocabulary is refused on the signing host, so our
   typo never reaches a customer.
3. **Verify before it leaves**, against the published public key:
   `correlix-licence verify --pubkey "<published base64>" acme-networks.json`.
   A file that verifies here verifies on the customer's host, because it is the
   same code.
4. **Record** the issue in the log (§7): licence id, customer, tier, expiry,
   key id, who signed, who witnessed.
5. **Travel.** The signed file leaves on a **write-once or freshly wiped**
   medium — the licence document itself is not a secret (it carries no key
   material and is safe to email), but the medium must never carry anything
   else off the signing host. Nothing goes back *onto* the signing host except a
   verified repo checkout at a known tag.
6. **Reseal** the host, log the seal serial.

**Never**: sign on a laptop, sign from CI, copy the private key to sign
"somewhere more convenient", or leave the host unsealed between issues.

---

## 7. Audit logging

Two logs, both required, neither replacing the other.

**The ceremony log** — an append-only physical or offline record, held with the
custodians, never in this repository. One entry per event, each signed (initials
suffice) by both custodians and the scribe:

| Field | Example |
|---|---|
| date, time, location | 2026-__-__, __:__ UTC, safe room |
| event | generation · signing · seal opened · backup verified · rotation · compromise · DR |
| key id | `0edbb619f9b318e0`-shaped, 16 hex |
| who was present | both custodians + witness, by name |
| media serials touched | seal/medium ids |
| outcome, including verification result | "verified against published key: PASS" |

**The product-side record** — installing a licence is audited by the platform
already (`internal/licence/api.go` records both outcomes of every write through
the `Audit` seam), and the customer, tier and key id are visible on the licence
page and in `correlix-licence show`. That log answers *what a deployment was
given*; the ceremony log answers *what we signed and who was in the room*. Only
the pair is an audit trail.

**Never logged, anywhere:** private key material, the FDE passphrase, the HSM
PIN, or a photograph of any of them.

---

## 8. Rotation

The mechanical procedure is the one at the top of `keys.go` and it is the
authority; this section is the operational wrapper.

### 8.1 When

| Trigger | Urgency |
|---|---|
| Custodian departure or role change | plan it, next release |
| Suspected compromise of a medium, host or seal | immediate, §8.3 |
| Scheduled hygiene (recommend every 2 years, owner to confirm) | plan it |
| The lab key still being embedded at GA | immediate — that is §9 |

### 8.2 How, without invalidating anything

1. Generate the new key by the **same ceremony** (§3). A rotation is not a
   lighter-weight event than the first generation.
2. In `keys.go`: the current entry becomes `RolePrevious`; the new key is added
   as `RoleCurrent` with `purpose: PurposeProduction` and a note naming its
   ceremony.
3. Ship. **Both keys verify**, so every licence already in the field keeps
   working while new ones are issued under the new key. A document names the key
   it was signed with (`key_id`) and lookup is by that id — there is no "try
   every key until one works", so a rotation mistake is diagnosable rather than
   invisible.
4. Reissue outstanding licences under the new key as they renew.
5. **Only after the longest outstanding term has expired**, delete the previous
   entry and destroy its private key and backup media (log the destruction).

Never more than two entries. A build that trusts a long tail of retired keys has
no rotation story, it has an accumulation story. `TestKeyRotation` covers the
two-key window; `TestEmbeddedKeysAreUsable` and `TestEmbeddedKeysCarryAKnownPurpose`
cover the shipped set.

### 8.3 Compromise response

1. Declare it. Either custodian, alone, immediately. No approval needed.
2. Stop signing with the compromised key **now**.
3. Rotate (§8.2), treating the compromised key as retired the moment the new one
   is trusted rather than after the longest term.
4. Reissue every licence signed under it, on the accelerated schedule the
   compromise implies rather than at renewal.
5. Ship the build that drops the compromised entry, and tell customers what to
   install and why.
6. Record the whole sequence in the ceremony log, including what was compromised
   and how it was discovered.

---

## 9. Revocation — what exists, and what does not

**There is no revocation list, no CRL, no OCSP, no kill switch, and no phone
home.** That is by design (`licensing.md` §1), and it has a consequence that must
be stated rather than glossed:

> A licence file that has already been delivered **cannot be recalled** from a
> deployment that never contacts us.

So "revocation" means exactly two things, and nothing else:

1. **Stop honouring the key** — retire it from `keys.go` and ship a build that
   does not carry it. Every licence signed under it becomes
   `licence: unknown signing key` on that build **and every licence signed under
   it, not just the one you meant to revoke**. This is a blunt instrument; it is
   the compromise response (§8.3), not a commercial one.
2. **Let it expire.** A licence carries `expires_at` and an issuer-set
   `grace_days`. After grace, paid capability stops being *created and
   configured* — nothing is disabled, hidden or deleted, and no device is
   un-monitored. That is the honest commercial lever.

Revoking one customer's licence without touching everyone else's would need a
revocation list the product does not have and cannot check offline. Do not
promise one. If the owner ever wants per-licence revocation, it is a design
change to the model, not an operational procedure.

---

## 10. The release guard — the lab key cannot ship as the only key

Tracker 259 asks for a mechanical check, because a licence signed with the lab
key **verifies perfectly** — that is what the lab key is for — so nothing in the
verification path can tell a customer release from a lab build. The only place
the difference is visible is the set of keys the binary carries.

| Piece | Where | What it does |
|---|---|---|
| `PublicKey.Purpose` (`lab` \| `production`) | `internal/licence/document.go` | states what a key may sign. Closed vocabulary; an unlabelled key is treated as **not** production (fail closed) |
| `purpose:` on every embedded spec | `internal/licence/keys.go` | an unknown purpose **panics at first use** — a mislabelled key is loud, not silent |
| `licence.ReleaseReady() error` | `internal/licence/keys.go` | nil **only** when the trusted set contains a `production` key; otherwise `ErrNoProductionKey`, naming this runbook |
| `correlix-licence keys --release-check` | `cmd/correlix-licence/main.go` | the operator/release surface: prints the trusted set with its purposes, and **exits 1** while no production key is embedded |
| `TestEmbeddedSetIsNotReleaseReadyYet` | `internal/licence/keys_release_test.go` | the tripwire: records that today's set is lab-only. It **fails, and is deleted, the day the production key lands** |
| `TestLabKeyIsLabelledLab`, `TestReleaseReadyRequiresAProductionKey`, `TestEmbeddedKeysCarryAKnownPurpose` | same file | the lab key stays labelled lab; the guard refuses lab-only, empty and unlabelled sets and accepts a set containing a production key |

**Run it before cutting a release:**

```bash
cd src/backend && go run ./cmd/correlix-licence keys --release-check
# today:
#   embedded signing keys (1):
#     0edbb619f9b318e0  role=current  purpose=lab        Q+PMj3/…
#   release-ready: NO — licence: no production signing key is embedded in this build: …
# exit status 1
```

**Known limits, stated rather than implied:**

* The guard answers *"is a production key embedded?"* — the literal owner
  decision ("a release refuses when the only embedded key is marked lab"). It
  does **not** assert that the `RoleCurrent` key is the production one; the
  rotation procedure (§8.2) is what keeps that true, and a reviewer reading the
  two-line `keys.go` set is the check.
* It is **not** wired into `.github/workflows/release-*.yml`, and there is no
  `--release` flag on the Go build. The Go tests run in the normal CI gate, and
  the `keys --release-check` command is a release-procedure step. Wiring it into
  the tag workflow (or as a third `release_blockers` entry in
  `licensing-policy.json`, which `scripts/licensing-gate.py --release` already
  enforces) is a small follow-up and is the right home for it.
* It is deliberately **not** checked at boot. Shipping the lab key is the correct
  state today, and a running installation verifying a lab licence is doing what
  it should. The question is only asked when a release is cut.

---

## 11. Previous-key compatibility — the embedded set per release

This is the property that lets a key change without breaking a customer, and it
is worth stating precisely because getting it wrong is unrecoverable in the
field.

* **The build carries the set, the licence names its key.** Every document
  carries `key_id`; the verifier looks that id up in the embedded set. Verifying
  is a lookup, never a search, so a mismatch is a named error
  (`licence: unknown signing key: key_id "…"`) instead of a mystery.
* **A release carries at most two keys: current + previous.** Adding a key is
  additive and safe: licences under the old key keep verifying because the old
  key is still there.
* **Retiring a key is the only irreversible step**, and its precondition is
  arithmetic, not judgement: *every licence signed under it has expired.* The
  longest outstanding term is the date. Retire earlier and those customers get
  `unknown signing key` at their next restart — a self-inflicted outage on a
  paying customer that no support action can fix except shipping a build that
  carries the key again.
* **An old build never learns a new key.** A customer running a release from
  before the rotation cannot verify a licence signed with the new key. Either
  issue their file under the previous key (still valid, still embedded) or
  upgrade them first. This is why step 4 of §8.2 exists.
* **Downgrade is a trap.** Rolling a customer back to a build older than the
  rotation invalidates any licence issued after it. Check the key id before
  recommending a downgrade.

| You want to | Do this | Never |
|---|---|---|
| add a new key | new entry `RoleCurrent`, demote the old one to `RolePrevious`, ship | ship three keys |
| retire an old key | wait for the longest term to expire, then delete the entry | delete it "because we already reissued most of them" |
| support an old build | issue under the key that build carries | ask them to trust a key by editing anything |

---

## 12. Disaster recovery

| Scenario | Response |
|---|---|
| **Signing host destroyed, backups intact** | Rebuild the host per §2b, restore from one backup medium with both custodians present, re-derive the key id and confirm it matches the log, re-verify an existing customer licence with `verify --pubkey`. Reseal both media. Nothing changes for customers |
| **One backup medium lost or its seal broken** | Treat as suspected compromise (§8.3) unless the seal is intact and the loss is explained. Recreate a second medium from the signing host before anything else |
| **All copies of the private key lost** (host + both media) | The key is gone and **cannot be recovered** — ed25519 has no escrow and no derivation. Existing licences keep verifying (they need only the public key). You simply cannot sign new ones. Run a full ceremony (§3) for a new key, ship it as `RoleCurrent` with the lost key as `RolePrevious`, and reissue as licences renew. Do **not** retire the lost key early: its licences are still in the field and still valid |
| **Key compromised** | §8.3 |
| **Both custodians unavailable** (illness, departure) | Signing stops until the owner names replacements and a ceremony transfers custody — which means a **new key** (§8.1), not a handover of the old material. Plan succession before this happens |
| **A customer's licence will not verify after an upgrade** | Almost always a retired key: `correlix-licence show` their file, compare `key_id` with the ids the error lists, and reissue under the current key. `licensing.md` §9 has the full refusal table |

**Recovery is not proven.** Nothing above has been rehearsed, because there is no
key to rehearse with. The first DR drill is owed as soon as the ceremony
happens — restore from a backup medium onto a rebuilt host and re-derive the key
id — and its result belongs in `docs/audit/INVARIANTS.md`, not here.

---

## 13. What is still open

| Item | Owner action |
|---|---|
| **Custodians** | **TO BE NAMED BY THE OWNER** — this blocks everything else |
| HSM vs sealed offline machine (§2) | choose; if HSM, schedule the PKCS#11/detached-signature tooling work first (allowlist amendment likely) |
| Ceremony date, location, witness | schedule after custodians exist |
| Rotation interval (§8.1 suggests 2 years) | confirm or set |
| Wiring `keys --release-check` into the tag workflow or `licensing-policy.json` release blockers (§10) | small engineering follow-up |
| Commercial blockers that also gate GA | the Correlix Enterprise licence TEXT and the CLA process are **still awaiting legal** (`licensing.md` §6.3). Do not draft, paraphrase or generate either |
