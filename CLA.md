# Contributor License Agreement — PLACEHOLDER, NOT AN AGREEMENT

> **There is no CLA text in this file, and nothing here is an agreement.**
> The Correlix Contributor License Agreement is **pending counsel approval**.
> Until counsel delivers the drafted text and the owner records it here, this
> file is a reserved location and a statement of intent — nothing more.
>
> **Signing nothing is possible, because there is nothing to sign.** Do not read
> this page as terms, do not treat a pull request, a comment, a commit trailer or
> a bot check as acceptance of it, and do not rely on it as evidence that any
> rights have been granted to or by anyone.

---

## Why this file is empty

Engineering does not draft, paraphrase, borrow or generate licence or CLA text.
That rule is recorded in [`NetOps_Observability/docs/runbooks/licensing.md`](NetOps_Observability/docs/runbooks/licensing.md)
alongside the identical rule for `LICENSES/Correlix-Enterprise.txt`, and it exists
because a plausible-looking agreement that no lawyer wrote is worse than an empty
file: it invites reliance on rights the project does not actually hold.

An empty, loudly-labelled slot is the honest state. It is also the state the
release gate can see (below), which a private "we'll get to it" cannot be.

## What will land here

A Contributor License Agreement in **two variants**, covering contributions to
this repository:

| Variant | Signer | Covers |
|---|---|---|
| Individual | the contributing person | contributions made by that person on their own behalf |
| Entity / corporate | an authorised signatory of the employer or contracting company | contributions made by that organisation's people in the course of their work |

Its purpose is the one already stated in [`CONTRIBUTING.md`](CONTRIBUTING.md) §1
and it does not change here: Correlix is open core, the same repository produces
an Apache-2.0 edition and a commercial edition, and a module may move between
them. The CLA is what lets one party place a contribution under both licences —
**while the contributor keeps the copyright in their own work. A CLA is not an
assignment.** It carries a second purpose that matters as much: the contributor's
own statement that they have the right to contribute what they are contributing.

The **scope** of the grant, the **representations** it asks for, and the
**signing mechanism** are all counsel's to settle. None of them is decided, and
none may be guessed at from this page.

## What it blocks while it is a placeholder

**Contributions cannot be merged.** Not code, not tests, not configuration, not
documentation; not from individuals and not from companies. The rights the open
core model depends on cannot be established without a signed CLA, and merging
first and papering it over later is exactly the thing a CLA exists to prevent.

This is not a soft preference. It is recorded in three places that outlive any
one conversation:

1. **[`CONTRIBUTING.md`](CONTRIBUTING.md) §1** — the contributor-facing statement,
   carrying the `CLA-PROCESS-TBD` marker.
2. **`NetOps_Observability/licensing-policy.json` → `release_blockers` →
   `cla-process-undefined`** — the machine-readable blocker. `python3
   NetOps_Observability/scripts/licensing-gate.py --release` FAILS while the
   marker is present, so no release can quietly pass over it.
3. **[`.github/workflows/cla-check.yml`](.github/workflows/cla-check.yml)** — the
   enforcement mechanism, present but **disabled** (`if: false`). It is wired and
   pinned so that enabling it is a one-line owner decision once the text lands,
   and it cannot run before then.

## What has to happen, and by whom

| | Step | Owner |
|---|---|---|
| 1 | Obtain the drafted individual and entity CLA from counsel | 👤 owner + counsel |
| 2 | Replace the whole of this file with the approved text | 👤 owner |
| 3 | Choose the signing mechanism — a CLA assistant on the repository, or a countersigned document recorded in a contributor register | 👤 owner |
| 4 | Record that mechanism in `CONTRIBUTING.md` §1, replacing the `CLA-PROCESS-TBD` marker | 👤 owner |
| 5 | If the mechanism is the bot: review the pinned action, create the signatures store and its token, and remove `if: false` from `.github/workflows/cla-check.yml` | 👤 owner |
| 6 | Confirm `python3 NetOps_Observability/scripts/licensing-gate.py --release` no longer reports `cla-process-undefined` | anyone |

Steps 1–3 are **owner and counsel decisions**. Nothing in this repository may
anticipate their outcome.

---

Licensing of the project itself is a separate question, already decided and
documented: see [`LICENSE`](LICENSE) and [`LICENSING.md`](LICENSING.md).
