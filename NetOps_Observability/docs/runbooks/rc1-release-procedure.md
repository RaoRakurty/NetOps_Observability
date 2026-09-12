# Runbook: the `v0.9.0-rc1` release procedure — PROPOSED, NOT AUTHORIZED

> # ⛔ NOTHING IN THIS DOCUMENT IS AUTHORIZED, AND NOTHING IN IT HAS BEEN RUN.
>
> Every command below is written as a **PROPOSED ACTION**. Not one of them has
> been executed. No branch-protection ruleset has been changed, no merge to
> `main` has been made, **no `v0.9.0-rc1` tag exists**, no release has been
> published, no image has been pushed to GHCR, and no registry access has been
> granted.
>
> This page exists so that when the owner *does* authorize a release, the exact
> sequence, the exact payloads and the exact verifications are already written
> down and reviewed — not improvised at the point of no return. It is a
> **proposal awaiting authorization**, not a checklist to work through.
>
> **Each of the six steps requires its own explicit owner authorization.**
> Authorizing step 1 does not authorize step 2. There is no blanket approval,
> and an agent may not execute any of these on its own initiative — see
> `docs/RELEASE_CHECKLIST.md` §6, where the whole sequence is marked 👤
> owner-only and not delegable.

---

## What this page is, and what it is not

| | |
|---|---|
| **This page** | the ordered, authorization-gated **procedure**: the six release-changing actions, their preconditions, and how each one is verified afterwards |
| [`docs/RELEASE_CHECKLIST.md`](../RELEASE_CHECKLIST.md) | the **readiness state** — what is automated, what is manual, what is missing, and what still blocks a final tag. It is the source for whether the preconditions below are *true*; this page only says what to do once they are |
| [`docs/runbooks/ci-branch-protection.md`](ci-branch-protection.md) | the **required-check list of record** (§1.1) and the branch-protection payload (§4). Step 1 reproduces it; it does not replace it |
| [`docs/runbooks/release-qualification.md`](release-qualification.md) | the reference-capacity qualification run, which is what would let the `-rc1` suffix be dropped. **It has never been executed** |
| [`docs/RELEASE_NOTES_v0.9.0-rc1.md`](../RELEASE_NOTES_v0.9.0-rc1.md) | the customer-voice notes step 4 would publish |

The number is `v0.9.0-rc1` and the `-rc1` is load-bearing: the reference-capacity
regression (`RELEASE_CHECKLIST.md` §3.1) has never been run, so no build has been
qualified. Dropping `-rc1` is a separate decision that this page does not cover.

---

## 0. Preconditions that gate the whole sequence

These are not per-step. If any is false, **no step below may be authorized.**

| | Precondition | How it is established | State at the time of writing |
|---|---|---|---|
| 0.1 | **CI is green on the exact commit** that will be tagged — all 19 blocking checks of `ci-branch-protection.md` §1.1 | `gh run list --branch <branch> --limit 5`, and after step 2 `gh run list --branch main --limit 5` | not established — the work is on `feat/observability-platform` |
| 0.2 | **Licence release blockers are cleared** | `python3 scripts/licensing-gate.py --release` exits **0** | **FAILS.** Two blockers are open: `enterprise-text-placeholder` (`LICENSES/Correlix-Enterprise.txt` is a placeholder) and `cla-process-undefined` (`CONTRIBUTING.md` carries `CLA-PROCESS-TBD`; the CLA text at `CLA.md` is pending counsel). Both are 👤 owner + counsel actions |
| 0.3 | **OCI source-compliance passes in release mode** for every image that will be published | the `oci-compliance` matrix job in `.github/workflows/publish-images.yml` runs `python3 scripts/oci-compliance.py --sbom … --image … --digest … --source-dir "$OFFER" --manifest … --release` against **each pushed digest**. It is `needs:`-gated by `release-gate.yml`, so it cannot be skipped. Offline pre-check: `python3 scripts/oci-compliance.py --selftest` | the gate exists and is wired; it has never run on a real tag, because no `v*` tag has ever existed |
| 0.4 | **Working tree clean at the commit to be tagged** | `git status --porcelain` prints nothing | not established |
| 0.5 | **The gate machinery itself is consistent** | `python3 -m pytest tests/test_required_checks_consistency.py -q` and `actionlint` over `.github/workflows/` | the pytest passes today |

> **0.2 is currently FALSE.** A release cannot honestly proceed past step 3 while
> `licensing-gate.py --release` fails: the tag is what publishes artifacts, and
> those artifacts would carry an identifier that resolves to no terms. This is
> stated here so that nobody discovers it after the tag is pushed.

---

## Step 1 — Branch protection: require the 19 checks on `main`

**PROPOSED ACTION: apply the branch-protection ruleset with the 19 required
status checks — requires explicit owner authorization**

The payload is reproduced **verbatim** from `docs/runbooks/ci-branch-protection.md`
§4, which is the list of record and is machine-checked against the workflows'
real job `name:` fields by `tests/test_required_checks_consistency.py`. Do not
retype it and do not reorder it — the test compares the ordered lists.

```bash
# Requires: gh auth login AS A REPO ADMIN. This cannot be done from CI or by an
# agent; branch protection is an admin setting and is not in the repository.
gh api -X PUT repos/RaoRakurty/NetOps_Observability/branches/main/protection \
  -H "Accept: application/vnd.github+json" \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "checks": [
      {"context": "build · vet · test · race"},
      {"context": "offline vendor build (blocking)"},
      {"context": "Postgres integration (blocking)"},
      {"context": "govulncheck (blocking)"},
      {"context": "staticcheck + gosec (crypto/trust packages, blocking)"},
      {"context": "golangci-lint (repo-wide, blocking)"},
      {"context": "pytest (blocking)"},
      {"context": "ruff · bandit · mypy · pip-audit (blocking)"},
      {"context": "tsc -b && vite build (blocking)"},
      {"context": "npm audit (blocking)"},
      {"context": "Playwright E2E (blocking)"},
      {"context": "panel↔metric contract (blocking)"},
      {"context": "Trivy filesystem scan (blocking)"},
      {"context": "gitleaks secret scan (blocking, full history)"},
      {"context": "CIS-Docker policy gate (blocking)"},
      {"context": "Third-party licence gate (blocking)"},
      {"context": "OCI image compliance (inherited layers, blocking)"},
      {"context": "ingest + storage contracts (blocking)"},
      {"context": "invariants · conformance · pytest (blocking)"}
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {"required_approving_review_count": 1},
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```

**PRECONDITIONS**

- §0.5 — `pytest tests/test_required_checks_consistency.py` passes, so the
  payload above, the runbook's §1.1 table and the workflows agree.
- Every one of the 19 checks has **reported at least once** on this repository.
  A context that has never run does not appear in GitHub's picker and the `PUT`
  is rejected as an unknown context. Open one pull request first if so.
- The admin has decided about the three `fresh-install-integrity` checks of
  runbook §1.2. They are **optional on the branch ruleset** and **mandatory in
  the tag gate** either way; requiring them charges every PR ~45 minutes.

**VERIFICATION**

```bash
# Must print the 19 contexts, in the same order as the payload above.
gh api repos/RaoRakurty/NetOps_Observability/branches/main/protection \
  | jq -r '.required_status_checks.checks[].context'

# And the count, explicitly:
gh api repos/RaoRakurty/NetOps_Observability/branches/main/protection \
  | jq '.required_status_checks.checks | length'   # -> 19
```

A mismatch here is not cosmetic: a required context that names no job pins every
future PR at *"Expected — Waiting for status to be reported"* forever, and a
blocking job that is **not** required runs, goes green and enforces nothing.

**IF IT GOES WRONG:** re-`PUT` the corrected payload. This step is fully
reversible and is the only one on this page that is.

---

## Step 2 — Merge `feat/observability-platform` to `main`

**PROPOSED ACTION: open and merge a pull request from
`feat/observability-platform` into `main` — requires explicit owner
authorization**

```bash
git checkout main && git pull --ff-only
gh pr create --base main --head feat/observability-platform
# then merge through the UI or `gh pr merge`, only once all 19 checks are green
```

**PRECONDITIONS**

- Step 1 is done and verified. Merging first would mean the ruleset guards a
  release without ever having been exercised on a pull request.
- §0.1 CI green, §0.4 clean tree.
- The release is tagged **on `main`**: `release-bundle.yml` carries a
  `branches: [main]` leg and every "on main" assumption in the publishing
  workflows follows from it. Tagging any other branch makes those wrong.

**VERIFICATION**

```bash
git checkout main && git pull --ff-only
git log --oneline -1                 # the commit that will be tagged
git status --porcelain               # must be empty (§0.4)
gh run list --branch main --limit 5  # all 19 checks green ON THIS COMMIT
python3 scripts/licensing-gate.py    # the eight everyday checks: PASS
```

**IF IT GOES WRONG:** nothing has been published; fix forward on a branch and
merge again. This step is recoverable.

---

## Step 3 — Create and sign the `v0.9.0-rc1` tag (locally, not pushed)

**PROPOSED ACTION: `git tag -s -a v0.9.0-rc1 -m "Correlix v0.9.0-rc1"` on the
green `main` commit — requires explicit owner authorization**

```bash
git tag -s -a v0.9.0-rc1 -m "Correlix v0.9.0-rc1"
git tag -v v0.9.0-rc1        # verify the signature BEFORE it leaves the machine
```

Annotated **and GPG-signed**. Until image signing exists (`RELEASE_CHECKLIST.md`
§4.9) the tag is the only signed link between the source and the artifacts.

**PRECONDITIONS**

- Steps 1–2 done and verified; `HEAD` is the green `main` commit.
- §0.2 — `python3 scripts/licensing-gate.py --release` exits 0. **It does not
  today.** A tag is the trigger for publishing, so this is the last point at
  which an open licence blocker can still be stopped cheaply.
- A GPG signing key is available to `git` on this machine and its public half is
  published where a verifier can fetch it.

**VERIFICATION**

```bash
git tag -v v0.9.0-rc1                        # "Good signature"
git rev-parse v0.9.0-rc1^{commit}            # == the verified main commit
git ls-remote --tags origin | grep v0.9.0-rc1 || echo "not pushed (correct)"
```

**IF IT GOES WRONG:** `git tag -d v0.9.0-rc1`. Nothing has left the machine.
This is the last fully-reversible step.

---

## Step 4 — Push the tag, and publish the release

**PROPOSED ACTION: `git push origin v0.9.0-rc1` — THE POINT OF NO RETURN —
requires explicit owner authorization**

```bash
git push origin v0.9.0-rc1
```

> **One push authorizes two publications.** This single command triggers
> **both** `release-bundle.yml` (step 4, the release and its assets) **and**
> `publish-images.yml` (step 5, four images to GHCR). They cannot be authorized
> separately at the moment of the push, so the authorization for step 4 must
> cover step 5 as well, or the push must not happen. A pushed image digest
> cannot be unpublished from a customer's cache.

Each workflow runs `release-gate.yml` as its first job — the full blocking gate
against the tag's exact commit, ~45–60 minutes because of the TLS install leg —
and every other job `needs:` it, so a failed, cancelled or skipped gate leaves
publishing unreachable. `release-bundle.yml` then builds the offline bundle,
smoke-tests it (`sha256sum -c`, `zstd -t`, git-SHA lockstep, a full `docker load`
round-trip, the source-offer assertions) and runs
`gh release create --verify-tag` + `gh release upload --clobber`.

The **manual half** of publishing the release page:

**PROPOSED ACTION: publish the GitHub release page from
`docs/RELEASE_NOTES_v0.9.0-rc1.md`, marked PRE-RELEASE — requires explicit owner
authorization**

- GitHub → Releases → the `v0.9.0-rc1` release created by the workflow.
- Body from `docs/RELEASE_NOTES_v0.9.0-rc1.md`, including its honest known
  limitations.
- ☑ **Set as a pre-release.** The tag carries `-rc1` because §3.1's
  qualification has never been run; a release page that does not say so
  contradicts the tag.

**PRECONDITIONS**

- Steps 1–3 done and verified.
- §0.2 licence blockers cleared — after this push, artifacts carrying those
  identifiers are in customers' hands.
- §0.3 the `oci-compliance … --release` matrix will run inside
  `publish-images.yml`; confirm it is still `needs:`-gated:
  `python3 -m pytest tests/test_required_checks_consistency.py -q`.
- The authorization explicitly covers step 5 as well (see the box above).

**VERIFICATION**

```bash
gh run watch                                        # both workflows, to completion
gh run list --workflow=release-bundle.yml --limit 3
gh release view v0.9.0-rc1                          # exists, PRE-RELEASE, assets attached
gh release download v0.9.0-rc1 -D /tmp/rc1 && cd /tmp/rc1 && sha256sum -c SHA256SUMS
```

Then the post-tag proofs of `RELEASE_CHECKLIST.md` §7 — install the bundle
**downloaded from the release page** on a clean host, `scripts/deploy-qualify.sh`
(exit **0** only; `2` is INCOMPLETE, which is not a pass), `GET /admin/version`,
and `scripts/verify-critical-alert-channel.sh --send`.

**IF IT GOES WRONG:** if a gate fails, nothing is published and the tag stands
with no artifacts — delete the tag locally and remotely, fix, re-tag. Once
assets are attached and images are pushed, deletion is a **withdrawal**, not an
undo.

---

## Step 5 — Publish the GHCR images

**PROPOSED ACTION: publish `netops-{api,correlation,nginx,frontend}` to GHCR —
executed by `publish-images.yml` on the step-4 tag push; requires explicit owner
authorization AS PART OF the step-4 authorization**

There is no separate command. `publish-images.yml` fires on `push: tags:
['v*.*.*']`, runs `release-gate.yml` first, and only then builds and pushes the
four images tagged `semver`, `major.minor` and `sha`, attaching to each digest a
keyless Sigstore **SLSA build-provenance attestation** and a per-image
**CycloneDX SBOM**, and running the `oci-compliance … --release` gate against the
pushed digest.

This is called out as its own step because it is a **distinct irreversible
publication** with its own failure modes — not because it can be triggered
independently. If the owner wants images published without a release, or a
release without images, that is a workflow change decided **before** step 4, not
a decision available at push time.

**PRECONDITIONS**

- Step 4 authorized with this step explicitly included.
- §0.3 — the release-mode OCI compliance gate is wired and `needs:`-gated.
- Understand what "publish" means here: packages are **private on first push**.
  Nobody outside the org can pull them until step 6.

**VERIFICATION**

```bash
gh run list --workflow=publish-images.yml --limit 3         # success
gh api user/packages/container/netops-api/versions | jq -r '.[0].metadata.container.tags[]'

# The provenance a customer would actually check:
gh attestation verify oci://ghcr.io/raorakurty/netops-api@<digest> --owner RaoRakurty
```

Also download the `oci-compliance-*` manifest artifacts from the run and confirm
each records `PASS` in release mode.

**IF IT GOES WRONG:** a bad digest can be untagged and the package version
deleted, but **anything already pulled is out**. Treat it as a withdrawal:
publish a corrected `-rc2`, do not attempt to make a bad digest disappear.

---

## Step 6 — Registry access

**PROPOSED ACTION: decide and grant GHCR read access —
public, or per-customer read tokens — requires explicit owner authorization**

GitHub → Packages → `netops-api`, `netops-correlation`, `netops-nginx`,
`netops-frontend` → Package settings → visibility / *Manage Actions access* /
per-package collaborators.

> **This is a disclosure decision, not a convenience one.** The
> `netops-correlation` image carries **readable Python source**. Making it public
> publishes that source to anyone who pulls it. Decide that deliberately, with
> the open-core boundary in `LICENSING.md` in front of you, and record the
> decision.

**PRECONDITIONS**

- Step 5 verified: the images exist, their provenance verifies, and their
  release-mode compliance manifests pass.
- The visibility decision is **made and recorded** before it is applied.
- If the answer is per-customer tokens: the token issuance, scope and rotation
  story exists first (`docs/runbooks/secret-rotation.md` is the model), because
  a read token handed out with no rotation path is a permanent grant.

**VERIFICATION**

```bash
# From an unauthenticated shell — proves what an outsider can actually do.
docker logout ghcr.io
docker pull ghcr.io/raorakurty/netops-api:v0.9.0-rc1
#   public  -> succeeds
#   private -> denied, which is the CORRECT result until the decision says otherwise
```

Then have one named recipient perform the pull with the credentials they were
actually given. A grant nobody has exercised is a grant nobody has verified.

**IF IT GOES WRONG:** visibility can be set back to private, but **what was
pulled while it was public stays pulled.** For the correlation image that means
source disclosure, which is not revocable.

---

## Authorization record

To be filled in by the owner **at the time of authorization**, one row per step.
An empty row means the step is not authorized and must not be run.

| Step | Action | Authorized by | Date (UTC) | Executed by | Result |
|---|---|---|---|---|---|
| 1 | branch protection — 19 required checks | | | | |
| 2 | merge to `main` | | | | |
| 3 | create + sign `v0.9.0-rc1` | | | | |
| 4 | push the tag · publish the release | | | | |
| 5 | publish GHCR images | | | | |
| 6 | registry access | | | | |

**As of the writing of this page every row is empty, and that is the accurate
state of the release.**
