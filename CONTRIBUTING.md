# Contributing to Correlix

Correlix is open core: the engine, the pipeline, the isolation model and the
investigation surface are Apache-2.0, and a named set of commercial add-on
modules is source-available under the Correlix Enterprise License. See
[`LICENSING.md`](LICENSING.md) for the directory-by-directory map.

---

## 1. The Contributor License Agreement

**Every contribution requires a signed Contributor License Agreement (CLA)
before it can be merged.** This applies to code, tests, configuration and
documentation, from individuals and from companies.

The agreement itself lives at [`CLA.md`](CLA.md). **It is a placeholder: the text
is pending counsel approval and there are no terms in it.** Nothing on that page
is an agreement, and nothing you do — opening a pull request, commenting on one,
adding a trailer to a commit — constitutes signing it. Until the approved text
lands there and a signing mechanism is recorded below, **no contribution can be
merged.**

### Why

Open core only works if one party can place the same code under both licences.
Correlix ships Apache-2.0 core and a commercial edition built from the same
repository, and it may need to move a module between them: a feature that
starts in core, or a commercial module that is opened later. Under inbound=
outbound licensing alone, Correlix would receive your contribution under
Apache-2.0 only, and could not include it in the commercial edition or relicense
it without tracking down and re-asking every contributor who ever touched the
file.

The CLA is what makes that possible. It asks you to grant Correlix the rights to
use and relicense your contribution — including into the commercial edition —
**while you keep the copyright in your own work.** A CLA is not an assignment.

It also serves a second purpose that matters as much: it is your statement that
you have the right to contribute what you are contributing — that it is yours, or
that your employer has authorised it. That assurance is what lets a customer
rely on the provenance of the code they run.

### How

<!-- CLA-PROCESS-TBD -->

**The signing process has not been chosen yet.** It is an owner decision, and
inventing a URL or a workflow here would be worse than saying so. The two
candidate mechanisms:

- a CLA assistant bot on the repository, which comments on a first pull request
  and records the signature against the GitHub account; or
- a countersigned document (individual and corporate variants) exchanged out of
  band and recorded in a contributor register.

Until one is chosen and recorded here, **external contributions cannot be
merged**, because the rights the project depends on cannot be established.

**This repository does not use a DCO.** There is no `Signed-off-by` requirement,
no `Developer Certificate of Origin` in the tree and no DCO check in
`.github/workflows/`; no commit in this repository's history carries the trailer.
Do not add one and do not read one into the requirement above — a DCO certifies
provenance, it does not grant the relicensing right open core depends on, and
adopting one here would be inventing exactly the process this section says is
undecided. The signing mechanism is pending counsel along with the text.

The half of the mechanism that *can* be prepared without counsel is prepared:
[`.github/workflows/cla-check.yml`](.github/workflows/cla-check.yml) carries a
SHA-pinned CLA-assistant action with its job **disabled** (`if: false`), so if
the owner picks the bot in step 3 below, enabling it is a reviewed one-line
change rather than a new dependency introduced on ship day. It cannot run in its
current state.

`scripts/licensing-gate.py --release` fails while the `CLA-PROCESS-TBD` marker
above is present, so this cannot be forgotten on the way to a release. Owner
action: obtain the text from counsel and put it in [`CLA.md`](CLA.md), choose the
mechanism, then replace this section with it. The full sequence, and who owns
each step, is the table at the end of [`CLA.md`](CLA.md).

---

## 2. Before you open a change

**Read [`CLAUDE.md`](CLAUDE.md).** It is the engineering contract for this
repository, not a style preference. The parts that reject the most changes:

| Rule | What it means for your change |
|---|---|
| §2 Architecture | No business logic in `/cmd`. No circular dependencies. No `utils` package. |
| §3a Tenant isolation | Any surface that stores or returns data scopes by the authenticated principal, default-closed, and **ships a cross-org isolation test with the feature**. There is no exception to this one. |
| §5 Code quality | Explicit types. No ignored errors. No globals. Interfaces for external dependencies. |
| §6 Dependencies | The Go backend is standard-library by default. Third-party modules come only from the §6 allowlist, and adding one means amending that table first, with the four gates answered. |
| §11 Testing | Unit tests per module, integration tests at service boundaries. A feature without tests is not finished. |
| §16 Scripts | Shell scripts, cron jobs and installers get the same bar as the Go code. Read [`NetOps_Observability/scripts/CLAUDE.md`](NetOps_Observability/scripts/CLAUDE.md) before writing one. |

Licensing rules for a change:

- New code is **Apache-2.0 by default**. Do not mark anything
  `LicenseRef-Correlix-Enterprise` unless it implements an entitlement in the
  locked commercial set in `LICENSING.md`, and the owner has said so.
- Never make isolation, correctness or safety code commercial.
- If you add a top-level directory, classify it in
  `NetOps_Observability/licensing-policy.json` and re-run
  `python3 scripts/gen-licensing-map.py --write`. The consistency test fails
  otherwise, by design.

---

## 3. Making the change

1. **Branch.** Never commit to `main`. Branch from it, one bounded context per
   branch (§7): do not refactor a second domain along the way.
2. **Write the tests with the code**, not after. For anything tenant-scoped,
   `org_isolation_test.go` is the template.
3. **Run the gate locally before pushing.** The tools are not on a default
   `PATH`; export it or you get a green run that checked nothing.

   ```bash
   cd NetOps_Observability/src/backend
   go build ./... && go vet ./... && go test ./... && go test -race ./...
   bash ../../scripts/ci-backend-guard.sh     # build + vet + the exact golangci-lint CI uses

   cd ../correlation && python3 -m pytest && ruff check .
   cd ../frontend && npx tsc --noEmit && npm run build
   ```

4. **Explain the why in the code.** This repository's comments record why a
   thing is the way it is, and what happened when it was not. Match that.

---

## 4. The CI gate

Everything in `.github/workflows/` is **blocking**. Any failure blocks the
merge; there is no override and no "the model wrote it" exemption (§15 LLM03).

- `backend-ci` — gofmt, `go build`, `go vet`, `go test`, `go test -race`, the
  offline vendored build, Postgres integration with the full RLS/tenant-isolation
  corpus, `govulncheck`, staticcheck, gosec, golangci-lint.
- `correlation-ci` — `pytest`, ruff, bandit, mypy, pip-audit.
- `frontend-ci` — `tsc -b && vite build`, `npm audit`, Playwright E2E, the
  panel/metric contract.
- `supply-chain` — Trivy, gitleaks over full history, the CIS-Docker policy gate.
- `fresh-install-integrity` — a full TLS install and boot on a clean runner.
- Licensing consistency — `pytest tests/test_licensing_consistency.py` plus
  `python3 scripts/licensing-gate.py`.

---

## 5. Reporting a security issue

Do not open a public issue for a vulnerability. Security reports go to the owner
privately; see [`NetOps_Observability/docs/security/`](NetOps_Observability/docs/security/)
for the current disclosure contact.
