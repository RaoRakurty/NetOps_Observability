# OPERATIONAL SCRIPTS & CRON (SAME BAR AS THE CODE)

> Moved out of the root `CLAUDE.md` (was §16) so it loads when you work on
> scripts instead of in every session. **It still applies to EVERY shell script
> in the repo** — `tests/`, `deployment/docker/`, bundled `dist/` scripts — not
> only the ones in this directory. Section numbers below are kept as `16.x` so
> existing cross-references still resolve.

Shell scripts, cron jobs, watchdogs, hygiene sweepers and installers are
**production software that runs unattended on the host customer data flows
through.** They get the FAANG-grade bar the Go code gets — not "it's just a
script." Most of these SHIP in the customer package (`scripts/*.sh`,
`install-correlix.sh`, `prepare-host.sh`, `docker-hygiene.sh`); operator-only
tooling is excluded via `make-installer.sh`'s `LAB_PATHS`. Assume a script ships
unless that exclude list proves otherwise, and hold it to this section regardless
— an operator script guards the same production host.

## 16.1 NEVER swallow an error (the cardinal rule)

`cmd >/dev/null 2>&1 || true` is **forbidden** as a way to "handle" failure. It
is the shell form of the §2/§10 accept-and-ignore defect the 2026-07-21 audit
exists to kill: it hides `command not found`, permission errors and real
failures, then reports success. This class already cost us a live incident — a
hygiene cron ran every 10 minutes reporting `91% -> 91%` while reclaiming
nothing, because `go` was not on cron's PATH and `go clean -cache 2>/dev/null ||
true` ate the error.

- Capture the command's stderr and **report it** (log line, metric, alert).
  Suppress output only when you have *inspected* it and it is genuinely noise —
  and say so in a comment.
- `|| true` is allowed ONLY for a genuinely optional step, with a comment
  stating why the failure is safe to ignore. "It's convenient" is not a why.
- Tally failures and make a degraded run **loud**: non-zero exit + an alert.
  A maintenance job that cannot do its job must be as visible as the condition
  it maintains against.

## 16.2 Cron runs in a hostile, minimal environment — assume nothing

- **PATH is `/usr/bin:/bin` only.** Tools in `~/.local/…`, `~/go/bin`,
  `/usr/local/bin` are NOT found. Set an explicit PATH at the top of every
  script, or `command -v` each tool and WARN by name if missing.
- No interactive shell, so `~/.bashrc`/`~/.profile` are NOT sourced. Every env
  var the script needs is set explicitly or read from a checked-in config file.
- `HOME` may be unset. Resolve it defensively.
- A quiet cron is unobservable: emit a heartbeat file the watchdog can check,
  so "the job stopped running" is itself detectable.

## 16.3 Bash hygiene (non-negotiable)

- `set -euo pipefail` at the top. Quote every expansion (`"$var"`). `[ ]` tests
  guard empty/unset.
- **Idempotent** (§9): safe to run twice; a partial run leaves no corruption.
- **Dry-run before destructive action.** Anything that deletes, prunes, or
  overwrites states what it will touch and never runs against a live volume it
  was not pointed at. Confirm the target exists and is the intended one first.
- **Every external call bounded** (§9): `timeout`, `curl -m`, connect timeouts.
  A wedged dependency must not hang the job forever.
- `shellcheck` clean is the merge bar, the same way `staticcheck`/`golangci` is
  for Go (§8, §12). `bash -n` is the floor, not the ceiling.

## 16.4 Schedule the RIGHT work — don't cron what should be event-driven

Cron is for genuinely periodic maintenance, not for producing release artifacts.
Building a customer package on a daily timer is wrong: it burns disk and CPU
whether or not anything shipped, competes with the very disk it needs (our
`bundle-autoupdate` skipped for days because it had filled the disk it required),
and decouples the artifact from the commit that should trigger it.

- **Release artifacts** (customer bundles, VM images) are **event-driven** — on
  a git tag / release, in CI, gated on the build passing — not on a wall-clock
  timer. Tie the artifact to the SHA that warrants it (see §build-provenance).
- **Retention is explicit and bounded**: keep N newest, prune the rest, and the
  prune must cover *every* sibling artifact (the bundle dir AND its VM image AND
  its tarballs), or the uncovered one accumulates forever.
- **Disk preflight** before any large build, and it must be a real gate, not a
  skip that silently means "no fresh artifact for three days."

## 16.5 Ship-safety

- **No secrets, tokens, internal hostnames, or lab fixtures in a shipped
  script.** `make-installer.sh` guards this; keep that guard green and never
  route around it. A build log or lab script leaking into the customer tarball
  is a release-integrity failure, not a cosmetic one.
- Scripts that touch customer data or credentials obey §8 (no secrets in code /
  logs, sanitize output) exactly as the Go code does.
