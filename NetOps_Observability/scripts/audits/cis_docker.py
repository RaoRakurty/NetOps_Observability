#!/usr/bin/env python3
"""CIS-Docker policy gate (gap-report #7) — a deterministic, dependency-free check
that the container posture we CONTROL cannot silently regress.

Trivy's `misconfig` scanner already flags generic Dockerfile/IaC issues, but its
rules evolve and can be ignore-listed; this gate pins the project's specific,
non-negotiable invariants so a dropped `USER` line or an added capability fails CI:

  Dockerfiles (the images WE build):
    * declare a non-root runtime user (CIS 4.1) — distroless `:nonroot` counts;
    * pin the runtime base image by @sha256 digest (CIS 4.x / supply-chain).

  docker-compose services (the ones WE own):
    * security_opt: no-new-privileges:true   (CIS 5.25 — block setuid escalation)
    * cap_drop: [ALL]                          (CIS 5.3 — drop all Linux caps)
    * never `privileged: true`                 (CIS 5.4)
    * cap_add only from a justified allowlist   (least privilege)

Exemptions are explicit and reasoned (swtpm TPM-emulation sidecar; lab tooling).
Pure stdlib, no Docker daemon needed. Exit 0 = compliant, 1 = violation(s).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Repo layout: this file is NetOps_Observability/scripts/audits/cis_docker.py
ROOT = Path(__file__).resolve().parents[2]
DOCKER = ROOT / "deployment" / "docker"
COMPOSE = DOCKER / "docker-compose.yml"

# Dockerfiles for images WE build and ship — each must run non-root + digest-pin.
OWNED_DOCKERFILES = [
    DOCKER / "Dockerfile.backend",
    DOCKER / "Dockerfile.correlation",
    DOCKER / "Dockerfile.frontend",
    DOCKER / "Dockerfile.nginx",
]
# Reasoned exemptions (documented, not silent):
#   swtpm-sidecar     — TPM emulation needs elevated access; dormant `seal` profile.
#   Dockerfile.frontend.full / traffic-generator — build-variant / lab tooling, not
#     part of the shipped runtime surface.

# Compose services WE own (the app tier). Third-party images (postgres, redis,
# keycloak, redpanda, opensearch, …) are upstream and hardened at the orchestration
# layer separately; this gate governs the services whose posture we author.
OWNED_SERVICES = ["api", "correlation", "frontend", "nginx", "prober"]
# cap_add is least-privilege: only these (service -> allowed caps) are permitted.
CAP_ADD_ALLOW = {"prober": {"NET_RAW"}}  # ICMP synthetics need raw sockets

DIGEST_PIN = re.compile(r"@sha256:[0-9a-f]{64}")


def check_dockerfiles() -> list[str]:
    problems: list[str] = []
    for df in OWNED_DOCKERFILES:
        if not df.exists():
            problems.append(f"{df.name}: MISSING (expected an owned Dockerfile)")
            continue
        lines = df.read_text().splitlines()
        froms = [l for l in lines if l.strip().upper().startswith("FROM ")]
        users = [l.strip() for l in lines if l.strip().upper().startswith("USER ")]
        if not froms:
            problems.append(f"{df.name}: no FROM instruction")
            continue
        runtime = froms[-1]  # the final stage is what actually ships
        if not DIGEST_PIN.search(runtime):
            problems.append(f"{df.name}: runtime base image not @sha256 digest-pinned ({runtime.strip()})")
        # Non-root: either an explicit non-root USER, or a distroless :nonroot base.
        non_root_user = any(
            u.split()[1].split(":")[0] not in ("", "root", "0") for u in users if len(u.split()) > 1
        )
        distroless_nonroot = "nonroot" in runtime.lower()
        if not (non_root_user or distroless_nonroot):
            problems.append(f"{df.name}: no non-root USER (CIS 4.1) — runs as root")
    return problems


def _service_blocks(text: str) -> dict[str, str]:
    """Split the compose `services:` map into {name: block-text}. Services are at a
    stable 2-space indent (`  name:`); a block runs until the next 2-space key."""
    lines = text.splitlines()
    # find the services: section bounds
    start = next((i for i, l in enumerate(lines) if re.match(r"^services:\s*$", l)), None)
    if start is None:
        return {}
    blocks: dict[str, str] = {}
    cur: str | None = None
    buf: list[str] = []
    for l in lines[start + 1:]:
        if re.match(r"^[a-zA-Z]", l):  # dedented to column 0 → left services:
            break
        m = re.match(r"^  ([A-Za-z0-9_.-]+):\s*$", l)
        if m:
            if cur is not None:
                blocks[cur] = "\n".join(buf)
            cur, buf = m.group(1), []
        elif cur is not None:
            buf.append(l)
    if cur is not None:
        blocks[cur] = "\n".join(buf)
    return blocks


def check_compose() -> list[str]:
    problems: list[str] = []
    if not COMPOSE.exists():
        return [f"{COMPOSE}: MISSING"]
    text = COMPOSE.read_text()
    blocks = _service_blocks(text)

    # No service anywhere may be privileged.
    for name, body in blocks.items():
        if re.search(r"^\s*privileged:\s*true", body, re.M):
            problems.append(f"service '{name}': privileged:true is forbidden (CIS 5.4)")

    for svc in OWNED_SERVICES:
        body = blocks.get(svc)
        if body is None:
            problems.append(f"service '{svc}': not found in compose (owned app-tier service)")
            continue
        if "no-new-privileges:true" not in body:
            problems.append(f"service '{svc}': missing security_opt no-new-privileges:true (CIS 5.25)")
        if not re.search(r"cap_drop:\s*\[?\s*ALL", body):
            problems.append(f"service '{svc}': missing cap_drop: [ALL] (CIS 5.3)")
        # cap_add must be within the justified allowlist.
        added = set(re.findall(r"cap_add:\s*\[?\s*([A-Z_,\s]+)", body))
        caps = {c.strip() for grp in added for c in grp.split(",") if c.strip()}
        allowed = CAP_ADD_ALLOW.get(svc, set())
        if caps - allowed:
            problems.append(f"service '{svc}': cap_add {sorted(caps - allowed)} not in allowlist {sorted(allowed) or '∅'}")
    return problems


def _selftest() -> int:
    """Proves the gate BITES (a gate that can't fail is worthless). Points the module
    globals at synthetic broken fixtures and asserts each violation is caught + a
    compliant fixture passes. No pytest (this dir's platform.py shadows stdlib under
    pytest) and no deps — runs in CI before the real gate."""
    import tempfile
    global OWNED_DOCKERFILES, COMPOSE, OWNED_SERVICES
    saved = (OWNED_DOCKERFILES, COMPOSE, OWNED_SERVICES)

    good_df = ("FROM build@sha256:" + "a" * 64 + " AS b\n"
               "FROM gcr.io/distroless/static:nonroot@sha256:" + "b" * 64 + "\nUSER nonroot\n")
    good_compose = ("services:\n"
                    "  api:\n    security_opt: [\"no-new-privileges:true\"]\n    cap_drop: [ALL]\n"
                    "  prober:\n    security_opt: [\"no-new-privileges:true\"]\n    cap_drop: [ALL]\n    cap_add: [NET_RAW]\n")

    def wire(df_text: str, compose_text: str, td: Path):
        global OWNED_DOCKERFILES, COMPOSE, OWNED_SERVICES
        df = td / "Dockerfile.api"; df.write_text(df_text)
        comp = td / "docker-compose.yml"; comp.write_text(compose_text)
        OWNED_DOCKERFILES, COMPOSE, OWNED_SERVICES = [df], comp, ["api", "prober"]

    cases: list[tuple[str, bool]] = []  # (label, passed)
    try:
        with tempfile.TemporaryDirectory() as d:
            td = Path(d)
            wire(good_df, good_compose, td)
            cases.append(("compliant fixture passes", check_dockerfiles() == [] and check_compose() == []))
            wire("FROM debian@sha256:" + "c" * 64 + "\n", good_compose, td)
            cases.append(("root user flagged", any("non-root" in p for p in check_dockerfiles())))
            wire("FROM x:nonroot\nUSER nonroot\n", good_compose, td)
            cases.append(("unpinned base flagged", any("digest-pinned" in p for p in check_dockerfiles())))
            wire(good_df, "services:\n  api:\n    image: x\n  prober:\n    image: y\n", td)
            cases.append(("missing hardening flagged", len(check_compose()) >= 2))
            wire(good_df, good_compose + "  bad:\n    privileged: true\n", td)
            cases.append(("privileged forbidden", any("privileged" in p for p in check_compose())))
            wire(good_df, good_compose.replace("  api:\n", "  api:\n    cap_add: [SYS_ADMIN]\n"), td)
            cases.append(("disallowed cap_add flagged", any("SYS_ADMIN" in p for p in check_compose())))
            blocks = _service_blocks(good_compose)
            cases.append(("block parser", set(blocks) == {"api", "prober"} and "NET_RAW" not in blocks["api"]))
    finally:
        OWNED_DOCKERFILES, COMPOSE, OWNED_SERVICES = saved

    failed = [label for label, ok in cases if not ok]
    for label, ok in cases:
        print(f"  {'✓' if ok else '✗'} selftest: {label}")
    if failed:
        print(f"\nselftest FAILED: {failed}")
        return 1
    print(f"selftest PASS ({len(cases)} checks) — the gate bites\n")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        rc = _selftest()
        if rc:
            return rc
    problems = check_dockerfiles() + check_compose()
    if problems:
        print("CIS-Docker gate: FAIL")
        for p in problems:
            print(f"  ✗ {p}")
        print(f"\n{len(problems)} violation(s).")
        return 1
    print("CIS-Docker gate: PASS")
    print(f"  ✓ {len(OWNED_DOCKERFILES)} owned Dockerfiles non-root + digest-pinned")
    print(f"  ✓ {len(OWNED_SERVICES)} owned services no-new-privileges + cap_drop ALL, no privileged, caps allowlisted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
