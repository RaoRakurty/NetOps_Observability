#!/usr/bin/env python3
"""twin.py — CORRELIX Network Digital Twin, phase T1 CORE (tracker 152).

Runs a labeled multi-tenant fault scenario against the LIVE stack and measures
what today is unproven (design §1.1): G-1 multi-tenant partition SPREAD under
sustained load, and G-2 RCA ACCURACY against machine-readable ground truth.

    twin.py run      --scenario FILE [--duration-minutes N] [--dry-run]
                     [--keep] [--force]
    twin.py score    --runid X            # re-score an existing run dir
    twin.py teardown --runid X            # verified teardown, always runnable

T1-CORE lanes: syslog (console producer → netops.syslog over the TLS
listener), probes + cloud + metrics bus-direct. SNMP/snmpsim, traps-over-UDP,
IPFIX, gNMI and the `twinnet` source-ip overlay are a LATER wave — attribution
rides the per-NAME registry rows (`hostname` fallback, design §3.4).

Exit codes: 0 = the run executed and (unless --keep) tore down verified-clean
— story accuracy is MEASUREMENT OUTPUT (accuracy-report.md), not a tool
verdict; 1 = the tool itself failed (emission, gates, teardown residue);
2 = refused before touching the stack.

Credentials (mini-ladder contract, never on argv): MLX_ADMIN_USER /
MLX_ADMIN_PASSWORD env, else ADMIN_USERNAME / ADMIN_INITIAL_PASSWORD from
--env-file (deployment/docker/.env). §16.2: PATH is pinned; the run root
carries a last-run.json heartbeat plus an in-run heartbeat file so a wedged
run is itself detectable.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import random
import signal
import string
import sys
import time
from datetime import datetime, timezone

# Cron-proof PATH (§16.2): docker lives in /usr/bin or /usr/local/bin.
os.environ["PATH"] = "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

# twin-local modules (flat, self-contained package — nothing enters
# src/backend or src/correlation).
import lifecycle
import scorer as scorer_mod
import spread as spread_mod
from emitters import Injector
from scenario import (
    ScenarioError,
    check_budget,
    load_scenario,
    steady_eps,
)
from stack import Stack, env_get, log, warn
from stories import build_run_plan, plan_end_s

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(SCRIPT_DIR)))
POST_EMISSION_WAIT_S = 75          # engine window settle (correlation_e2e)
POST_DRAIN_BUDGET_S = 600


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def die(msg: str, code: int = 2) -> None:
    print(f"twin: ERROR: {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


def run_root(args: argparse.Namespace) -> str:
    return args.run_root or os.path.join(REPO_ROOT, "data", "twin")


def enrichment_dir(env_file: str) -> str:
    """The host path of the api container's TENANT_ENRICHMENT_DIR volume —
    <deploy>/../../data/api/enrichment relative to the compose .env (the same
    tree layout install.py builds)."""
    return os.path.normpath(os.path.join(
        os.path.dirname(env_file), "..", "..", "data", "api", "enrichment"))


def write_json(path: str, doc: object) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, default=str)


def heartbeat(root: str, doc: dict) -> None:
    try:
        write_json(os.path.join(root, "last-run.json"), doc)
    except OSError as exc:
        warn(f"heartbeat write failed: {exc}")


# ── run ─────────────────────────────────────────────────────────────────────

class Run:
    def __init__(self, args: argparse.Namespace, sc: dict):
        self.args = args
        self.sc = sc
        self.runid = (datetime.now(timezone.utc).strftime("%m%d%H%M")
                      + "".join(random.choices(
                          string.ascii_lowercase + string.digits, k=4)))
        self.prefix = f"twx-{self.runid}-"
        self.stack = Stack(args.env_file, args.base_url, args.project)
        self.partitions = int(env_get(args.env_file, "BUS_PARTITIONS") or "1")
        self.root = run_root(args)
        self.run_dir = os.path.join(
            self.root,
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + "-" + self.runid)
        self.state: dict = {"runid": self.runid, "prefix": self.prefix,
                            "created": utcnow(), "scenario": args.scenario}
        self.gates: dict = {}
        self.report: dict = {}
        self.organic: dict[int, float] = {}

    def save_state(self) -> None:
        write_json(os.path.join(self.run_dir, "state.json"), self.state)

    def hb(self, phase: str) -> None:
        try:
            write_json(os.path.join(self.run_dir, "heartbeat.json"),
                       {"ts": utcnow(), "phase": phase, "runid": self.runid})
        except OSError as exc:
            warn(f"in-run heartbeat failed: {exc}")

    # -- phases ------------------------------------------------------------
    def setup(self) -> None:
        self.hb("preflight")
        self.gates["preflight"] = lifecycle.preflight(self.stack,
                                                      self.partitions)
        baseline_reg = self.gates["preflight"]["baseline_registry_identities"]

        self.hb("tenancy")
        tenants, orgs = lifecycle.setup_tenancy(self.stack, self.sc,
                                                self.runid, self.partitions)
        self.state["tenants"] = tenants
        self.state["orgs"] = orgs
        self.state["device_tenants"] = {d["name"]: d["tenant"]
                                        for d in self.sc["devices"]}
        self.save_state()

        self.hb("devices")
        self.state["devices"] = lifecycle.register_devices(
            self.stack, self.sc, self.prefix, self.runid, tenants)
        self.save_state()

        self.hb("registry-gate")
        self.gates["registry"] = lifecycle.registry_gate(
            self.stack, baseline_reg, len(self.state["devices"]))

        self.hb("seams")
        seam_result = lifecycle.register_seams(
            self.stack, self.sc, self.prefix, tenants,
            enrichment_dir(self.args.env_file))
        self.gates["seams"] = seam_result
        self.state["seam_mode"] = seam_result["mode"]
        self.state["seams"] = [self.prefix + s["seam_id"]
                               for s in self.sc.get("seams") or []]
        self.save_state()

        self.hb("canary")
        first_dev = self.sc["devices"][0]
        lifecycle.canary(self.stack, self.prefix, first_dev["name"],
                         tenants[first_dev["tenant"]]["tenant_id"])
        self.gates["canary"] = "ok"

    def emit(self) -> tuple[Injector, spread_mod.SpreadSampler, list[dict]]:
        duration_s = self.args.duration_minutes * 60.0
        plan = build_run_plan(self.sc, duration_s)
        end_s = plan_end_s(plan)
        if end_s > duration_s:
            log(f"note: stories extend the run to {end_s:.0f}s "
                f"(> --duration-minutes {self.args.duration_minutes})")

        items = list(plan["baseline"])
        for stx in plan["stories"]:
            items.extend(stx["items"])
        items.sort(key=lambda e: (e["t"], e["lane"], e["device"]))
        log(f"emission plan: {len(items)} events over {end_s:.0f}s "
            f"({steady_eps(self.sc):.2f} steady EPS, "
            f"{len(plan['stories'])} stories)")

        tenant_ids = {a: t["tenant_id"]
                      for a, t in self.state["tenants"].items()}
        injector = Injector(
            self.stack, self.prefix, tenant_ids,
            os.path.join(self.run_dir, "events.jsonl"))
        sampler = spread_mod.SpreadSampler(
            self.stack, os.path.join(self.run_dir, "spread-samples.jsonl"))

        gt_path = os.path.join(self.run_dir, "ground_truth.jsonl")
        ground_truth: list[dict] = []
        by_id = {stx["id"]: stx for stx in plan["stories"]}

        def gt_cb(story_id: str) -> None:
            stx = by_id[story_id]
            extra = []
            for st in self.sc.get("stories") or []:
                if st["id"] == story_id:
                    cloud = (st.get("params") or {}).get("cloud") or {}
                    if cloud.get("resource_id"):
                        extra.append(str(cloud["resource_id"]))
            rec = {
                "story_id": story_id,
                "template": stx["template"],
                "t0_offset_s": stx["t0"],
                "fired_at": utcnow(),
                "affected": stx["affected"],
                "entities": [self.prefix + d
                             for d in stx["affected"].get("devices") or []],
                "extra_entities": extra,
                "expect": stx["expect"],
            }
            ground_truth.append(rec)
            with open(gt_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
            log(f"story fired: {story_id} ({stx['template']})")

        def hb_cb() -> None:
            self.hb("emitting")
            sampler.sample()

        # Pre-run ORGANIC window: the lab stack's own syslog (untenanted →
        # keyed "global" → one partition) would otherwise pollute that
        # partition's delta and fail the ±20% gate spuriously. Measure it for
        # 45 s and let spread_report subtract it (estimate is in the report).
        self.hb("organic-baseline")
        organic_sampler = spread_mod.SpreadSampler(
            self.stack, os.path.join(self.run_dir, "organic-samples.jsonl"))
        organic_sampler.sample(force=True)
        time.sleep(45)
        organic_sampler.sample(force=True)
        self.organic = spread_mod.organic_rates(organic_sampler.samples)
        log(f"organic per-partition consumed rate (ev/s): "
            f"{ {k: round(v, 2) for k, v in self.organic.items()} }")

        self.hb("emitting")
        sampler.sample(force=True)
        t0 = time.monotonic()
        ok = injector.run_schedule(items, t0, ground_truth_cb=gt_cb,
                                   heartbeat_cb=hb_cb)
        sampler.sample(force=True)
        if not ok:
            raise lifecycle.LifecycleError(
                f"emission failed: {injector.produce_failures[:3]}")
        log(f"emission complete: {injector.emitted} "
            f"(per tenant: {injector.emitted_by_tenant.get('syslog', {})})")
        return injector, sampler, ground_truth

    def settle_and_measure(self, injector: Injector,
                           sampler: spread_mod.SpreadSampler,
                           ground_truth: list[dict]) -> None:
        # engine window + drain settle before scoring (correlation_e2e wait +
        # the mini-ladder drain gate)
        self.hb("settling")
        log(f"waiting {POST_EMISSION_WAIT_S}s engine window …")
        time.sleep(POST_EMISSION_WAIT_S)
        deadline = time.monotonic() + POST_DRAIN_BUDGET_S
        lag = -1
        while time.monotonic() < deadline:
            lag, _m = self.stack.group_lag_total("netops-correlation")
            if 0 <= lag <= 100:
                break
            time.sleep(10)
        self.gates["post_drain_lag"] = lag
        sampler.sample(force=True)

        # spread report (design §6)
        self.hb("spread")
        assignment = spread_mod.replica_assignment(self.stack)
        tenant_parts = {a: t["partition"]
                        for a, t in self.state["tenants"].items()}
        emitted = injector.emitted_by_tenant.get("syslog", {})
        sp = spread_mod.spread_report(sampler.samples, assignment,
                                      tenant_parts, emitted,
                                      organic=getattr(self, "organic", None))
        write_json(os.path.join(self.run_dir, "spread-report.json"), sp)
        log(f"partition spread: {sp['status']} "
            f"(deltas {sp.get('consumed_delta_by_partition')})")

        # accuracy scorer (design §8.4)
        self.hb("scoring")
        acc = scorer_mod.score_run(self.stack, ground_truth, self.state,
                                   injector.emitted_by_story)
        write_json(os.path.join(self.run_dir, "accuracy-report.json"), acc)
        with open(os.path.join(self.run_dir, "accuracy-report.md"), "w",
                  encoding="utf-8") as f:
            f.write(scorer_mod.render_md(acc))
        log(f"accuracy: {acc['stories_passed']}/{acc['stories_total']} "
            f"stories PASS (specificity {acc['specificity']:.2f})")

        self.report = {
            "harness": "twin-t1-core",
            "runid": self.runid,
            "generated": utcnow(),
            "scenario": self.args.scenario,
            "gates": self.gates,
            "emitted_by_lane": injector.emitted,
            "emitted_by_tenant": injector.emitted_by_tenant,
            "emitted_by_story": injector.emitted_by_story,
            "produce_failures": injector.produce_failures,
            "partition_coverage": {a: t["partition"] for a, t in
                                   self.state["tenants"].items()},
            "spread": {k: sp[k] for k in ("status", "problems", "replicas")},
            "accuracy": {k: acc[k] for k in
                         ("accuracy_slo", "stories_total", "stories_passed",
                          "detection_rate", "specificity")},
        }
        write_json(os.path.join(self.run_dir, "twin-report.json"), self.report)

    def execute(self) -> int:
        os.makedirs(self.run_dir, exist_ok=True)
        log(f"run {self.runid} -> {self.run_dir}")
        self.save_state()
        tool_ok = False
        teardown_problems: list[str] | None = None
        try:
            self.setup()
            injector, sampler, ground_truth = self.emit()
            self.settle_and_measure(injector, sampler, ground_truth)
            tool_ok = True
        except KeyboardInterrupt:
            warn("interrupted — running teardown before exit")
        except lifecycle.LifecycleError as exc:
            warn(str(exc))
        finally:
            if self.args.keep:
                log("--keep: entities left standing for inspection; run "
                    f"`twin.py teardown --runid {self.runid}` when done")
            else:
                try:
                    self.hb("teardown")
                    teardown_problems = lifecycle.teardown(
                        self.stack, self.state,
                        enrichment_dir(self.args.env_file))
                    for p in teardown_problems:
                        warn(f"teardown: {p}")
                except Exception as exc:  # noqa: BLE001 — teardown crash must be loud, never masked
                    warn(f"teardown crashed: {exc!r}")
                    teardown_problems = [f"teardown crashed: {exc!r}"]
            heartbeat(self.root, {
                "ts": utcnow(), "runid": self.runid,
                "run_dir": self.run_dir,
                "tool_ok": tool_ok,
                "teardown_problems": teardown_problems,
                "accuracy": self.report.get("accuracy"),
                "spread": (self.report.get("spread") or {}).get("status"),
            })
        if not tool_ok:
            return 1
        if teardown_problems:
            return 1
        return 0


# ── score / teardown subcommands ────────────────────────────────────────────

def find_run_dir(root: str, runid: str) -> str:
    hits = sorted(glob.glob(os.path.join(root, f"*-{runid}")))
    if not hits:
        die(f"no run dir matching *-{runid} under {root}")
    return hits[-1]


def cmd_score(args: argparse.Namespace) -> int:
    rd = find_run_dir(run_root(args), args.runid)
    with open(os.path.join(rd, "state.json"), encoding="utf-8") as f:
        state = json.load(f)
    gt_path = os.path.join(rd, "ground_truth.jsonl")
    try:
        with open(gt_path, encoding="utf-8") as f:
            ground_truth = [json.loads(ln) for ln in f if ln.strip()]
    except OSError as exc:
        die(f"cannot read {gt_path}: {exc} — did the run reach emission?")
    # Rebuild per-story journal counts from events.jsonl so the evidence
    # trail's emission half survives a re-score (signals may have been purged
    # by teardown; the journal is the run's own record).
    journal_by_story: dict[str, dict[str, int]] = {}
    try:
        with open(os.path.join(rd, "events.jsonl"), encoding="utf-8") as f:
            for ln in f:
                ev = json.loads(ln)
                sid = ev.get("story_id")
                if sid:
                    lane_counts = journal_by_story.setdefault(sid, {})
                    lane_counts[ev["lane"]] = lane_counts.get(ev["lane"], 0) + 1
    except OSError as exc:
        warn(f"events.jsonl unreadable ({exc}) — evidence trails will lack "
             f"emission counts")
    stack = Stack(args.env_file, args.base_url, args.project)
    stack.login()
    acc = scorer_mod.score_run(stack, ground_truth, state, journal_by_story)
    write_json(os.path.join(rd, "accuracy-report.json"), acc)
    with open(os.path.join(rd, "accuracy-report.md"), "w",
              encoding="utf-8") as f:
        f.write(scorer_mod.render_md(acc))
    log(f"accuracy: {acc['stories_passed']}/{acc['stories_total']} — report "
        f"in {rd}")
    return 0


def cmd_teardown(args: argparse.Namespace) -> int:
    rd = find_run_dir(run_root(args), args.runid)
    state_path = os.path.join(rd, "state.json")
    try:
        with open(state_path, encoding="utf-8") as f:
            state = json.load(f)
    except OSError as exc:
        die(f"cannot read {state_path}: {exc}")
    stack = Stack(args.env_file, args.base_url, args.project)
    stack.login()
    problems = lifecycle.teardown(stack, state,
                                  enrichment_dir(args.env_file))
    for p in problems:
        warn(f"teardown: {p}")
    return 1 if problems else 0


# ── CLI ─────────────────────────────────────────────────────────────────────

def parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="twin.py",
        description="CORRELIX network digital twin — T1 core "
                    "(see module docstring)")
    ap.add_argument("--env-file",
                    default=os.path.join(REPO_ROOT, "deployment", "docker",
                                         ".env"),
                    help="compose .env for credentials/topology")
    ap.add_argument("--base-url", default="",
                    help="API base URL (default http://localhost:<BASE_PORT>)")
    ap.add_argument("--project", default="",
                    help="compose project (default COMPOSE_PROJECT_NAME|netops)")
    ap.add_argument("--run-root", default="",
                    help="run-dir root (default <repo>/data/twin)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    rp = sub.add_parser("run", help="execute a scenario end to end")
    rp.add_argument("--scenario", required=True)
    rp.add_argument("--duration-minutes", type=float, default=10.0)
    rp.add_argument("--dry-run", action="store_true",
                    help="validate + print the plan; touch nothing")
    rp.add_argument("--keep", action="store_true",
                    help="skip teardown (inspect entities afterwards)")
    rp.add_argument("--force", action="store_true",
                    help="run past the T1 steady-EPS budget refusal")

    spp = sub.add_parser("score", help="re-score an existing run")
    spp.add_argument("--runid", required=True)

    tp = sub.add_parser("teardown", help="verified teardown of a run")
    tp.add_argument("--runid", required=True)

    args = ap.parse_args(argv)
    if args.cmd == "run" and not (0.5 <= args.duration_minutes <= 120):
        ap.error("--duration-minutes must be between 0.5 and 120")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if not os.path.isfile(args.env_file):
        die(f"env file not found: {args.env_file} (use --env-file)")
    if not args.project:
        args.project = env_get(args.env_file, "COMPOSE_PROJECT_NAME") or "netops"
    if not args.base_url:
        port = env_get(args.env_file, "BASE_PORT") or "8000"
        args.base_url = f"http://localhost:{port}"

    # ^C and SIGTERM both reach the finally-teardown path.
    signal.signal(signal.SIGTERM,
                  lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))

    if args.cmd == "score":
        return cmd_score(args)
    if args.cmd == "teardown":
        return cmd_teardown(args)

    try:
        sc = load_scenario(args.scenario)
        budget_line = check_budget(sc, force=args.force)
    except ScenarioError as exc:
        die(str(exc))
        return 2  # unreachable; keeps type-checkers honest

    if args.dry_run:
        plan = build_run_plan(sc, args.duration_minutes * 60.0)
        n_items = len(plan["baseline"]) + sum(len(s["items"])
                                              for s in plan["stories"])
        print("twin DRY RUN — nothing will be touched")
        print(f"  scenario   : {sc['meta']['name']} (seed "
              f"{sc['meta']['seed']})")
        print(f"  tenants    : {[t['alias'] for t in sc['tenants']]} "
              f"(partition placement computed at run start from real ids)")
        print(f"  devices    : {len(sc['devices'])} (twx-<runid>- prefixed, "
              f"addresses 198.19.0.0/16)")
        print(f"  seams      : {[s['seam_id'] for s in sc.get('seams') or []]}")
        print(f"  {budget_line}")
        print(f"  plan       : {n_items} events over "
              f"{plan_end_s(plan):.0f}s; stories: "
              f"{[(s['id'], s['template'], s['t0']) for s in plan['stories']]}")
        print("  lifecycle  : preflight → orgs/tenants → devices(as_tenant) → "
              "registry gate → seams → canary → emit → settle → spread + "
              "accuracy reports → verified teardown")
        return 0

    log(budget_line)
    return Run(args, sc).execute()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
