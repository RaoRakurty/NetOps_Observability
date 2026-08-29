"""Offline reproduction of the storm-s02 lifecycle-merge loop stall.

    python3 bench_lifecycle_merge_storm.py                # the fix
    python3 bench_lifecycle_merge_storm.py --legacy-index  # the defect

WHAT IT REPRODUCES. Run storm-s02 (2026-08-29 20:01:09→20:01:44Z, replica-4)
took a 35,690 ms event-loop stall — past the 30 s Kafka session timeout, so the
consumer was ejected twice. No stage span covered it. The suspect was
`_epoch_lifecycle`'s `find_merges(survivors, candidates)` over a storm
population (open objects ~10k, survivors 2,347–7,313, candidates ~2,500).

The bench builds that population from genuine `run_window` output and sweeps
the one estate variable the live gauges did NOT expose: how many seams the
tenant inventory holds. `run_window` stamps the WHOLE inventory into EVERY
snapshot it emits, so the survivor index's seam clauses — keyed, before the
fix, on every EMBEDDED seam — mapped each inventory token to the entire
population and returned it for every probe. The index degenerated into the
O(survivors x candidates) cross-product it existed to remove, silently, in
proportion to how many devices are seam endpoints.

MEASURED, 8,000 objects / 2,500 devices, 5,000 survivors x 2,500 candidates,
4-core box. `--legacy-index` restores the pre-fix EV keying, so both halves of
this table come out of this one harness. "on-loop" is index build + predicate,
which is exactly what `_epoch_lifecycle` used to run on the event-loop thread:

              --------- --legacy-index (the defect) --------   ----- shipped -----
    seams        pairs examined   build + predicate = on-loop   pairs      on-loop
        0                 3,530     66 +     60 =      126 ms   3,530       144 ms
      200             2,351,375  1,764 +  3,426 =    5,190 ms   3,530       132 ms
    1,000             8,532,694 10,177 + 12,488 =   22,665 ms   3,530       135 ms
    2,500            12,500,000 21,581 + 23,539 =   45,120 ms   3,530       149 ms
                    ^ the full 5,000 x 2,500 cross-product

The 1,000-seam row (22.7 s) and the 2,500-seam row (45.1 s) bracket the observed
35,690 ms stall. After the fix (seam clauses keyed on GROUNDED seams only — see
`engine.ContinuationIndex`) seam density stops mattering at all: the same 3,530
pairs and the same ~140 ms on every row, a 300x reduction at the top.

This is a BENCH, not a test — the equivalence and loop-bound guarantees are
pinned by `test_lifecycle_merge_storm_p1.py`, which runs in the suite. Keep it
runnable so the numbers above stay re-derivable rather than folklore.
"""
from __future__ import annotations

import argparse
import dataclasses
import random
import time

from catalog import builtin_catalog
from engine import ContinuationIndex, EngineConfig, SeamView, find_merges, run_window
from signals import EntityType
from test_engine import sig

# The pre-fix index, kept as an executable witness beside the tests that pin it.
from test_lifecycle_merge_storm_p1 import _EVKeyedIndex

CAT = builtin_catalog()
CFG = EngineConfig()


def build(n: int, devices: int) -> list:
    """`n` distinct open objects over `devices` devices — real engine output."""
    out: list = []
    i = 0
    while len(out) < n:
        d = f"dev-{i % devices}"
        out.extend(run_window(
            [sig("device_cpu_high", EntityType.DEVICE, d, offset_s=i * 0.5),
             sig("if_errors", EntityType.INTERFACE, f"{d}:Gi0/{i % 8}",
                 offset_s=i * 0.5 + 5)], CAT, (), CFG))
        i += 1
    uniq: dict = {}
    for s in out[:n]:
        uniq.setdefault(s.correlation_id, s)
    return list(uniq.values())


def inventory(n: int) -> tuple[SeamView, ...]:
    """One seam per device: every device in the estate is a seam ENDPOINT."""
    return tuple(
        SeamView(seam_id=f"seam-{i}", tenant_id="", seam_type="DX",
                 endpoints=(("member_edge", f"dev-{i}"),
                            ("provider_resource", f"dxcon-{i}/vif")))
        for i in range(n))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--objects", type=int, default=8000)
    ap.add_argument("--devices", type=int, default=2500)
    ap.add_argument("--survivors", type=int, default=5000)
    ap.add_argument("--candidates", type=int, default=2500)
    ap.add_argument("--legacy-index", action="store_true",
                    help="use the pre-fix EV keying — reproduces the stall")
    args = ap.parse_args()
    build_index = _EVKeyedIndex if args.legacy_index else ContinuationIndex

    t0 = time.perf_counter()
    base = build(args.objects, args.devices)
    print(f"built {len(base)} open objects over {args.devices} devices "
          f"in {time.perf_counter() - t0:.1f}s")
    which = ("LEGACY EV keying (the defect)" if args.legacy_index
             else "grounded-seam keying (shipped)")
    print(f"index: {which}\n")
    print(f"{'seams':>7}  {'index build':>12}  {'pairs examined':>15}  "
          f"{'find_merges':>12}  {'merges':>7}")

    for nseams in (0, 200, 1000, 2500):
        seams = inventory(nseams)
        # Attaching the inventory afterwards is byte-identical to what
        # run_window emits: it passes `seams=` straight to every snapshot.
        pop = [dataclasses.replace(s, seams=seams) for s in base]
        random.Random(20260829).shuffle(pop)
        surv = pop[:args.survivors]
        cand = pop[args.survivors:args.survivors + args.candidates]

        t0 = time.perf_counter()
        idx = build_index(surv)
        t_idx = time.perf_counter() - t0
        t0 = time.perf_counter()
        res = find_merges(surv, cand, index=idx)
        t_fm = time.perf_counter() - t0
        print(f"{nseams:>7}  {t_idx * 1000:>10.1f} ms  "
              f"{idx.candidates_returned:>15,}  {t_fm * 1000:>9.1f} ms  "
              f"{len(res):>7}")


if __name__ == "__main__":
    main()
