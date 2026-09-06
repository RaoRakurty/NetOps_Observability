#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""In-situ A/B: the same drain sweep with the memo in compact vs object form."""
from __future__ import annotations

import argparse
import asyncio
import gc
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone

os.environ.setdefault("CORR_SIGNALS_ENABLED", "true")
os.environ.setdefault("CORR_ENGINE_ENABLED", "true")

import bench_memflat_p2 as bm
import main
import rank_memo as RM
from bench_profile_p2 import load, make_signals


async def drive(args, memo):
    now = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
    main.ch = bm.MockCH()
    main.RANK_MEMO = memo
    seq = 0
    for i in range(args.arrival_epochs):
        batch = make_signals(args.signals, args.devices,
                             t_end=now + timedelta(seconds=30 * i),
                             span_s=args.span_s, seq0=seq, burst=args.burst)
        load(batch); seq += args.signals; del batch
        epoch = await main._begin_epoch(now + timedelta(seconds=60 * i))
        epoch.storm = True
        cohorts = 0
        for _ in range(args.cohorts):
            await main.engine_cycle(epoch)
            epoch.cohorts = cohorts = cohorts + 1
            if not epoch.pending():
                break
        await main._epoch_lifecycle(epoch, main._make_loop_yield()[0])
        main._close_epoch(epoch)


def run(args, compact):
    memo = RM.RankMemo(max_entries=50_000, compact=compact)
    t0 = time.perf_counter()
    asyncio.run(drive(args, memo))
    wall = time.perf_counter() - t0
    gc.collect()
    st = memo.stats()
    st["wall_s"] = round(wall, 2)
    st["rss_mib"] = bm.rss_kib()["VmRSS"] // 1024
    st["open_objects"] = len(main.OPEN_OBJECTS)
    st["per_entry"] = round(st["bytes"] / max(1, st["entries"]), 1)
    return st


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--devices", type=int, default=400)
    ap.add_argument("--signals", type=int, default=3000)
    ap.add_argument("--arrival-epochs", type=int, default=3)
    ap.add_argument("--cohorts", type=int, default=8)
    ap.add_argument("--span-s", type=float, default=300.0)
    ap.add_argument("--burst", type=int, default=6)
    ap.add_argument("--compact", type=int, default=1)
    a = ap.parse_args()
    logging.disable(logging.CRITICAL)
    print(json.dumps(run(a, bool(a.compact))))
