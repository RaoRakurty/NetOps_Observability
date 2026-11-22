// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// useMeasuredPaths — the prober's measured paths for Investigate → Paths, read
// ONCE by the page and handed to whichever tab is open (each row carries its own
// path; measuredFold.ts says how a path finds its row). Every read is the
// caller's own workspace's: /api/probe/paths, /api/paths/health and /api/devices
// are tenant-scoped on the server.
//
// The paths read decides whether there is anything to show: when it fails, the
// tabs say so in one line and keep their own rows. Health and inventory only
// enrich the paths, so either failing leaves the paths judged on their trace and
// named by address.

import { useEffect, useState } from "react";
import { api } from "../../services/api";
import { buildMeasuredIndex, type MeasuredIndex } from "./measuredFold";

export interface MeasuredState {
  index: MeasuredIndex | null;
  /** The paths read failed; the rows still show, without their paths. */
  error: string | null;
  loaded: boolean;
}

const REFRESH_MS = 30_000;

export function useMeasuredPaths(): MeasuredState {
  const [state, setState] = useState<MeasuredState>({ index: null, error: null, loaded: false });

  useEffect(() => {
    let alive = true;
    const load = async () => {
      const [paths, health, devices] = await Promise.allSettled([
        api.probePaths(),
        api.pathsHealth(),
        api.devices(),
      ]);
      if (!alive) return;
      if (paths.status === "rejected") {
        setState((s) => ({ index: s.index, error: "Measured paths could not be read.", loaded: true }));
        return;
      }
      setState({
        index: buildMeasuredIndex(
          paths.value,
          health.status === "fulfilled" ? health.value?.paths : [],
          devices.status === "fulfilled" ? devices.value : [],
        ),
        error: null,
        loaded: true,
      });
    };
    void load();
    const id = setInterval(() => void load(), REFRESH_MS);
    return () => { alive = false; clearInterval(id); };
  }, []);

  return state;
}
