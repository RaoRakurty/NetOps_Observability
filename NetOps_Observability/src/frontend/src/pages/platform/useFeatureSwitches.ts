// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// useFeatureSwitches — read and change the platform feature switches, and
// restart to apply them. Shared by Platform → Features and the Sensors
// section of Administration → Discovery, so both pages keep the same honesty
// rules (Features.tsx): a restart-class switch shows what is RUNNING until the
// restart happens, and after a restart the page shows what it reads back.
//
// GATE. /api/platform/features and /api/platform/restart are
// requirePlatformAdmin; a 403 is an answer ("denied"), not a failure.

import { useCallback, useEffect, useState } from "react";
import { api, type PlatformFeatures } from "../../services/api";
import { httpFailure, operatorError } from "../../lib/errors";

export type FeatureLoad =
  | { kind: "loading" }
  | { kind: "denied" }
  | { kind: "error"; message: string }
  | { kind: "ready"; data: PlatformFeatures };

export type RestartState = { kind: "idle" } | { kind: "restarting"; since: number } | { kind: "done" } | { kind: "failed"; message: string };

export const RESTART_POLL_MS = 3000;
export const RESTART_GIVE_UP_MS = 180_000;

export function useFeatureSwitches(enabled = true) {
  const [load, setLoad] = useState<FeatureLoad>({ kind: "loading" });
  const [busy, setBusy] = useState<string | null>(null);
  const [rowError, setRowError] = useState<{ env: string; message: string } | null>(null);
  const [restart, setRestart] = useState<RestartState>({ kind: "idle" });

  const refresh = useCallback(async () => {
    try {
      const data = await api.platformFeatures();
      setLoad({ kind: "ready", data });
      return data;
    } catch (e) {
      const f = httpFailure(e);
      if (f?.status === 403) setLoad({ kind: "denied" });
      else setLoad({ kind: "error", message: operatorError(e, "Feature settings could not be read.") });
      return null;
    }
  }, []);

  useEffect(() => {
    if (enabled) void refresh();
  }, [enabled, refresh]);

  // While restarting: poll until the server answers with nothing pending.
  useEffect(() => {
    if (restart.kind !== "restarting") return;
    const id = setInterval(async () => {
      if (Date.now() - restart.since > RESTART_GIVE_UP_MS) {
        setRestart({ kind: "failed", message: "Correlix has not come back after three minutes. Check Stack Health." });
        return;
      }
      try {
        const data = await api.platformFeatures();
        setLoad({ kind: "ready", data });
        setRestart(data.restart_pending ? { kind: "failed", message: "Correlix restarted, but some settings are still waiting. Restart again or check Stack Health." } : { kind: "done" });
      } catch {
        /* still restarting */
      }
    }, RESTART_POLL_MS);
    return () => clearInterval(id);
  }, [restart]);

  /** Save one switch. `acknowledged` passes the confirmation a risky switch needs. */
  const save = useCallback(
    async (env: string, value: boolean, acknowledged: boolean) => {
      setBusy(env);
      setRowError(null);
      try {
        await api.setPlatformFeature(env, value, acknowledged ? env : undefined);
        await refresh();
      } catch (e) {
        // operatorError carries the server's own sentence (e.g. a step-up
        // refusal names what to do), never the raw HTTP envelope.
        setRowError({ env, message: operatorError(e, "The change was not saved.") });
      } finally {
        setBusy(null);
      }
    },
    [refresh],
  );

  const requestRestart = useCallback(async () => {
    try {
      await api.restartPlatform();
      setRestart({ kind: "restarting", since: Date.now() });
    } catch (e) {
      setRestart({ kind: "failed", message: operatorError(e, "The restart was not requested.") });
    }
  }, []);

  return { load, refresh, busy, rowError, save, restart, requestRestart };
}
