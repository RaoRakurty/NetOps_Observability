// useVerification — data hook for the Active Verification panel (RCA spec
// item 8). Loads the latest run for a case, polls while a run is in flight,
// and exposes the manual "Verify now" trigger. Honesty rules: a 404 (feature
// dormant, or the case is not visible to this tenant) makes the whole panel
// unavailable — we never guess at capability; server errors surface verbatim.
//
// A 404 and a 502 are NOT the same event. Treating both as "dormant" nulled the
// status, which made the poll guard (`status.run.status === "running"`) false
// forever — the loop never restarted and the panel silently vanished mid-run, so
// a transport blip looked like "this case has no verification". A transient
// failure now keeps the last known status, exposes `error`, and keeps polling.

import { useCallback, useEffect, useRef, useState } from "react";
import { api, type VerificationStatus } from "../../services/api";

const POLL_MS = 5000;

// The API client formats failures as "<status> <statusText>: <body>", so the code
// is readable off the message. Only a genuine 404 means "not available here".
function isNotFound(e: unknown): boolean {
  return /^\s*404\b/.test(String((e as Error)?.message ?? e));
}

export function useVerification(correlationId: string) {
  const [status, setStatus] = useState<VerificationStatus | null>(null);
  const [available, setAvailable] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  // A failed READ (not a 404). Distinct from `message`, which reports the outcome
  // of an operator-triggered run.
  const [error, setError] = useState("");
  const timer = useRef<number | undefined>(undefined);

  const load = useCallback(() => {
    if (!correlationId) return;
    api.verificationStatus(correlationId)
      .then((s) => { setStatus(s); setAvailable(true); setError(""); })
      .catch((e: unknown) => {
        if (isNotFound(e)) {
          // Dormant feature / case not visible to this tenant — a real answer.
          setStatus(null); setAvailable(false); setError("");
          return;
        }
        // Transient: keep whatever we last knew and say the read failed.
        setError(String((e as Error)?.message ?? e));
      });
  }, [correlationId]);

  useEffect(() => {
    setStatus(null); setAvailable(false); setMessage(""); setError("");
    load();
  }, [correlationId, load]);

  // Poll while a run is executing (bounded server-side by the run budget) AND
  // while a read is failing, so a transient error self-heals instead of parking
  // the panel in a dead state.
  useEffect(() => {
    if (status?.run?.status !== "running" && !error) return;
    timer.current = window.setInterval(load, POLL_MS);
    return () => window.clearInterval(timer.current);
  }, [status?.run?.status, error, load]);

  const trigger = useCallback(async () => {
    setBusy(true); setMessage("");
    try {
      await api.verificationRun(correlationId);
      setMessage("Verification started — interrogating the implicated devices…");
      window.setTimeout(load, 1200);
    } catch (e: unknown) {
      setMessage(String((e as Error)?.message ?? e));
    } finally {
      setBusy(false);
    }
  }, [correlationId, load]);

  return { status, available, busy, message, error, trigger, reload: load };
}
