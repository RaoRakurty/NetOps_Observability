// useVerification — data hook for the Active Verification panel (RCA spec
// item 8). Loads the latest run for a case, polls while a run is in flight,
// and exposes the manual "Verify now" trigger. Honesty rules: a 404 (feature
// dormant, or the case is not visible to this tenant) makes the whole panel
// unavailable — we never guess at capability; server errors surface verbatim.

import { useCallback, useEffect, useRef, useState } from "react";
import { api, type VerificationStatus } from "../../services/api";

const POLL_MS = 5000;

export function useVerification(correlationId: string) {
  const [status, setStatus] = useState<VerificationStatus | null>(null);
  const [available, setAvailable] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const timer = useRef<number | undefined>(undefined);

  const load = useCallback(() => {
    if (!correlationId) return;
    api.verificationStatus(correlationId)
      .then((s) => { setStatus(s); setAvailable(true); })
      .catch(() => { setStatus(null); setAvailable(false); });
  }, [correlationId]);

  useEffect(() => {
    setStatus(null); setAvailable(false); setMessage("");
    load();
  }, [correlationId, load]);

  // Poll only while a run is executing (bounded server-side by the run budget).
  useEffect(() => {
    if (status?.run?.status !== "running") return;
    timer.current = window.setInterval(load, POLL_MS);
    return () => window.clearInterval(timer.current);
  }, [status?.run?.status, load]);

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

  return { status, available, busy, message, trigger, reload: load };
}
