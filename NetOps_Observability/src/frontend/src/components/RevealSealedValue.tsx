import { useState } from "react";
import { api } from "../services/api";
import { Modal } from "./ui";

// RevealSealedValue — the operator-facing half of reversible masking.
//
// A sealed value renders as an opaque token wherever it appears. This component
// is the ONLY way to turn one back into plaintext, and it is deliberately built
// to feel like a deliberate act rather than a convenience:
//
//   - a justification is REQUIRED before the request is sent. The server records
//     it, and "who read a card number and why" is the question the audit trail
//     has to answer. Making it optional would make it absent exactly when it
//     matters.
//   - the revealed value is held in component state only, is never written to
//     the URL, and disappears when the dialog closes. There is no "keep it open"
//     mode and no clipboard-by-default.
//   - the reveal is not remembered. Closing and reopening asks the server again,
//     which means it audits again — an accurate count of how many times a secret
//     was actually looked at, not how many times a page was rendered.

export function isSealed(v: unknown): boolean {
  return typeof v === "string" && v.startsWith("<enc:") && v.endsWith(">");
}

type Props = {
  /** The sealed token as it appears in the record. */
  value: string;
  /** Optional narrowing hints when the caller knows which processor sealed it. */
  processorId?: string;
  field?: string;
  dataType?: string;
};

export default function RevealSealedValue({ value, processorId, field, dataType }: Props) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [revealed, setRevealed] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Reset everything on close: the plaintext must not survive the dialog.
  function close() {
    setOpen(false);
    setRevealed(null);
    setReason("");
    setError(null);
    setBusy(false);
  }

  async function submit() {
    if (!reason.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api.processorUnseal({
        value,
        reason: reason.trim(),
        processor_id: processorId,
        field,
        data_type: dataType,
      });
      setRevealed(res.value);
    } catch (e) {
      // Show the server's reason verbatim: it distinguishes "you may not" (403)
      // from "this value is damaged" (400) from "the key is gone forever" (410),
      // and an operator needs to tell those apart to know what to do next.
      setError(e instanceof Error ? e.message : "Could not reveal this value.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button
        type="button"
        className="ccw-btn ccw-btn-ghost ccw-btn-xs"
        onClick={() => setOpen(true)}
        title="This value is sealed. Revealing it is recorded."
      >
        🔒 Reveal
      </button>

      {open && (
        <Modal title="Reveal sealed value" onClose={close}>
          {revealed === null ? (
            <div className="ccw-stack">
              <p className="ccw-hint">
                This value was encrypted at ingest. Revealing it is recorded in the
                audit trail with your name, the time, and the reason you give below.
              </p>
              {(field || dataType) && (
                <p className="ccw-hint">
                  Field <code>{field ?? "—"}</code>
                  {dataType ? <> · type <code>{dataType}</code></> : null}
                </p>
              )}
              <label className="ccw-field">
                <span>Reason for access</span>
                <input
                  autoFocus
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder="e.g. PCI dispute #4471"
                  maxLength={512}
                />
              </label>
              {error && <p className="ccw-error">{error}</p>}
              <div className="ccw-row-end">
                <button type="button" className="ccw-btn" onClick={close}>
                  Cancel
                </button>
                <button
                  type="button"
                  className="ccw-btn ccw-btn-primary"
                  disabled={busy || !reason.trim()}
                  onClick={submit}
                >
                  {busy ? "Revealing…" : "Reveal"}
                </button>
              </div>
            </div>
          ) : (
            <div className="ccw-stack">
              <p className="ccw-hint">
                Revealed and recorded. This closes without keeping a copy.
              </p>
              {/* Escaped React text — never dangerouslySetInnerHTML. The value is
                  untrusted data that happens to have come from our own store. */}
              <pre className="ccw-code ccw-selectable">{revealed}</pre>
              <div className="ccw-row-end">
                <button type="button" className="ccw-btn ccw-btn-primary" onClick={close}>
                  Done
                </button>
              </div>
            </div>
          )}
        </Modal>
      )}
    </>
  );
}
