import { useCallback, useEffect, useState } from "react";
import { fmtDateTime } from "../lib/time";
import { api, AuditEvent } from "../services/api";
import DataTable, { Column } from "../components/DataTable";
import { Chip } from "../components/noc";
import AskIris from "../components/AskIris";
import { operatorError } from "../lib/errors";
// Sensitive Data Access — who revealed protected data, when, and why.
//
// This is the counterpart to the reveal endpoint: auditing a reveal is only
// worth something if someone can read the result back. It is the page a
// compliance reviewer opens, so two properties matter more than any feature:
//
//  1. It shows REFUSALS as well as successes. A denied attempt is the more
//     interesting record — it is the one that suggests someone tried.
//  2. It NEVER shows a revealed value. The server does not record plaintext, so
//     there is none to render; this page has no code path that could.
//
// The filtering is done SERVER-side. A client-side filter over a capped page
// would render an empty table whenever reveals sit below the newest audit rows —
// and a compliance surface that reports "nobody read anything" when someone did
// is the single failure this page must never have.

type Row = AuditEvent & {
  detail?: {
    outcome?: string;
    reason?: string;
    data_type?: string;
    field?: string;
    key_version?: number;
    value_tenant?: string;
    token_preview?: string;
  };
};

const OUTCOME_TONE: Record<string, "ok" | "warn" | "bad"> = {
  granted: "ok",
  unreadable: "warn",
  key_unavailable: "warn",
  denied_cross_tenant: "bad",
};

const OUTCOME_LABEL: Record<string, string> = {
  granted: "Revealed",
  unreadable: "Failed integrity",
  key_unavailable: "Key retired",
  denied_cross_tenant: "Refused — other tenant",
};

// Rotating the sealing key is a one-way, tenant-wide act: everything sealed from
// here on names a new key version. So the control is deliberately two-step — the
// first click only ARMS it — and it reports back the version it landed on rather
// than a green tick, because "it worked" is not the fact an operator needs. The
// endpoint's own honesty note travels with the result: the router still holds the
// previous key until it reloads its config. Values sealed under earlier versions
// stay readable; retiring one is a separate, deliberate act.
function SealingKeyCard() {
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [version, setVersion] = useState<number | null>(null);
  const [note, setNote] = useState<string>("");
  const [error, setError] = useState<string | null>(null);

  const rotate = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await api.sealRotate();
      setVersion(r.key_version ?? null);
      setNote(r.note ?? "");
      setArmed(false);
    } catch (e) {
      setError(operatorError(e, "Could not rotate the sealing key."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="ccw-panel">
      <div className="ccw-panel-h">
        Sealing key
        <AskIris topic="seal.key-rotation" label="Sealing key" />
      </div>
      {!armed ? (
        <div>
          <button type="button" className="btn" onClick={() => setArmed(true)} disabled={busy}>
            Rotate
          </button>
        </div>
      ) : (
        <div className="ccw-copyline">
          <button type="button" className="btn btn-accent" onClick={() => void rotate()} disabled={busy}>
            {busy ? "Rotating…" : "Confirm rotate"}
          </button>
          <button type="button" className="btn" onClick={() => setArmed(false)} disabled={busy}>
            Cancel
          </button>
        </div>
      )}
      {version !== null && (
        <p className="ccw-hint">
          Now on <strong>v{version}</strong>. {note}
        </p>
      )}
      {error && (
        <div className="ccw-error" role="alert">
          {error}
        </div>
      )}
    </section>
  );
}

export default function SensitiveDataAccess() {
  const [rows, setRows] = useState<Row[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const events = await api.sealAccessAudit(200);
      setRows(events as Row[]);
    } catch (e) {
      // An ERROR is not an empty trail. Rendering a failed fetch as "no access
      // recorded" would be the most dangerous lie this page could tell.
      setRows(null);
      setError(operatorError(e, "Could not load the access trail."));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const columns: Column<Row>[] = [
    {
      key: "time", header: "When",
      render: (r) => fmtDateTime(r.time),
    },
    {
      key: "actor", header: "Who",
      render: (r) => r.actor || "—",
    },
    {
      key: "outcome", header: "Outcome",
      render: (r) => {
        const o = r.detail?.outcome ?? (r.decision === "allow" ? "granted" : "denied");
        return <Chip tone={OUTCOME_TONE[o] ?? "warn"} label={OUTCOME_LABEL[o] ?? o} />;
      },
    },
    {
      key: "what", header: "What",
      render: (r) =>
        r.detail?.data_type || r.detail?.field
          ? `${r.detail?.data_type ?? "—"}${r.detail?.field ? ` · ${r.detail.field}` : ""}`
          : "—",
    },
    {
      key: "reason", header: "Stated reason",
      render: (r) => r.detail?.reason || <span className="ccw-muted">— none given —</span>,
    },
    {
      key: "value", header: "Value",
      // A short hash of the CIPHERTEXT, so repeated reveals of the same value
      // are correlatable without the trail storing the value itself.
      render: (r) => (r.detail?.token_preview ? <code>{r.detail.token_preview}</code> : "—"),
    },
    {
      key: "key", header: "Key",
      render: (r) => (r.detail?.key_version ? `v${r.detail.key_version}` : "—"),
    },
  ];

  return (
    <div className="ccw-stack">
      <header className="ccw-page-head">
        <h2>Sensitive Data Access</h2>
        <p className="ccw-hint">
          Every attempt to reveal a sealed value — successful or refused. Revealed
          values are never recorded here, only the fact of the access.
        </p>
      </header>

      <SealingKeyCard />

      {error && (
        <div className="ccw-error" role="alert">
          {error} — this is a load failure, <strong>not</strong> an empty access trail.
          <button type="button" className="ccw-btn ccw-btn-xs" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}

      {!error && rows !== null && rows.length === 0 && (
        <p className="ccw-muted">
          No reveal attempts recorded. Sealed values have not been accessed.
        </p>
      )}

      {rows !== null && rows.length > 0 && (
        <DataTable<Row> rows={rows} columns={columns} rowKey={(r) => r.id} />
      )}
    </div>
  );
}
