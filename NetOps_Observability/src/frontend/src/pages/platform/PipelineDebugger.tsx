// PipelineDebugger.tsx — Administration → Platform → Tools → Pipeline Debugger.
//
// WHAT THIS SCREEN IS FOR. One record is sent through the stack's own ingress
// with a marker on it, and this page follows that marker hop by hop: the bus,
// the three stores, correlation and the product API, with an honest verdict per
// hop and the delay between the hops that saw it. When telemetry "is not
// showing up", this answers the only question that matters — the last hop that
// had it — instead of leaving an operator to grep ten containers.
//
// PLATFORM-ONLY, AND WHY (CLAUDE.md §3a rule 3). A trace reads one tenant's
// telemetry back out of the SHARED stores, a raised log level changes every
// tenant's service, and a module log file can contain a customer's own log
// line. Every route behind this page is requirePlatformAdmin on the server and
// audited there; the gate here is the same rule stated in the product, not the
// enforcement. A tenant or org admin holds full administration rights and still
// must not reach any of it.
//
// FOUR STATES, NEVER TWO. A hop is seen, not seen, not observable (with the
// reason), or still being waited on. The third is the one this screen exists to
// keep honest: two hops are collected on the HOST by the command-line tool, and
// rendering them as misses would send an operator after a hop that was fine.
//
// NOTHING FROM THE API IS EVER RENDERED AS MARKUP. Module log lines, stage
// reasons and evidence payloads are escaped React text (§15 LLM02's rule
// generalises: treat every payload as data, never as code).

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import "./pipelineDebugger.css";
import { api, type Device, type Tenant } from "../../services/api";
import {
  debugApi,
  isRouteAbsent,
  type DebugKind,
  type DebugModule,
  type DebugStageEntry,
  type LevelStatus,
  type ModuleLog,
  type ParseMarkerState,
  type SessionDetail,
  type SessionIndex,
  type TraceReceipt,
  type TraceStatus,
} from "../../services/api.debug";
import { useAuth } from "../../hooks/useAuth";
import Icon from "../../components/Icon";
import { operatorError } from "../../lib/errors";
import {
  bundleCommand,
  buildStageRows,
  formatBytes,
  formatLatency,
  formatWhen,
  logsCommand,
  maskNeedle,
  parseMarkerCommand,
  secondsUntil,
  sessionTally,
  stageLabel,
  stateLabel,
  stateTone,
  traceCommand,
  type StageRow,
  type Tone,
} from "./pipelineDebugger.model";

/** How often a running trace is re-read. */
const FOLLOW_INTERVAL_MS = 2000;

/**
 * The closed set of modules, and which of them actually have a runtime switch —
 * the same table the api dispatches on. It is only used when the api is too old
 * to report its own state: offering to raise a module that has no switch would
 * be a promise the request cannot keep.
 */
const ALL_MODULES: { module: DebugModule; switchable: boolean; reason?: string }[] = [
  { module: "api", switchable: true },
  { module: "correlation", switchable: true },
  { module: "vector", switchable: false, reason: "not runtime-switchable: it reads its level when it starts." },
  { module: "router", switchable: false, reason: "not runtime-switchable: it reads its level when it starts." },
  { module: "ingress", switchable: false, reason: "its level is applied when it starts, and restarting the ingest edge is not a debug action." },
];

/** The hard cap the api enforces, restated so the form cannot ask past it. */
const MAX_WINDOW_MINUTES = 30;

// ── small shared pieces ─────────────────────────────────────────────────────

function Pill({ tone, children }: { tone: Tone; children: ReactNode }) {
  return <span className={`pdbg-pill pdbg-${tone}`}>{children}</span>;
}

function Section({
  id,
  title,
  note,
  actions,
  children,
}: {
  id: string;
  title: string;
  note?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="pdbg-sec" data-section={id} role="region" aria-label={title}>
      <div className="pdbg-sec-hd">
        <h2>{title}</h2>
        {note && <span className="pdbg-sec-note">{note}</span>}
        <span className="pdbg-sp" />
        {actions}
      </div>
      <div className="pdbg-sec-bd">{children}</div>
    </section>
  );
}

function Honest({ tone, headline, detail }: { tone: Tone; headline: string; detail?: string }) {
  return (
    <div className={`pdbg-honest pdbg-${tone}`} role="note">
      <strong>{headline}</strong>
      {detail && <span>{detail}</span>}
    </div>
  );
}

function Loading({ what }: { what: string }) {
  return <div className="pdbg-loading">Reading {what}…</div>;
}

/** The command line that does the same thing, shown beside the action. */
function Cli({ children }: { children: string }) {
  return (
    <code className="pdbg-cli" aria-label="the same action from a terminal">
      {children}
    </code>
  );
}

type Panel<T> = { data: T | null; error: string | null; absent: boolean; loading: boolean };

const idlePanel = <T,>(): Panel<T> => ({ data: null, error: null, absent: false, loading: false });

/**
 * One independent read. `read` of null disables the panel entirely (a caller
 * who may not make the request does not make it), and an api that does not have
 * the route is recorded as ABSENT rather than as a failure — an older build is
 * a fact about the deployment, not something to retry.
 */
function usePanel<T>(read: (() => Promise<T>) | null, fallback: string): [Panel<T>, () => void] {
  const [state, setState] = useState<Panel<T>>(() => ({ data: null, error: null, absent: false, loading: !!read }));
  const readRef = useRef(read);
  readRef.current = read;
  const enabled = !!read;
  const reload = useCallback(() => {
    const fn = readRef.current;
    if (!fn) {
      setState(idlePanel<T>());
      return;
    }
    setState((p) => ({ ...p, loading: true }));
    fn()
      .then((data) => setState({ data, error: null, absent: false, loading: false }))
      .catch((e: unknown) =>
        setState({
          data: null,
          error: isRouteAbsent(e) ? null : operatorError(e, fallback),
          absent: isRouteAbsent(e),
          loading: false,
        }),
      );
    // `enabled` is the dependency that re-runs this once the caller is known to
    // be a platform operator; readRef keeps the identity of `read` out of it.
  }, [fallback, enabled]);
  useEffect(() => {
    reload();
  }, [reload]);
  return [state, reload];
}

// ── the stage table ─────────────────────────────────────────────────────────

function StageTable({
  rows,
  expanded,
  onToggle,
  evidence,
  caption,
}: {
  rows: StageRow[];
  expanded: string | null;
  onToggle: (stage: string) => void;
  evidence: (row: StageRow) => ReactNode;
  caption: string;
}) {
  return (
    <div className="pdbg-tblwrap">
      <table className="pdbg-tbl" aria-label={caption}>
        <thead>
          <tr>
            <th scope="col">#</th>
            <th scope="col">Hop</th>
            <th scope="col">Verdict</th>
            <th scope="col">From previous hop</th>
            <th scope="col">Evidence</th>
            <th scope="col"> </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const open = expanded === row.stage;
            return (
              <tr key={row.stage} data-stage={row.stage} data-state={row.state}>
                <td className="pdbg-num">{row.index}</td>
                <th scope="row">{row.label}</th>
                <td>
                  <Pill tone={stateTone(row.state)}>{stateLabel(row.state)}</Pill>
                </td>
                <td>{formatLatency(row.latencyMs)}</td>
                <td className="pdbg-reason">
                  {row.reason || row.query || "—"}
                  {open && <div className="pdbg-evidence">{evidence(row)}</div>}
                </td>
                <td>
                  <button type="button" className="pdbg-rowbtn" onClick={() => onToggle(row.stage)}>
                    {open ? "Hide" : "Read this hop"}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── the page ────────────────────────────────────────────────────────────────

export default function PipelineDebugger() {
  const { user, loading: authLoading } = useAuth();
  const platformAdmin = !!user?.platform_admin;
  const enabled = platformAdmin && !authLoading;

  // Is there a debugger in the running api at all? The parser-filter route is
  // the probe: it is the oldest member of the family, so an api that does not
  // have it does not have any of it.
  const [probe] = usePanel<ParseMarkerState>(enabled ? () => debugApi.parseMarker() : null, "The debugger state could not be read.");

  // ── form state ───────────────────────────────────────────────────────────
  const [kind, setKind] = useState<DebugKind>("syslog");
  const [device, setDevice] = useState("");
  const [tenant, setTenant] = useState("");
  const [ttlSeconds, setTtlSeconds] = useState(60);
  const [sinceMinutes, setSinceMinutes] = useState(10);
  const [pathFilter, setPathFilter] = useState("");
  const passive = kind === "gnmi";

  const [devices] = usePanel<Device[]>(enabled ? () => api.devices() : null, "Inventory did not answer.");
  const [tenants] = usePanel<Tenant[]>(enabled ? () => api.listTenants() : null, "The tenant list could not be read.");

  // ── the running trace ────────────────────────────────────────────────────
  const [receipt, setReceipt] = useState<TraceReceipt | null>(null);
  const [status, setStatus] = useState<TraceStatus | null>(null);
  const [traceError, setTraceError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [expandedStage, setExpandedStage] = useState<string | null>(null);
  const [stageEvidence, setStageEvidence] = useState<Record<string, DebugStageEntry | string>>({});

  // ── sessions ─────────────────────────────────────────────────────────────
  const [sessions, reloadSessions] = usePanel<SessionIndex>(
    enabled ? () => debugApi.sessions(50) : null,
    "The saved runs could not be read.",
  );
  const [openSession, setOpenSession] = useState<SessionDetail | null>(null);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [sessionStage, setSessionStage] = useState<string | null>(null);
  const [moduleLogs, setModuleLogs] = useState<Record<string, ModuleLog | string>>({});
  const [downloaded, setDownloaded] = useState<string | null>(null);

  // ── log levels ───────────────────────────────────────────────────────────
  const [levels, reloadLevels] = usePanel<LevelStatus>(
    enabled ? () => debugApi.levelStatus() : null,
    "The log levels could not be read.",
  );
  const [levelModules, setLevelModules] = useState<DebugModule[]>(["api"]);
  const [levelMinutes, setLevelMinutes] = useState(5);
  const [levelNote, setLevelNote] = useState<string | null>(null);
  const [levelError, setLevelError] = useState<string | null>(null);

  // ── the parser filter ────────────────────────────────────────────────────
  const [marker, reloadMarker] = usePanel<ParseMarkerState>(
    enabled ? () => debugApi.parseMarker() : null,
    "The parser filter state could not be read.",
  );
  const [needle, setNeedle] = useState("");
  const [needleMinutes, setNeedleMinutes] = useState(5);
  const [needleError, setNeedleError] = useState<string | null>(null);

  // A run is still going until a status says otherwise — INCLUDING the moment
  // before the first status arrives. Treating "no status yet" as finished would
  // draw every hop as "did not report", which is the opposite of the truth.
  const running = !!receipt && (!status || !status.done);

  // Follow the marker while the run is going. The api holds the result for a
  // bounded window after it finishes, so there is nothing to keep asking for
  // once `done` arrives.
  useEffect(() => {
    if (!receipt) return undefined;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = () => {
      debugApi
        .traceStatus(receipt.marker)
        .then((st) => {
          if (cancelled) return;
          setStatus(st);
          if (!st.done) {
            timer = setTimeout(tick, FOLLOW_INTERVAL_MS);
          } else {
            reloadSessions();
          }
        })
        .catch((e: unknown) => {
          if (!cancelled) setTraceError(operatorError(e, "The run could not be read."));
        });
    };
    tick();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [receipt, reloadSessions]);

  const rows = useMemo(() => buildStageRows(status?.stages ?? [], running), [status, running]);
  const sessionRows = useMemo(
    () => buildStageRows(openSession?.timeline?.entries ?? [], false),
    [openSession],
  );

  const startTrace = () => {
    setStarting(true);
    setTraceError(null);
    setStatus(null);
    setExpandedStage(null);
    setStageEvidence({});
    debugApi
      .startTrace({
        kind,
        device: device.trim(),
        tenant: tenant || undefined,
        ttl_seconds: ttlSeconds,
        passive,
        since_seconds: passive ? sinceMinutes * 60 : undefined,
        path: passive && pathFilter ? pathFilter : undefined,
        // The screen has no host-side collector, so the api writes the session
        // this run can be reopened and bundled from.
        persist: true,
      })
      .then((r) => {
        setReceipt(r);
        setStarting(false);
      })
      .catch((e: unknown) => {
        setStarting(false);
        setTraceError(operatorError(e, "The run could not be started."));
      });
  };

  const toggleStage = (stage: string) => {
    const next = expandedStage === stage ? null : stage;
    setExpandedStage(next);
    if (!next || !receipt || stageEvidence[stage] !== undefined) return;
    const row = rows.find((r) => r.stage === stage);
    if (!row?.readableHere) return;
    debugApi
      .stageEvidence(stage, { marker: receipt.marker, kind: receipt.kind, tenant: receipt.tenant, device: receipt.device })
      .then((entry) => setStageEvidence((prev) => ({ ...prev, [stage]: entry })))
      .catch((e: unknown) =>
        setStageEvidence((prev) => ({ ...prev, [stage]: operatorError(e, "That hop could not be read.") })),
      );
  };

  const openOne = (id: string) => {
    setSessionError(null);
    setSessionStage(null);
    setModuleLogs({});
    debugApi
      .session(id)
      .then(setOpenSession)
      .catch((e: unknown) => setSessionError(operatorError(e, "That saved run could not be read.")));
  };

  const readModule = (stage: string) => {
    const next = sessionStage === stage ? null : stage;
    setSessionStage(next);
    if (!next || !openSession || moduleLogs[stage] !== undefined) return;
    debugApi
      .sessionModule(openSession.session.id, stage)
      .then((log) => setModuleLogs((prev) => ({ ...prev, [stage]: log })))
      .catch((e: unknown) =>
        setModuleLogs((prev) => ({ ...prev, [stage]: operatorError(e, "That module file could not be read.") })),
      );
  };

  const download = (id: string) => {
    setSessionError(null);
    debugApi
      .downloadSessionBundle(id)
      .then((r) => setDownloaded(`${r.filename} · ${formatBytes(r.bytes)} · SHA-256 ${r.sha256.slice(0, 16)}…`))
      .catch((e: unknown) => setSessionError(operatorError(e, "The archive could not be downloaded.")));
  };

  const raiseLevels = (level: "debug" | "info") => {
    setLevelError(null);
    setLevelNote(null);
    const seconds = Math.min(levelMinutes, MAX_WINDOW_MINUTES) * 60;
    Promise.all(levelModules.map((m) => debugApi.setLevel({ module: m, level, for_seconds: seconds })))
      .then((changes) => {
        const refused = changes.filter((c) => !c.applied);
        setLevelNote(
          refused.length
            ? refused.map((c) => `${c.module}: ${c.reason ?? "no runtime switch"}`).join(" · ")
            : `${changes.length} module(s) at ${level}. Each one returns to its shipped level on its own.`,
        );
        reloadLevels();
      })
      .catch((e: unknown) => setLevelError(operatorError(e, "The level could not be changed.")));
  };

  const armMarker = () => {
    setNeedleError(null);
    debugApi
      .armParseMarker({ marker: needle.trim(), for_seconds: Math.min(needleMinutes, MAX_WINDOW_MINUTES) * 60 })
      .then(() => {
        setNeedle("");
        reloadMarker();
      })
      .catch((e: unknown) => setNeedleError(operatorError(e, "The parser filter could not be armed.")));
  };

  const disarmMarker = () => {
    setNeedleError(null);
    debugApi
      .disarmParseMarker()
      .then(() => reloadMarker())
      .catch((e: unknown) => setNeedleError(operatorError(e, "The parser filter could not be turned off.")));
  };

  // ── gating and the older-build state ─────────────────────────────────────

  if (!authLoading && !platformAdmin) {
    return (
      <div className="pdbg">
        <Honest
          tone="muted"
          headline="This is a platform operator tool."
          detail="A run reads one tenant's telemetry back out of the shared stores and a raised log level changes every tenant's service, so it is open to the platform operator only."
        />
      </div>
    );
  }

  if (probe.absent) {
    return (
      <div className="pdbg">
        <Honest
          tone="warn"
          headline="The running api does not carry the pipeline debugger."
          detail="Update the stack to a build that has it, or run correlix-debug on the host — the command-line tool works against this api as it is."
        />
      </div>
    );
  }

  const deviceList = devices.data ?? [];
  const tenantList = tenants.data ?? [];
  const levelRows = levels.data?.modules ?? [];
  const now = Date.now();

  return (
    <div className="pdbg">
      {/* ── 1. run a trace ─────────────────────────────────────────────── */}
      <Section
        id="trace"
        title="Follow one record"
        note="One marked record through the stack's own ingress — never to a device."
      >
        <div className="pdbg-form">
          <label className="pdbg-field">
            <span>Telemetry</span>
            <select className="pdbg-input" aria-label="Telemetry" value={kind} onChange={(e) => setKind(e.target.value as DebugKind)}>
              <option value="syslog">Syslog</option>
              <option value="trap">SNMP trap</option>
              <option value="flow">Flow</option>
              <option value="gnmi">gNMI (follow only)</option>
            </select>
          </label>
          <label className="pdbg-field">
            <span>Device</span>
            {deviceList.length ? (
              <select className="pdbg-input" aria-label="Device" value={device} onChange={(e) => setDevice(e.target.value)}>
                <option value="">Choose a device</option>
                {deviceList.map((d) => (
                  <option key={d.id} value={d.name || d.id}>
                    {d.name || d.id}
                  </option>
                ))}
              </select>
            ) : (
              <input
                className="pdbg-input"
                aria-label="Device"
                value={device}
                onChange={(e) => setDevice(e.target.value)}
                placeholder="device name"
              />
            )}
          </label>
          <label className="pdbg-field">
            <span>Tenant</span>
            <select className="pdbg-input" aria-label="Tenant" value={tenant} onChange={(e) => setTenant(e.target.value)}>
              <option value="">Every tenant this operator can read</option>
              {tenantList.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name || t.id}
                </option>
              ))}
            </select>
          </label>
          {passive ? (
            <>
              <label className="pdbg-field">
                <span>Look back (minutes)</span>
                <input
                  className="pdbg-input"
                  aria-label="Look back (minutes)"
                  type="number"
                  min={1}
                  max={1440}
                  value={sinceMinutes}
                  onChange={(e) => setSinceMinutes(Number(e.target.value) || 1)}
                />
              </label>
              <label className="pdbg-field">
                <span>Path (optional)</span>
                <input
                  className="pdbg-input"
                  aria-label="Path (optional)"
                  value={pathFilter}
                  onChange={(e) => setPathFilter(e.target.value)}
                />
              </label>
            </>
          ) : (
            <label className="pdbg-field">
              <span>Wait (seconds)</span>
              <input
                className="pdbg-input"
                aria-label="Wait (seconds)"
                type="number"
                min={5}
                max={300}
                value={ttlSeconds}
                onChange={(e) => setTtlSeconds(Number(e.target.value) || 60)}
              />
            </label>
          )}
        </div>

        {passive && (
          <Honest
            tone="muted"
            headline="A gNMI update starts on the device, so nothing is sent."
            detail="This follows real traffic for the device and window above. No device is ever written to."
          />
        )}

        <div className="pdbg-actions">
          <button type="button" className="btn sm accent" disabled={starting || !device.trim()} onClick={startTrace}>
            <Icon name="search" size={13} /> {passive ? "Follow real traffic" : "Send one record and follow it"}
          </button>
          {receipt && <span className="pdbg-mono">Marker {receipt.marker}</span>}
        </div>
        <Cli>
          {traceCommand({
            kind,
            device: device.trim() || "<device>",
            tenant: tenant || undefined,
            ttlSeconds,
            passive,
            sinceSeconds: sinceMinutes * 60,
            path: pathFilter,
          })}
        </Cli>

        {traceError && <Honest tone="bad" headline={traceError} detail="Nothing on this table is a statement about the pipeline until a run answers." />}

        {receipt && (
          <Honest
            tone={receipt.injected || receipt.passive ? "good" : "bad"}
            headline={
              receipt.passive
                ? "Following real traffic — nothing was sent."
                : receipt.injected
                  ? "One marked record was sent into the stack's own ingress."
                  : "The record could not be sent."
            }
            detail={
              receipt.inject_error ||
              receipt.session_note ||
              (receipt.session_id ? `Saved as ${receipt.session_id} when the run ends.` : undefined)
            }
          />
        )}

        {receipt && (
          <StageTable
            caption="Hops this record crossed"
            rows={rows}
            expanded={expandedStage}
            onToggle={toggleStage}
            evidence={(row) => {
              const got = stageEvidence[row.stage];
              if (typeof got === "string") return <span className="pdbg-reason">{got}</span>;
              const entry = got ?? (status?.stages ?? []).find((e) => e.stage === row.stage);
              if (!entry) {
                return (
                  <span className="pdbg-reason">
                    {row.readableHere ? "Reading…" : hostNote(row)}
                  </span>
                );
              }
              return (
                <>
                  {entry.query && <div className="pdbg-mono">{entry.query}</div>}
                  {entry.reason && <span className="pdbg-reason">{entry.reason}</span>}
                  <pre className="pdbg-pre">{JSON.stringify(entry.detail ?? {}, null, 2)}</pre>
                </>
              );
            }}
          />
        )}
        {receipt && running && <Loading what="the remaining hops" />}
      </Section>

      {/* ── 2. saved runs ───────────────────────────────────────────────── */}
      <Section
        id="sessions"
        title="Saved runs"
        note="Each run keeps one file per module, on the api, readable and downloadable."
        actions={
          <button type="button" className="btn sm" onClick={reloadSessions}>
            <Icon name="refresh" size={13} /> Read again
          </button>
        }
      >
        <Cli>{bundleCommand(openSession?.session.id)}</Cli>
        {sessions.absent ? (
          <Honest
            tone="warn"
            headline="The running api does not keep saved runs yet."
            detail="A newer api build stores each run on disk. Until then, run correlix-debug on the host — it writes the same files under data/debug/."
          />
        ) : sessions.error ? (
          <Honest tone="bad" headline={sessions.error} />
        ) : sessions.loading && !sessions.data ? (
          <Loading what="the saved runs" />
        ) : (sessions.data?.sessions.length ?? 0) === 0 ? (
          <Honest tone="muted" headline="Nothing has been saved here yet." detail={sessions.data?.reason} />
        ) : (
          <ul className="pdbg-sessions">
            {(sessions.data?.sessions ?? []).map((s) => (
              <li key={s.id} className={`pdbg-session${openSession?.session.id === s.id ? " on" : ""}`}>
                <span>
                  <span className="pdbg-session-id">{s.id}</span>
                  <br />
                  <span className="pdbg-session-meta">
                    {(s.kind ?? "—") + " · " + (s.device || "—") + " · " + (s.tenant || "every tenant") + " · " + formatWhen(s.started)}
                  </span>
                </span>
                <span className="pdbg-session-meta">{sessionTally(s)}</span>
                <span className="pdbg-actions">
                  <button type="button" className="btn sm" onClick={() => openOne(s.id)}>
                    Open
                  </button>
                  <button type="button" className="btn sm" onClick={() => download(s.id)}>
                    Download
                  </button>
                </span>
              </li>
            ))}
          </ul>
        )}

        {downloaded && <Honest tone="good" headline="Archive downloaded." detail={downloaded} />}
        {sessionError && <Honest tone="bad" headline={sessionError} />}

        {openSession && (
          <>
            <StageTable
              caption="Hops in this saved run"
              rows={sessionRows}
              expanded={sessionStage}
              onToggle={readModule}
              evidence={(row) => {
                const got = moduleLogs[row.stage];
                if (typeof got === "string") return <span className="pdbg-reason">{got}</span>;
                if (!got) return <span className="pdbg-reason">Reading…</span>;
                return (
                  <>
                    <span className="pdbg-reason">
                      {got.file} · {formatBytes(got.bytes)}
                      {got.truncated ? " · shortened" : ""}
                    </span>
                    {got.reason && <span className="pdbg-reason">{got.reason}</span>}
                    <ul className="pdbg-lines">
                      {got.lines.map((line, i) => (
                        <li key={`${row.stage}-${i}`}>{line}</li>
                      ))}
                    </ul>
                  </>
                );
              }}
            />
            {openSession.summary_text && <pre className="pdbg-pre">{openSession.summary_text}</pre>}
          </>
        )}
      </Section>

      {/* ── 3. log levels ───────────────────────────────────────────────── */}
      <Section
        id="levels"
        title="Log detail"
        note={`Raised for a bounded window — ${MAX_WINDOW_MINUTES} minutes at the very most, and every raise returns on its own.`}
        actions={
          <button type="button" className="btn sm" onClick={reloadLevels}>
            <Icon name="refresh" size={13} /> Read again
          </button>
        }
      >
        {levels.absent && (
          <Honest
            tone="warn"
            headline="The running api cannot report which modules are raised."
            detail="Raising and lowering still work here, and every raise still returns on its own inside the module that was raised."
          />
        )}
        {levels.error && <Honest tone="bad" headline={levels.error} />}
        <div className="pdbg-levels">
          {(levelRows.length ? levelRows : ALL_MODULES.map((m) => ({ ...m, source: "unknown" as const }))).map((m) => {
            const secs = "revert_at" in m ? secondsUntil(m.revert_at, now) : 0;
            const raised = "level" in m && m.level === "debug";
            return (
              <div className="pdbg-level" key={m.module}>
                <div className="pdbg-level-hd">
                  <input
                    type="checkbox"
                    aria-label={`Include ${m.module}`}
                    checked={levelModules.includes(m.module)}
                    disabled={!m.switchable}
                    onChange={(e) =>
                      setLevelModules((prev) =>
                        e.target.checked ? [...prev, m.module] : prev.filter((x) => x !== m.module),
                      )
                    }
                  />
                  <strong>{m.module}</strong>
                  <Pill tone={raised ? "warn" : "muted"}>
                    {raised ? "Full detail" : "level" in m && m.level ? "Normal" : "Not reported"}
                  </Pill>
                </div>
                {raised && secs > 0 && <span className="pdbg-session-meta">Returns to normal in {secs}s</span>}
                {"source" in m && m.source === "last-request" && (
                  <span className="pdbg-session-meta">Last change asked for from here, not a reading of that module.</span>
                )}
                {!m.switchable && <span className="pdbg-session-meta">{"reason" in m ? m.reason : ""}</span>}
              </div>
            );
          })}
        </div>
        <div className="pdbg-actions">
          <label className="pdbg-field">
            <span>Detail window (minutes)</span>
            <input
              className="pdbg-input"
              aria-label="Detail window (minutes)"
              type="number"
              min={1}
              max={MAX_WINDOW_MINUTES}
              value={levelMinutes}
              onChange={(e) => setLevelMinutes(Math.min(MAX_WINDOW_MINUTES, Number(e.target.value) || 1))}
            />
          </label>
          <button type="button" className="btn sm accent" disabled={!levelModules.length} onClick={() => raiseLevels("debug")}>
            Raise to full detail
          </button>
          <button type="button" className="btn sm" disabled={!levelModules.length} onClick={() => raiseLevels("info")}>
            Return to normal now
          </button>
        </div>
        <Cli>{logsCommand(levelModules, Math.min(levelMinutes, MAX_WINDOW_MINUTES) * 60)}</Cli>
        {levelNote && <Honest tone="muted" headline={levelNote} />}
        {levelError && <Honest tone="bad" headline={levelError} />}
      </Section>

      {/* ── 4. the parser filter ────────────────────────────────────────── */}
      <Section
        id="parsemarker"
        title="Parser decision trail"
        note="For a real, unmarked record: the parser records how it decided, for a bounded window."
      >
        {marker.error && <Honest tone="bad" headline={marker.error} />}
        {marker.loading && !marker.data ? (
          <Loading what="the parser filter" />
        ) : (
          <Honest
            tone={marker.data?.armed ? "warn" : "muted"}
            headline={marker.data?.armed ? `Armed on ${maskNeedle(marker.data.marker)}` : "Off."}
            detail={
              marker.data?.armed
                ? `Turns itself off in ${secondsUntil(marker.data.until, now)}s, inside the process that is tracing.`
                : marker.data?.reason
            }
          />
        )}
        <div className="pdbg-form">
          <label className="pdbg-field">
            <span>Text to match</span>
            <input
              className="pdbg-input"
              aria-label="Text to match"
              value={needle}
              onChange={(e) => setNeedle(e.target.value)}
            />
          </label>
          <label className="pdbg-field">
            <span>Filter window (minutes)</span>
            <input
              className="pdbg-input"
              aria-label="Filter window (minutes)"
              type="number"
              min={1}
              max={MAX_WINDOW_MINUTES}
              value={needleMinutes}
              onChange={(e) => setNeedleMinutes(Math.min(MAX_WINDOW_MINUTES, Number(e.target.value) || 1))}
            />
          </label>
        </div>
        <div className="pdbg-actions">
          <button type="button" className="btn sm accent" disabled={!needle.trim()} onClick={armMarker}>
            Arm
          </button>
          <button type="button" className="btn sm" onClick={disarmMarker}>
            Turn off
          </button>
        </div>
        <Cli>{parseMarkerCommand(Math.min(needleMinutes, MAX_WINDOW_MINUTES) * 60)}</Cli>
        {needleError && <Honest tone="bad" headline={needleError} />}
        <span className="pdbg-session-meta">
          What you arm is never shown back in full — only its first characters and its length.
        </span>
      </Section>
    </div>
  );
}

/** The note a hop this screen cannot reach carries inside its evidence block. */
function hostNote(row: StageRow): string {
  return row.reason || `${stageLabel(row.stage)} is collected on the host by correlix-debug.`;
}
