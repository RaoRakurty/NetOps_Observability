// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { parseTs } from "../lib/time";
import { startTransition, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { api, OSHit, ExportFmt, LogSampling, LogSearchOpts } from "../services/api";
import { severityLabel, severityRank, severityVar } from "../theme/severity";
import { LogTime, LogLevel, LogMessage } from "../lib/logfmt";
import {
  LogClause, LogEvent, LogSignal, TransitionGroup, addClause, buildFacets, groupTransitions, isIpLike, queryHasClause,
  removeClause, toLogEvent,
} from "../lib/logEvent";
import DataTable, { Column } from "../components/DataTable";
import EventDetailPanel from "../components/event/EventDetailPanel";
import EvIcon from "../components/event/EvIcon";
import {
  SEVERITY_GROUPS, SeverityGroup, SeverityTiles, fieldClause, optionsFrom, pager, severityGroupClause, tilesFrom, withClauses,
} from "../lib/logFilters";
import { humanize } from "../lib/eventModel";
import { SEVERITY_TONES } from "../theme/severity";
import { useAuth } from "../hooks/useAuth";
import {
  ROUTINE_TOGGLE_LABEL, RoutineSummary, loadShowRoutine, routineNote, saveShowRoutine,
} from "../lib/routineMgmt";

const EXPORT_FORMATS: { id: ExportFmt; label: string }[] = [
  { id: "csv", label: "CSV" },
  { id: "json", label: "JSON" },
  { id: "ndjson", label: "NDJSON" },
  { id: "xlsx", label: "Excel" },
];
const EXPORT_COLUMNS = ["time", "source", "level", "application", "message"];

// triggerDownload navigates to a signed export URL; the server's
// Content-Disposition: attachment makes the browser download (not navigate).
function triggerDownload(url: string) {
  const a = document.createElement("a");
  a.href = url;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
}

const RANGES: { label: string; minutes: number }[] = [
  { label: "Last 15m", minutes: 15 },
  { label: "Last 1h", minutes: 60 },
  { label: "Last 6h", minutes: 360 },
  { label: "Last 24h", minutes: 1440 },
];

type SignalId = "" | "applogs" | "syslog" | "snmptrap" | "flows" | "firewall";

// Sub-tabs (owner screenshot A): Events is every store, Logs is device syslog.
const SIGNALS: { id: SignalId; label: string }[] = [
  { id: "", label: "Events" },
  { id: "syslog", label: "Logs" },
  { id: "snmptrap", label: "Traps" },
  { id: "flows", label: "Flows" },
  { id: "firewall", label: "Firewall" },
  { id: "applogs", label: "App logs" },
];

// A type quick filter switches the Type control instead of adding a clause: the
// `signal` field is not mapped on the app-log index and holds "netflow" on flow
// documents, so a `signal:` clause would silently find nothing for those. The Type
// control picks the index itself, which is always the right answer. A type with no
// control here (cloud, unknown) is not offered as a filter.
const SIGNAL_CONTROL: Partial<Record<LogSignal, SignalId>> = {
  syslog: "syslog", trap: "snmptrap", flow: "flows", app: "applogs",
};

const STREAM_ROW_HEIGHT = 44;
const PHONE_ROW_HEIGHT = 92;
const PHONE_QUERY = "(max-width: 640px)";

// Rows are laid out by the table's own grid tracks, so a phone needs different
// columns rather than different CSS.
function useIsPhone(): boolean {
  return useSyncExternalStore(
    (notify) => {
      if (typeof window.matchMedia !== "function") return () => undefined;
      const mq = window.matchMedia(PHONE_QUERY);
      mq.addEventListener("change", notify);
      return () => mq.removeEventListener("change", notify);
    },
    () => typeof window.matchMedia === "function" && window.matchMedia(PHONE_QUERY).matches,
  );
}

// The title of a row. Addresses are set in mono; a flow's is nothing but addresses.
function RowTitle({ ev, group }: { ev: LogEvent; group?: TransitionGroup }) {
  const flow = ev.flow;
  const isTuple = flow && (flow.source.address || flow.destination.address) && ev.title.includes("→");
  return (
    <div className="lv-line lv-title-line">
      {isTuple
        ? <span className="lv-trunc lv-mono" title={ev.title}>{ev.title}</span>
        : <LogMessage text={ev.title} highlight="stream" />}
      {ev.lifecycle && <span className="lv-quiet-chip">{ev.lifecycle}</span>}
      {ev.chips.filter((c) => c.stream).map((c) => <span key={c.label} className="lv-quiet-chip">{c.label}</span>)}
      {group && (
        <span className="lv-quiet-chip" title={`One BGP transition, reported by ${group.count} traps on this page (${group.firstSeen} to ${group.lastSeen})`}>
          {group.count} reports
        </span>
      )}
    </div>
  );
}

function RowDetail({ ev }: { ev: LogEvent }) {
  if (!ev.detailLine) return null;
  return (
    <div className="lv-line lv-detail-line">
      {ev.flow
        ? <span className="lv-trunc lv-mono" title={ev.detailLine}>{ev.detailLine}</span>
        : <LogMessage text={ev.detailLine} highlight="stream" />}
    </div>
  );
}

function DeviceName({ label }: { label: string }) {
  if (!label) return <span className="lv-none">—</span>;
  return <span className={`lv-trunc lv-device${isIpLike(label) ? " lv-mono" : ""}`} title={label}>{label}</span>;
}

// Sample honesty (finder 2026-08-14): the flows signal reads netops-flows-*,
// which holds the router's 1-in-N OpenSearch sample (ClickHouse keeps the
// canonical, unsampled flow store — the Flows tab). Fallback rate when a
// response predates the backend's sampling metadata; MUST match the router's
// flows_os_sample rate and logs.go flowsOSSampleRate
// (tests/test_ingest_contract.py pins all of them together).
const FLOWS_OS_SAMPLE_RATE = 50;

// #81 — "Firewall (all vendors)" is a convenience filter over the syslog index:
// it narrows to records a firewall vendor parser produced (FortiGate .fgt,
// Palo Alto .pan, Versa .versa) or that carry the vendor-neutral app contract
// (.app_id). Vendor-agnostic by construction; new vendors slot in by adding their
// parsed namespace here. (The bare `vendor` field is on every device, so it can't
// mark "firewall" — the parsed namespace is the reliable signal.)
const FIREWALL_FILTER = "(_exists_:fgt OR _exists_:pan OR _exists_:versa OR _exists_:app_id)";

type Props = {
  // Supplied by the shell so the global omni-search and time-range govern
  // this view. When undefined the component works standalone.
  initialQuery?: string;
  rangeMinutes?: number;
  // Device/alert pivots set this so the drawer opens scoped to the device's own
  // syslog (signal=syslog + a host: field query), NOT a free-text all-signals
  // search that would also surface internal app-logs mentioning the device.
  initialSignal?: SignalId;
};

export default function Logs({ initialQuery, rangeMinutes, initialSignal }: Props = {}) {
  const [query, setQuery] = useState(initialQuery ?? "*");
  const [signal, setSignal] = useState<SignalId>(initialSignal ?? "");
  const [minutes, setMinutes] = useState(rangeMinutes ?? 15);
  const [size, setSize] = useState(200);
  const [hits, setHits] = useState<OSHit[]>([]);
  const [total, setTotal] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  // The exact request the current result set came from — a page change re-issues
  // it with an offset so every page belongs to the SAME window and query.
  const lastRun = useRef<LogSearchOpts | null>(null);
  const [page, setPage] = useState(1);
  // The dropdown filters. Each becomes a quoted clause AND-ed onto the query on the
  // server; `typePick`/`familyPick` hold "field\u0000value".
  const [sevGroup, setSevGroup] = useState<SeverityGroup | "">("");
  const [typePick, setTypePick] = useState("");
  const [familyPick, setFamilyPick] = useState("");
  // Severity counts across EVERY matching record, counted by the store.
  const [tiles, setTiles] = useState<SeverityTiles | null>(null);
  const filtersRef = useRef({ sevGroup, typePick, familyPick });
  filtersRef.current = { sevGroup, typePick, familyPick };
  // Sampling disclosure from the last search response (flows: 1:50 sample).
  const [sampling, setSampling] = useState<LogSampling | null>(null);
  // Routine management sessions (owner 2026-11-11): hidden unless the viewer
  // turns them on; the choice is remembered in this browser. The server decides
  // what is routine and says how many it left out.
  const [showRoutine, setShowRoutine] = useState<boolean>(() => loadShowRoutine());
  const showRoutineRef = useRef(showRoutine);
  showRoutineRef.current = showRoutine;
  const [routine, setRoutine] = useState<RoutineSummary | null>(null);
  const toggleRoutine = (show: boolean) => {
    saveShowRoutine(show);
    setShowRoutine(show);
  };
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [exporting, setExporting] = useState(false);
  const [exportMsg, setExportMsg] = useState<string | null>(null);
  const [detailId, setDetailId] = useState<string | null>(null);
  const [helpOpen, setHelpOpen] = useState(false);
  const isPhone = useIsPhone();
  // A quick filter can fire searches faster than they answer; only the latest may
  // fill the table.
  const runSeq = useRef(0);
  const { user } = useAuth();
  // "App logs" are the platform's own container/API logs — platform-owner only.
  // Tenant-scoped users don't see the option (the backend also refuses the signal).
  const platform = !!user?.platform_admin;
  const signals = useMemo(
    () => SIGNALS.filter((s) => s.id !== "applogs" || platform),
    [platform],
  );

  const run = async (q = query, m = minutes, sig = signal, sz = size, pg = 1) => {
    const seq = ++runSeq.current;
    setBusy(true);
    setError(null);
    try {
      const end = new Date();
      const start = new Date(end.getTime() - m * 60_000);
      const backendSignal = sig === "firewall" ? "syslog" : sig;
      const { all, withoutSeverity } = effectiveQueries(q, sig);
      const opts: LogSearchOpts = {
        query: all,
        from: start.toISOString(),
        to: end.toISOString(),
        size: sz,
        signal: backendSignal,
        include_routine_mgmt: showRoutineRef.current,
        ...(pg > 1 ? { offset: (pg - 1) * sz } : {}),
      };
      // The tiles count every match for the query without the severity pick, so a
      // tile still shows its siblings while one is selected. A count that fails
      // hides the tiles rather than guessing them from the loaded rows.
      api.logSeverityCounts({ query: withoutSeverity, signal: backendSignal, from: opts.from!, to: opts.to!, include_routine_mgmt: opts.include_routine_mgmt })
        .then((c) => { if (seq === runSeq.current) setTiles(tilesFrom(c)); })
        .catch(() => { if (seq === runSeq.current) setTiles(null); });
      const r = await api.searchLogs(opts);
      if (seq !== runSeq.current) return;
      lastRun.current = opts;
      setPage(pg);
      // A result set can be tens of thousands of rows; mapping and committing it
      // is the single most expensive thing this page does. As a transition it
      // yields to the operator's next keystroke or click instead of blocking it.
      startTransition(() => {
        setHits(r?.hits?.hits ?? []);
      });
      setTotal(r?.hits?.total?.value ?? null);
      // Sample honesty: trust the response's metadata; fall back to the known
      // rate so a flows result is NEVER presented as exact.
      setSampling(r?.sampling ?? (sig === "flows" ? { rate: FLOWS_OS_SAMPLE_RATE } : null));
      setRoutine(r?.routine_mgmt ?? null);
      setSelected(new Set()); // a new result set invalidates row indices
    } catch (e) {
      if (seq !== runSeq.current) return;
      setError((e as Error).message);
      setHits([]);
      setTotal(null);
      setSampling(null);
      setRoutine(null);
    } finally {
      if (seq === runSeq.current) setBusy(false);
    }
  };

  // The query as the server runs it: the operator's words, the Firewall narrowing,
  // then each dropdown as its own quoted clause.
  const effectiveQueries = (q: string, sig: SignalId) => {
    const base = sig === "firewall"
      ? (q && q.trim() && q.trim() !== "*" ? `(${q}) AND ${FIREWALL_FILTER}` : FIREWALL_FILTER)
      : q;
    const f = filtersRef.current;
    const pick = (v: string) => {
      const [field, value] = v.split("\u0000");
      return field && value ? fieldClause(field, value) : "";
    };
    const others = [pick(f.typePick), pick(f.familyPick)];
    const sev = f.sevGroup ? severityGroupClause(f.sevGroup, sig) : "";
    return { all: withClauses(base, [sev, ...others]), withoutSeverity: withClauses(base, others) };
  };

  // React to the global search query / time range: re-run with the
  // external query (also fires once on mount).
  useEffect(() => {
    const q = initialQuery ?? "*";
    const m = rangeMinutes ?? minutes;
    setQuery(q);
    setMinutes(m);
    run(q, m, signal, size);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialQuery, rangeMinutes]);

  // Local filter changes (signal/size) re-run with whatever's in the box,
  // without clobbering a query the user typed here. Skips the mount run.
  const mounted = useRef(false);
  useEffect(() => {
    if (!mounted.current) {
      mounted.current = true;
      return;
    }
    run(query, minutes, signal, size);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [signal, size, sevGroup, typePick, familyPick, showRoutine]);

  // A store that has no such field cannot keep a pick made on another store.
  useEffect(() => {
    setTypePick("");
    setFamilyPick("");
  }, [signal]);

  // Numbered pages through hits.total: each page re-issues the SAME request (query,
  // frozen window, filters) with an offset. OpenSearch pages only inside its
  // 10,000-row window; past it the export serves the full set, and the pager says so.
  const goPage = async (pg: number) => {
    const base = lastRun.current;
    if (!base) return;
    const seq = ++runSeq.current;
    setBusy(true);
    setError(null);
    try {
      const opts = { ...base, offset: pg > 1 ? (pg - 1) * (base.size ?? size) : undefined };
      const r = await api.searchLogs(opts);
      if (seq !== runSeq.current) return;
      lastRun.current = opts;
      startTransition(() => setHits(r?.hits?.hits ?? []));
      setTotal(r?.hits?.total?.value ?? total);
      if (r?.routine_mgmt) setRoutine(r.routine_mgmt);
      setPage(pg);
      setSelected(new Set());
    } catch (e) {
      if (seq === runSeq.current) setError((e as Error).message);
    } finally {
      if (seq === runSeq.current) setBusy(false);
    }
  };

  const saveSearch = async () => {
    const name = window.prompt("Name this saved search:", query === "*" ? "All logs" : query);
    if (!name) return;
    try {
      await api.createSaved("saved_search", name, { query, signal });
      window.alert(`Saved "${name}". Find it under Explore → Saved Searches.`);
    } catch (e) {
      window.alert(`Save failed: ${(e as Error).message}`);
    }
  };

  const lines = useMemo(() => {
    return hits.map((h, i) => {
      const ev = toLogEvent(h);
      const src = ev.raw; // the redacted copy; nothing below can reach a secret
      // The export columns keep their meaning: what follows is what a downloaded
      // row has always held. The on-screen row reads the presenter instead.
      const message = src.summary || src.message || src.msg || JSON.stringify(src);
      // Flow records enter via the collector's stdout, so they carry its
      // container name — show the flow's real source host (src_addr) instead.
      const flowHost = src.src_addr ? String(src.src_addr) : "";
      const source =
        flowHost || src.compose_service || src.container_name || src.hostname || src.appname || h._index;
      const level = src.level || src.severity || "";
      // Application name (#81): the firewall/router/cloud classifier's app label,
      // surfaced so app traffic reads as "Teams / Zoom / Dropbox" not a raw 5-tuple.
      // Vendor-neutral app_id first (the fusion contract), then FortiGate's nested
      // fgt.app, then a bare app field — "" when the record carries no app identity.
      const fgt = (src.fgt && typeof src.fgt === "object") ? (src.fgt as Record<string, unknown>) : {};
      const app = String(src.app_id || src.app || (fgt.app ?? "") || "");
      // Stable id so selection survives DataTable's internal sort (was index).
      const id = h._id || `${h._index}#${i}`;
      return { id, ts: ev.time, message: String(message), source: String(source), level: String(level), app, index: h._index, raw: src, resolved: h._resolved ?? null, matched: h.matched_queries, ev };
    });
  }, [hits]);
  // One BGP transition's reports fold into one row on the stream (tracker 387); the
  // selection, export and facets still read every loaded record.
  const streamLines = useMemo(() => groupTransitions(lines), [lines]);
  type Line = (typeof streamLines)[number];

  const allSelected = lines.length > 0 && selected.size === lines.length;
  const toggleRow = (id: string) =>
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  const toggleAll = () => setSelected(allSelected ? new Set() : new Set(lines.map((l) => l.id)));

  // Row body click (not the export checkbox) opens the Event Intelligence panel over
  // the list, in every shell and at every width (full screen on a phone). The panel
  // reads the same hit the row did, so the redaction and resolved names are shared.
  const selectLine = (l: Line) => setDetailId(l.id);
  const detailLine = detailId ? lines.find((l) => l.id === detailId) : undefined;

  // Mode A — render the selected (loaded) rows to a file via the server encoders.
  const exportSelected = async (format: ExportFmt) => {
    const rows = lines.filter((l) => selected.has(l.id)).map((l) => [l.ts, l.source, l.level, l.app, l.message]);
    if (rows.length === 0) return;
    setExporting(true);
    setExportMsg(null);
    try {
      await api.exportLogRows(format, EXPORT_COLUMNS, rows, "logs-selected");
    } catch (e) {
      setExportMsg((e as Error).message);
    } finally {
      setExporting(false);
    }
  };

  // Sample honesty: the flows signal serves a 1:N OpenSearch sample — every
  // count shown or exported for it is an estimate (multiply by N).
  const sampleRate = sampling?.rate ?? FLOWS_OS_SAMPLE_RATE;
  const flowsSampled = signal === "flows";
  const flowsExportNote = flowsSampled
    ? ` Flows are a 1:${sampleRate} sample — totals are estimates (×${sampleRate}).`
    : "";

  // Mode B — export the ENTIRE result set for the current query/time/signal.
  // Small sets download immediately; large sets queue and we poll for the link.
  const exportAll = async (format: ExportFmt) => {
    setExporting(true);
    setExportMsg(null);
    try {
      const end = new Date();
      const start = new Date(end.getTime() - minutes * 60_000);
      // The same query run() sends (Firewall narrowing and every dropdown filter), so
      // an export matches the on-screen view.
      const backendSignal = signal === "firewall" ? "syslog" : signal;
      const effQuery = effectiveQueries(query, signal).all;
      const { executionId, matched } = await api.exportLogQuery({
        format,
        query: effQuery,
        signal: backendSignal,
        from: start.toISOString(),
        to: end.toISOString(),
        // "Export all" holds what the page lists: the same routine choice.
        include_routine_mgmt: showRoutine,
      });
      if (!executionId) {
        setExportMsg(`Export downloaded.${flowsExportNote}`);
        return;
      }
      setExportMsg(`Large export (${matched ?? "?"} rows) queued — preparing…${flowsExportNote}`);
      for (let i = 0; i < 160; i++) {
        await new Promise((r) => setTimeout(r, 1500));
        const st = await api.exportStatus(executionId);
        if (st.status === "completed" && st.download_url) {
          triggerDownload(st.download_url);
          setExportMsg(`Export ready — downloaded.${flowsExportNote}`);
          return;
        }
        if (st.status === "failed") throw new Error(st.error || "The export could not be produced.");
      }
      setExportMsg("Export still running — check back shortly.");
    } catch (e) {
      setExportMsg((e as Error).message);
    } finally {
      setExporting(false);
    }
  };

  // Counted over the rows on screen only, and labelled that way on the page.
  const facets = useMemo(() => buildFacets(lines.map((l) => l.ev)), [lines]);
  const toggleClause = (c: LogClause) => {
    const next = queryHasClause(query, c) ? removeClause(query, c) : addClause(query, c);
    setQuery(next);
    run(next, minutes, signal, size);
  };
  const hasApp = useMemo(() => lines.some((l) => l.app), [lines]);

  // Dropdown options come from the loaded rows and say so; picking one narrows on
  // the server with a quoted clause over a field that store maps (event_type on
  // syslog and traps; family on traps, event_category on syslog).
  const pickOptions = (fieldsBySignal: (sig: string) => string[]) => {
    const vals: string[] = [];
    for (const l of lines) {
      const sig = l.ev.signal === "trap" ? "snmptrap" : l.ev.signal;
      for (const f of fieldsBySignal(sig)) {
        const v = typeof l.raw[f] === "string" ? l.raw[f].trim() : "";
        if (v) vals.push(`${f}\u0000${v}`);
      }
    }
    return optionsFrom(vals).map((o) => {
      const [, v] = o.value.split("\u0000");
      return { key: o.value, label: `${humanize(v)} · ${o.count.toLocaleString()} loaded` };
    });
  };
  const typeOptions = useMemo(
    () => pickOptions((sig) => (sig === "syslog" || sig === "snmptrap" ? ["event_type"] : [])),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [lines],
  );
  const familyOptions = useMemo(
    () => pickOptions((sig) => (sig === "snmptrap" ? ["family"] : sig === "syslog" ? ["event_category"] : [])),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [lines],
  );
  const pg = total !== null ? pager(total, lastRun.current?.size ?? size, page, lines.length) : null;

  const columns = useMemo<Column<Line>[]>(() => {
    const select: Column<Line> = {
      key: "sel", width: 42,
      header: <input type="checkbox" checked={allSelected} onChange={toggleAll} title="Select all rows in view" aria-label="Select all rows in view" />,
      render: (l) => (
        <input type="checkbox" checked={selected.has(l.id)} aria-label={`Select row: ${l.ev.title}`}
          onClick={(e) => e.stopPropagation()} onChange={() => toggleRow(l.id)} />
      ),
    };
    const sortTime = (l: Line) => parseTs(l.ts)?.getTime() || 0;
    if (isPhone) {
      return [select, {
        key: "ts", header: "Event", sortable: true, sortValue: sortTime,
        render: (l) => (
          <div className="lv-phone-cell">
            <div className="lv-phone-top">
              {l.ev.severity && <LogLevel level={l.ev.severity} />}
              <LogTime ts={l.ts} withDate={false} />
            </div>
            <RowTitle ev={l.ev} group={l.group} />
            <div className="lv-line lv-detail-line">
              <DeviceName label={l.ev.deviceLabel} />
              <span className="lv-signal">{l.ev.signalLabel}</span>
            </div>
            <RowDetail ev={l.ev} />
          </div>
        ),
      }];
    }
    return [
      select,
      {
        key: "ts", header: "Time", width: 124, sortable: true, sortValue: sortTime,
        render: (l) => <LogTime ts={l.ts} stacked />,
      },
      {
        key: "level", header: "Severity", width: 118, sortable: true,
        text: (l) => l.ev.severity ?? "",
        sortValue: (l) => (l.ev.severity ? severityRank(l.ev.severity) : 99),
        render: (l) => (l.ev.severity ? <LogLevel level={l.ev.severity} /> : <span className="lv-none">—</span>),
      },
      {
        key: "signal", header: "Type", width: 76, sortable: true, text: (l) => l.ev.signalLabel,
        render: (l) => <span className="lv-signal">{l.ev.signalLabel}</span>,
      },
      {
        key: "source", header: "Device", width: 184, sortable: true, text: (l) => l.ev.deviceLabel,
        render: (l) => (
          <div className="lv-two">
            <DeviceName label={l.ev.deviceLabel} />
            {l.ev.deviceAddress && <span className="lv-trunc lv-addr" title={l.ev.deviceAddress}>{l.ev.deviceAddress}</span>}
          </div>
        ),
      },
      // #81 — the identified application (firewall App-ID / NBAR2 / cloud), the
      // payoff of the fusion engine: app traffic named, not a raw 5-tuple. Only
      // there when a loaded row has one, so it does not hold a blank column open.
      ...(hasApp ? [{
        key: "app", header: "Application", width: 140, sortable: true, text: (l: Line) => l.app,
        render: (l: Line) => l.app
          ? <span className="lv-trunc lv-app" title={l.app}>{l.app.replace(/_/g, " · ")}</span>
          : <span className="lv-none">—</span>,
      }] : []),
      {
        key: "message", header: "Event", text: (l) => `${l.ev.title} ${l.ev.detailLine}`,
        render: (l) => (
          <div className="lv-two">
            <RowTitle ev={l.ev} group={l.group} />
            <RowDetail ev={l.ev} />
          </div>
        ),
      },
    ];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lines, selected, allSelected, isPhone, hasApp]);

  return (
    <div className="lv">
      <div className="card">
        <div className="lv-head">
          <h2 className="lv-title">Log search</h2>
          <button type="button" className="lv-help-btn" aria-label="Search examples" title="Search examples"
            aria-expanded={helpOpen} aria-controls="lv-help" onClick={() => setHelpOpen((o) => !o)}>
            ?
          </button>
        </div>
        {helpOpen && (
          <div className="lv-help" id="lv-help" data-testid="logs-search-help">
            <code>severity:err</code>
            <code>hostname:"edge-1"</code>
            <code>src_addr:10.0.0.5 AND dst_port:22</code>
          </div>
        )}
        <form className="xpl-bar" onSubmit={(e) => { e.preventDefault(); run(); }}>
          <input
            className="xpl-q lv-mono"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="*"
            aria-label="Search query"
          />
          <button className="btn-primary" disabled={busy} type="submit">
            {busy ? "Searching…" : "Search"}
          </button>
          <button className="btn-ghost" type="button" onClick={saveSearch} title="Save this search">
            ★ Save
          </button>
        </form>
        {tiles && (
          <div className="lv-tiles-wrap" data-testid="logs-severity-tiles">
            <div className="lv-tiles" role="group" aria-label="Severity across every matching record">
              {tiles.tiles.map((t) => {
                const on = sevGroup === t.id;
                return (
                  <button key={t.id} type="button" className={`lv-tile lv-tile-${t.tone}`} aria-pressed={on}
                    aria-label={`${t.label}: ${t.count.toLocaleString()} matching. ${on ? "Showing only these; press to show all" : "Press to show only these"}`}
                    onClick={() => setSevGroup(on ? "" : t.id)}>
                    <span className="lv-tile-ico" aria-hidden="true"><EvIcon name={SEVERITY_TONES[t.tone].icon} size={20} /></span>
                    <span className="lv-tile-txt">
                      <span className="lv-tile-n">{t.count.toLocaleString()}</span>
                      <span className="lv-tile-k">{t.label}</span>
                    </span>
                  </button>
                );
              })}
            </div>
            <p className="lv-tiles-note">
              Counted by the store across all {tiles.total.toLocaleString()} matching records
              {tiles.unrated > 0 && `; ${tiles.unrated.toLocaleString()} carry no severity`}
              {tiles.other > 0 && `; ${tiles.other.toLocaleString()} use other words`}
              {tiles.sampled && `; a 1:${sampleRate} sample`}.
            </p>
          </div>
        )}
        <div className="lv-subtabs" role="group" aria-label="Log type">
          {signals.map((o) => (
            <button key={o.id} type="button" className="lv-subtab" aria-pressed={signal === o.id} onClick={() => setSignal(o.id)}>
              {o.label}
              {signal === o.id && total !== null && <span className="lv-subtab-n" aria-hidden="true"> ({total.toLocaleString()})</span>}
            </button>
          ))}
        </div>
        <div className="lv-filters">
          {rangeMinutes === undefined && (
            <select value={minutes} aria-label="Time range" onChange={(e) => setMinutes(Number(e.target.value))}>
              {RANGES.map((r) => (
                <option key={r.minutes} value={r.minutes}>
                  {r.label}
                </option>
              ))}
            </select>
          )}
          <select value={sevGroup} aria-label="Severity" onChange={(e) => setSevGroup(e.target.value as SeverityGroup | "")}>
            <option value="">All Severities</option>
            {SEVERITY_GROUPS.map((g) => <option key={g.id} value={g.id}>{g.label}</option>)}
          </select>
          {typeOptions.length > 0 || typePick ? (
            <select value={typePick} aria-label="Event type" onChange={(e) => setTypePick(e.target.value)}>
              <option value="">All Types</option>
              {typeOptions.map((o) => <option key={o.key} value={o.key}>{o.label}</option>)}
            </select>
          ) : null}
          {familyOptions.length > 0 || familyPick ? (
            <select value={familyPick} aria-label="Family" onChange={(e) => setFamilyPick(e.target.value)}>
              <option value="">All Families</option>
              {familyOptions.map((o) => <option key={o.key} value={o.key}>{o.label}</option>)}
            </select>
          ) : null}
          <select value={size} aria-label="Rows per page" onChange={(e) => setSize(Number(e.target.value))}>
            {[10, 50, 100, 200, 500, 1000].map((n) => (
              <option key={n} value={n}>
                {n} per page
              </option>
            ))}
          </select>
        </div>
        {/* Routine management sessions (owner 2026-11-11). Flows have their own
            toggle on the Flows tab, so the control is not offered there. */}
        {signal !== "flows" && (
          <div className="lv-routine" data-testid="logs-routine">
            <label>
              <input type="checkbox" checked={showRoutine} onChange={(e) => toggleRoutine(e.target.checked)} />
              {ROUTINE_TOGGLE_LABEL}
            </label>
            {routine && <span className="lv-routine-note" data-testid="logs-routine-note">{routineNote(routine)}</span>}
          </div>
        )}
        {error && (
          <p className="lv-error">
            <strong>Error:</strong> {error}
          </p>
        )}
      </div>

      <div className="card">
        <div className="lv-results-head">
          <div className="lv-results-count">
            <h2 className="lv-results-title">Results</h2>
            <span className="fact-line">
              {total !== null && total > lines.length
                ? `${lines.length.toLocaleString()} of ${total.toLocaleString()} matched`
                : `${lines.length.toLocaleString()}${total !== null ? " · all matches" : ""}`}
            </span>
          </div>
          <div className="lv-actions">
            {selected.size > 0 && (
              <>
                <span className="lv-actions-label">{selected.size} selected →</span>
                {EXPORT_FORMATS.map((f) => (
                  <button key={f.id} type="button" className="chip" disabled={exporting} onClick={() => exportSelected(f.id)} title={`Export ${selected.size} selected rows as ${f.label}`}>
                    {f.label}
                  </button>
                ))}
                <button type="button" className="chip" onClick={() => setSelected(new Set())}>Clear</button>
                <span className="lv-sep">|</span>
              </>
            )}
            {lines.length > 0 && (
              <>
                <span className="lv-actions-label">
                  Export all{total !== null ? ` (${total})` : ""}:
                </span>
                {EXPORT_FORMATS.map((f) => (
                  <button key={`all-${f.id}`} type="button" className="chip" disabled={exporting} onClick={() => exportAll(f.id)} title={`Export the entire result set as ${f.label}`}>
                    {f.label}
                  </button>
                ))}
              </>
            )}
          </div>
        </div>
        {/* Sample honesty (owner directive: DON'T HIDE): the flows store is a
            1:N sample, so its "matched"/"total" figures are never exact. */}
        {flowsSampled && lines.length > 0 && (
          <p data-testid="flows-sampling-note" className="lv-flow-sample">
            Flow search reads a 1:{sampleRate} sample — totals are estimates (×{sampleRate}).
            Exact flow analytics live in the Flows tab (unsampled store).
          </p>
        )}
        {exportMsg && (
          <p className="lv-meta">
            {exporting ? "⏳ " : ""}
            {exportMsg}
          </p>
        )}
        {lines.length > 0 && (
          <div className="lv-facets" data-testid="logs-facets" role="group" aria-label="Quick filters over the loaded rows">
            <span className="lv-facets-label">In these {lines.length.toLocaleString()} loaded rows:</span>
            <span className="lv-facet-group">
            {facets.severity.map((f) => {
              const on = queryHasClause(query, f.clause);
              return (
                <button key={f.key} type="button" className="lv-facet" aria-pressed={on}
                  aria-label={`Filter by severity ${severityLabel(f.label)}, ${f.count} in the loaded rows`}
                  onClick={() => toggleClause(f.clause)}>
                  <span className="lv-facet-dot" style={{ background: severityVar(f.label) }} aria-hidden="true" />
                  <span className="lv-facet-name">{severityLabel(f.label)}</span>
                  <span className="lv-facet-n">{f.count.toLocaleString()}</span>
                </button>
              );
            })}
            </span>
            <span className="lv-facet-group">
            {signal === "" && facets.signal.map((f) => {
              const target = SIGNAL_CONTROL[f.signal];
              if (target === undefined || !signals.some((s) => s.id === target)) return null;
              return (
                <button key={f.key} type="button" className="lv-facet" aria-pressed={false}
                  aria-label={`Show only ${f.label}, ${f.count} in the loaded rows`}
                  onClick={() => setSignal(target)}>
                  <span className="lv-facet-name">{f.label}</span>
                  <span className="lv-facet-n">{f.count.toLocaleString()}</span>
                </button>
              );
            })}
            </span>
            <span className="lv-facet-group">
            {facets.device.map((f) => {
              const on = queryHasClause(query, f.clause);
              return (
                <button key={f.key} type="button" className="lv-facet" aria-pressed={on} title={f.label}
                  aria-label={`Filter by device ${f.label}, ${f.count} in the loaded rows`}
                  onClick={() => toggleClause(f.clause)}>
                  <span className={`lv-facet-name${isIpLike(f.label) ? " lv-mono" : ""}`}>{f.label}</span>
                  <span className="lv-facet-n">{f.count.toLocaleString()}</span>
                </button>
              );
            })}
            </span>
          </div>
        )}
        {lines.length === 0 ? (
          <div className="empty">
            {busy ? "Loading…" : "No results. Try widening the time range or relaxing the filter."}
          </div>
        ) : (
          <div className="lv-stream">
            <DataTable<Line>
              rows={streamLines}
              columns={columns}
              rowKey={(l) => l.id}
              height="60vh"
              rowHeight={isPhone ? PHONE_ROW_HEIGHT : STREAM_ROW_HEIGHT}
              ariaLabel="Log results"
              onRowClick={(l) => selectLine(l)}
              rowAccent={(l) => (l.ev.severity ? severityVar(l.ev.severity) : undefined)}
              rowClassName={(l) => (detailId === l.id ? "dtv-selected" : "")}
              rowSelected={(l) => detailId === l.id}
              empty="No results."
            />
          </div>
        )}
        {/* Every truncated list SAYS it's truncated and offers the rest. */}
        {/* Numbered pages over the exact total. Every truncated list SAYS so. */}
        {pg && pg.total > 0 && lines.length > 0 && (
          <nav className="lv-pager" aria-label="Result pages">
            <span className="lv-pager-txt" data-testid="logs-pager-text">
              Showing {pg.first.toLocaleString()}–{pg.last.toLocaleString()} of {pg.total.toLocaleString()} {pg.total === 1 ? "event" : "events"}
              {flowsSampled && " (sampled)"}
            </span>
            {pg.pages > 1 && (
              <span className="lv-pages">
                <button type="button" className="lv-page" disabled={busy || pg.page <= 1} aria-label="Previous page" onClick={() => goPage(pg.page - 1)}>‹</button>
                {pg.items.map((n, i) => (n === null
                  ? <span key={`gap${i}`} className="lv-page-gap" aria-hidden="true">…</span>
                  : (
                    <button key={n} type="button" className="lv-page" aria-current={n === pg.page ? "page" : undefined}
                      aria-label={`Page ${n}`} disabled={busy && n !== pg.page} onClick={() => n !== pg.page && goPage(n)}>
                      {n.toLocaleString()}
                    </button>
                  )))}
                <button type="button" className="lv-page" disabled={busy || pg.page >= pg.pages} aria-label="Next page" onClick={() => goPage(pg.page + 1)}>›</button>
              </span>
            )}
          </nav>
        )}
        {pg?.capped && lines.length > 0 && (
          <p className="lv-meta lv-center">
            Pages reach the first {(10000).toLocaleString()} records — use “Export all” above to get the
            full {pg.total.toLocaleString()}-record result set.
          </p>
        )}
        {detailLine && (
          <EventDetailPanel
            key={detailLine.id}
            hit={{ _index: detailLine.index, _id: detailLine.id, _source: detailLine.raw, _resolved: detailLine.resolved, matched_queries: detailLine.matched }}
            onClose={() => setDetailId(null)}
          />
        )}
      </div>
    </div>
  );
}
