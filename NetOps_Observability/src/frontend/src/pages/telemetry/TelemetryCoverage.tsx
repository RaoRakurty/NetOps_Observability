// Telemetry coverage (Administration → Data Collection) — parser programme A6.
//
// Two honest questions, answered side by side:
//   1. "What does the parser actually recognize?"  — the platform-wide rule
//      inventory, its evidence fidelity, and how much of the admitted stream is
//      promoted to semantics. Platform-admin only; a tenant admin gets a
//      "platform-admin only" card here, NOT an error (§3a: pick the right gate,
//      and a legitimate 403 is an answer, not a failure).
//   2. "What is my network saying that we do NOT understand yet?" — the
//      tenant's unrecognized message shapes, mined into masked templates, with
//      a one-click DRAFT catalog row per shape.
//
// Security posture (§15 LLM02 / §3 zero trust): every string on this page comes
// from devices or the backend and is rendered as ESCAPED React text. React's
// raw-HTML escape hatch, the DOM raw-HTML setter and dynamic evaluation are all
// absent from this file by design (a test asserts it) — the drafted YAML is
// displayed in a read-only <pre><code> block and copied to the clipboard; the
// UI never applies it. Landing a row is a human pull request.

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  api,
  type CatalogProposal,
  type ParserRuleStat,
  type ParserStats,
  type UnrecognizedItem,
  type UnrecognizedPage,
} from "../../services/api";
import FidelityBadge from "../../components/FidelityBadge";
import DataTable, { type Column } from "../../components/DataTable";
import { Segmented, Stat, StatStrip } from "../../components/ui";
import { useWorkspace } from "../../context/workspace";
import { fmtDateTime } from "../../lib/time";
import {
  CATALOG_DOCS_URL,
  fidelityRank,
  isForbidden,
  promotionDisplay,
  ruleRows,
  ruleSummary,
  severityBadgeClass,
  severityLabel,
  unrecognizedItems,
  unrecognizedNote,
} from "./coverageModel";

const DAYS = 7;
const LIMIT = 50;

type LaneChoice = "all" | "syslog" | "trap";

// ── small chrome (mirrors the other Administration surfaces) ────────────────

function AdminHead({ title, sub }: { title: string; sub: string }) {
  return (
    <div className="admin-head">
      <h2 style={{ margin: 0, fontSize: "var(--fs-lg)" }}>{title}</h2>
      <p className="admin-sub">{sub}</p>
    </div>
  );
}

function ErrLine({ msg }: { msg: string | null }) {
  if (!msg) return null;
  return (
    <p role="alert" style={{ color: "var(--bad)", fontSize: "var(--fs-meta)", margin: "0 0 var(--sp-2)" }}>{msg}</p>
  );
}

// Read-only code block with a copy button. `content` is rendered as text inside
// <pre><code> — never parsed as markup.
function CodeBlock({ title, content }: { title: string; content: string }) {
  const [done, setDone] = useState(false);
  const copy = () => {
    try {
      void navigator.clipboard?.writeText(content);
      setDone(true);
      setTimeout(() => setDone(false), 1400);
    } catch { /* clipboard unavailable — the text is selectable regardless */ }
  };
  return (
    <div className="ccw-code" style={{ marginBottom: "var(--sp-3)" }}>
      <div className="ccw-code-h">
        <span>{title}</span>
        <button type="button" className="btn ccw-copy" onClick={copy} aria-label={`Copy ${title}`}>
          {done ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="ccw-pre"><code>{content}</code></pre>
    </div>
  );
}

// The Inspector body for a drafted proposal. Exported so the page can also
// render it inline when the workspace shell (and therefore the docked
// Inspector) is disabled — the draft is never shown in a way that hides it.
export function ProposalBody({ proposal, template }: { proposal: CatalogProposal; template: string }) {
  return (
    <div>
      <p className="mini-meta" style={{ marginTop: 0 }}>
        Proposal <span className="mono">{proposal.proposal_id}</span> · status {proposal.status}
      </p>
      <p className="mini-meta">
        Drafted deterministically from the template <span className="mono">{template}</span>. Nothing has been
        applied: review the row, then land it through a pull request.
      </p>
      <CodeBlock title="Draft catalog row (YAML)" content={proposal.catalog_row} />
      <CodeBlock title="Fixture" content={proposal.fixture} />
      <p className="mini-meta">
        <a href={CATALOG_DOCS_URL} target="_blank" rel="noreferrer">
          How to land a catalog row via a pull request →
        </a>
      </p>
    </div>
  );
}

// ── parser stats half ───────────────────────────────────────────────────────

function ParserStatsSection({ stats, err, loaded }: { stats: ParserStats | null; err: string | null; loaded: boolean }) {
  const [filter, setFilter] = useState("");

  const columns = useMemo<Column<ParserRuleStat>[]>(() => [
    {
      key: "rule_id", header: "Rule", sortable: true, text: (r) => r.rule_id,
      render: (r) => <span className="mono">{r.rule_id}</span>,
    },
    { key: "lane", header: "Lane", width: 90, sortable: true, text: (r) => r.lane, render: (r) => r.lane },
    { key: "kind", header: "Kind", width: 160, sortable: true, text: (r) => r.kind, render: (r) => r.kind || "—" },
    {
      key: "fidelity", header: "Fidelity", width: 140, sortable: true,
      text: (r) => r.fidelity, sortValue: (r) => fidelityRank(r.fidelity),
      render: (r) => <FidelityBadge fidelity={r.fidelity} />,
    },
    {
      key: "hits", header: "Hits", width: 100, align: "right", sortable: true,
      text: (r) => String(r.hits), sortValue: (r) => r.hits,
      render: (r) => <span className="mono">{r.hits.toLocaleString("en-US")}</span>,
    },
    {
      key: "shadow", header: "Shadow", width: 100, sortable: true,
      text: (r) => (r.shadow ? "shadow" : ""), sortValue: (r) => (r.shadow ? 1 : 0),
      render: (r) => (r.shadow
        ? <span className="badge warn" title="Matches but does not promote — evaluation only">shadow</span>
        : <span className="mini-meta">—</span>),
    },
  ], []);

  if (err && isForbidden(err)) {
    return (
      <div className="card">
        <h3 style={{ margin: "0 0 var(--sp-2)" }}>Parser coverage — platform-admin only</h3>
        <p className="admin-sub" style={{ margin: 0 }}>
          Parser revision, rule inventory and promotion rate are platform-global plumbing shared by every
          tenant, so they are visible to platform administrators only. Your own unrecognized message shapes
          are below and need no platform access.
        </p>
      </div>
    );
  }
  if (err) return <ErrLine msg={err} />;
  if (!loaded) return <div className="empty" role="status">Loading parser coverage…</div>;
  if (!stats) return <div className="empty">Parser coverage is unavailable.</div>;

  const rows = ruleRows(stats);
  const summary = ruleSummary(rows);
  const promo = promotionDisplay(stats);

  return (
    <>
      <div className="ds-toolbar">
        <span className="mini-meta">
          parser rev <span className="mono">{stats.parser_rev}</span>
          {" · "}rules hash <span className="mono">{stats.rules_hash}</span>
          {" · "}generated {fmtDateTime(stats.generated_at)}
        </span>
      </div>

      <div className="card" style={{ display: "flex", alignItems: "baseline", gap: "var(--sp-4)", flexWrap: "wrap" }}>
        <div>
          <div className="ds-stat-num mono" style={{ fontSize: 34 }}>{promo.value}</div>
          <div className="admin-sub" style={{ margin: "4px 0 0" }}>{promo.caption}</div>
        </div>
        <h3 style={{ margin: 0 }}>Semantic promotion rate</h3>
      </div>

      <StatStrip>
        <Stat label="Prefilter passed" value={stats.prefilter.passed.toLocaleString("en-US")} />
        <Stat label="Prefilter rejected" value={stats.prefilter.rejected.toLocaleString("en-US")} tone={stats.prefilter.rejected > 0 ? "warn" : ""} />
        <Stat label="Generic fallback (syslog)" value={stats.generic_fallback.syslog.toLocaleString("en-US")} tone={stats.generic_fallback.syslog > 0 ? "warn" : ""} />
        <Stat label="Generic fallback (trap)" value={stats.generic_fallback.trap.toLocaleString("en-US")} tone={stats.generic_fallback.trap > 0 ? "warn" : ""} />
        <Stat label="Rules" value={summary.total} />
        <Stat label="Validated rules" value={summary.validated} tone="good" />
        <Stat label="Shadow rules" value={summary.shadow} tone={summary.shadow > 0 ? "accent" : ""} />
      </StatStrip>

      <div className="ds-toolbar">
        <label className="mini-meta" htmlFor="tc-rule-filter">Filter rules</label>
        <input
          id="tc-rule-filter"
          className="input"
          style={{ width: 260 }}
          placeholder="rule id, lane, kind, fidelity…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <span className="mini-meta" role="status" aria-live="polite">{summary.total} rules registered</span>
      </div>

      <div className="card" style={{ paddingTop: 8 }}>
        <DataTable
          rows={rows}
          columns={columns}
          rowKey={(r) => r.rule_id}
          filter={filter}
          initialSort={{ key: "hits", dir: "desc" }}
          height={360}
          ariaLabel="Parser rules"
          empty={<div className="empty">No parser rules are registered — nothing is being promoted to semantics.</div>}
        />
      </div>
    </>
  );
}

// ── the page ────────────────────────────────────────────────────────────────

export default function TelemetryCoverage() {
  const ws = useWorkspace();

  const [stats, setStats] = useState<ParserStats | null>(null);
  const [statsErr, setStatsErr] = useState<string | null>(null);
  const [statsLoaded, setStatsLoaded] = useState(false);

  const [lane, setLane] = useState<LaneChoice>("all");
  const [page, setPage] = useState<UnrecognizedPage | null>(null);
  const [pageErr, setPageErr] = useState<string | null>(null);
  const [pageLoaded, setPageLoaded] = useState(false);

  const [proposal, setProposal] = useState<{ p: CatalogProposal; template: string } | null>(null);
  const [proposeErr, setProposeErr] = useState<string | null>(null);
  const [drafting, setDrafting] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    api.parserStats()
      .then((s) => { if (alive) { setStats(s); setStatsErr(null); } })
      .catch((e: Error) => { if (alive) setStatsErr(e.message); })
      .finally(() => { if (alive) setStatsLoaded(true); });
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    let alive = true;
    setPageLoaded(false);
    api.unrecognizedTemplates({ days: DAYS, limit: LIMIT, ...(lane === "all" ? {} : { lane }) })
      .then((p) => { if (alive) { setPage(p); setPageErr(null); } })
      .catch((e: Error) => { if (alive) { setPage(null); setPageErr(e.message); } })
      .finally(() => { if (alive) setPageLoaded(true); });
    return () => { alive = false; };
  }, [lane]);

  const draft = useCallback(async (item: UnrecognizedItem) => {
    setDrafting(item.template_id);
    setProposeErr(null);
    try {
      const p = await api.proposeCatalogRow(item.template_id);
      setProposal({ p, template: item.template });
      if (ws.enabled) {
        ws.openInspector(<ProposalBody proposal={p} template={item.template} />, {
          title: "Draft catalog row",
          subtitle: item.template_id,
        });
      }
    } catch (e) {
      setProposeErr((e as Error).message);
    } finally {
      setDrafting(null);
    }
  }, [ws]);

  const items = unrecognizedItems(page);

  const columns = useMemo<Column<UnrecognizedItem>[]>(() => [
    {
      key: "template", header: "Template", sortable: true, text: (i) => i.template,
      // Escaped text in a mono cell — the wildcards are literal <*> characters,
      // never markup.
      render: (i) => <span className="mono" title={i.template}>{i.template}</span>,
    },
    {
      key: "count", header: "Count", width: 90, align: "right", sortable: true,
      text: (i) => String(i.count), sortValue: (i) => i.count,
      render: (i) => <span className="mono">{i.count.toLocaleString("en-US")}</span>,
    },
    {
      key: "devices", header: "Devices", width: 90, align: "right", sortable: true,
      text: (i) => String(i.devices), sortValue: (i) => i.devices,
      render: (i) => <span className="mono">{i.devices.toLocaleString("en-US")}</span>,
    },
    {
      key: "severity", header: "Max severity", width: 130, sortable: true,
      text: (i) => severityLabel(i.severity_max), sortValue: (i) => -i.severity_max,
      render: (i) => <span className={severityBadgeClass(i.severity_max)}>{severityLabel(i.severity_max)}</span>,
    },
    {
      key: "first_seen", header: "First seen", width: 170, sortable: true,
      text: (i) => i.first_seen, render: (i) => fmtDateTime(i.first_seen),
    },
    {
      key: "last_seen", header: "Last seen", width: 170, sortable: true,
      text: (i) => i.last_seen, render: (i) => fmtDateTime(i.last_seen),
    },
    {
      key: "sample", header: "Sample", sortable: false, text: (i) => i.sample,
      render: (i) => <span className="mono" title={i.sample}>{i.sample}</span>,
    },
  ], []);

  return (
    <>
      <AdminHead
        title="Telemetry coverage"
        sub="What the parser recognizes today, and what your network is saying that it does not understand yet."
      />

      <ParserStatsSection stats={stats} err={statsErr} loaded={statsLoaded} />

      <h3 style={{ margin: "var(--sp-4) 0 var(--sp-2)" }}>Unrecognized message shapes</h3>
      <p className="admin-sub" style={{ marginTop: 0 }}>
        Lines admitted from your devices that no parser rule claimed, grouped into masked templates over the
        last {DAYS} days. Drafting a catalog row proposes a rule — it never applies one.
      </p>

      <div className="ds-toolbar">
        <Segmented<LaneChoice>
          value={lane}
          onChange={setLane}
          ariaLabel="Lane"
          options={[
            { value: "all", label: "All lanes" },
            { value: "syslog", label: "Syslog" },
            { value: "trap", label: "Trap" },
          ]}
        />
        <span className="mini-meta" role="status" aria-live="polite">{unrecognizedNote(page)}</span>
        {page && <span className="mini-meta">generated {fmtDateTime(page.generated_at)}</span>}
      </div>

      <ErrLine msg={pageErr} />
      <ErrLine msg={proposeErr} />

      {!pageLoaded ? (
        <div className="empty" role="status">Loading unrecognized shapes…</div>
      ) : items.length === 0 ? (
        <div className="empty">{unrecognizedNote(page) || "No unrecognized message shapes."}</div>
      ) : (
        <div className="card" style={{ paddingTop: 8 }}>
          <DataTable
            rows={items}
            columns={columns}
            rowKey={(i) => i.template_id}
            initialSort={{ key: "count", dir: "desc" }}
            height={360}
            ariaLabel="Unrecognized message shapes"
            rowActions={(i) => (
              <button
                type="button"
                className="btn"
                disabled={drafting === i.template_id}
                onClick={() => { void draft(i); }}
              >
                {drafting === i.template_id ? "Drafting…" : "Draft catalog row"}
              </button>
            )}
          />
        </div>
      )}

      {!ws.enabled && proposal && (
        <div className="card" style={{ marginTop: "var(--sp-3)" }}>
          <h3 style={{ margin: "0 0 var(--sp-2)" }}>Draft catalog row</h3>
          <ProposalBody proposal={proposal.p} template={proposal.template} />
        </div>
      )}
    </>
  );
}
