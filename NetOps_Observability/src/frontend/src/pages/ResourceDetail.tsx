// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useEffect, useState } from "react";
import {
  api,
  CloudResourceDetailResponse,
  CloudResourceRow,
  FeedItem,
} from "../services/api";
import { Segmented, Skeleton } from "../components/ui";
import { Chip, Muted } from "../components/noc";
import {
  EmptyState,
  ProviderBadge,
  ConfidenceBadge,
  AppIdentityPill,
  HealthBadge,
  ConsoleLink,
  fmtBytes,
} from "./appobs/badges";
import ResourceMetricsPanel from "./appobs/ResourceMetricsPanel";

// ResourceDetail — the permanent, shareable page behind #/resource/{kind}/{id}
// (Wave 6 #20). The id in the URL is the canonical opaque resource id; a
// cross-tenant or unknown id renders the SAME honest not-found view (the
// backend answers an indistinguishable 404 — existence is never leaked).
//
// Identity header + tabbed panels, REUSING the Service View's building blocks
// (ResourceMetricsPanel, badges) by import — never a re-implementation. Every
// tab has an honest empty state: absence of telemetry is shown as absence.

type Tab = "overview" | "metrics" | "flows" | "events" | "service";

const TABS: { value: Tab; label: string }[] = [
  { value: "overview", label: "Overview" },
  { value: "metrics", label: "Metrics" },
  { value: "flows", label: "Flows" },
  { value: "events", label: "Events" },
  { value: "service", label: "Service" },
];

export default function ResourceDetail({ kind, id }: { kind: string; id: string }) {
  const [tab, setTab] = useState<Tab>("overview");
  const [detail, setDetail] = useState<CloudResourceDetailResponse | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "notfound" | "error">("loading");
  const [errMsg, setErrMsg] = useState("");

  useEffect(() => {
    // Only the cloud-inventory kind exists today; an unknown kind is the same
    // honest not-found (never a guess).
    if (kind !== "cloud") {
      setState("notfound");
      return;
    }
    let alive = true;
    setState("loading");
    setDetail(null);
    api
      .cloudResource(id)
      .then((d) => {
        if (!alive) return;
        setDetail(d);
        setState("ready");
      })
      .catch((e) => {
        if (!alive) return;
        const msg = (e as Error).message || "";
        if (msg.startsWith("404")) {
          setState("notfound");
        } else {
          setErrMsg(msg);
          setState("error");
        }
      });
    return () => {
      alive = false;
    };
  }, [kind, id]);

  if (state === "loading") {
    return (
      <div className="resource-page" data-testid="resource-loading" role="status" aria-label="Loading resource">
        <Skeleton w="40%" h={28} />
        <Skeleton w="60%" h={16} style={{ marginTop: 8 }} />
        <Skeleton w="100%" h={220} style={{ marginTop: 16 }} />
      </div>
    );
  }
  if (state === "notfound") {
    return (
      <div className="resource-page">
        <EmptyState
          title="Resource not found"
          hint="This resource doesn't exist, is no longer in the inventory, or you don't have access to it."
          action={
            <a className="ao-console-link" href="#/operations/services/resources">
              Browse resources
            </a>
          }
        />
      </div>
    );
  }
  if (state === "error" || !detail) {
    return (
      <div className="resource-page">
        <EmptyState title="Couldn't load this resource" hint={errMsg || "Inventory did not answer."} />
      </div>
    );
  }

  const r = detail.resource;
  const name = r.resource_name || r.resource_id;

  return (
    <div className="resource-page">
      <div className="resource-head">
        <div className="resource-title">
          <h1>{name}</h1>
          <div className="resource-badges">
            <ProviderBadge provider={r.cloud_provider || "—"} />
            <Chip label={r.resource_type} title="resource class" />
            {detail.health && <HealthBadge status={toHealth(detail.health)} />}
            {r.power_state && <Chip label={r.power_state} title="provider lifecycle state" />}
            <ConfidenceBadge level={r.confidence} />
          </div>
        </div>
        <div className="resource-sub">
          <Muted>
            {r.resource_id}
            {" · "}
            {r.account_id || "no account"}
            {r.region ? ` · ${r.region}` : ""}
            {r.zone ? ` · ${r.zone}` : ""}
          </Muted>
          {detail.console_url && <ConsoleLink href={detail.console_url} label="Open in provider console" />}
        </div>
      </div>

      <Segmented value={tab} options={TABS} onChange={setTab} ariaLabel="Resource detail sections" />

      {tab === "overview" && <OverviewTab d={detail} />}
      {tab === "metrics" && (
        <ResourceMetricsPanel targets={[{ id: r.resource_id, name }]} subject={name} />
      )}
      {tab === "flows" && <FlowsTab r={r} />}
      {tab === "events" && <EventsTab r={r} />}
      {tab === "service" && <ServiceTab r={r} />}
    </div>
  );
}

function toHealth(h: string): "healthy" | "degraded" | "down" | "unknown" {
  return h === "healthy" || h === "degraded" || h === "down" ? h : "unknown";
}

// ── Overview ─────────────────────────────────────────────────────────────────

function OverviewTab({ d }: { d: CloudResourceDetailResponse }) {
  const r = d.resource;
  const ips = [...(r.private_ips ?? []), ...(r.public_ips ?? [])];
  const tags = Object.entries(r.tags ?? {});
  return (
    <div className="resource-body">
      <table className="ao-kv">
        <tbody>
          <Row k="Resource id" v={r.resource_id} />
          {r.resource_arn_or_uri && <Row k="ARN / URI" v={r.resource_arn_or_uri} />}
          <Row k="Provider" v={r.cloud_provider || "—"} />
          <Row k="Account" v={r.account_id || "—"} />
          <Row k="Region" v={r.region || "—"} />
          {r.zone && <Row k="Zone" v={r.zone} />}
          <Row k="Class" v={r.resource_type} />
          {r.power_state && <Row k="Power state" v={r.power_state} />}
          <Row k="IP addresses" v={ips.length ? ips.join(", ") : "none recorded"} />
          {d.health && <Row k="Health" v={`${d.health}${d.health_basis ? ` (${d.health_basis})` : ""}`} />}
          {d.traffic_bytes !== undefined && <Row k="Traffic (30m)" v={fmtBytes(d.traffic_bytes)} />}
          {d.cpu_pct !== undefined && <Row k="CPU" v={`${d.cpu_pct.toFixed(1)}%`} />}
          <Row k="Last seen" v={r.last_seen_at || "—"} />
        </tbody>
      </table>
      <div className="resource-tags">
        <h3>Tags</h3>
        {tags.length === 0 && <Muted>No tags on this resource.</Muted>}
        {tags.map(([k, v]) => (
          <Chip key={k} label={`${k}=${v}`} />
        ))}
      </div>
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <tr>
      <th scope="row">{k}</th>
      <td>{v}</td>
    </tr>
  );
}

// ── Flows — conversations this resource's addresses take part in ────────────

type ConvRow = { peer: string; dir: "out" | "in"; bytes: number; flows: number };

function FlowsTab({ r }: { r: CloudResourceRow }) {
  const ip = (r.private_ips ?? [])[0] || (r.public_ips ?? [])[0] || "";
  const [rows, setRows] = useState<ConvRow[] | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!ip) return;
    let alive = true;
    Promise.allSettled([
      api.topTalkers(86400, 15, "", { src: ip }),
      api.topTalkers(86400, 15, "", { dst: ip }),
    ]).then(([out, inn]) => {
      if (!alive) return;
      if (out.status === "rejected" && inn.status === "rejected") {
        setFailed(true);
        return;
      }
      const conv: ConvRow[] = [];
      if (out.status === "fulfilled") {
        for (const row of out.value.data ?? []) {
          conv.push({ peer: String(row.dst), dir: "out", bytes: Number(row.bytes_total) || 0, flows: Number(row.flows) || 0 });
        }
      }
      if (inn.status === "fulfilled") {
        for (const row of inn.value.data ?? []) {
          conv.push({ peer: String(row.src), dir: "in", bytes: Number(row.bytes_total) || 0, flows: Number(row.flows) || 0 });
        }
      }
      conv.sort((a, b) => b.bytes - a.bytes);
      setRows(conv.slice(0, 20));
    });
    return () => {
      alive = false;
    };
  }, [ip]);

  if (!ip) {
    return (
      <EmptyState
        title="No IP addresses recorded"
        hint="Flow telemetry is joined by IP; this resource's inventory record carries none."
      />
    );
  }
  if (failed) return <EmptyState title="Flow data unavailable" hint="The flow store did not answer." />;
  if (rows === null) return <Skeleton w="100%" h={160} />;
  if (rows.length === 0) {
    return (
      <EmptyState
        title="No flows in the last 24 hours"
        hint={`No flow records mention ${ip}. Absence of telemetry is shown as absence — not as zero traffic.`}
      />
    );
  }
  return (
    <div className="ao-table-wrap">
      <table className="ds-table" aria-label="Flow conversations">
        <thead>
          <tr>
            <th scope="col">Peer</th>
            <th scope="col">Direction</th>
            <th scope="col">Bytes (24h)</th>
            <th scope="col">Flows</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((c, i) => (
            <tr key={`${c.dir}:${c.peer}:${i}`}>
              <td>{c.peer}</td>
              <td>{c.dir === "out" ? "outbound" : "inbound"}</td>
              <td>{fmtBytes(c.bytes)}</td>
              <td>{c.flows}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Events — recent feed items referencing this resource ─────────────────────

function EventsTab({ r }: { r: CloudResourceRow }) {
  const needle = r.resource_name || r.resource_id;
  const [items, setItems] = useState<FeedItem[] | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let alive = true;
    api
      .eventsFeed({ q: needle, from: "168h", limit: "50" })
      .then((resp) => alive && setItems(resp.items ?? []))
      .catch(() => alive && setFailed(true));
    return () => {
      alive = false;
    };
  }, [needle]);

  if (failed) return <EmptyState title="Event data unavailable" hint="The event feed did not answer." />;
  if (items === null) return <Skeleton w="100%" h={160} />;
  if (items.length === 0) {
    return (
      <EmptyState
        title="No recent events"
        hint={`Nothing in the last 7 days mentions “${needle}”.`}
      />
    );
  }
  return (
    <div className="ao-table-wrap">
      <table className="ds-table" aria-label="Recent events">
        <thead>
          <tr>
            <th scope="col">Time</th>
            <th scope="col">Severity</th>
            <th scope="col">Event</th>
            <th scope="col">Source</th>
          </tr>
        </thead>
        <tbody>
          {items.map((e) => (
            <tr key={e.signal_id}>
              <td>{e.ts}</td>
              <td>{e.severity}</td>
              <td>
                {e.correlation_id ? (
                  <a href={`#/investigate/rca?id=${encodeURIComponent(e.correlation_id)}`}>{e.title}</a>
                ) : (
                  e.title
                )}
              </td>
              <td>{e.source}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Service — the resource's app attribution ─────────────────────────────────

function ServiceTab({ r }: { r: CloudResourceRow }) {
  const attributed = !!r.app_id && r.confidence !== "unknown";
  if (!attributed) {
    return (
      <EmptyState
        title="Not attributed to a service"
        hint="No evidence links this resource to a service yet. Attribution comes from tags, the cloud graph, the operator catalog or traffic identity — never a guess."
        action={
          <a className="ao-console-link" href="#/operations/services/resources">
            Review attribution in Service View
          </a>
        }
      />
    );
  }
  return (
    <div className="resource-body">
      <div className="resource-service">
        <AppIdentityPill app={r.app_name || r.app_id || ""} source={r.source} confidence={r.confidence} />
        <table className="ao-kv">
          <tbody>
            <Row k="Service" v={r.app_name || r.app_id || ""} />
            {r.owner && <Row k="Owner" v={r.owner} />}
            {r.env && <Row k="Environment" v={r.env} />}
            <Row k="Attribution" v={`${r.source} · ${r.confidence}`} />
          </tbody>
        </table>
        <a className="ao-console-link" href="#/operations/services/services">
          Open in Service View
        </a>
      </div>
    </div>
  );
}
