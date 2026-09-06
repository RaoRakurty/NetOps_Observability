// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useEffect, useState } from "react";
import { api, SystemNetworkConfig, SystemNetworkStatus } from "../services/api";
import Icon from "../components/Icon";

// DNS and NTP settings — two separate Settings boxes, each a tile with a
// Configure button that opens a popup to edit that setting. Both persist to the
// one platform config (/api/system/network); each save preserves the other's
// values. Platform-owner only (rendered gated in Settings; backend enforces).

const toList = (s: string): string[] => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
const fromList = (a?: string[]): string => (a ?? []).join("\n");

const taStyle: React.CSSProperties = {
  background: "var(--surface-2)", border: "1px solid var(--border, var(--panel-border))",
  borderRadius: 8, color: "var(--fg)", font: "inherit", fontSize: 13, padding: "8px 10px",
  resize: "vertical", width: "100%",
};
const labelStyle: React.CSSProperties = { fontSize: 12, fontWeight: 600, color: "var(--muted)" };
const hintStyle: React.CSSProperties = { fontSize: 11.5, color: "var(--muted)" };

type Kind = "dns" | "ntp";

export default function SystemNetworkCards() {
  const [cfg, setCfg] = useState<SystemNetworkConfig>({ dns_servers: [], search_domains: [], ntp_servers: [] });
  const [editing, setEditing] = useState<Kind | null>(null);

  useEffect(() => { api.systemNetwork().then(setCfg).catch(() => {}); }, []);

  const tile = (kind: Kind, icon: string, title: string, desc: string, count: number) => (
    <div className="card" style={{ display: "flex", alignItems: "center", gap: 12 }}>
      <div style={{ width: 34, height: 34, borderRadius: 8, background: "var(--surface-2)", display: "grid", placeItems: "center" }}>
        <Icon name={icon} size={20} />
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ fontWeight: 700 }}>{title}</div>
        <div style={{ fontSize: 12, color: "var(--muted)" }}>
          {desc} {count > 0 && <span style={{ color: "var(--fg)" }}>· {count} configured</span>}
        </div>
      </div>
      <button className="btn" onClick={() => setEditing(kind)}>Configure</button>
    </div>
  );

  return (
    <>
      {tile("dns", "external", "DNS", "Preferred DNS resolvers for outbound URLs — validate with Test connectivity.", cfg.dns_servers?.length ?? 0)}
      {tile("ntp", "refresh", "NTP", "The time sources Correlix tracks its clock against.", cfg.ntp_servers?.length ?? 0)}

      {editing && (
        <div
          onClick={() => setEditing(null)}
          style={{ position: "fixed", inset: 0, background: "rgba(10,10,20,.45)", display: "grid", placeItems: "center", zIndex: 50, padding: 16 }}
        >
          <div onClick={(e) => e.stopPropagation()} style={{ maxWidth: 640, width: "100%", maxHeight: "86vh", overflow: "auto" }}>
            <ConfigureForm kind={editing} cfg={cfg} onSaved={setCfg} onClose={() => setEditing(null)} />
          </div>
        </div>
      )}
    </>
  );
}

// ConfigureForm — the popup body for one setting (DNS or NTP). Saves the merged
// config so editing one never clears the other; Test runs the live probe.
function ConfigureForm({ kind, cfg, onSaved, onClose }: { kind: Kind; cfg: SystemNetworkConfig; onSaved: (c: SystemNetworkConfig) => void; onClose: () => void }) {
  const isDNS = kind === "dns";
  const [dns, setDns] = useState(fromList(cfg.dns_servers));
  const [search, setSearch] = useState(fromList(cfg.search_domains));
  const [ntp, setNtp] = useState(fromList(cfg.ntp_servers));
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState(false);
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [status, setStatus] = useState<SystemNetworkStatus | null>(null);

  const save = async () => {
    setBusy(true); setMsg(null);
    try {
      // Merge: only overwrite the fields this popup owns; keep the rest.
      const next: SystemNetworkConfig = isDNS
        ? { ...cfg, dns_servers: toList(dns), search_domains: toList(search) }
        : { ...cfg, ntp_servers: toList(ntp) };
      const saved = await api.setSystemNetwork(next);
      onSaved(saved);
      setMsg({ kind: "ok", text: "Saved" });
    } catch (e) { setMsg({ kind: "err", text: (e as Error).message }); } finally { setBusy(false); }
  };

  const test = async () => {
    setTesting(true); setStatus(null); setMsg(null);
    try { setStatus(await api.testSystemNetwork()); }
    catch (e) { setMsg({ kind: "err", text: (e as Error).message }); } finally { setTesting(false); }
  };

  const fmtOffset = (ms?: number) => (ms === undefined ? "—" : `${ms >= 0 ? "+" : ""}${ms.toFixed(0)} ms`);

  return (
    <div className="card">
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
        <div style={{ width: 30, height: 30, borderRadius: 8, background: "var(--surface-2)", display: "grid", placeItems: "center" }}>
          <Icon name={isDNS ? "external" : "refresh"} size={17} />
        </div>
        <h3 style={{ margin: 0 }}>{isDNS ? "DNS" : "NTP"}</h3>
      </div>
      <p style={{ color: "var(--muted)", fontSize: 12.5, marginTop: 0, marginBottom: 14 }}>
        {isDNS
          ? "Preferred DNS resolvers for resolving outbound URLs (integrations, webhooks, providers). Use Test connectivity to confirm they resolve names."
          : "The NTP time sources Correlix tracks its clock against. Test reports the measured clock offset per server."}
        {msg && <span style={{ color: msg.kind === "ok" ? "var(--ok)" : "var(--crit)" }}> · {msg.text}</span>}
      </p>

      <div style={{ display: "grid", gap: 14 }}>
        {isDNS ? (
          <>
            <div style={{ display: "grid", gap: 5 }}>
              <span style={labelStyle}>DNS servers <span style={{ fontWeight: 400 }}>(one per line — IP addresses)</span></span>
              <textarea rows={3} value={dns} onChange={(e) => setDns(e.target.value)} placeholder={"1.1.1.1\n8.8.8.8"} style={taStyle} />
            </div>
            <div style={{ display: "grid", gap: 5 }}>
              <span style={labelStyle}>Search domains <span style={{ fontWeight: 400 }}>(optional)</span></span>
              <textarea rows={2} value={search} onChange={(e) => setSearch(e.target.value)} placeholder={"corp.example.com"} style={taStyle} />
            </div>
          </>
        ) : (
          <div style={{ display: "grid", gap: 5 }}>
            <span style={labelStyle}>NTP servers <span style={{ fontWeight: 400 }}>(one per line — host or IP)</span></span>
            <textarea rows={3} value={ntp} onChange={(e) => setNtp(e.target.value)} placeholder={"pool.ntp.org\ntime.cloudflare.com"} style={taStyle} />
          </div>
        )}

        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <button className="btn-accent" onClick={save} disabled={busy}>{busy ? "Saving…" : "Save"}</button>
          <button className="btn" onClick={test} disabled={testing}>{testing ? "Testing…" : "Test connectivity"}</button>
          <button className="btn" onClick={onClose} style={{ marginLeft: "auto" }}>Close</button>
        </div>
      </div>

      {status && isDNS && (
        <div style={{ marginTop: 14, borderTop: "1px solid var(--border, var(--panel-border))", paddingTop: 12 }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
            <thead>
              <tr style={{ color: "var(--muted)", textAlign: "left" }}>
                <th style={{ fontWeight: 600, padding: "2px 6px" }}>Query</th>
                <th style={{ fontWeight: 600, padding: "2px 6px", textAlign: "center" }}>Result</th>
                <th style={{ fontWeight: 600, padding: "2px 6px" }}>Answer</th>
              </tr>
            </thead>
            <tbody>
              <tr style={{ borderTop: "1px solid var(--border, var(--panel-border))" }}>
                <td style={{ padding: "3px 6px", fontFamily: "var(--font-mono, monospace)" }}>{status.dns.test_host}</td>
                <td style={{ padding: "3px 6px", textAlign: "center", color: status.dns.ok ? "var(--ok)" : "var(--crit)" }}>{status.dns.ok ? "resolved" : "failed"}</td>
                <td style={{ padding: "3px 6px", fontFamily: "var(--font-mono, monospace)" }}>
                  {status.dns.ok
                    ? `${status.dns.resolved?.[0] ?? "—"}${(status.dns.resolved?.length ?? 0) > 1 ? `  +${(status.dns.resolved!.length - 1)}` : ""}`
                    : (status.dns.error || "—")}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      )}
      {status && !isDNS && (
        <div style={{ marginTop: 14, borderTop: "1px solid var(--border, var(--panel-border))", paddingTop: 12 }}>
          {status.ntp.results.length === 0 ? (
            <div style={hintStyle}>No NTP servers configured.</div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
              <thead>
                <tr style={{ color: "var(--muted)", textAlign: "left" }}>
                  <th style={{ fontWeight: 600, padding: "2px 6px" }}>Server</th>
                  <th style={{ fontWeight: 600, padding: "2px 6px", textAlign: "center" }}>Reachable</th>
                  <th style={{ fontWeight: 600, padding: "2px 6px", textAlign: "center" }}>Stratum</th>
                  <th style={{ fontWeight: 600, padding: "2px 6px", textAlign: "right" }}>Offset</th>
                  <th style={{ fontWeight: 600, padding: "2px 6px", textAlign: "right" }}>RTT</th>
                </tr>
              </thead>
              <tbody>
                {status.ntp.results.map((r) => (
                  <tr key={r.server} style={{ borderTop: "1px solid var(--border, var(--panel-border))" }}>
                    <td style={{ padding: "3px 6px", fontFamily: "var(--font-mono, monospace)" }}>{r.server}</td>
                    <td style={{ padding: "3px 6px", textAlign: "center", color: r.reachable ? "var(--ok)" : "var(--crit)" }}>{r.reachable ? "yes" : "no"}</td>
                    <td style={{ padding: "3px 6px", textAlign: "center" }}>{r.stratum || "—"}</td>
                    <td style={{ padding: "3px 6px", textAlign: "right", color: Math.abs(r.offset_ms ?? 0) > 1000 ? "var(--warn)" : undefined }}>{r.reachable ? fmtOffset(r.offset_ms) : (r.error || "—")}</td>
                    <td style={{ padding: "3px 6px", textAlign: "right" }}>{r.reachable ? `${(r.rtt_ms ?? 0).toFixed(0)} ms` : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
