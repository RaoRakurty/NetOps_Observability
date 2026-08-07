import { useEffect, useState } from "react";
import { api, BackupConfig, BackupStatus, SnapshotPolicy } from "../services/api";
import Icon from "../components/Icon";

// Data Protection — platform-global backup/DR posture. Two halves:
//   1. a LIVE status panel (repo registered? last snapshot age? on-host-only?),
//      honest by construction so an operator sees the truth, not a blank form;
//   2. a config form for the off-host destination + the scheduled full backup.
// Platform-owner only (backend enforces requirePlatformAdmin).
//
// The full-stack backup schedule is deliberately OFF by default and cannot be
// enabled without an off-host remote — a local-only nightly backup fills the
// disk it needs (F-55). OpenSearch snapshots are separate: incremental, daily,
// cheap, run by the cluster itself.

const labelStyle: React.CSSProperties = { fontSize: 12, fontWeight: 600, color: "var(--muted)" };
const hintStyle: React.CSSProperties = { fontSize: 11.5, color: "var(--muted)" };
const inputStyle: React.CSSProperties = {
  background: "var(--surface-2)", border: "1px solid var(--border, var(--panel-border))",
  borderRadius: 8, color: "var(--fg)", font: "inherit", fontSize: 13, padding: "8px 10px", width: "100%",
};

function Pill({ ok, warn, children }: { ok?: boolean; warn?: boolean; children: React.ReactNode }) {
  const bg = ok ? "var(--ok-bg, #10361f)" : warn ? "var(--warn-bg, #3a2f10)" : "var(--err-bg, #3a1414)";
  const fg = ok ? "var(--ok, #38d16a)" : warn ? "var(--warn, #e0b341)" : "var(--err, #ff6b6b)";
  return <span style={{ background: bg, color: fg, borderRadius: 6, padding: "2px 8px", fontSize: 12, fontWeight: 600 }}>{children}</span>;
}

function fmtBytes(n: number): string {
  if (n >= 1 << 30) return (n / (1 << 30)).toFixed(1) + " GiB";
  if (n >= 1 << 20) return (n / (1 << 20)).toFixed(1) + " MiB";
  if (n >= 1 << 10) return (n / (1 << 10)).toFixed(1) + " KiB";
  return n + " B";
}

export default function DataProtection() {
  const [cfg, setCfg] = useState<BackupConfig>({ remote_url: "", schedule_enabled: false });
  const [status, setStatus] = useState<BackupStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  // #150: the OpenSearch snapshot policy — live controls over netops-daily.
  const [snap, setSnap] = useState<SnapshotPolicy | null>(null);
  const [snapBusy, setSnapBusy] = useState(false);
  const [snapMsg, setSnapMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const load = () => {
    api.backupConfig().then((r) => { setCfg(r.config); setStatus(r.status); }).catch(() => {});
    api.snapshotPolicy().then(setSnap).catch(() => {});
  };
  useEffect(() => { load(); }, []);

  const saveSnap = async (upd: { enabled?: boolean; schedule_cron?: string; retention_max_count?: number }) => {
    setSnapBusy(true); setSnapMsg(null);
    try {
      const r = await api.setSnapshotPolicy(upd);
      setSnap(r);
      setSnapMsg({ kind: "ok", text: "Snapshot policy updated." });
    } catch (e: unknown) {
      setSnapMsg({ kind: "err", text: e instanceof Error ? e.message : "Update failed" });
    } finally { setSnapBusy(false); }
  };

  const save = async () => {
    setBusy(true); setMsg(null);
    try {
      const r = await api.setBackupConfig(cfg);
      setCfg(r.config); setStatus(r.status);
      setMsg({ kind: "ok", text: "Saved. A host-side applier writes the schedule/remote on the next install run." });
    } catch (e: unknown) {
      setMsg({ kind: "err", text: e instanceof Error ? e.message : "Save failed" });
    } finally { setBusy(false); }
  };

  return (
    <div style={{ display: "grid", gap: 16, maxWidth: 720 }}>
      {/* ── LIVE DR STATUS ── */}
      <div className="card" style={{ display: "grid", gap: 10 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Icon name="shield" size={20} />
          <div style={{ fontWeight: 700 }}>Disaster-recovery status</div>
        </div>
        {status ? (
          <div style={{ display: "grid", gap: 8, fontSize: 13 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span>Search-tier snapshots (OpenSearch)</span>
              <Pill ok={status.os_snapshot_repo_ok && (status.os_last_snapshot_age_hours ?? 999) < 48}
                    warn={status.os_snapshot_repo_ok && (status.os_last_snapshot_age_hours ?? 999) >= 48}>
                {status.os_snapshot_detail}
              </Pill>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span>Off-host copy (disaster recovery)</span>
              {status.remote_configured
                ? <Pill ok>configured</Pill>
                : <Pill warn>on-host only — NOT disaster recovery</Pill>}
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span>Scheduled full backup</span>
              {status.schedule_enabled ? <Pill ok>enabled</Pill> : <Pill warn>disabled</Pill>}
            </div>
            {status.last_drill_result && (
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span>Last restore drill</span>
                <Pill ok={status.last_drill_result === "pass"}>{status.last_drill_result} · {status.last_drill_at}</Pill>
              </div>
            )}
            {status.full_backup && (
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span>Last full backup</span>
                <Pill ok={status.full_backup.status === "success"}>
                  {status.full_backup.status} · {status.full_backup.ended} · {fmtBytes(status.full_backup.size_bytes)} · {status.full_backup.duration_seconds}s
                </Pill>
              </div>
            )}
            {!status.full_backup && status.schedule_enabled && (
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span>Last full backup</span>
                <Pill warn>no run report — never ran, or the host cron is not reporting</Pill>
              </div>
            )}
            {status.on_host_only_warning && (
              <div style={{ ...hintStyle, marginTop: 4 }}>
                ⚠ Backups currently share the primary data's disk/host. One disk failure loses both.
                Set an off-host remote below to make this real DR.
              </div>
            )}
          </div>
        ) : <div style={hintStyle}>Loading status…</div>}
      </div>

      {/* ── SNAPSHOT POLICY (#150: live control over the netops-daily SM policy) ── */}
      <div className="card" style={{ display: "grid", gap: 12 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ fontWeight: 700 }}>Search-tier snapshots (OpenSearch)</div>
          {snap && (
            <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
              <input type="checkbox" checked={snap.enabled} disabled={snapBusy}
                     onChange={(e) => saveSnap({ enabled: e.target.checked })} />
              Enabled
            </label>
          )}
        </div>
        {snap ? (
          <>
            {snap.detail && <div style={{ fontSize: 12.5, color: "var(--warn, #e0b341)" }}>{snap.detail}</div>}
            {!snap.enabled && (
              <div style={{ fontSize: 12.5, color: "var(--warn, #e0b341)" }}>
                ⚠ Snapshots are DISABLED — the search tier has no ongoing backup. Disabling is the explicit act; the default is on.
              </div>
            )}
            <div style={{ display: "grid", gap: 8, fontSize: 13 }}>
              {snap.last_run && (
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span>Last snapshot run</span>
                  <Pill ok={snap.last_run.status === "SUCCESS"}>
                    {snap.last_run.status}{snap.last_run.time ? ` · ${snap.last_run.time}` : ""}{snap.last_run.duration_seconds ? ` · ${snap.last_run.duration_seconds}s` : ""}
                  </Pill>
                </div>
              )}
              {snap.next_run && snap.enabled && (
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span>Next scheduled run</span>
                  <Pill ok>{snap.next_run}</Pill>
                </div>
              )}
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              <div style={{ display: "grid", gap: 4 }}>
                <label style={labelStyle}>Schedule (cron, UTC)</label>
                <input style={inputStyle} defaultValue={snap.schedule_cron} disabled={snapBusy}
                       onBlur={(e) => { if (e.target.value !== snap.schedule_cron) saveSnap({ schedule_cron: e.target.value }); }} />
              </div>
              <div style={{ display: "grid", gap: 4 }}>
                <label style={labelStyle}>Retention (keep newest N)</label>
                <input style={inputStyle} type="number" min={1} max={365} defaultValue={snap.retention_max_count} disabled={snapBusy}
                       onBlur={(e) => { const n = parseInt(e.target.value, 10); if (n && n !== snap.retention_max_count) saveSnap({ retention_max_count: n }); }} />
              </div>
            </div>
            <span style={hintStyle}>
              Incremental snapshots taken by the cluster itself (policy netops-daily). Restore is deliberately not
              available here — it is destructive and runbook-only.
            </span>
            {snapMsg && <div style={{ fontSize: 12.5, color: snapMsg.kind === "ok" ? "var(--ok, #38d16a)" : "var(--err, #ff6b6b)" }}>{snapMsg.text}</div>}
          </>
        ) : <div style={hintStyle}>Loading snapshot policy…</div>}
      </div>

      {/* ── CONFIG ── */}
      <div className="card" style={{ display: "grid", gap: 12 }}>
        <div style={{ fontWeight: 700 }}>Backup destination &amp; schedule</div>

        <div style={{ display: "grid", gap: 4 }}>
          <label style={labelStyle}>Off-host remote</label>
          <input style={inputStyle} placeholder="rsync://host/correlix/  ·  s3://bucket/  ·  /mnt/nas/correlix/"
                 value={cfg.remote_url} onChange={(e) => setCfg({ ...cfg, remote_url: e.target.value })} />
          <span style={hintStyle}>Where the full backup tarball is copied. Empty = on-host only (not DR).</span>
        </div>

        <div style={{ display: "grid", gap: 4 }}>
          <label style={labelStyle}>Push command (optional)</label>
          <input style={inputStyle} placeholder="rsync -a  (default)  ·  rclone copy"
                 value={cfg.push_command ?? ""} onChange={(e) => setCfg({ ...cfg, push_command: e.target.value })} />
        </div>

        <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
          <input type="checkbox" checked={cfg.schedule_enabled}
                 onChange={(e) => setCfg({ ...cfg, schedule_enabled: e.target.checked })} />
          Run the full backup on a schedule
        </label>
        <div style={{ display: "grid", gap: 4 }}>
          <label style={labelStyle}>Schedule (cron)</label>
          <input style={inputStyle} placeholder="30 2 * * *  (02:30 daily)"
                 value={cfg.schedule_cron ?? ""} onChange={(e) => setCfg({ ...cfg, schedule_cron: e.target.value })} />
          <span style={hintStyle}>
            The scheduled full backup needs an off-host remote first — a local-only nightly backup fills the disk it needs.
            OpenSearch snapshots run separately (incremental, daily, cheap).
          </span>
        </div>

        {msg && <div style={{ fontSize: 12.5, color: msg.kind === "ok" ? "var(--ok, #38d16a)" : "var(--err, #ff6b6b)" }}>{msg.text}</div>}
        <div>
          <button className="btn btn-primary" disabled={busy} onClick={save}>{busy ? "Saving…" : "Save"}</button>
        </div>
      </div>
    </div>
  );
}
