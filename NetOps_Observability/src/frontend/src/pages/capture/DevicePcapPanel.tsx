// DevicePcapPanel — the "Packet capture" tab of the device detail page.
//
// What it gives an operator, in one place: a bounded on-demand packet capture
// against ONE interface of ONE device, the live status of the capture while it
// runs, and the history of previous captures with their packet/byte counts,
// a download and a confirmed delete.
//
// SAFETY (§3 zero trust / §9 reliability). This is the surface that points a
// packet engine at production traffic, so nothing about it is open-ended:
//  · Duration is a slider hard-capped at 60 s; packets are hard-capped at
//    10 000. Both are re-checked by validateCapture() before the POST, and the
//    SERVER re-checks them again — its 400 is rendered inline, verbatim.
//  · The BPF filter is pre-validated against the same closed host/net/port/
//    proto grammar the backend enforces; shell metacharacters are refused with
//    the offending character named. An invalid filter is never "cleaned".
//  · Polling is BOUNDED: one poll every 2 s, at most MAX_POLLS of them, and it
//    stops the moment the capture reaches done/failed/expired.
//
// SECURITY. Capture metadata (interface, filter, server error text) is device-
// and operator-authored. Every field is rendered as an escaped React text node.
// There is no innerHTML, no dangerouslySetInnerHTML and no markup parsing here.
//
// FEATURE FLAG. The backend family is dormant unless FEATURE_PACKET_CAPTURE is
// set. A 404/501 is therefore a PRODUCT state — "not enabled on this
// deployment" — rendered as a calm card, never as an error.
//
// PERMISSIONS. Reads need infrastructure:read. Start, download and delete need
// infrastructure:write; the client gate is a courtesy only — a server 403 is
// caught and shown inline, because the client is never the authority.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, type Device, type PcapCapture } from "../../services/api";
import { fmtDateTime } from "../../lib/time";
import { interfaceExample, interfaceHint } from "../../lib/vendorTerms";
import { classifyError } from "../config/configModel";
import {
  DEFAULT_DURATION_S,
  DEFAULT_PACKETS,
  DOWNLOAD_BLOCKED_HINT,
  FEATURE_OFF_HINT,
  FEATURE_OFF_MESSAGE,
  FILTER_GRAMMAR_HINT,
  MAX_DURATION_S,
  MAX_FILTER_LEN,
  MAX_INTERFACE_LEN,
  MAX_PACKETS,
  MAX_POLLS,
  MIN_DURATION_S,
  MIN_PACKETS,
  NO_PERMISSION_MESSAGE,
  POLL_GAVE_UP_MESSAGE,
  POLL_INTERVAL_MS,
  STATUS_HELP,
  STATUS_LABEL,
  canDownload,
  fmtBytes,
  fmtFilter,
  fmtPackets,
  isTerminal,
  pcapErrorMessage,
  pcapStatusOf,
  statusTone,
  validateCapture,
  validateFilter,
  type FieldErrors,
} from "./pcapModel";

type Notice = { tone: "good" | "bad"; text: string };

/** Interface options discovered from the device's own port inventory. */
type IfaceOption = { value: string; label: string };

export default function DevicePcapPanel({ device }: { device: Device }) {
  const [items, setItems] = useState<PcapCapture[]>([]);
  const [off, setOff] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [canWrite, setCanWrite] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [confirmId, setConfirmId] = useState<string | null>(null);

  // The form.
  const [iface, setIface] = useState("");
  const [duration, setDuration] = useState<number>(DEFAULT_DURATION_S);
  const [packets, setPackets] = useState<string>(String(DEFAULT_PACKETS));
  const [filter, setFilter] = useState("");
  const [errors, setErrors] = useState<FieldErrors>({});

  // Interface inventory. `null` = not looked up yet / unavailable, which is the
  // honest trigger for the free-text fallback — never an empty picker that
  // silently offers nothing.
  const [ifaces, setIfaces] = useState<IfaceOption[] | null>(null);

  const alive = useRef(true);
  const timer = useRef<number | undefined>(undefined);
  const polls = useRef(0);

  const deviceLabel = device.name || device.id;

  const load = useCallback(async () => {
    try {
      const page = await api.pcapList(device.id);
      if (!alive.current) return;
      setItems(Array.isArray(page?.items) ? page.items : []);
      setOff(false);
      setErr(null);
    } catch (e) {
      if (!alive.current) return;
      if (classifyError(e) === "off") {
        setOff(true);
        setErr(null);
      } else {
        setErr(pcapErrorMessage(e));
      }
    } finally {
      if (alive.current) setLoaded(true);
    }
  }, [device.id]);

  useEffect(() => {
    alive.current = true;
    void load();
    api.permissions()
      .then((p) => { if (alive.current) setCanWrite((p.permissions?.infrastructure ?? 0) >= 2); })
      .catch(() => { if (alive.current) setCanWrite(false); });
    return () => {
      alive.current = false;
      if (timer.current !== undefined) window.clearTimeout(timer.current);
    };
  }, [load]);

  // Interface picker source: the device's discovered port inventory. When the
  // call fails or the device has no ports on record we fall back to a text
  // field carrying the VENDOR's own interface-naming hint.
  useEffect(() => {
    let on = true;
    const qs = new URLSearchParams({ device: deviceLabel, limit: "500" });
    api.portInterfaces(qs.toString())
      .then((r) => {
        if (!on) return;
        // One option per distinct port name, labelled with its description when
        // the device reports one. A device with no ports on record yields null,
        // which is the honest trigger for the free-text fallback below.
        const byName = new Map<string, string>();
        for (const p of r.interfaces ?? []) {
          const name = String(p.port_name ?? "").trim();
          if (name === "" || byName.has(name)) continue;
          byName.set(name, String(p.if_alias ?? "").trim());
        }
        const options = Array.from(byName.entries())
          .sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true }))
          .map(([name, alias]) => ({ value: name, label: alias ? `${name} — ${alias}` : name }));
        setIfaces(options.length === 0 ? null : options);
      })
      .catch(() => { if (on) setIfaces(null); });
    return () => { on = false; };
  }, [deviceLabel]);

  const running = useMemo(() => items.find((c) => pcapStatusOf(c.status) === "running") ?? null, [items]);

  // ── bounded polling ───────────────────────────────────────────────────────
  // One timeout at a time, at most MAX_POLLS of them, torn down the instant the
  // capture reaches a terminal state or the panel unmounts. Never an interval:
  // a slow response must not stack requests (§9 backpressure).
  useEffect(() => {
    if (timer.current !== undefined) {
      window.clearTimeout(timer.current);
      timer.current = undefined;
    }
    if (!running) {
      polls.current = 0;
      return;
    }
    if (polls.current >= MAX_POLLS) {
      setNotice({ tone: "bad", text: POLL_GAVE_UP_MESSAGE });
      return;
    }
    const id = running.capture_id;
    timer.current = window.setTimeout(() => {
      polls.current += 1;
      api.pcapCapture(device.id, id)
        .then((c) => {
          if (!alive.current) return;
          setItems((prev) => prev.map((r) => (r.capture_id === id ? { ...r, ...c } : r)));
          if (isTerminal(pcapStatusOf(c.status))) void load();
        })
        .catch((e) => {
          if (!alive.current) return;
          // A poll failure is not a reason to hammer: mark the row failed so the
          // effect stops re-arming, and say why.
          setItems((prev) => prev.map((r) => (r.capture_id === id ? { ...r, status: "failed" } : r)));
          setNotice({ tone: "bad", text: pcapErrorMessage(e) });
        });
    }, POLL_INTERVAL_MS);
    return () => {
      if (timer.current !== undefined) {
        window.clearTimeout(timer.current);
        timer.current = undefined;
      }
    };
  }, [running, device.id, load]);

  // ── actions ───────────────────────────────────────────────────────────────

  const start = async () => {
    setNotice(null);
    const check = validateCapture({ interface: iface, duration_s: duration, max_packets: packets, filter });
    if (!check.ok) {
      setErrors(check.errors);
      return;
    }
    setErrors({});
    setBusy(true);
    try {
      const started = await api.pcapStart(device.id, check.request);
      if (!alive.current) return;
      polls.current = 0;
      setNotice({
        tone: "good",
        text:
          `Capture ${started.capture_id} started on ${check.request.interface} — ` +
          `up to ${check.request.duration_s} s or ${fmtPackets(check.request.max_packets)} packets. ` +
          `It expires at ${fmtDateTime(started.expires_at)}.`,
      });
      await load();
    } catch (e) {
      if (!alive.current) return;
      setNotice({ tone: "bad", text: pcapErrorMessage(e) });
    } finally {
      if (alive.current) setBusy(false);
    }
  };

  const download = async (c: PcapCapture) => {
    setNotice(null);
    try {
      await api.pcapDownload(device.id, c.capture_id);
      if (!alive.current) return;
      setNotice({
        tone: "good",
        text: `Downloading ${fmtBytes(c.bytes)} of capture ${c.capture_id}. ${DOWNLOAD_BLOCKED_HINT}`,
      });
    } catch (e) {
      if (alive.current) setNotice({ tone: "bad", text: pcapErrorMessage(e) });
    }
  };

  const remove = async (c: PcapCapture) => {
    setBusy(true);
    setNotice(null);
    try {
      await api.pcapDelete(device.id, c.capture_id);
      if (!alive.current) return;
      setConfirmId(null);
      setNotice({ tone: "good", text: `Capture ${c.capture_id} deleted.` });
      await load();
    } catch (e) {
      if (!alive.current) return;
      setNotice({ tone: "bad", text: pcapErrorMessage(e) });
    } finally {
      if (alive.current) setBusy(false);
    }
  };

  // ── product states ────────────────────────────────────────────────────────

  if (off) {
    return (
      <section className="cfg-panel" aria-label="Packet capture">
        <h3 className="cfg-h">Packet capture</h3>
        <div className="empty" role="status">
          {FEATURE_OFF_MESSAGE}. {FEATURE_OFF_HINT}
        </div>
      </section>
    );
  }

  if (err) {
    return (
      <section className="cfg-panel" aria-label="Packet capture">
        <h3 className="cfg-h">Packet capture</h3>
        <div className="empty cfg-bad" role="alert">{err}</div>
      </section>
    );
  }

  if (!loaded) {
    return (
      <section className="cfg-panel" aria-label="Packet capture">
        <h3 className="cfg-h">Packet capture</h3>
        <div className="empty" role="status">Loading captures…</div>
      </section>
    );
  }

  const liveFilter = validateFilter(filter);
  const filterError = errors.filter ?? (filter.trim() !== "" && !liveFilter.ok ? liveFilter.reason : undefined);
  const blocked = canWrite === false || busy || !!running;

  return (
    <section className="cfg-panel" aria-label="Packet capture">
      <h3 className="cfg-h">Packet capture</h3>
      <p className="mini-meta cfg-note">
        Captures run on the device itself and are bounded on purpose: at most {MAX_DURATION_S} seconds
        or {fmtPackets(MAX_PACKETS)} packets, one at a time per device.
      </p>

      {/* ── the request form ─────────────────────────────────────────────── */}
      <div className="pcap-form">
        <label className="pcap-field">
          <span>Interface</span>
          {ifaces && ifaces.length > 0 ? (
            <select
              value={iface}
              onChange={(e) => setIface(e.target.value)}
              disabled={blocked}
              aria-describedby={errors.interface ? "pcap-iface-err" : undefined}
            >
              <option value="">Choose an interface…</option>
              {ifaces.map((o) => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
          ) : (
            <input
              type="text"
              value={iface}
              maxLength={MAX_INTERFACE_LEN}
              placeholder={interfaceExample(device.vendor)}
              onChange={(e) => setIface(e.target.value)}
              disabled={blocked}
              aria-describedby={errors.interface ? "pcap-iface-err" : "pcap-iface-hint"}
            />
          )}
          {(!ifaces || ifaces.length === 0) && (
            <span className="mini-meta" id="pcap-iface-hint">{interfaceHint(device.vendor)}</span>
          )}
          {errors.interface && <span className="mini-meta cfg-bad" id="pcap-iface-err">{errors.interface}</span>}
        </label>

        <label className="pcap-field">
          <span>Duration — {duration} s</span>
          <input
            type="range"
            min={MIN_DURATION_S}
            max={MAX_DURATION_S}
            step={1}
            value={duration}
            onChange={(e) => setDuration(Number(e.target.value))}
            disabled={blocked}
            aria-label={`Capture duration in seconds, ${MIN_DURATION_S} to ${MAX_DURATION_S}`}
            aria-valuetext={`${duration} seconds`}
            aria-describedby={errors.duration_s ? "pcap-dur-err" : undefined}
          />
          <span className="mini-meta">Hard ceiling {MAX_DURATION_S} s — the server refuses anything longer.</span>
          {errors.duration_s && <span className="mini-meta cfg-bad" id="pcap-dur-err">{errors.duration_s}</span>}
        </label>

        <label className="pcap-field">
          <span>Max packets</span>
          <input
            type="number"
            min={MIN_PACKETS}
            max={MAX_PACKETS}
            step={1}
            value={packets}
            onChange={(e) => setPackets(e.target.value)}
            disabled={blocked}
            aria-describedby={errors.max_packets ? "pcap-pkt-err" : undefined}
          />
          <span className="mini-meta">Hard ceiling {fmtPackets(MAX_PACKETS)} packets.</span>
          {errors.max_packets && <span className="mini-meta cfg-bad" id="pcap-pkt-err">{errors.max_packets}</span>}
        </label>

        <label className="pcap-field pcap-field-wide">
          <span>Filter (optional)</span>
          <input
            type="text"
            value={filter}
            maxLength={MAX_FILTER_LEN}
            placeholder="host 10.0.0.1 and port 179"
            onChange={(e) => setFilter(e.target.value)}
            disabled={blocked}
            aria-invalid={filterError ? true : undefined}
            aria-describedby={filterError ? "pcap-filter-err" : "pcap-filter-hint"}
          />
          <span className="mini-meta" id="pcap-filter-hint">{FILTER_GRAMMAR_HINT}</span>
          {filterError && <span className="mini-meta cfg-bad" id="pcap-filter-err">{filterError}</span>}
        </label>

        <div className="pcap-actions">
          <button
            type="button"
            className="btn accent"
            onClick={() => { void start(); }}
            disabled={blocked}
            aria-label={`Start a packet capture on ${deviceLabel}`}
          >
            {busy ? "Starting…" : "Start capture"}
          </button>
        </div>
      </div>

      {canWrite === false && <p className="mini-meta cfg-note" role="status">{NO_PERMISSION_MESSAGE}</p>}
      {running && (
        <p className="mini-meta cfg-note" role="status">
          A capture is running on {running.interface} — the form is disabled until it finishes.
        </p>
      )}

      {/* Live region: every status change an operator needs is announced here. */}
      <p className={`mini-meta cfg-note${notice?.tone === "bad" ? " cfg-bad" : ""}`} role="status" aria-live="polite">
        {notice?.text ?? ""}
      </p>

      {/* ── history ──────────────────────────────────────────────────────── */}
      {items.length === 0 ? (
        <div className="empty">
          No packet capture has been run on this device yet. An empty list means nothing was
          captured — not that the interface is quiet.
        </div>
      ) : (
        <div className="ds-table-wrap">
          <table className="ds-table" aria-label={`Packet captures for ${deviceLabel}`}>
            <thead>
              <tr>
                <th scope="col">Capture</th>
                <th scope="col">Interface</th>
                <th scope="col">Started</th>
                <th scope="col">Ended</th>
                <th scope="col">Status</th>
                <th scope="col">Packets</th>
                <th scope="col">Size</th>
                <th scope="col">Filter</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((c) => {
                const st = pcapStatusOf(c.status);
                return (
                  <tr key={c.capture_id}>
                    {/* Untrusted ids/names — escaped React text nodes. */}
                    <th scope="row" className="mono cfg-sha" title={c.capture_id}>{c.capture_id}</th>
                    <td className="mono">{c.interface}</td>
                    <td>{c.started_at ? fmtDateTime(c.started_at) : "—"}</td>
                    <td>{c.ended_at ? fmtDateTime(c.ended_at) : "—"}</td>
                    <td>
                      <span className={`badge ${statusTone(st)}`} title={c.error || STATUS_HELP[st]}>
                        {STATUS_LABEL[st]}
                      </span>
                    </td>
                    <td className="mono">{fmtPackets(c.packets)}</td>
                    <td className="mono">{fmtBytes(c.bytes)}</td>
                    <td className="mono pcap-filter-cell">{fmtFilter(c.filter)}</td>
                    <td>
                      <div className="cfg-actions">
                        {canDownload(c) ? (
                          <button
                            type="button"
                            className="btn"
                            onClick={() => { void download(c); }}
                            disabled={canWrite === false}
                            aria-label={`Download capture ${c.capture_id} (${fmtBytes(c.bytes)})`}
                          >
                            Download {fmtBytes(c.bytes)}
                          </button>
                        ) : (
                          <span className="mini-meta">
                            {st === "running" ? "Still capturing" : st === "expired" ? "File expired" : "Nothing to download"}
                          </span>
                        )}
                        {canWrite !== false && (
                          confirmId === c.capture_id ? (
                            <>
                              <button
                                type="button" className="btn accent" disabled={busy}
                                aria-label={`Confirm deleting capture ${c.capture_id}`}
                                onClick={() => { void remove(c); }}
                              >
                                Confirm delete
                              </button>
                              <button
                                type="button" className="btn"
                                aria-label={`Cancel deleting capture ${c.capture_id}`}
                                onClick={() => setConfirmId(null)}
                              >
                                Cancel
                              </button>
                            </>
                          ) : (
                            <button
                              type="button" className="btn"
                              aria-label={`Delete capture ${c.capture_id}`}
                              onClick={() => setConfirmId(c.capture_id)}
                            >
                              Delete
                            </button>
                          )
                        )}
                      </div>
                      {c.error && <p className="mini-meta cfg-bad cfg-note">{c.error}</p>}
                      {confirmId === c.capture_id && (
                        <p className="mini-meta cfg-note" role="status">
                          Deleting {c.capture_id} removes the capture file for everyone. This cannot be undone.
                        </p>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
