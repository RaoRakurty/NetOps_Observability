// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { api, Device } from "../services/api";
import Icon from "../components/Icon";

// DeviceTerminal — in-browser SSH console for a device, backed by the Go
// WebSocket→SSH gateway (/api/devices/{id}/ssh, FEATURE_DEVICE_SSH). The operator
// authenticates to the device with their OWN credentials, supplied here and sent
// once over the (TLS-fronted) socket — they are never stored. Host-key TOFU is
// surfaced as a banner on first connect.

type Phase = "form" | "connecting" | "open" | "closed";

// sshSocketUrl builds the WebSocket URL for a device terminal. Exported (and
// pure) so a test can pin the security property directly: the ONLY credential
// in this URL is the one-time ticket. The session JWT must never appear here —
// nginx logs the request line, and a JWT in it was a reusable privileged
// credential written into the log pipeline on every terminal open.
export function sshSocketUrl(deviceId: string, ticket: string, loc: { protocol: string; host: string } = location): string {
  const proto = loc.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${loc.host}/api/devices/${encodeURIComponent(deviceId)}/ssh?ticket=${encodeURIComponent(ticket)}`;
}

export default function DeviceTerminal({ device, onClose }: { device: Device; onClose: () => void }) {
  const [phase, setPhase] = useState<Phase>("form");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [port, setPort] = useState(22);
  const [useKey, setUseKey] = useState(false);
  const [showPw, setShowPw] = useState(false);
  const [banner, setBanner] = useState<{ kind: "info" | "error"; text: string } | null>(null);

  const termHost = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // Tear down the socket + terminal on unmount.
  useEffect(() => {
    return () => {
      wsRef.current?.close();
      termRef.current?.dispose();
    };
  }, []);

  const connect = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim()) return;
    setPhase("connecting");
    setBanner(null);

    // Step 1: obtain a one-time WebSocket ticket over an ordinary authenticated
    // request. The session JWT stays in that request's Authorization header. The
    // browser WS API cannot set headers, so the socket carries only the ticket:
    // opaque, single-use, ~30s, bound to this device — worthless if logged.
    let ticket: string;
    try {
      ({ ticket } = await api.deviceSSHTicket(device.id));
    } catch (err) {
      setPhase("form");
      setBanner({ kind: "error", text: "Could not start the terminal session." });
      return;
    }
    const url = sshSocketUrl(device.id, ticket);

    // Defer terminal creation a tick so the host div is mounted.
    setTimeout(() => {
      const term = new Terminal({
        fontFamily: "var(--font-mono, ui-monospace, 'JetBrains Mono', Menlo, monospace)",
        fontSize: 13,
        cursorBlink: true,
        theme: { background: "#0b1020", foreground: "#d7e0f5", cursor: "#7aa2f7" },
        scrollback: 5000,
      });
      const fit = new FitAddon();
      term.loadAddon(fit);
      if (termHost.current) {
        term.open(termHost.current);
        fit.fit();
      }
      termRef.current = term;
      fitRef.current = fit;

      const ws = new WebSocket(url);
      ws.binaryType = "arraybuffer";
      wsRef.current = ws;

      ws.onopen = () => {
        setPhase("open");
        ws.send(
          JSON.stringify({
            username: username.trim(),
            password: useKey ? "" : password,
            key: useKey ? privateKey : "",
            passphrase: useKey ? passphrase : "",
            port,
            cols: term.cols,
            rows: term.rows,
          }),
        );
        term.focus();
      };

      ws.onmessage = (ev) => {
        if (typeof ev.data === "string") {
          // Control frames: error / status / hostkey.
          try {
            const msg = JSON.parse(ev.data);
            if (msg.type === "error") {
              setBanner({ kind: "error", text: msg.message });
              term.writeln(`\r\n\x1b[31m✗ ${msg.message}\x1b[0m`);
            } else if (msg.type === "status") {
              setBanner({ kind: "info", text: msg.message });
              term.writeln(`\r\n\x1b[33m• ${msg.message}\x1b[0m`);
            } else if (msg.type === "hostkey") {
              const note = msg.first_seen
                ? `Host key recorded (first connect): ${msg.fingerprint}`
                : `Host key verified: ${msg.fingerprint}`;
              setBanner({ kind: "info", text: note });
            }
          } catch {
            /* ignore malformed control frame */
          }
          return;
        }
        // Binary = raw device output.
        term.write(new Uint8Array(ev.data as ArrayBuffer));
      };

      ws.onclose = () => {
        setPhase("closed");
        term.writeln("\r\n\x1b[90m— session closed —\x1b[0m");
      };
      ws.onerror = () => setBanner({ kind: "error", text: "WebSocket error — is device login enabled?" });

      // Keystrokes → device (binary stdin).
      term.onData((d) => {
        if (ws.readyState === WebSocket.OPEN) ws.send(new TextEncoder().encode(d));
      });

      // Window changes → resize control frame.
      const onResize = () => {
        fit.fit();
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
        }
      };
      window.addEventListener("resize", onResize);
      // Stash remover on the term so cleanup can drop it.
      (term as unknown as { _onResize?: () => void })._onResize = onResize;
    }, 0);
  };

  // Clean up the resize listener when leaving.
  useEffect(() => {
    return () => {
      const t = termRef.current as unknown as { _onResize?: () => void } | null;
      if (t?._onResize) window.removeEventListener("resize", t._onResize);
    };
  }, []);

  return (
    <div className="modal-backdrop" style={backdrop} onClick={onClose}>
      <div className="card" style={panel} onClick={(e) => e.stopPropagation()}>
        <div style={header}>
          <div>
            <strong>SSH · {device.name || device.id}</strong>
            <span style={{ color: "var(--muted)", marginLeft: 8, fontSize: 12 }}>{device.address}</span>
          </div>
          <button className="btn" onClick={onClose}>Close</button>
        </div>

        {banner && (
          <div
            style={{
              padding: "6px 10px",
              fontSize: 12,
              borderRadius: 6,
              margin: "0 0 8px",
              background: banner.kind === "error" ? "var(--bad)" : "var(--surface-2)",
              color: banner.kind === "error" ? "#fff" : "var(--fg)",
            }}
          >
            {banner.text}
          </div>
        )}

        {phase === "form" ? (
          <form onSubmit={connect} className="form-grid">
            <p className="form-sub" style={{ gridColumn: "1 / -1", marginBottom: 2 }}>
              You authenticate to the device with your own credentials. They are sent once over the
              encrypted socket and never stored.
            </p>
            <div className="form-field">
              <label className="form-label" htmlFor="ssh-user">Username<span className="form-req">*</span></label>
              <input id="ssh-user" className="form-input" value={username} autoFocus
                onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
            </div>
            <div className="form-field">
              <label className="form-label" htmlFor="ssh-port">Port</label>
              <input id="ssh-port" className="form-input" type="number" min={1} value={port}
                onChange={(e) => setPort(Number(e.target.value) || 22)} />
            </div>

            <label className="form-check" style={{ gridColumn: "1 / -1" }}>
              <input type="checkbox" checked={useKey} onChange={(e) => setUseKey(e.target.checked)} />
              Use private key instead of password
            </label>

            {useKey ? (
              <>
                <div className="form-field wide">
                  <label className="form-label" htmlFor="ssh-key">Private key</label>
                  <textarea id="ssh-key" className="form-input mono" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                    value={privateKey} onChange={(e) => setPrivateKey(e.target.value)} rows={5}
                    style={{ height: "auto", padding: "8px 12px" }} />
                </div>
                <div className="form-field wide">
                  <label className="form-label" htmlFor="ssh-pass">Key passphrase</label>
                  <input id="ssh-pass" className="form-input" type="password" placeholder="optional"
                    value={passphrase} onChange={(e) => setPassphrase(e.target.value)} />
                </div>
              </>
            ) : (
              <div className="form-field wide">
                <label className="form-label" htmlFor="ssh-pw">Password</label>
                <div className="pw-input-wrap">
                  <input id="ssh-pw" className="pw-input" type={showPw ? "text" : "password"} value={password}
                    onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
                  <button type="button" className="pw-eye" onClick={() => setShowPw((s) => !s)}
                    aria-label={showPw ? "Hide password" : "Show password"} aria-pressed={showPw} tabIndex={-1}>
                    <Icon name={showPw ? "eye-off" : "eye"} size={16} />
                  </button>
                </div>
              </div>
            )}

            <div className="form-actions">
              <button className="btn-accent" type="submit" disabled={!username.trim()}>Connect</button>
            </div>
          </form>
        ) : (
          <div ref={termHost} style={{ height: "60vh", width: "100%", background: "#0b1020", borderRadius: 6, padding: 6 }} />
        )}
      </div>
    </div>
  );
}

const backdrop: React.CSSProperties = {
  position: "fixed", inset: 0, background: "rgba(8,12,24,.55)",
  display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1100,
};
const panel: React.CSSProperties = { width: "min(960px, 94vw)", maxHeight: "90vh", overflow: "auto" };
const header: React.CSSProperties = {
  display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8,
};
