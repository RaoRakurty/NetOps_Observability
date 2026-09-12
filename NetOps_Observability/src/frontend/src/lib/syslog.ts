// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// syslog.ts — turn raw vendor syslog into operator-friendly text for display.
// Many devices emit STRUCTURED logs the operator shouldn't have to decode, e.g.
// SR Linux / Nokia:  "debug|4236|4236|302146|TR||W: common  grpc_server_instance.cc:1965
//   BuildAndStartServer  Unable to retrieve TLS profile 'EDA'"
// The operator only needs: severity + the human message (+ subsystem). We parse
// what we recognize and fall back to the raw string untouched (never hide info).
// Display-layer only — the raw message is always kept and shown in the inspector.

export type FriendlyLog = { summary: string; severity?: string; subsystem?: string; raw: string };

const SRL_LEVEL: Record<string, string> = {
  D: "debug", I: "info", N: "notice", W: "warning", E: "error", C: "critical", A: "alert", F: "critical",
};

export function humanizeSyslog(raw: string): FriendlyLog {
  const r = String(raw ?? "");
  let s = r.trim();
  // strip leading RFC5424 nil placeholders ("- - -")
  s = s.replace(/^(?:-\s+)+/, "").trim();

  // SR Linux / Nokia structured: level|pid|tid|seq|app||X: subsys  file:line func  message
  const m = s.match(/^[a-zA-Z]+\|\d+\|\d+\|\d+\|[^|]*\|[^|]*\|([A-Z]):\s*(.+)$/);
  if (m) {
    const sev = SRL_LEVEL[m[1]] ?? undefined;
    // chunks split on 2+ spaces: [subsystem, "file:line func", …, human message]
    const chunks = m[2].split(/\s{2,}/).map((x) => x.trim()).filter(Boolean);
    if (chunks.length) {
      const summary = chunks[chunks.length - 1];
      const subsystem = chunks.length > 1 ? chunks[0] : undefined;
      // guard: if the "message" still looks like a file:line token, keep the raw tail
      if (summary && !/^\S+\.\w+:\d+$/.test(summary)) {
        return { summary, severity: sev, subsystem, raw: r };
      }
    }
  }
  return { summary: s || r, raw: r };
}
