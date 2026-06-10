import { useRef, useState } from "react";
import Icon from "../components/Icon";

// Grafana — embedded seamlessly in-app (same pattern as Source of Truth /
// NetBox). The osd-gate auto-logs-in the platform owner via Grafana's auth
// proxy (X-WEBAUTH-USER), so there's no separate Grafana login or "not signed
// in" state, and nginx re-skins it to the Correlix palette. Full-height frame
// with a fullscreen expand so it never reads as a cramped isolated window.
export default function GrafanaTab() {
  const ref = useRef<HTMLIFrameElement>(null);
  const [full, setFull] = useState(false);
  const reload = () => { if (ref.current) ref.current.src = ref.current.src; };

  return (
    <div className="sot-head">
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
        <div>
          <h2 style={{ margin: 0 }}>Metrics &amp; Dashboards</h2>
          <p style={{ color: "var(--muted)", fontSize: 13, margin: "2px 0 0" }}>
            Stack and network dashboards, signed in automatically.
          </p>
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          <button className="btn" onClick={reload} title="Reload">
            <Icon name="refresh" size={14} /> Reload
          </button>
          <button className="btn" onClick={() => setFull((v) => !v)} title={full ? "Exit fullscreen" : "Fullscreen"}>
            <Icon name="maximize" size={14} /> {full ? "Exit" : "Fullscreen"}
          </button>
        </div>
      </div>
      <div className={`sot-frame-wrap${full ? " full" : ""}`}>
        {full && (
          <button className="btn sot-exit" onClick={() => setFull(false)}>Exit fullscreen</button>
        )}
        <iframe
          ref={ref}
          title="Grafana"
          className="sot-frame"
          src="/grafana/"
        />
      </div>
    </div>
  );
}
