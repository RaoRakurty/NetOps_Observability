import { useState } from "react";
import { ExportPolicyForm } from "./admin";
import Icon from "../components/Icon";

// Administration → Settings. Trimmed (C1/C2/C3):
//   - the redundant per-integration credentials table is gone — each connector
//     shows its own status under Integrations / Notifications;
//   - discovery refresh moved to Automation → Source of Truth;
//   - log-export limits are now a tile that opens a guided setup modal.
export default function Settings() {
  const [showExport, setShowExport] = useState(false);

  return (
    <>
      <div className="card">
        <h2 style={{ margin: 0 }}>Settings</h2>
        <p style={{ color: "var(--muted)", fontSize: 13, marginTop: 6 }}>
          Platform configuration. Integration credentials live with their connectors
          (Administration → Integrations and Notifications); discovery sources are under
          Automation → Source of Truth.
        </p>
      </div>

      {/* Log export limits — tile + guided setup (C3). */}
      <div className="card" style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div
          style={{
            width: 34,
            height: 34,
            borderRadius: 8,
            background: "var(--panel-2, #f4f4f8)",
            display: "grid",
            placeItems: "center",
          }}
        >
          <Icon name="external" size={20} />
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700 }}>Log export limits</div>
          <div style={{ fontSize: 12, color: "var(--muted)" }}>
            Anti-exfiltration guardrails for log exports — rate, row/size caps, runtime, link TTL.
          </div>
        </div>
        <button className="btn" onClick={() => setShowExport(true)}>
          Configure
        </button>
      </div>

      {showExport && (
        <div
          onClick={() => setShowExport(false)}
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(10,10,20,.45)",
            display: "grid",
            placeItems: "center",
            zIndex: 50,
            padding: 16,
          }}
        >
          <div onClick={(e) => e.stopPropagation()} style={{ maxWidth: 640, width: "100%", maxHeight: "86vh", overflow: "auto" }}>
            <ExportPolicyForm />
            <div style={{ textAlign: "right", marginTop: 8 }}>
              <button className="btn" onClick={() => setShowExport(false)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
