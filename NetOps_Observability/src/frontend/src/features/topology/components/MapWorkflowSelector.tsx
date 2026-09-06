// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// MapWorkflowSelector — segmented control over operator workflows (PDF §9).
// Implemented workflows are clickable; not-yet-built ones stay visible but muted
// with a "soon" tag and the blurb on hover, so the roadmap is honest.

import type { WorkflowMode } from "../api/topologyTypes";

export default function MapWorkflowSelector({
  value,
  onChange,
  workflows,
}: {
  value: WorkflowMode;
  onChange: (m: WorkflowMode) => void;
  workflows: { id: WorkflowMode; label: string; implemented: boolean; blurb: string }[];
}) {
  return (
    <div
      role="group"
      aria-label="Workflow"
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 2,
        padding: 2,
        border: "1px solid var(--border)",
        borderRadius: 7,
        background: "var(--surface)",
      }}
    >
      {workflows.map((w) => {
        const active = w.id === value;
        const disabled = !w.implemented;
        return (
          <button
            key={w.id}
            type="button"
            disabled={disabled}
            onClick={() => !disabled && onChange(w.id)}
            title={w.blurb}
            aria-pressed={active}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 5,
              border: "none",
              borderRadius: 5,
              padding: "4px 9px",
              fontSize: 12.5,
              fontWeight: active ? 600 : 500,
              cursor: disabled ? "not-allowed" : "pointer",
              whiteSpace: "nowrap",
              background: active ? "var(--panel)" : "transparent",
              color: disabled ? "var(--fg-subtle)" : active ? "var(--fg)" : "var(--fg-muted)",
              opacity: disabled ? 0.6 : 1,
              boxShadow: active ? "0 1px 2px rgba(0,0,0,0.12)" : "none",
            }}
          >
            {w.label}
            {disabled ? (
              <span
                style={{
                  fontSize: 12.5,
                  fontWeight: 700,
                  letterSpacing: 0.4,
                  color: "var(--fg-subtle)",
                  border: "1px solid var(--border)",
                  borderRadius: 3,
                  padding: "0 3px",
                }}
              >
                soon
              </span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}
