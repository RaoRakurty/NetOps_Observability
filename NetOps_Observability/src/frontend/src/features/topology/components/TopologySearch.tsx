// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// TopologySearch — fuzzy locate across the view. Matching is inline (no util
// import): label/id/ip/vendor/model/site/role/owner/health/zone, plus interface
// names from edges mapped back to their nodes. Emits the matching node-id set as
// the operator types (debounced) so the canvas can highlight; picking focuses one.

import { useEffect, useMemo, useRef, useState } from "react";
import type { TopologyView, TopologyNode } from "../api/topologyTypes";

type Indexed = {
  node: TopologyNode;
  haystack: string;
  ports: string[];
};

function buildIndex(view: TopologyView): Indexed[] {
  // Collect interface names per node from edges.
  const portsByNode = new Map<string, Set<string>>();
  const add = (id: string, port?: string) => {
    if (!port) return;
    let set = portsByNode.get(id);
    if (!set) {
      set = new Set<string>();
      portsByNode.set(id, set);
    }
    set.add(port);
  };
  for (const e of view.edges) {
    add(e.source, e.source_port);
    add(e.target, e.target_port);
  }

  return view.nodes.map((node) => {
    const ports = Array.from(portsByNode.get(node.id) ?? []);
    const parts = [
      node.label,
      node.id,
      node.tags?.ip,
      node.vendor,
      node.model,
      node.site,
      node.role,
      node.owner,
      node.health,
      node.zone,
      ...ports,
    ].filter(Boolean) as string[];
    return { node, ports, haystack: parts.join(" ").toLowerCase() };
  });
}

export default function TopologySearch({
  view,
  onMatches,
  onPick,
}: {
  view: TopologyView;
  onMatches: (ids: Set<string>) => void;
  onPick: (nodeId: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const index = useMemo(() => buildIndex(view), [view]);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const results = useMemo<Indexed[]>(() => {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    return index.filter((i) => i.haystack.includes(q)).slice(0, 40);
  }, [query, index]);

  // Debounced emit of the matching id set.
  useEffect(() => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      const q = query.trim().toLowerCase();
      if (!q) {
        onMatches(new Set<string>());
        return;
      }
      onMatches(new Set(index.filter((i) => i.haystack.includes(q)).map((i) => i.node.id)));
    }, 150);
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, [query, index, onMatches]);

  return (
    <div style={{ position: "relative", width: 240 }}>
      <input
        value={query}
        onChange={(e) => {
          setQuery(e.target.value);
          setOpen(true);
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => setTimeout(() => setOpen(false), 120)}
        placeholder="Search devices, IPs, interfaces…"
        aria-label="Search topology"
        style={{
          width: "100%",
          boxSizing: "border-box",
          fontSize: 12.5,
          padding: "6px 9px",
          borderRadius: 7,
          border: "1px solid var(--border)",
          background: "var(--surface)",
          color: "var(--fg)",
          outline: "none",
        }}
      />

      {open && query.trim() ? (
        <div
          style={{
            position: "absolute",
            top: "calc(100% + 4px)",
            left: 0,
            right: 0,
            maxHeight: 280,
            overflowY: "auto",
            background: "var(--panel)",
            border: "1px solid var(--border)",
            borderRadius: 8,
            boxShadow: "0 8px 24px rgba(0,0,0,0.2)",
            zIndex: 30,
          }}
        >
          {results.length === 0 ? (
            <div style={{ padding: "10px 12px", fontSize: 12.5, color: "var(--fg-muted)" }}>
              No matches for “{query.trim()}”.
            </div>
          ) : (
            results.map(({ node, ports }) => (
              <button
                key={node.id}
                type="button"
                onMouseDown={(e) => {
                  e.preventDefault();
                  onPick(node.id);
                  setOpen(false);
                }}
                style={{
                  display: "block",
                  width: "100%",
                  textAlign: "left",
                  border: "none",
                  borderBottom: "1px solid var(--border)",
                  background: "transparent",
                  cursor: "pointer",
                  padding: "7px 11px",
                }}
              >
                <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--fg)" }}>{node.label}</div>
                <div
                  style={{
                    fontSize: 12.5,
                    color: "var(--fg-muted)",
                    fontFamily: "var(--font-mono, ui-monospace, monospace)",
                  }}
                >
                  {[node.tags?.ip, node.vendor, node.site, ports.slice(0, 2).join(", ")]
                    .filter(Boolean)
                    .join(" · ")}
                </div>
              </button>
            ))
          )}
        </div>
      ) : null}
    </div>
  );
}
