import { createContext, useContext, useMemo, useState, ReactNode } from "react";

// Workspace panes (#45 §11) — the VSCode-style dockable Inspector (right, entity
// context) + BottomDrawer (correlated logs/events/timeline for the selection).
// These are TRUE docked panes: the shell's CSS grid allocates a column/row for
// them so the center workspace reflows (shrinks) rather than being overlaid.
// Sizes live here so the shell can mirror them into grid-track CSS vars.
//
//   const ws = useWorkspace();
//   ws.openInspector(<DeviceContext .../>, { title: "leaf1", subtitle: "Arista" });
//   ws.openDrawer(<Logs initialQuery="leaf1" />, { title: "Logs · leaf1" });
//
// `enabled` is true only under shell-v2 — v1 views fall back to their own modals.

type PaneContent = { node: ReactNode; title?: string; subtitle?: string };

const INS_MIN = 300;
const DRW_MIN = 160;
const numOr = (key: string, def: number, min: number) => {
  const v = Number(localStorage.getItem(key));
  return v >= min ? v : def;
};

export interface WorkspaceApi {
  enabled: boolean;
  inspector: PaneContent | null;
  inspectorPinned: boolean;
  inspectorWidth: number;
  setInspectorWidth: (w: number) => void;
  drawer: PaneContent | null;
  drawerHeight: number;
  setDrawerHeight: (h: number) => void;
  openInspector: (node: ReactNode, meta?: { title?: string; subtitle?: string }) => void;
  closeInspector: () => void;
  toggleInspectorPin: () => void;
  openDrawer: (node: ReactNode, meta?: { title?: string }) => void;
  closeDrawer: () => void;
}

const noop = () => {};
const DISABLED: WorkspaceApi = {
  enabled: false,
  inspector: null,
  inspectorPinned: false,
  inspectorWidth: 380,
  setInspectorWidth: noop,
  drawer: null,
  drawerHeight: 300,
  setDrawerHeight: noop,
  openInspector: noop,
  closeInspector: noop,
  toggleInspectorPin: noop,
  openDrawer: noop,
  closeDrawer: noop,
};

const WorkspaceContext = createContext<WorkspaceApi>(DISABLED);

export function useWorkspace(): WorkspaceApi {
  return useContext(WorkspaceContext);
}

export function WorkspaceProvider({ enabled, children }: { enabled: boolean; children: ReactNode }) {
  const [inspector, setInspector] = useState<PaneContent | null>(null);
  const [inspectorPinned, setPinned] = useState(false);
  const [drawer, setDrawer] = useState<PaneContent | null>(null);
  const [inspectorWidth, setInsW] = useState(() => numOr("ws.inspectorW", 380, INS_MIN));
  const [drawerHeight, setDrwH] = useState(() => numOr("ws.drawerH", 300, DRW_MIN));

  const api = useMemo<WorkspaceApi>(() => {
    if (!enabled) return DISABLED;
    return {
      enabled: true,
      inspector,
      inspectorPinned,
      inspectorWidth,
      setInspectorWidth: (w) => {
        setInsW(w);
        localStorage.setItem("ws.inspectorW", String(w));
      },
      drawer,
      drawerHeight,
      setDrawerHeight: (h) => {
        setDrwH(h);
        localStorage.setItem("ws.drawerH", String(h));
      },
      openInspector: (node, meta) => setInspector({ node, ...meta }),
      closeInspector: () => {
        setInspector(null);
        setPinned(false);
      },
      toggleInspectorPin: () => setPinned((p) => !p),
      openDrawer: (node, meta) => setDrawer({ node, ...meta }),
      closeDrawer: () => setDrawer(null),
    };
  }, [enabled, inspector, inspectorPinned, inspectorWidth, drawer, drawerHeight]);

  return <WorkspaceContext.Provider value={api}>{children}</WorkspaceContext.Provider>;
}

export { INS_MIN, DRW_MIN };
