import { createContext, useContext, useMemo, useState, ReactNode } from "react";

// Workspace panes (#45) — the VSCode-style dockable Inspector (right, entity
// context) + BottomDrawer (correlated logs/events/timeline for the selection).
// Both are driven through this context so any module view can open them:
//
//   const ws = useWorkspace();
//   ws.openInspector(<DeviceContext .../>, { title: "leaf1", subtitle: "Arista" });
//   ws.openDrawer(<Logs initialQuery="leaf1" />, { title: "Logs · leaf1" });
//
// `enabled` is true only under shell-v2 — v1 views fall back to their own modals
// (Devices checks ws.enabled before pivoting to the inspector).

type PaneContent = { node: ReactNode; title?: string; subtitle?: string };

export interface WorkspaceApi {
  enabled: boolean;
  inspector: PaneContent | null;
  inspectorPinned: boolean;
  drawer: PaneContent | null;
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
  drawer: null,
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

  const api = useMemo<WorkspaceApi>(() => {
    if (!enabled) return DISABLED;
    return {
      enabled: true,
      inspector,
      inspectorPinned,
      drawer,
      openInspector: (node, meta) => setInspector({ node, ...meta }),
      closeInspector: () => {
        setInspector(null);
        setPinned(false);
      },
      toggleInspectorPin: () => setPinned((p) => !p),
      openDrawer: (node, meta) => setDrawer({ node, ...meta }),
      closeDrawer: () => setDrawer(null),
    };
  }, [enabled, inspector, inspectorPinned, drawer]);

  return <WorkspaceContext.Provider value={api}>{children}</WorkspaceContext.Provider>;
}
