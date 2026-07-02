import { createContext, useContext } from "react";

// Shell-wide state shared by the top bar, sidebar, and every section.
// This is what makes the app behave as ONE product instead of isolated
// tabs: a single time range and a single query flow through all sections.

export type TimeRange = { label: string; minutes: number };

export const TIME_RANGES: TimeRange[] = [
  { label: "Last 15 min", minutes: 15 },
  { label: "Last 1 hour", minutes: 60 },
  { label: "Last 6 hours", minutes: 360 },
  { label: "Last 24 hours", minutes: 1440 },
  { label: "Last 7 days", minutes: 10080 },
];

export type ShellState = {
  // Global time range (top-bar picker). Sections read .minutes.
  range: TimeRange;
  setRange: (r: TimeRange) => void;
  // Global query (top-bar omni-search). Handed to the Search section.
  query: string;
  setQuery: (q: string) => void;
  // Copilot slide-over.
  copilotOpen: boolean;
  setCopilotOpen: (b: boolean) => void;
  // Documentation ("?") slide-over — embeds the /docs portal.
  helpOpen: boolean;
  setHelpOpen: (b: boolean) => void;
  // Deep link inside the docs portal ("" = portal home). Set via openHelp.
  helpPath: string;
  // Open the Help drawer at a specific docs path (e.g. "/docs/send-data/syslog#step-1").
  openHelp: (path?: string) => void;
  // Imperative navigation to a route id, e.g. "search/logs".
  navigate: (route: string) => void;
};

export const ShellContext = createContext<ShellState | null>(null);

export function useShell(): ShellState {
  const ctx = useContext(ShellContext);
  if (!ctx) throw new Error("useShell must be used within <ShellContext.Provider>");
  return ctx;
}

// Context handed to each section's render() so it can react to the global
// time range and query without prop-drilling through the router.
export type SectionCtx = { rangeMinutes: number; query: string };
