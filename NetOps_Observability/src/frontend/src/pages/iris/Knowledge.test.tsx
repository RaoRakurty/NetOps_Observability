// Knowledge.test.tsx — Iris → Knowledge, the per-vendor coverage page.
//
// The page exists to be HONEST about coverage, so that is what is pinned:
//  · a planned dialect shows bound vs total intents, verified vs documented
//    commands and its plan version
//  · expanding it shows the per-class coverage INCLUDING the intents that class
//    cannot answer on this dialect, by name
//  · the per-intent table shows the command and how sure we are of it, and says
//    plainly when a dialect binds no command for an intent
//  · platforms with NO authored plan get their own section rather than being
//    quietly left out
//  · the unknown-output backlog renders as an explicit "not yet tracked", never
//    as a zero (a zero there would claim there is no backlog)
//  · a read that fails says what did not happen

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, act, within } from "@testing-library/react";
import type { TacKnowledge } from "../../services/api";

const mocks = vi.hoisted(() => ({
  tacKnowledge: vi.fn(),
  // The command templates tab (tracker 250).
  tacTemplates: vi.fn(), tacTemplate: vi.fn(),
}));
vi.mock("../../services/api", () => ({ api: { ...mocks } }));

import IrisKnowledge from "./Knowledge";
import {
  BACKLOG_NOT_TRACKED,
  COMMAND_POLICY_NO_EXCLUSIONS,
  DOC_CLAIMED_LABEL,
  KNOWLEDGE_FAILED,
  VERIFIED_LABEL,
} from "../troubleshoot/tacModel";

const knowledge = (over: Partial<TacKnowledge> = {}): TacKnowledge => ({
  catalog_version: "correlix-tac-classes-2026-09-05",
  engine_version: "correlix-tac-2026-09-05",
  classes: [
    { id: "ospf-adjacency", title: "OSPF adjacency will not form or is stuck", protocol: "ospf" },
    { id: "bgp-session", title: "BGP session down", protocol: "bgp" },
  ],
  intents: [
    { id: "system.version", area: "system", title: "Software version" },
    { id: "ospf.neighbors.detail", area: "ospf", title: "OSPF neighbours, detailed" },
    { id: "ospf.database.router", area: "ospf", title: "OSPF router LSA" },
  ],
  dialects: [
    {
      dialect: "cisco-iosxe", display: "Cisco IOS-XE", profile: "cisco/ios_xe",
      has_plan: true, plan_version: "correlix-tac-plan-cisco-iosxe-2026-09-05",
      baseline_intents: 6, optional_intents: 1, bound_intents: 2, total_intents: 3,
      verified_commands: 1, doc_claimed_commands: 1,
      excluded_by_policy: { dialect: "cisco-iosxe", config: 2, restart: 1, daemon: 4, total: 7 },
      classes: [
        {
          class_id: "ospf-adjacency", title: "OSPF adjacency will not form or is stuck",
          protocol: "ospf", bound: 1, total: 2, missing: ["ospf.database.router"],
        },
        { class_id: "bgp-session", title: "BGP session down", protocol: "bgp", bound: 2, total: 2, missing: [] },
      ],
      intents: [
        { intent: "system.version", title: "Software version", area: "system", bound: true, command: "show version", verified: "capture" },
        {
          intent: "ospf.neighbors.detail", title: "OSPF neighbours, detailed", area: "ospf",
          bound: true, command: "show ip ospf neighbor detail", verified: "doc_claimed",
        },
        { intent: "ospf.database.router", title: "OSPF router LSA", area: "ospf", bound: false },
      ],
    },
  ],
  unplanned_dialects: [
    {
      dialect: "nokia-srlinux", display: "Nokia SR Linux", profile: "nokia/srlinux",
      has_plan: false, baseline_intents: 0, optional_intents: 0, bound_intents: 0, total_intents: 3,
      verified_commands: 0, doc_claimed_commands: 0,
      excluded_by_policy: { dialect: "nokia-srlinux", config: 0, restart: 0, daemon: 0, total: 0 },
      classes: [
        { class_id: "ospf-adjacency", title: "OSPF adjacency will not form or is stuck", protocol: "ospf", bound: 0, total: 2, missing: ["ospf.interfaces", "ospf.database.router"] },
      ],
      intents: [],
    },
  ],
  command_policy: {
    version: "correlix-tac-forbidden-2026-09-05",
    generated: "2026-09-05",
    total: 38,
    by_family: { config: 6, restart: 0, daemon: 32 },
    families: [
      { id: "config", title: "changes configuration or persistent state", rule: "Entering configuration mode, writing, and clearing counters or protocol state." },
      { id: "restart", title: "restarts, reboots, halts or powers off the device", rule: "Nothing that can take a device out of service." },
      { id: "daemon", title: "addresses a named daemon or process", rule: "Per-process debug levels, process lifetime and process internals." },
    ],
  },
  ...over,
});

async function show(k: TacKnowledge = knowledge()) {
  mocks.tacKnowledge.mockResolvedValue(k);
  const utils = render(<IrisKnowledge />);
  await act(async () => { await Promise.resolve(); });
  return utils;
}

beforeEach(() => {
  mocks.tacKnowledge.mockReset();
  mocks.tacTemplates.mockReset();
  mocks.tacTemplate.mockReset();
  mocks.tacTemplates.mockResolvedValue({
    templates: [], defaults: [], count: 0, limit: 200, dialects: [], note: "",
  });
});
afterEach(() => cleanup());

// ── the catalogue header ─────────────────────────────────────────────────────

describe("the coverage page", () => {
  it("names the pinned catalogue and engine it is reading", async () => {
    await show();
    expect(screen.getByRole("heading", { name: "Knowledge", level: 1 })).toBeInTheDocument();
    expect(screen.getByText(/correlix-tac-classes-2026-09-05/)).toBeInTheDocument();
    expect(screen.getByText(/2 issue classes · 3 command intents/)).toBeInTheDocument();
  });

  it("says what did not happen when the catalogue cannot be read", async () => {
    mocks.tacKnowledge.mockRejectedValue(new Error("TypeError: fetch failed"));
    render(<IrisKnowledge />);
    expect(await screen.findByRole("alert")).toHaveTextContent(KNOWLEDGE_FAILED);
  });
});

// ── per-dialect coverage ─────────────────────────────────────────────────────

describe("coverage per vendor dialect", () => {
  it("counts bound intents, verified commands and documented ones on the row", async () => {
    await show();
    const row = screen.getByTestId("tac-dialect-cisco-iosxe");
    expect(row).toHaveTextContent("Cisco IOS-XE");
    expect(row).toHaveTextContent("2 of 3 intents bound");
    expect(row).toHaveTextContent("1 verified · 1 documented");
    expect(row).toHaveTextContent("plan correlix-tac-plan-cisco-iosxe-2026-09-05");
  });

  it("stays collapsed until the operator opens it", async () => {
    await show();
    expect(screen.queryByTestId("tac-dialect-body-cisco-iosxe")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /Cisco IOS-XE/ }));
    expect(screen.getByTestId("tac-dialect-body-cisco-iosxe")).toBeInTheDocument();
  });

  it("names the intents a class cannot answer on this dialect", async () => {
    await show();
    fireEvent.click(screen.getByRole("button", { name: /Cisco IOS-XE/ }));
    const body = within(screen.getByTestId("tac-dialect-body-cisco-iosxe"));
    expect(body.getByText(/1 of 2 intents bound/)).toBeInTheDocument();
    expect(body.getByText(/missing: ospf.database.router/)).toBeInTheDocument();
  });

  it("shows each intent's command and how sure we are of it", async () => {
    await show();
    fireEvent.click(screen.getByRole("button", { name: /Cisco IOS-XE/ }));
    const body = within(screen.getByTestId("tac-dialect-body-cisco-iosxe"));
    expect(body.getByText("show version")).toBeInTheDocument();
    expect(body.getByText(VERIFIED_LABEL)).toBeInTheDocument();
    expect(body.getByText("show ip ospf neighbor detail")).toBeInTheDocument();
    expect(body.getByText(DOC_CLAIMED_LABEL)).toBeInTheDocument();
    expect(body.getByText("this dialect binds no command for it")).toBeInTheDocument();
  });
});

// ── the honest half of coverage ──────────────────────────────────────────────

describe("platforms with no authored plan", () => {
  it("lists them by name instead of leaving them out", async () => {
    await show();
    const un = screen.getByTestId("tac-unplanned");
    expect(un).toHaveTextContent("Nokia SR Linux");
    expect(un).toHaveTextContent("0 of 3 intents bound");
    expect(un).toHaveTextContent("1 classes unplannable");
  });

  it("says so plainly when every recognised platform is planned", async () => {
    await show(knowledge({ unplanned_dialects: [] }));
    expect(screen.queryByTestId("tac-unplanned")).toBeNull();
    expect(screen.getByText("Every platform Correlix recognises carries an authored plan.")).toBeInTheDocument();
  });
});

describe("how the knowledge grows", () => {
  it("points at where research is filed and how it is merged", async () => {
    await show();
    expect(screen.getByText(/ai\/tac\/research/)).toBeInTheDocument();
    expect(screen.getByText(/tac-merge-research\.py/)).toBeInTheDocument();
  });

  it("renders the unknown-output backlog as NOT TRACKED, never as a zero", async () => {
    await show();
    const backlog = screen.getByTestId("tac-backlog");
    expect(backlog).toHaveTextContent(BACKLOG_NOT_TRACKED);
    expect(backlog.textContent).not.toMatch(/\b0\b/);
  });
});

// ── the owner's output-only command policy (2026-09-05) ─────────────────────
//
// The page must say what Correlix WILL NOT LEARN, and must say it as a COUNT.
// A config / restart / daemon command is not knowledge Correlix holds, and this
// page is knowledge — so the count is rendered and the command never is.

describe("the output-only command policy", () => {
  it("states the excluded total and the three family counts, and nothing else", async () => {
    await show();
    const line = screen.getByTestId("tac-policy-excluded");
    expect(line).toHaveTextContent("Excluded by policy: 38");
    expect(line).toHaveTextContent("config 6");
    expect(line).toHaveTextContent("restart 0");
    expect(line).toHaveTextContent("daemon 32");
  });

  it("names the three families and pins the policy version", async () => {
    await show();
    expect(screen.getByRole("heading", { name: "What Correlix will not learn", level: 2 })).toBeInTheDocument();
    expect(screen.getByText("changes configuration or persistent state")).toBeInTheDocument();
    expect(screen.getByText("restarts, reboots, halts or powers off the device")).toBeInTheDocument();
    expect(screen.getByText("addresses a named daemon or process")).toBeInTheDocument();
    expect(screen.getByText(/correlix-tac-forbidden-2026-09-05/)).toBeInTheDocument();
  });

  it("never renders a forbidden command anywhere on the page", async () => {
    const { container } = await show();
    for (const command of ["configure terminal", "reload", "diagnose test application", "write memory"]) {
      expect(container.textContent).not.toContain(command);
    }
  });

  it("says so plainly when nothing was excluded, rather than showing a bare 0", async () => {
    await show(knowledge({
      command_policy: {
        version: "correlix-tac-forbidden-2026-09-05",
        total: 0,
        by_family: { config: 0, restart: 0, daemon: 0 },
        families: [],
      },
    }));
    expect(screen.getByTestId("tac-policy-excluded")).toHaveTextContent(COMMAND_POLICY_NO_EXCLUSIONS);
  });

  it("shows a dialect's own exclusion count on its row, as a count", async () => {
    await show();
    expect(screen.getByTestId("tac-dialect-cisco-iosxe")).toHaveTextContent("7 excluded by policy");
  });
});

// ── command templates (tracker 250) ──────────────────────────────────────────
//
// The Knowledge page is where Correlix says what it knows. The command sets an
// escalation can run from are part of that: its own defaults, generated from the
// plans above, and the tenant's own — with what each one CHANGED about the
// default it forked, because a fork whose difference is invisible is a fork
// nobody can review.

describe("the command templates tab", () => {
  it("lists Correlix's defaults with their version and the standing policy", async () => {
    mocks.tacTemplates.mockResolvedValue({
      templates: [],
      defaults: [{
        id: "correlix:cisco-iosxe:baseline", dialect: "cisco-iosxe",
        name: "Cisco IOS-XE — TAC baseline", source: "correlix-default",
        steps: [{ title: "", command: "show version" }], version: 1,
      }],
      count: 0, limit: 200, dialects: ["cisco-iosxe"], note: "",
    });
    await show();
    const list = await screen.findByTestId("tac-tpl-defaults");
    expect(list.textContent).toContain("Cisco IOS-XE — TAC baseline");
    expect(list.textContent).toContain("Correlix default v1");
    expect(screen.getByTestId("tac-tpl-policy").textContent).toContain("Output only");
  });

  it("says plainly when the tenant has saved none — never an empty table read as coverage", async () => {
    await show();
    expect((await screen.findByTestId("tac-tpl-none")).textContent)
      .toContain("saved no command set yet");
  });

  it("shows a tenant set's difference from the default it was forked from", async () => {
    mocks.tacTemplates.mockResolvedValue({
      templates: [{
        id: "tpl-1", dialect: "cisco-iosxe", name: "ACME IOS-XE baseline", source: "tenant",
        based_on: "correlix:cisco-iosxe:baseline", version: 2, created_by: "noc@acme",
        steps: [{ title: "", command: "show ip nhrp brief" }],
      }],
      defaults: [], count: 1, limit: 200, dialects: ["cisco-iosxe"], note: "",
    });
    mocks.tacTemplate.mockResolvedValue({
      template: {
        id: "tpl-1", dialect: "cisco-iosxe", name: "ACME IOS-XE baseline", source: "tenant",
        based_on: "correlix:cisco-iosxe:baseline", version: 2, steps: [],
      },
      editable: true,
      diff_vs_default: [
        { kind: "added", command: "show ip nhrp brief" },
        { kind: "removed", command: "show version" },
      ],
    });
    await show();
    const row = await screen.findByTestId("tac-tpl-tpl-1");
    await act(async () => { fireEvent.click(within(row).getByRole("button")); });
    const diff = await screen.findByTestId("tac-tpl-diff-tpl-1");
    expect(diff.textContent).toContain("added");
    expect(diff.textContent).toContain("show ip nhrp brief");
    expect(diff.textContent).toContain("removed");
    expect(diff.textContent).toContain("show version");
  });
});
