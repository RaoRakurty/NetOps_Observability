// IrisLane.test.tsx — the IRIS co-pilot lane of the investigation surface.
//
// Two contracts are pinned here.
//
// GROUNDING: the ask carries the investigation and NOTHING else — the
// correlation id when a case drives it, the operator's own symptom words when
// one does not. No secrets, no other tenant's data, no other API call (§15
// LLM06 sensitive-information disclosure, LLM08 no excessive agency).
//
// OUTPUT HANDLING (§15 LLM02): every model-authored string — the narrative, the
// skill name, the tool name, each citation label — is rendered as ESCAPED React
// text, and a citation href is a link ONLY when it is a same-origin relative
// path. A model that answers with markup gets that markup shown as characters.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
import type { AiAnswer, AiCitation, AiSkillHop } from "../../services/api";

// The WHOLE api surface is mocked, so "the lane called something else" is an
// assertable failure rather than an invisible network call.
const mocks = vi.hoisted(() => ({
  aiAsk: vi.fn(),
  other: {
    correlations: vi.fn(), correlationDetail: vi.fn(), eventsFeed: vi.fn(),
    metricNames: vi.fn(), metricsQuery: vi.fn(), pathsHealth: vi.fn(),
    probePaths: vi.fn(), flowsByType: vi.fn(), topTalkers: vi.fn(),
    copilotChat: vi.fn(), devices: vi.fn(),
  } as Record<string, ReturnType<typeof vi.fn>>,
}));
vi.mock("../../services/api", () => ({ api: { aiAsk: mocks.aiAsk, ...mocks.other } }));

const aiAsk = mocks.aiAsk;
const otherApi = mocks.other;

import IrisLane, { chainHops, citeProvenance, hopSelectionLabel, safeCiteHref } from "./IrisLane";

const answer = (over: Partial<AiAnswer> = {}): AiAnswer => ({
  mode: "grounded", intent: "explain", modules: [], text: "Nothing is wrong right now.",
  citations: [], disclaimers: [], ...over,
} as AiAnswer);

const cite = (over: Partial<AiCitation> = {}): AiCitation =>
  ({ id: "c1", kind: "correlation", label: "P-ABC123", href: "/correlations/1", ...over });

const hop = (over: Partial<AiSkillHop> = {}): AiSkillHop =>
  ({ name: "bgp-session-down", layer: "bgp", version: 3, selected: "entry", round: 1, ...over });

beforeEach(() => {
  aiAsk.mockReset();
  Object.values(otherApi).forEach((f) => f.mockReset());
  aiAsk.mockResolvedValue(answer());
});
afterEach(() => cleanup());

// ── safeCiteHref: the link allowlist ─────────────────────────────────────────

describe("safeCiteHref", () => {
  it.each(["/correlations/1", "/api/events/feed?from=1h", "/", "/a#b"])(
    "keeps the same-origin relative path %p", (h) => { expect(safeCiteHref(h)).toBe(h); },
  );

  it.each([
    "//evil.example/steal",
    "/\\evil.example",              // browsers normalise "/\" to "//"
    "javascript:alert(1)",
    "JavaScript:alert(1)",
    "http://evil.example",
    "https://evil.example",
    "data:text/html,<script>",
    "vbscript:msgbox(1)",
    "correlations/1",               // not rooted: could resolve anywhere
    "",
    "   ",
  ])("refuses %p", (h) => { expect(safeCiteHref(h)).toBeNull(); });

  it("refuses an absent href", () => { expect(safeCiteHref(undefined)).toBeNull(); });

  it("trims before deciding, so whitespace cannot smuggle a scheme", () => {
    expect(safeCiteHref("  javascript:alert(1)")).toBeNull();
    expect(safeCiteHref("  /ok")).toBe("/ok");
  });
});

// ── citeProvenance ───────────────────────────────────────────────────────────

describe("citeProvenance", () => {
  it("names the tool and pluralises its id count", () => {
    expect(citeProvenance(cite({ tool: "get_correlation", ids: ["a"] }))).toBe("get_correlation · 1 id");
    expect(citeProvenance(cite({ tool: "get_correlation", ids: ["a", "b"] }))).toBe("get_correlation · 2 ids");
  });

  it("names the tool alone when it returned no ids", () => {
    expect(citeProvenance(cite({ tool: "get_correlation" }))).toBe("get_correlation");
    expect(citeProvenance(cite({ tool: "get_correlation", ids: [] }))).toBe("get_correlation");
  });

  it("is empty when the backend named no tool — never an invented one", () => {
    expect(citeProvenance(cite())).toBe("");
    expect(citeProvenance(cite({ tool: "   " }))).toBe("");
  });
});

// ── the ask ──────────────────────────────────────────────────────────────────

describe("the ask carries the investigation and nothing else", () => {
  it("sends the correlation id when a case drives the investigation", async () => {
    render(<IrisLane caseId="corr-abc123" />);
    fireEvent.click(screen.getByRole("button", { name: "Ask Iris" }));
    await waitFor(() => expect(aiAsk).toHaveBeenCalledTimes(1));
    expect(aiAsk).toHaveBeenCalledWith(
      "Explain this problem and what to check next.",
      { correlation_id: "corr-abc123" },
    );
  });

  it("sends the operator's own symptom words when no case backs it", async () => {
    render(<IrisLane symptomLabel="An app is slow or unreachable" />);
    fireEvent.click(screen.getByRole("button", { name: "Ask Iris" }));
    await waitFor(() => expect(aiAsk).toHaveBeenCalledTimes(1));
    const [question, ctx] = aiAsk.mock.calls[0];
    expect(question).toContain("An app is slow or unreachable");
    expect(ctx).toEqual({});
  });

  it("asks a bare question when neither a case nor a symptom is chosen", async () => {
    render(<IrisLane />);
    fireEvent.click(screen.getByRole("button", { name: "Ask Iris" }));
    await waitFor(() => expect(aiAsk).toHaveBeenCalledTimes(1));
    expect(aiAsk).toHaveBeenCalledWith("What is going on right now?", {});
  });

  it("calls NOTHING but the ask endpoint", async () => {
    render(<IrisLane caseId="corr-abc123" symptomLabel="A site or device is down" />);
    fireEvent.click(screen.getByRole("button", { name: "Ask Iris" }));
    await waitFor(() => expect(aiAsk).toHaveBeenCalledTimes(1));
    for (const [name, fn] of Object.entries(otherApi)) {
      expect(fn, `${name} must not be called`).not.toHaveBeenCalled();
    }
    // and the grounding object carries exactly one key
    expect(Object.keys(aiAsk.mock.calls[0][1] as object)).toEqual(["correlation_id"]);
  });

  it("names the endpoint it reads and offers no execution", () => {
    render(<IrisLane />);
    expect(screen.getByText("/api/ai/ask")).toBeInTheDocument();
    expect(screen.getByText(/never changes anything on your network/i)).toBeInTheDocument();
  });

  it("disables the button while thinking and re-labels it after an answer", async () => {
    let resolve!: (a: AiAnswer) => void;
    aiAsk.mockReturnValue(new Promise<AiAnswer>((r) => { resolve = r; }));
    render(<IrisLane />);
    fireEvent.click(screen.getByRole("button", { name: "Ask Iris" }));
    const busy = await screen.findByRole("button", { name: "Thinking…" });
    expect(busy).toBeDisabled();
    resolve(answer());
    expect(await screen.findByRole("button", { name: "Re-ask" })).toBeEnabled();
    expect(aiAsk).toHaveBeenCalledTimes(1);
  });

  it("renders the failure verbatim instead of an empty answer", async () => {
    aiAsk.mockRejectedValue(new Error("503 copilot disabled"));
    render(<IrisLane />);
    fireEvent.click(screen.getByRole("button", { name: "Ask Iris" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("503 copilot disabled");
  });

  it("renders the drawer control only when the shell offered one", async () => {
    const open = vi.fn();
    const { unmount } = render(<IrisLane onOpenDrawer={open} />);
    fireEvent.click(screen.getByRole("button", { name: "Open Iris" }));
    expect(open).toHaveBeenCalledTimes(1);
    unmount();
    render(<IrisLane />);
    expect(screen.queryByRole("button", { name: "Open Iris" })).toBeNull();
  });
});

// ── provenance + untrusted output ────────────────────────────────────────────

describe("provenance chips", () => {
  it("renders the skill chip only when the backend named a skill", async () => {
    aiAsk.mockResolvedValue(answer({ skill: { name: "bgp_triage", version: "3", layer: "routing" } }));
    render(<IrisLane />);
    fireEvent.click(screen.getByRole("button", { name: "Ask Iris" }));
    const chip = await screen.findByTestId("iris-skill-chip");
    expect(chip).toHaveTextContent("Skill: bgp_triage v3 · routing");
  });

  it("renders NO skill chip when the backend named none", async () => {
    aiAsk.mockResolvedValue(answer({ text: "answered" }));
    render(<IrisLane />);
    fireEvent.click(screen.getByRole("button", { name: "Ask Iris" }));
    expect(await screen.findByText("answered")).toBeInTheDocument();
    expect(screen.queryByTestId("iris-skill-chip")).toBeNull();
  });

  it("renders a per-citation provenance chip only when a tool is named", async () => {
    aiAsk.mockResolvedValue(answer({
      citations: [
        cite({ id: "a", label: "with-tool", tool: "get_correlation", ids: ["x", "y"] }),
        cite({ id: "b", label: "no-tool" }),
      ],
    }));
    render(<IrisLane />);
    fireEvent.click(screen.getByRole("button", { name: "Ask Iris" }));
    expect(await screen.findByTestId("iris-cite-provenance")).toHaveTextContent("get_correlation · 2 ids");
    expect(screen.getAllByTestId("iris-cite-provenance")).toHaveLength(1);
    expect(screen.getByText("no-tool")).toBeInTheDocument();
  });

  it("renders the disclaimers the backend attached", async () => {
    aiAsk.mockResolvedValue(answer({ disclaimers: ["Evidence-only mode.", "No action was taken."] }));
    render(<IrisLane />);
    fireEvent.click(screen.getByRole("button", { name: "Ask Iris" }));
    expect(await screen.findByText("Evidence-only mode.")).toBeInTheDocument();
    expect(screen.getByText("No action was taken.")).toBeInTheDocument();
  });
});

// ── the investigation chain (Phase A2) ───────────────────────────────────────

describe("chainHops", () => {
  it("draws nothing for a pre-A2 backend or a single-method turn", () => {
    expect(chainHops(null)).toEqual([]);
    expect(chainHops(answer())).toEqual([]);
    expect(chainHops(answer({ chain: [hop()] }))).toEqual([]);
  });

  it("keeps every hop, in the backend's order, once there is a real chain", () => {
    const chain = [hop(), hop({ name: "interface-down", selected: "rule", round: 2 })];
    expect(chainHops(answer({ chain })).map((h) => h.name))
      .toEqual(["bgp-session-down", "interface-down"]);
  });
});

describe("hopSelectionLabel", () => {
  it.each([["entry", "entry"], ["rule", "rule"], ["model", "proposed"]])(
    "renders %p as %p", (selected, want) => {
      expect(hopSelectionLabel(hop({ selected }))).toBe(want);
    });

  it("passes an unrecognised value through instead of inventing one", () => {
    expect(hopSelectionLabel(hop({ selected: "future-mode" }))).toBe("future-mode");
    expect(hopSelectionLabel(hop({ selected: undefined }))).toBe("");
  });
});

describe("the chain breadcrumb", () => {
  it("renders one chip per hop, in order, with how it was chosen", async () => {
    aiAsk.mockResolvedValue(answer({
      skill: { name: "interface-down", version: 2, layer: "physical" },
      chain: [
        hop(),
        hop({ name: "interface-down", layer: "physical", version: 2, selected: "rule", round: 2,
              reason: "the RCA verdict names a link" }),
      ],
    }));
    render(<IrisLane />);
    fireEvent.click(screen.getByRole("button", { name: "Ask Iris" }));
    await screen.findByTestId("iris-chain");
    const chips = screen.getAllByTestId("iris-chain-hop");
    expect(chips.map((c) => c.textContent)).toEqual([
      "bgp-session-down · entry",
      "interface-down · rule",
    ]);
    expect(chips[1]).toHaveAttribute("title", "the RCA verdict names a link");
    // The skill chip still names the LAST method, unchanged from Phase A.
    expect(screen.getByTestId("iris-skill-chip")).toHaveTextContent("Skill: interface-down v2 · physical");
  });

  it("renders NO breadcrumb when the backend sent no chain", async () => {
    aiAsk.mockResolvedValue(answer({ skill: { name: "bgp-session-down" } }));
    render(<IrisLane />);
    fireEvent.click(screen.getByRole("button", { name: "Ask Iris" }));
    await screen.findByTestId("iris-skill-chip");
    expect(screen.queryByTestId("iris-chain")).toBeNull();
  });

  it("renders a hostile hop name as characters, never as markup", async () => {
    aiAsk.mockResolvedValue(answer({
      chain: [hop({ name: "<img src=x onerror=alert(1)>" }), hop({ name: "interface-down", selected: "model" })],
    }));
    const { container } = render(<IrisLane />);
    fireEvent.click(screen.getByRole("button", { name: "Ask Iris" }));
    const chips = await screen.findAllByTestId("iris-chain-hop");
    expect(chips[0]).toHaveTextContent("<img src=x onerror=alert(1)> · entry");
    expect(chips[1]).toHaveTextContent("interface-down · proposed");
    expect(container.querySelector("img")).toBeNull();
    expect(container.innerHTML).toContain("&lt;img");
  });
});

describe("model output is untrusted (§15 LLM02)", () => {
  it("renders the narrative as text — markup appears literally, not as elements", async () => {
    const hostile = '<img src=x onerror="alert(1)"> and <b>bold</b>';
    aiAsk.mockResolvedValue(answer({ text: hostile }));
    const { container } = render(<IrisLane />);
    fireEvent.click(screen.getByRole("button", { name: "Ask Iris" }));
    expect(await screen.findByText(hostile)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    expect(container.innerHTML).toContain("&lt;img");
  });

  it("renders a citation with an unsafe href as inert text, never a link", async () => {
    aiAsk.mockResolvedValue(answer({
      citations: [
        cite({ id: "bad", label: "javascript payload", href: "javascript:alert(1)" }),
        cite({ id: "rel", label: "protocol relative", href: "//evil.example/x" }),
        cite({ id: "abs", label: "absolute", href: "https://evil.example/x" }),
        cite({ id: "ok", label: "safe link", href: "/correlations/1" }),
      ],
    }));
    const { container } = render(<IrisLane />);
    fireEvent.click(screen.getByRole("button", { name: "Ask Iris" }));
    await screen.findByText("safe link");

    const links = Array.from(container.querySelectorAll("a"));
    expect(links).toHaveLength(1);
    expect(links[0]).toHaveAttribute("href", "/correlations/1");

    for (const label of ["javascript payload", "protocol relative", "absolute"]) {
      const el = screen.getByText(label);
      expect(el.tagName).toBe("SPAN");
      expect(el.closest("a")).toBeNull();
    }
    expect(container.innerHTML).not.toContain("javascript:");
    expect(container.innerHTML).not.toContain("evil.example");
  });

  it("renders a skill name containing markup as characters", async () => {
    aiAsk.mockResolvedValue(answer({ skill: { name: "<script>x</script>" } }));
    const { container } = render(<IrisLane />);
    fireEvent.click(screen.getByRole("button", { name: "Ask Iris" }));
    const chip = await screen.findByTestId("iris-skill-chip");
    expect(chip).toHaveTextContent("Skill: <script>x</script>");
    expect(container.querySelector("script")).toBeNull();
  });

  it("falls back to an honest placeholder when the model returned no text", async () => {
    aiAsk.mockResolvedValue(answer({ text: "" }));
    render(<IrisLane />);
    fireEvent.click(screen.getByRole("button", { name: "Ask Iris" }));
    expect(await screen.findByText("No answer.")).toBeInTheDocument();
  });
});
