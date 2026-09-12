# Network Expert Knowledge Base

The Network Expert KB gives Iris AI **CCIE-level troubleshooting knowledge** so
it can reason about *what to check* and *who owns it* — while live Correlix evidence
always remains the source of truth.

## What it is

- Curated, **vendor-neutral** playbooks under `src/backend/ai/network_expert/*.md`,
  embedded into the binary (`//go:embed`, like `copilot_knowledge.md`) so they ship
  offline and require no network call.
- Parsed + indexed by `src/backend/ai/kb.go` (`LoadKB`). Each playbook has
  frontmatter (`id`, `title`, `owner`, `fault_domains`, `signals`, `keywords`) and
  the standard sections (Symptoms, Fault domains, Correlix evidence to check,
  Supporting/Contradicting/Missing evidence, Recommended owner, Next actions,
  Escalation note, ITSM note template).

> Do **not** paste copyrighted books/courses here. Only original, curated,
> RFC-/best-practice-derived content.

## How it's used

1. **RCA enrichment (primary).** When explaining a problem, the orchestrator
   retrieves the top playbooks keyed on the problem's title + missing evidence,
   biased by its owner domain, and adds them to the prompt under a clearly fenced
   *"SUPPORTING NETWORK-ENGINEERING KNOWLEDGE (general guidance, NOT Correlix
   evidence — the evidence above wins)"* block. The referenced playbook is
   disclosed in the answer's disclaimers.
2. **Direct query.** "How do I troubleshoot a BGP flap?" / `/playbook bgp flap`
   routes to `network_kb` intent → `answerKB`, which returns the matching playbook
   **deterministically** (no LLM needed — curated content) as an
   `investigation_plan` answer with owner + next actions, framed as guidance.

## Retrieval

`KB.Search(query, hints, limit)` scores playbooks by term overlap (keywords 3,
fault domain 2, signal 2, title 2, body 1; hint overlaps +2) with a stopword filter
and a **minimum-score floor of 3** so an off-topic question gets *no* playbook
rather than a spurious one. Retrieval is supporting context only — it never
overrides live evidence.

## Adding a playbook

1. Add `src/backend/ai/network_expert/<id>.md` with the frontmatter + sections.
2. `go test ./ai/` — `TestLoadKB` validates it parses (id/title/keywords/next
   actions present); add a retrieval case to `TestKBSearch` for the symptom.
3. Nothing else — it's embedded and indexed at startup.
