# Correlix documentation portal

Customer-facing product documentation for Correlix, built with
[Docusaurus](https://docusaurus.io/). The same build serves two homes: embedded
in the product at `/docs/` (the in-app Help drawer) and standalone at
`docs.correlix.io` when built with `DOCS_BASE_URL=/`.

## Read before writing

- **[`STYLE.md`](STYLE.md)** — the binding style guide: voice, banned words and
  shapes, the five page types and their required structure, the information
  architecture, the terminology table, and the sample-data rule.
- **[`AUDIT_2026-09-03.md`](AUDIT_2026-09-03.md)** — what the portal looked like
  before the 2026-09 rebuild, what shipped that it did not cover, and the
  benchmark study behind the style guide.

## Structure

| Path | What it is |
|---|---|
| `docs/` | All content, as Markdown with `title`, `description` and `page_type` in front matter. |
| `sidebars.js` | The navigation, declared **explicitly**. A page's place in the sidebar is independent of its file path. |
| `docusaurus.config.js` | Site config. `onBrokenLinks` is `throw`. |
| `src/css/custom.css` | The theme. |
| `scripts/generate-reference.py` | Generates three reference pages from source. |
| `tests/voice.test.js` | The mechanical half of `STYLE.md`. |

## Three pages are generated

`docs/reference/api.md`, `docs/reference/feature-flags.md` and
`docs/reference/alert-rules.md` are written by a script from the route table,
the flag reads in the backend, and the shipped alert rule files. Do not edit
them by hand:

```bash
python3 docs-portal/scripts/generate-reference.py
```

## Some file paths are load-bearing

`src/backend/ai/docs_corpus/` is a byte-for-byte mirror of `docs/`, compiled
into the backend so Iris can cite documentation pages, and
`src/backend/ai/docs_corpus_drift_test.go` fails the build when the two
disagree. `src/backend/ai/docs_index_test.go` additionally asserts that specific
questions retrieve specific slugs, so these paths must keep their subject
matter:

```
intro.md (slug /)                        onboard-devices/streaming-gnmi
getting-started/quickstart               send-data/traps
onboard-devices/snmp-discovery           send-data/syslog
dashboards-reports/reports               monitoring/create-a-monitor
reference/connectivity-requirements      incident-response/*
```

The explicit sidebar exists so those paths can stay put while the reader sees a
coherent structure.

## Develop

```bash
npm install
npm start          # dev server with hot reload
npm run build      # production build → ./build
npm run serve      # serve the production build locally
```

Requires Node.js 18 or later.

## Before you open a change

```bash
cd docs-portal
npm test                                # voice, structure, front matter, links
npm run build                           # onBrokenLinks is 'throw'
cd .. && scripts/sync-docs-corpus.sh    # mirror into the Iris corpus
go test ./ai/...                        # from src/backend: drift + retrieval
```

`VOICE_FULL=1 npm test` prints every hit instead of the first 40, which helps
when working through a backlog.
