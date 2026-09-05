// Package tacdata is the EMBEDDED TAC-escalation knowledge: the issue-class
// taxonomy and the per-dialect command plans, as reviewed data.
//
// It holds no logic on purpose. It sits under ai/ because this is Iris's
// knowledge surface — the sibling of ai/skills and ai/docs_corpus, and the thing
// the Iris → Knowledge page renders — while the engine that validates and runs
// it lives in internal/tac (CLAUDE.md §2). The split is what lets the data be
// reviewed like a skill and the engine be tested like code.
package tacdata

import "embed"

// FS carries the taxonomy and every authored dialect plan. research/*.yaml is
// deliberately NOT embedded: it is merge INPUT (scripts/tac-merge-research.py),
// never something the running platform reads.
//
//go:embed classes.yaml plans/*.yaml
var FS embed.FS
