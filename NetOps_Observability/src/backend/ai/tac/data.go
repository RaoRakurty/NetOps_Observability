// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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

// FS carries the taxonomy, the OUTPUT-ONLY command policy and every authored
// dialect plan. research/*.yaml is deliberately NOT embedded: it is merge INPUT
// (scripts/tac-merge-research.py), never something the running platform reads.
//
// forbidden.yaml is the owner's 2026-09-05 command policy (config / restart /
// daemon are not knowledge Correlix carries). It is embedded because the LOADER
// and the GATE both re-apply it at runtime — the purge that keeps the corpus
// clean is the first layer, not the only one.
//
//go:embed classes.yaml forbidden.yaml plans/*.yaml
var FS embed.FS
