// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package modelc

// examples.go — the example library for example-RAG: worked question → AST
// pairs derived from the golden corpus (N-C6), with every entity id replaced
// by a placeholder so no example can hand the model a usable id. Regenerate
// with NLQ_WRITE_MODEL_EXAMPLES=1 go test ./internal/nlquery -run
// TestWriteModelExamples; examples_test.go proves every entry decodes strictly
// and validates.

import (
	_ "embed"
	"encoding/json"
)

type jsonRaw = json.RawMessage

//go:embed examples.v1.json
var embeddedExamples []byte

// EmbeddedExamples parses the embedded library. A library that does not parse
// is a build defect (examples_test.go); at runtime it degrades to no examples.
func EmbeddedExamples() []Example {
	var f struct {
		Examples []Example `json:"examples"`
	}
	if err := json.Unmarshal(embeddedExamples, &f); err != nil {
		return nil
	}
	return f.Examples
}
