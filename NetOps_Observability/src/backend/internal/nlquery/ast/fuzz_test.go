// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ast

import (
	"strings"
	"testing"
)

// FuzzDecodeAST: Decode never panics, and nothing it accepts can carry a
// tenant — the re-encoded form of any accepted input has no tenant key.
func FuzzDecodeAST(f *testing.F) {
	f.Add([]byte(good))
	f.Add([]byte(`{"v":1,"query_type":"change_list","target":"change","time_range":{"kind":"relative","last":"24h"}}`))
	f.Add([]byte(`{"v":1,"tenant":"x"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		a, err := Decode(raw)
		if err != nil {
			return
		}
		enc, err := a.Canonical()
		if err != nil {
			t.Fatalf("an accepted AST must re-encode: %v", err)
		}
		if strings.Contains(strings.ToLower(string(enc)), `"tenant`) {
			t.Fatalf("an accepted AST carries a tenant key: %s", enc)
		}
	})
}
