// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package lex

import (
	"reflect"
	"testing"
)

func TestSplit(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{"What is going on right now? What should the NOC focus on first?", []string{"What is going on right now?", "What should the NOC focus on first?"}},
		{"cpu on edge-1; memory on edge-2", []string{"cpu on edge-1", "memory on edge-2"}},
		{"show cpu on edge-1 and also list open incidents", []string{"show cpu on edge-1", "list open incidents"}},
		{"show cpu on edge-1, then show memory", []string{"show cpu on edge-1", "show memory"}},
		{"Show jitter. Then list incidents.", []string{"Show jitter", "Then list incidents"}},
		// one question: unchanged
		{"latency to 10.0.0.1 over the last hour?", []string{"latency to 10.0.0.1 over the last hour?"}},
		{"cpu and memory on edge-1", []string{"cpu and memory on edge-1"}},
		{"version v1.2 devices", []string{"version v1.2 devices"}},
		// more than MaxParts: read whole, as before
		{"a? b? c? d?", []string{"a? b? c? d?"}},
		{"   ", nil},
		{"???", []string{"???"}},
	} {
		if got := Split(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("Split(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
