// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package devreach

import "testing"

func TestFold(t *testing.T) {
	maxUp := map[string]float64{"a": 1, "b": 0, "c": 1}
	minUp := map[string]float64{"a": 1, "b": 0, "c": 0}
	for dev, want := range map[string]string{"a": Up, "b": Down, "c": Partial, "nope": Unknown} {
		if got := Fold(maxUp, minUp, dev); got != want {
			t.Errorf("%s: %s, want %s", dev, got, want)
		}
	}
	// A store that could not be read gives empty maps: unknown, never down.
	if got := Fold(nil, nil, "a"); got != Unknown {
		t.Fatalf("unread store: %s", got)
	}
}
