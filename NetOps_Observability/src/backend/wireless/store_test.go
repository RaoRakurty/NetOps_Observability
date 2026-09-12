// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package wireless

import "testing"

// Moved from the integrator with the store (the data-column encoder contract).
// TestWirelessJSONBlobSurfacesEncodeFailures: the `data` column encoder used to
// answer "{}" for an encode failure, so a row landed with every non-column field
// silently dropped and the upsert still reported success.
func TestWirelessJSONBlobSurfacesEncodeFailures(t *testing.T) {
	if _, err := jsonBlob(map[string]string{"ok": "yes"}); err != nil {
		t.Fatalf("a normal record must encode: %v", err)
	}
	if _, err := jsonBlob(map[string]any{"bad": make(chan int)}); err == nil {
		t.Fatal("an unencodable record must return an error, not a silent empty object")
	}
}
