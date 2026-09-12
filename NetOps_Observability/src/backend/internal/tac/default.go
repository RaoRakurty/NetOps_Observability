// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// default.go — the process-wide loaded catalog.
//
// The data is embedded (ai/tac), so loading cannot fail for an environmental
// reason: a failure here is a BUG IN THE DATA, caught by the package's own test
// long before a deployment. Default therefore memoizes the result and exposes
// the error rather than panicking — a caller that cannot get a catalog degrades
// to the honest "TAC escalation is unavailable on this build" path instead of
// taking the api down.

import (
	"sync"

	tacdata "netops/backend/ai/tac"
)

var defaultCatalog = sync.OnceValues(func() (*Catalog, error) { return Load(tacdata.FS) })

// Default returns the shared immutable catalog built from the embedded data.
func Default() (*Catalog, error) { return defaultCatalog() }

// MustDefault is Default for call sites that have already proven the data loads
// (the package's own tests, and the server constructor after it has checked).
// It returns nil on error rather than panicking; callers check.
func MustDefault() *Catalog {
	c, err := Default()
	if err != nil {
		return nil
	}
	return c
}
