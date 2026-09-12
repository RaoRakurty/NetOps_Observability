// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

import (
	"fmt"
	"time"
)

// ── #103 delivery-error classification ──────────────────────────────────────

// PermanentDeliveryError marks a provider rejection that retries cannot fix
// (payload 400, revoked credential 401/403) — dead-letter, don't burn retries.
type PermanentDeliveryError struct{ Err error }

func (e PermanentDeliveryError) Error() string { return e.Err.Error() }
func (e PermanentDeliveryError) Unwrap() error { return e.Err }

// RateLimitedError carries the provider's Retry-After so the outbox honors it
// instead of the default backoff curve.
type RateLimitedError struct{ After time.Duration }

func (e RateLimitedError) Error() string {
	return fmt.Sprintf("rate limited; retry after %s", e.After)
}

func DedupeKey(tenant, corrID, system string) string {
	return fmt.Sprintf("%s:%s:%s", normTenant(tenant), corrID, system)
}
