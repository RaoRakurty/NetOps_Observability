// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	"netops/backend/collectors"
)

// routing_direction_enrichment.go — exports the directed forwarding pairs computed by
// the BGP-LS collector's SPF (collectors.FetchRoutingDirection) to the shared
// enrichment dir as routing_direction.json, for the correlation engine's C7.5
// routing-direction source (the precedence-3, computed-direction signal).
//
// Mirrors the other enrichers: atomic write, 60s refresh, no-op without the shared
// volume. The pairs are device names (BGP-LS hostnames = correlation device ids), so
// no further resolution is needed; the per-tenant oracle only orients pairs whose
// devices appear in that tenant's component → zero-leak. Empty (no LSDB) → an empty
// file → the source abstains, exactly the engine's pre-C7.5 behaviour.

func (s *server) startRoutingDirectionEnrichment(ctx context.Context) {
	dir := os.Getenv("TENANT_ENRICHMENT_DIR")
	if dir == "" {
		return
	}
	write := func() {
		pairs, err := collectors.FetchRoutingDirection(ctx)
		if err != nil {
			// KEEP THE LAST FILE, AND SAY WHY (tracker 307). This is the caller the
			// fold hurt most: FetchRoutingDirection used to answer an unread channel
			// with an empty slice and a nil error, so this enricher overwrote
			// routing_direction.json with `[]` — the C7.5 direction source then
			// abstained on every pair in the estate, and abstaining is silent by
			// design. Keeping the previous file degrades to "stale direction" instead
			// of "no direction", which is recoverable; the log line is the only thing
			// that distinguishes this from a genuinely empty LSDB.
			if errShareChannelUnread(err) {
				logWarn("enrichment", "routing-direction evidence unread — routing_direction.json is left as it was, so the C7.5 direction source is working from the PREVIOUS SPF result, not this one",
					map[string]any{"error": err.Error()})
			}
			return
		}
		if pairs == nil {
			pairs = []collectors.RoutingPair{}
		}
		data, err := json.Marshal(pairs)
		if err != nil {
			log.Printf("routing-direction-enrichment: marshal: %v", err)
			return
		}
		if err := writeFileAtomic(filepath.Join(dir, "routing_direction.json"), data, 0o644); err != nil {
			log.Printf("routing-direction-enrichment: write: %v", err)
			return
		}
		if len(pairs) > 0 {
			log.Printf("routing-direction-enrichment: exported %d forwarding pair(s)", len(pairs))
		}
	}
	go func() {
		write()
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				write()
			}
		}
	}()
}
