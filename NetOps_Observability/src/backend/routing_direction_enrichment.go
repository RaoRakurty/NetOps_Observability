package main

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
			return // Redis down → keep the last file
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
