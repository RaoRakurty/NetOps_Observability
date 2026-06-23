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

// probe_paths_enrichment.go — exports measured forwarding paths (traceroute / probe
// hop sequences) to the shared enrichment dir as probe_paths.json, for the C7.4
// active-path-trace direction source. Hop order IS direction: an earlier hop is
// upstream of a later one — the highest-precedence (measured) direction signal.
//
// Mirrors the other enrichment exporters: atomic write, 60s refresh, no-op without
// the shared volume. NOT tenant-tagged — the correlation service resolves each hop
// IP → device through the per-tenant EntityResolver (C7.1), so a tenant only ever
// orients pairs of its OWN devices (a hop in another tenant won't resolve → that
// pair abstains): zero-leak by construction. Absent paths → the source abstains.

type probePathExport struct {
	Hops []string `json:"hops"` // ordered hop IPs = the measured forwarding path
}

func (s *server) startProbePathsEnrichment(ctx context.Context) {
	dir := os.Getenv("TENANT_ENRICHMENT_DIR")
	if dir == "" {
		return
	}
	write := func() {
		raw, err := collectors.FetchProbePaths(ctx)
		if err != nil || raw == "" {
			return // no paths published (traceroute off / Redis empty) → keep last file
		}
		var paths []collectors.PathResult
		if json.Unmarshal([]byte(raw), &paths) != nil {
			return
		}
		out := make([]probePathExport, 0, len(paths))
		for _, p := range paths {
			ips := make([]string, 0, len(p.Hops))
			for _, h := range p.Hops {
				if h.IP != "" { // skip unresponsive hops; relative order is preserved
					ips = append(ips, h.IP)
				}
			}
			if len(ips) >= 2 { // need ≥2 resolvable hops for any direction
				out = append(out, probePathExport{Hops: ips})
			}
		}
		data, err := json.Marshal(out)
		if err != nil {
			log.Printf("probe-paths-enrichment: marshal: %v", err)
			return
		}
		if err := writeFileAtomic(filepath.Join(dir, "probe_paths.json"), data, 0o644); err != nil {
			log.Printf("probe-paths-enrichment: write: %v", err)
			return
		}
		log.Printf("probe-paths-enrichment: exported %d path(s)", len(out))
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
