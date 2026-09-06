// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

// catalog_holder.go — the atomically-swapped application catalog (Phase-2
// W4.7, extracted from package main's appid_catalog.go): the holder over the
// parsed feed set, multi-format feed reload with per-file error accounting,
// and the periodic refresh loop. The feeds dir comes from the caller (env
// stays in main); the resolve/status handlers and per-tenant signal gathering
// stay in main.

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

type CatalogHolder struct {
	cur      atomic.Pointer[Catalog]
	dom      atomic.Pointer[DomainIndex] // global domain matcher (#81 P2, from M365 urls)
	feedsDir string
}

func NewCatalogHolder(feedsDir string) *CatalogHolder {
	h := &CatalogHolder{feedsDir: feedsDir}
	h.cur.Store(NewCatalog(nil)) // empty until loaded; resolve is safe + unknown
	h.dom.Store(NewDomainIndex())
	return h
}

// FeedsDir reports the configured feed directory ("" = catalog disabled).
func (h *CatalogHolder) FeedsDir() string { return h.feedsDir }

func (h *CatalogHolder) Get() *Catalog         { return h.cur.Load() }
func (h *CatalogHolder) Domains() *DomainIndex { return h.dom.Load() }

// feedParsers maps a snapshot filename to its parser.
var feedParsers = []struct {
	file  string
	parse func([]byte) ([]CatalogEntry, error)
}{
	{"aws.json", ParseAWS},
	{"azure.json", ParseAzure},
	{"gcp.json", ParseGCP},
	{"m365.json", ParseM365},
}

// reload rebuilds the catalog from the snapshot dir and swaps it in. Missing or
// unparseable files are skipped (best-effort, offline-safe); returns the new size.
// A per-file error is logged via the returned slice, never fatal.
func (h *CatalogHolder) Reload() (int, []error) {
	if h.feedsDir == "" {
		return 0, nil
	}
	var entries []CatalogEntry
	var errs []error
	for _, fp := range feedParsers {
		raw, err := os.ReadFile(filepath.Join(h.feedsDir, fp.file))
		if err != nil {
			continue // feed not present — fine
		}
		es, perr := fp.parse(raw)
		if perr != nil {
			errs = append(errs, perr)
			continue
		}
		entries = append(entries, es...)
	}
	cat := NewCatalog(entries)
	h.cur.Store(cat)
	// #81 P2: build the global domain matcher from the M365 endpoints feed's urls[].
	di := NewDomainIndex()
	if raw, err := os.ReadFile(filepath.Join(h.feedsDir, "m365.json")); err == nil {
		if des, e := M365Domains(raw); e == nil {
			for _, de := range des {
				di.Add(de.Pattern, de.App, SrcDNS, 0) // a domain is a strong signal
			}
		}
	}
	h.dom.Store(di)
	return cat.Size(), errs
}

// startRefresh periodically re-reads the snapshot dir and hot-swaps the catalog,
// so an out-of-band feed refresh (cron running fetch-appid-feeds.sh) is picked up
// without an API restart. No-op unless feeds are configured. Interval from
// APPID_REFRESH_MINUTES (default 360 = 6h; ≤0 disables). The initial load already
// happened synchronously in newServer.
func (h *CatalogHolder) StartRefresh(ctx context.Context, interval time.Duration) {
	if h.feedsDir == "" {
		return
	}
	if interval <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				n, errs := h.Reload()
				if len(errs) > 0 {
					log.Printf("appid: refreshed catalog to %d prefixes (%d feed errors)", n, len(errs))
				}
			}
		}
	}()
}

// ── handlers ──────────────────────────────────────────────────────────────────

// keyAppSignals gathers every identification signal for one record key. An IP
// key consults the global vendor catalog + the tenant's operator prefix
// overrides; ANY key (IP, ENI, cloud resource id, …) additionally consults the
// NGFW app-id and cloud identity-map resolvers, which match exact keys. This is
// the ONE gather path shared by the single resolve, batch resolve and feed
// enrichment — a new source added here lands everywhere at once (#81 P3G).
// Nil-safe on every optional subsystem; tenant-scoped default-closed.
