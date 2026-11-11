// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package logroutine

import (
	"context"
	"net"
	"net/url"
	"sync"
	"time"

	"netops/backend/nms"
)

// ControllerStore is the slice of the NMS store the controller addresses are
// read from. Both reads are tenant-scoped (FORCE-RLS on Postgres).
type ControllerStore interface {
	List(ctx context.Context, tenant string, cross bool) ([]nms.Integration, error)
	Devices(ctx context.Context, tenant string, cross bool, integrationID string) ([]nms.ControllerDevice, error)
}

// ControllerTTL is how long one principal scope's controller addresses are
// reused. Controller nodes change rarely; a log search must not cost a
// database read of a whole fabric's inventory each time.
const ControllerTTL = 2 * time.Minute

// maxCacheEntries bounds the cache (§9): one entry per tenant scope.
const maxCacheEntries = 1024

// ControllerAddrs resolves the addresses of a principal's own SD-WAN
// controller nodes. Safe for concurrent use. A nil *ControllerAddrs (no
// controller integrations on this install) resolves none.
type ControllerAddrs struct {
	store ControllerStore
	ttl   time.Duration
	now   func() time.Time

	mu      sync.Mutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	addrs []string
	at    time.Time
}

// NewControllerAddrs builds the resolver over st. A nil store resolves none.
func NewControllerAddrs(st ControllerStore, ttl time.Duration, now func() time.Time) *ControllerAddrs {
	if ttl <= 0 {
		ttl = ControllerTTL
	}
	if now == nil {
		now = time.Now
	}
	return &ControllerAddrs{store: st, ttl: ttl, now: now, entries: map[string]cacheEntry{}}
}

// Addrs returns the controller node addresses visible to (tenant, cross):
// for a tenant principal only its own integrations' nodes, for a cross-tenant
// principal every tenant's (the search it serves reads every tenant too).
//
// A node is a controller's OWN node (Managed=false: vManage, vSmart, vBond),
// never a managed edge: an edge's sessions to another edge are not routine.
// Its system IP, its management address and the integration's own address
// (when the base URL names an IP) are kept.
//
// On a store error the error is returned with no addresses; the caller hides
// fewer records, never more.
func (c *ControllerAddrs) Addrs(ctx context.Context, tenant string, cross bool) ([]string, error) {
	if c == nil || c.store == nil {
		return nil, nil
	}
	key := tenant + "\x00own"
	if cross {
		key = tenant + "\x00cross"
	}
	now := c.now()
	c.mu.Lock()
	if e, ok := c.entries[key]; ok && now.Sub(e.at) < c.ttl {
		c.mu.Unlock()
		return append([]string(nil), e.addrs...), nil
	}
	c.mu.Unlock()

	addrs, err := c.read(ctx, tenant, cross)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if len(c.entries) >= maxCacheEntries {
		c.entries = map[string]cacheEntry{}
	}
	c.entries[key] = cacheEntry{addrs: addrs, at: now}
	c.mu.Unlock()
	return append([]string(nil), addrs...), nil
}

func (c *ControllerAddrs) read(ctx context.Context, tenant string, cross bool) ([]string, error) {
	ints, err := c.store.List(ctx, tenant, cross)
	if err != nil {
		return nil, err
	}
	var raw []string
	for _, ic := range ints {
		if !ic.Enabled {
			continue
		}
		if u, err := url.Parse(ic.BaseURL); err == nil && net.ParseIP(u.Hostname()) != nil {
			raw = append(raw, u.Hostname())
		}
		// The integration's own tenant, never the caller's word for it: a
		// cross-tenant principal still reads each integration's devices under
		// that integration's owner.
		devs, err := c.store.Devices(ctx, ic.Tenant, false, ic.ID)
		if err != nil {
			return nil, err
		}
		for _, d := range devs {
			if d.Managed {
				continue
			}
			raw = append(raw, d.MgmtAddr)
			if d.KeyKind == nms.KeySystemIP {
				raw = append(raw, d.Key)
			}
			if d.Aliases != nil {
				raw = append(raw, d.Aliases["system_ip"])
			}
		}
	}
	return CleanAddrs(raw), nil
}
