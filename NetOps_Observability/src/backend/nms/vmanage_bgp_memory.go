// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"container/list"
	"sort"
	"sync"
)

// vmanage_bgp_memory.go — each BGP peer's recent reports, kept ACROSS polls
// (tracker 387 on the controller lane).
//
// vManage's bgp-peer-state-change carries only the NEW state. Within one poll
// the prior state comes from the same peer's earlier report in the batch; this
// memory carries it across polls, the shape of the trap receiver's peer memory
// (collectors/trap_transitions.go). Without it, a neighbour that churns idle <->
// active forever classifies "unknown" at the start of every poll and reads as a
// session down each time.
//
// What it must NOT do is infer a prior state it has not seen. An established
// session reports nothing while it is up, and IOS / IOS-XE clears the remote
// router-id on teardown, so a session that was up for days drops with ONE idle
// report and peer-routerid 0.0.0.0. With no remembered report that drop stays
// "unknown" and reads as a down (fail-open), never "never established".
//
// §3a: every key starts with the tenant AND the integration, so two tenants, or
// two integrations of one tenant (two vManage fabrics reusing system-ips), never
// share a peer's history.
//
// Bounded: at most vmBGPMemoryMaxPeers peers (least recently reported evicted)
// and vmBGPMemoryReports reports per peer. TTL: a remembered report older than
// vmBGPMemoryTTL before the report being classified is not evidence of its prior
// state. 24 h, because a never-established neighbour's reports come at its retry
// timers' pace (seconds to minutes; IOS backs off ConnectRetry and the idle hold
// time but stays well under hours), so a churning peer keeps refreshing its own
// memory and stays classified, while a report a day old says nothing about a
// session today. Times are the controller's event times, not the wall clock, so
// classification is deterministic and re-polls of the 2-minute overlap
// (poll.go) classify the same way twice.
//
// Process-local: after a restart the first report of each peer has no memory and
// reads "unknown", like the trap lane's.

const (
	vmBGPMemoryMaxPeers = 16384
	vmBGPMemoryReports  = 32
	vmBGPMemoryTTLms    = int64(24 * 60 * 60 * 1000)
)

type vmBGPPeerMemory struct {
	key     string
	reports []vmBGPReport // sorted by at, deduplicated, at most maxReports
}

// vmBGPMemory is safe for concurrent use: integrations poll in parallel.
type vmBGPMemory struct {
	mu         sync.Mutex
	maxPeers   int
	maxReports int
	ttlMS      int64
	lru        *list.List               // front = most recently reported
	peers      map[string]*list.Element // key → element holding *vmBGPPeerMemory
}

func newVMBGPMemory(maxPeers, maxReports int, ttlMS int64) *vmBGPMemory {
	return &vmBGPMemory{
		maxPeers: maxPeers, maxReports: maxReports, ttlMS: ttlMS,
		lru: list.New(), peers: map[string]*list.Element{},
	}
}

// vmBGPMemoryKey scopes a device|peer to its tenant and integration (§3a).
func vmBGPMemoryKey(tenant, integrationID, peerKey string) string {
	return tenant + "\x00" + integrationID + "\x00" + peerKey
}

// recall returns the remembered reports of key no older than ttl before
// `notBefore` (the earliest report about to be classified). nil-safe.
func (m *vmBGPMemory) recall(key string, notBefore int64) []vmBGPReport {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.peers[key]
	if !ok {
		return nil
	}
	horizon := notBefore - m.ttlMS
	var out []vmBGPReport
	for _, r := range el.Value.(*vmBGPPeerMemory).reports {
		if r.at >= horizon {
			out = append(out, r)
		}
	}
	return out
}

// remember merges reports into key's memory, keeping the newest maxReports, and
// evicts the least recently reported peer past maxPeers. nil-safe.
func (m *vmBGPMemory) remember(key string, reports []vmBGPReport) {
	if m == nil || len(reports) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var pm *vmBGPPeerMemory
	if el, ok := m.peers[key]; ok {
		pm = el.Value.(*vmBGPPeerMemory)
		m.lru.MoveToFront(el)
	} else {
		pm = &vmBGPPeerMemory{key: key}
		m.peers[key] = m.lru.PushFront(pm)
	}
	merged := mergeVMBGPReports(pm.reports, reports)
	if len(merged) > m.maxReports {
		merged = merged[len(merged)-m.maxReports:]
	}
	pm.reports = merged
	for m.lru.Len() > m.maxPeers {
		oldest := m.lru.Back()
		delete(m.peers, oldest.Value.(*vmBGPPeerMemory).key)
		m.lru.Remove(oldest)
	}
}

// size is the number of peers remembered (tests, observability).
func (m *vmBGPMemory) size() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lru.Len()
}

// mergeVMBGPReports is the sorted union of two report lists; an identical
// (at, state) pair — the same report polled twice in the overlap — appears once.
func mergeVMBGPReports(a, b []vmBGPReport) []vmBGPReport {
	out := make([]vmBGPReport, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].at != out[j].at {
			return out[i].at < out[j].at
		}
		return out[i].state < out[j].state
	})
	dedup := out[:0]
	for _, r := range out {
		if len(dedup) > 0 && r == dedup[len(dedup)-1] {
			continue
		}
		dedup = append(dedup, r)
	}
	return dedup
}
