// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"container/list"
	"sync"
)

// dedupe.go — a bounded LRU seen-set for collapsing re-delivered / re-polled
// controller events by dedupe key. Bounded so a noisy controller can't grow it
// without limit (§9 reliability: all queues/sets bounded).

// SeenSet is a fixed-capacity LRU of dedupe keys. Safe for concurrent use.
type SeenSet struct {
	mu    sync.Mutex
	cap   int
	items map[string]*list.Element
	order *list.List // front = most recent
}

// NewSeenSet builds a seen-set holding up to cap keys (min 1).
func NewSeenSet(capacity int) *SeenSet {
	if capacity < 1 {
		capacity = 1
	}
	return &SeenSet{cap: capacity, items: make(map[string]*list.Element), order: list.New()}
}

// Seen reports whether key was already present, and records it. First sighting
// returns false; a repeat within the window returns true. Evicts the LRU entry
// when full.
func (s *SeenSet) Seen(key string) bool {
	if key == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.items[key]; ok {
		s.order.MoveToFront(el)
		return true
	}
	el := s.order.PushFront(key)
	s.items[key] = el
	if s.order.Len() > s.cap {
		last := s.order.Back()
		if last != nil {
			s.order.Remove(last)
			delete(s.items, last.Value.(string))
		}
	}
	return false
}

// Len returns the current number of tracked keys (for tests/metrics).
func (s *SeenSet) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.order.Len()
}

// DedupeEvents filters a slice to first-seen events, stamping each with its
// dedupe key. Order preserved.
func (s *SeenSet) DedupeEvents(evs []ControllerEvent) []ControllerEvent {
	out := evs[:0:0]
	for _, e := range evs {
		if e.DedupeKey == "" {
			e.DedupeKey = DedupeKey(e)
		}
		if s.Seen(e.DedupeKey) {
			continue
		}
		out = append(out, e)
	}
	return out
}
