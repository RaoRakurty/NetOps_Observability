// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import "container/list"

// lruMap is a bounded map that forgets its least recently used key (CLAUDE.md
// §9: every receiver-side memory is bounded). Not safe for concurrent use: the
// owner holds its own lock.
type lruMap[V any] struct {
	max   int
	order *list.List
	items map[string]*list.Element
}

type lruEntry[V any] struct {
	key string
	val V
}

func newLRUMap[V any](max int) *lruMap[V] {
	if max <= 0 {
		max = 1
	}
	return &lruMap[V]{max: max, order: list.New(), items: map[string]*list.Element{}}
}

// get returns the value and marks it recently used.
func (m *lruMap[V]) get(key string) (V, bool) {
	if el, ok := m.items[key]; ok {
		m.order.MoveToFront(el)
		return el.Value.(*lruEntry[V]).val, true
	}
	var zero V
	return zero, false
}

// put stores the value, evicting the oldest key past the bound.
func (m *lruMap[V]) put(key string, v V) {
	if el, ok := m.items[key]; ok {
		el.Value.(*lruEntry[V]).val = v
		m.order.MoveToFront(el)
		return
	}
	m.items[key] = m.order.PushFront(&lruEntry[V]{key: key, val: v})
	for m.order.Len() > m.max {
		old := m.order.Back()
		m.order.Remove(old)
		delete(m.items, old.Value.(*lruEntry[V]).key)
	}
}

func (m *lruMap[V]) len() int { return m.order.Len() }
