// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chatops

// store_mem.go — the in-memory backend: the non-Postgres build and tests (the
// wireless MemStore convention). Everything is keyed by tenant IN the store
// (CLAUDE.md §3a rule 4), so no method can return another tenant's rows. It is
// not durable: on the file backend a restart drops connections and links and
// admins reconnect — chat is a Postgres-deployment feature.

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemStore implements Store in memory.
type MemStore struct {
	mu    sync.Mutex
	conns map[string]map[Platform]Connection // tenant → platform → connection
	links map[string]map[string]Link         // tenant → id → link
	codes map[string]map[string]LinkCode     // tenant → code hash → code
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{
		conns: map[string]map[Platform]Connection{},
		links: map[string]map[string]Link{},
		codes: map[string]map[string]LinkCode{},
	}
}

func (m *MemStore) ConnectionByToken(_ context.Context, token string) (Connection, bool, error) {
	if token == "" {
		return Connection{}, false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, byP := range m.conns {
		for _, c := range byP {
			if c.WebhookToken == token {
				return c, true, nil
			}
		}
	}
	return Connection{}, false, nil
}

func (m *MemStore) Connections(_ context.Context, tenant string) ([]Connection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Connection{}
	for _, c := range m.conns[NormTenant(tenant)] {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Platform < out[j].Platform })
	return out, nil
}

func (m *MemStore) GetConnection(_ context.Context, tenant string, p Platform) (Connection, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.conns[NormTenant(tenant)][p]
	return c, ok, nil
}

func (m *MemStore) PutConnection(_ context.Context, tenant string, c Connection) error {
	t := NormTenant(tenant)
	c.TenantID = t
	m.mu.Lock()
	defer m.mu.Unlock()
	for ot, byP := range m.conns {
		for op, oc := range byP {
			if oc.WebhookToken == c.WebhookToken && (ot != t || op != c.Platform) {
				return ErrLinked // token collision: practically impossible, never silently shared
			}
		}
	}
	if m.conns[t] == nil {
		m.conns[t] = map[Platform]Connection{}
	}
	m.conns[t][c.Platform] = c
	return nil
}

func (m *MemStore) DeleteConnection(_ context.Context, tenant string, p Platform) (bool, error) {
	t := NormTenant(tenant)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.conns[t][p]; !ok {
		return false, nil
	}
	delete(m.conns[t], p)
	return true, nil
}

func (m *MemStore) ActiveLink(_ context.Context, tenant string, p Platform, workspace, chatUser string) (Link, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.activeLocked(NormTenant(tenant), p, workspace, chatUser)
	return l, ok, nil
}

func (m *MemStore) activeLocked(t string, p Platform, workspace, chatUser string) (Link, bool) {
	for _, l := range m.links[t] {
		if l.Platform == p && l.WorkspaceID == workspace && l.ChatUserID == chatUser &&
			(l.Status == LinkPending || l.Status == LinkApproved) {
			return l, true
		}
	}
	return Link{}, false
}

func (m *MemStore) Links(_ context.Context, tenant string) ([]Link, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return sortedLinks(m.links[NormTenant(tenant)], ""), nil
}

func (m *MemStore) UserLinks(_ context.Context, tenant, userID string) ([]Link, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return sortedLinks(m.links[NormTenant(tenant)], userID), nil
}

func sortedLinks(byID map[string]Link, user string) []Link {
	out := []Link{}
	for _, l := range byID {
		if user == "" || l.UserID == user {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].RequestedAt.Equal(out[j].RequestedAt) {
			return out[i].RequestedAt.After(out[j].RequestedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (m *MemStore) PutCode(_ context.Context, tenant string, c LinkCode) error {
	t := NormTenant(tenant)
	c.TenantID = t
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.codes[t] == nil {
		m.codes[t] = map[string]LinkCode{}
	}
	for h, old := range m.codes[t] { // one outstanding code per chat account
		if old.Platform == c.Platform && old.WorkspaceID == c.WorkspaceID && old.ChatUserID == c.ChatUserID {
			delete(m.codes[t], h)
		}
	}
	m.codes[t][c.CodeHash] = c
	return nil
}

func (m *MemStore) RedeemCode(_ context.Context, tenant, codeHash, userID string, now time.Time) (Link, error) {
	t := NormTenant(tenant)
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.codes[t][codeHash]
	if !ok {
		return Link{}, ErrNotFound
	}
	delete(m.codes[t], codeHash) // spent whatever happens next
	if !now.Before(c.ExpiresAt) {
		return Link{}, ErrNotFound
	}
	if _, active := m.activeLocked(t, c.Platform, c.WorkspaceID, c.ChatUserID); active {
		return Link{}, ErrLinked
	}
	id, err := NewID()
	if err != nil {
		return Link{}, err
	}
	l := Link{TenantID: t, ID: id, Platform: c.Platform, WorkspaceID: c.WorkspaceID, ChatUserID: c.ChatUserID,
		ChatName: c.ChatName, UserID: userID, Status: LinkPending, RequestedAt: now.UTC()}
	if m.links[t] == nil {
		m.links[t] = map[string]Link{}
	}
	m.links[t][id] = l
	return l, nil
}

func (m *MemStore) DecideLink(_ context.Context, tenant, id, decidedBy string, approve bool, now time.Time) (Link, error) {
	t := NormTenant(tenant)
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.links[t][id]
	if !ok {
		return Link{}, ErrNotFound
	}
	next, err := decide(l, decidedBy, approve, now)
	if err != nil {
		return Link{}, err
	}
	m.links[t][id] = next
	return next, nil
}

// decide is the one link state machine both backends apply.
func decide(l Link, decidedBy string, approve bool, now time.Time) (Link, error) {
	switch {
	case approve && l.Status != LinkPending:
		return Link{}, ErrNotFound // only a pending link can be approved
	case approve && l.UserID == decidedBy:
		return Link{}, ErrSelf
	case !approve && l.Status == LinkRevoked:
		return Link{}, ErrNotFound
	}
	l.DecidedBy, l.DecidedAt = decidedBy, now.UTC()
	if approve {
		l.Status = LinkApproved
	} else {
		l.Status = LinkRevoked
	}
	return l, nil
}

var _ Store = (*MemStore)(nil)
