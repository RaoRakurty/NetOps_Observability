// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisconvo

// pg.go — the Postgres store over iris_conversations (migration 0053).
// Every statement runs inside WithTenant(tenant, cross=false), so the FORCE-RLS
// tenant_iso policy confines it to the principal's tenant; owner_sub is
// filtered explicitly on top, because RLS knows tenants, not people.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// DB is the injected relational seam (the investigation-memory idiom).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// PGStore is the Postgres Store.
type PGStore struct {
	db  DB
	now func() time.Time
}

// NewPGStore builds the Postgres store.
func NewPGStore(db DB) *PGStore {
	return &PGStore{db: db, now: func() time.Time { return time.Now().UTC() }}
}

const pgTimeout = 10 * time.Second

// Create starts a conversation, pruning the tenant's expired ones and the
// owner's least recently used ones past MaxPerOwner, in the same transaction.
func (p *PGStore) Create(ctx context.Context, tenant, owner string) (Conversation, error) {
	if err := checkPrincipal(tenant, owner); err != nil {
		return Conversation{}, err
	}
	id, err := NewID()
	if err != nil {
		return Conversation{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	now := p.now()
	c := Conversation{TenantID: tenant, Owner: owner, ID: id, CreatedAt: now, UpdatedAt: now, Turns: []Turn{}}
	err = p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM iris_conversations WHERE tenant_id = $1::text AND updated_at < $2::timestamptz`,
			tenant, now.Add(-TTL)); err != nil {
			return fmt.Errorf("prune expired: %w", err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM iris_conversations WHERE tenant_id = $1::text AND id IN (
		        SELECT id FROM iris_conversations WHERE tenant_id = $1::text AND owner_sub = $2::text
		         ORDER BY updated_at DESC, id ASC OFFSET $3::int)`,
			tenant, owner, MaxPerOwner-1); err != nil {
			return fmt.Errorf("prune owner: %w", err)
		}
		_, err := tx.Exec(ctx, `INSERT INTO iris_conversations (tenant_id, id, owner_sub, turns, state, created_at, updated_at)
		    VALUES ($1, $2, $3, '[]'::jsonb, '{}'::jsonb, $4, $4)`, tenant, id, owner, now)
		return err
	})
	if err != nil {
		return Conversation{}, fmt.Errorf("irisconvo: create: %w", err)
	}
	return c, nil
}

// Get returns the caller's own live conversation.
func (p *PGStore) Get(ctx context.Context, tenant, owner, id string) (Conversation, error) {
	if !ValidID(id) {
		return Conversation{}, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var c Conversation
	err := p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		var err error
		c, err = p.load(ctx, tx, tenant, owner, id, false)
		return err
	})
	if err != nil {
		return Conversation{}, err
	}
	return c, nil
}

// Append records a turn and replaces the state, under a row lock so two
// concurrent turns cannot both pass the turn cap.
func (p *PGStore) Append(ctx context.Context, tenant, owner, id string, t Turn, st State) (Conversation, error) {
	t, err := NormalizeTurn(t)
	if err != nil {
		return Conversation{}, err
	}
	if !ValidID(id) {
		return Conversation{}, ErrNotFound
	}
	st = NormalizeState(st)
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var out Conversation
	err = p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		c, err := p.load(ctx, tx, tenant, owner, id, true)
		if err != nil {
			return err
		}
		if len(c.Turns) >= MaxTurns {
			return ErrFull
		}
		c.Turns = append(c.Turns, t)
		c.State = st
		c.UpdatedAt = p.now()
		turns, err := json.Marshal(c.Turns)
		if err != nil {
			return fmt.Errorf("encode turns: %w", err)
		}
		state, err := json.Marshal(c.State)
		if err != nil {
			return fmt.Errorf("encode state: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE iris_conversations SET turns = $4::jsonb, state = $5::jsonb, updated_at = $6
		    WHERE tenant_id = $1::text AND id = $2::uuid AND owner_sub = $3::text`,
			tenant, id, owner, string(turns), string(state), c.UpdatedAt); err != nil {
			return err
		}
		out = c
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrFull) {
			return Conversation{}, err
		}
		return Conversation{}, fmt.Errorf("irisconvo: append: %w", err)
	}
	return out, nil
}

func (p *PGStore) load(ctx context.Context, tx pgx.Tx, tenant, owner, id string, lock bool) (Conversation, error) {
	q := `SELECT turns, state, created_at, updated_at FROM iris_conversations
	    WHERE tenant_id = $1::text AND id = $2::uuid AND owner_sub = $3::text`
	if lock {
		q += ` FOR UPDATE`
	}
	var turns, state []byte
	c := Conversation{TenantID: tenant, Owner: owner, ID: id}
	err := tx.QueryRow(ctx, q, tenant, id, owner).Scan(&turns, &state, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Conversation{}, ErrNotFound
	}
	if err != nil {
		return Conversation{}, err
	}
	if expired(c, p.now()) {
		return Conversation{}, ErrNotFound
	}
	if err := json.Unmarshal(turns, &c.Turns); err != nil {
		return Conversation{}, fmt.Errorf("irisconvo: stored turns unreadable: %w", err)
	}
	// Stored state is re-bounded on read: the database is not trusted to still
	// hold what the store wrote.
	var raw State
	if err := json.Unmarshal(state, &raw); err != nil {
		return Conversation{}, fmt.Errorf("irisconvo: stored state unreadable: %w", err)
	}
	c.State = NormalizeState(raw)
	return c, nil
}

var _ Store = (*PGStore)(nil)
