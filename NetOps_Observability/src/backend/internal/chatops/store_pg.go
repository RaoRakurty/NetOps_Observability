// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chatops

// store_pg.go — the Postgres backend (migration 0074, tenant_iso FORCE-RLS on
// all three tables, read and written only through the WithTenant seam).
// Secrets are sealed per tenant and field by the injected Crypter (the
// platform vault) before they reach a row, and unsealed only into memory.
// ConnectionByToken is the single cross-tenant read: an inbound request has no
// tenant until its token names one.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// DB is the tenant-scoped transaction seam (platformdb).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// Crypter seals and unseals one secret field for one tenant (the vault).
type Crypter interface {
	Encrypt(tenant, fieldID, plaintext string) (string, error)
	Decrypt(tenant, fieldID, stored string) (string, error)
}

type pgStore struct {
	db    DB
	crypt Crypter
}

// NewPGStore builds the Postgres store. A nil crypt refuses to store secrets
// rather than keeping them in clear.
func NewPGStore(db DB, crypt Crypter) Store { return &pgStore{db: db, crypt: crypt} }

const connCols = `tenant_id, platform, workspace_id, app_id, app_tenant, webhook_token, public_url,
    channel_replies, enabled, signing_secret, bot_token, app_password, updated_by, updated_at`

func secretField(p Platform, name string) string { return "chatops." + string(p) + "." + name }

func (s *pgStore) seal(tenant string, p Platform, name, v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if s.crypt == nil {
		return "", errors.New("chatops: secrets need the platform vault, which is not available")
	}
	return s.crypt.Encrypt(tenant, secretField(p, name), v)
}

func (s *pgStore) unseal(tenant string, p Platform, name, v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if s.crypt == nil {
		return "", errors.New("chatops: secrets need the platform vault, which is not available")
	}
	return s.crypt.Decrypt(tenant, secretField(p, name), v)
}

func (s *pgStore) scanConn(row pgx.Row) (Connection, error) {
	var (
		c                      Connection
		platform, replies      string
		sign, bot, appPassword string
	)
	if err := row.Scan(&c.TenantID, &platform, &c.WorkspaceID, &c.AppID, &c.AppTenant, &c.WebhookToken, &c.PublicURL,
		&replies, &c.Enabled, &sign, &bot, &appPassword, &c.UpdatedBy, &c.UpdatedAt); err != nil {
		return Connection{}, err
	}
	c.Platform, c.ChannelReplies = Platform(platform), ChannelReplies(replies)
	var err error
	if c.SigningSecret, err = s.unseal(c.TenantID, c.Platform, "signing_secret", sign); err != nil {
		return Connection{}, fmt.Errorf("chatops: unseal: %w", err)
	}
	if c.BotToken, err = s.unseal(c.TenantID, c.Platform, "bot_token", bot); err != nil {
		return Connection{}, fmt.Errorf("chatops: unseal: %w", err)
	}
	if c.AppPassword, err = s.unseal(c.TenantID, c.Platform, "app_password", appPassword); err != nil {
		return Connection{}, fmt.Errorf("chatops: unseal: %w", err)
	}
	c.UpdatedAt = c.UpdatedAt.UTC()
	return c, nil
}

func (s *pgStore) ConnectionByToken(ctx context.Context, token string) (Connection, bool, error) {
	if token == "" {
		return Connection{}, false, nil
	}
	var (
		c     Connection
		found bool
	)
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		got, err := s.scanConn(tx.QueryRow(ctx, `SELECT `+connCols+` FROM chatops_connections WHERE webhook_token = $1`, token))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		c, found = got, true
		return nil
	})
	return c, found, err
}

func (s *pgStore) Connections(ctx context.Context, tenant string) ([]Connection, error) {
	t := NormTenant(tenant)
	out := []Connection{}
	err := s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+connCols+` FROM chatops_connections WHERE tenant_id = $1 ORDER BY platform`, t)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := s.scanConn(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

func (s *pgStore) GetConnection(ctx context.Context, tenant string, p Platform) (Connection, bool, error) {
	t := NormTenant(tenant)
	var (
		c     Connection
		found bool
	)
	err := s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		got, err := s.scanConn(tx.QueryRow(ctx, `SELECT `+connCols+` FROM chatops_connections WHERE tenant_id = $1 AND platform = $2`, t, string(p)))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		c, found = got, true
		return nil
	})
	return c, found, err
}

func (s *pgStore) PutConnection(ctx context.Context, tenant string, c Connection) error {
	t := NormTenant(tenant)
	sign, err := s.seal(t, c.Platform, "signing_secret", c.SigningSecret)
	if err != nil {
		return err
	}
	bot, err := s.seal(t, c.Platform, "bot_token", c.BotToken)
	if err != nil {
		return err
	}
	pass, err := s.seal(t, c.Platform, "app_password", c.AppPassword)
	if err != nil {
		return err
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = time.Now().UTC()
	}
	return s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO chatops_connections (`+connCols+`)
		    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		    ON CONFLICT (tenant_id, platform) DO UPDATE SET
		      workspace_id = EXCLUDED.workspace_id, app_id = EXCLUDED.app_id, app_tenant = EXCLUDED.app_tenant,
		      webhook_token = EXCLUDED.webhook_token, public_url = EXCLUDED.public_url,
		      channel_replies = EXCLUDED.channel_replies, enabled = EXCLUDED.enabled,
		      signing_secret = EXCLUDED.signing_secret, bot_token = EXCLUDED.bot_token,
		      app_password = EXCLUDED.app_password, updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`,
			t, string(c.Platform), c.WorkspaceID, c.AppID, c.AppTenant, c.WebhookToken, c.PublicURL,
			string(c.ChannelReplies), c.Enabled, sign, bot, pass, c.UpdatedBy, c.UpdatedAt)
		return err
	})
}

func (s *pgStore) DeleteConnection(ctx context.Context, tenant string, p Platform) (bool, error) {
	t := NormTenant(tenant)
	var n int64
	err := s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM chatops_connections WHERE tenant_id = $1 AND platform = $2`, t, string(p))
		n = tag.RowsAffected()
		return err
	})
	return n > 0, err
}

const linkCols = `tenant_id, id, platform, workspace_id, chat_user_id, chat_name, user_id, status,
    requested_at, decided_by, decided_at`

func scanLink(row pgx.Row) (Link, error) {
	var (
		l                Link
		platform, status string
		decidedAt        *time.Time
	)
	if err := row.Scan(&l.TenantID, &l.ID, &platform, &l.WorkspaceID, &l.ChatUserID, &l.ChatName, &l.UserID, &status,
		&l.RequestedAt, &l.DecidedBy, &decidedAt); err != nil {
		return Link{}, err
	}
	l.Platform, l.Status = Platform(platform), LinkStatus(status)
	l.RequestedAt = l.RequestedAt.UTC()
	if decidedAt != nil {
		l.DecidedAt = decidedAt.UTC()
	}
	return l, nil
}

func (s *pgStore) ActiveLink(ctx context.Context, tenant string, p Platform, workspace, chatUser string) (Link, bool, error) {
	t := NormTenant(tenant)
	var (
		l     Link
		found bool
	)
	err := s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		got, err := scanLink(tx.QueryRow(ctx, `SELECT `+linkCols+` FROM chatops_links
		    WHERE tenant_id = $1 AND platform = $2 AND workspace_id = $3 AND chat_user_id = $4
		      AND status IN ('pending','approved')`, t, string(p), workspace, chatUser))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		l, found = got, true
		return nil
	})
	return l, found, err
}

func (s *pgStore) queryLinks(ctx context.Context, tenant, user string) ([]Link, error) {
	t := NormTenant(tenant)
	out := []Link{}
	err := s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		q, args := `SELECT `+linkCols+` FROM chatops_links WHERE tenant_id = $1`, []any{t}
		if user != "" {
			q += ` AND user_id = $2`
			args = append(args, user)
		}
		rows, err := tx.Query(ctx, q+` ORDER BY requested_at DESC, id ASC LIMIT 500`, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			l, err := scanLink(rows)
			if err != nil {
				return err
			}
			out = append(out, l)
		}
		return rows.Err()
	})
	return out, err
}

func (s *pgStore) Links(ctx context.Context, tenant string) ([]Link, error) {
	return s.queryLinks(ctx, tenant, "")
}

func (s *pgStore) UserLinks(ctx context.Context, tenant, userID string) ([]Link, error) {
	if userID == "" {
		return []Link{}, nil
	}
	return s.queryLinks(ctx, tenant, userID)
}

func (s *pgStore) PutCode(ctx context.Context, tenant string, c LinkCode) error {
	t := NormTenant(tenant)
	return s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM chatops_link_codes
		    WHERE tenant_id = $1 AND ((platform = $2 AND workspace_id = $3 AND chat_user_id = $4) OR expires_at < now())`,
			t, string(c.Platform), c.WorkspaceID, c.ChatUserID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO chatops_link_codes
		    (tenant_id, code_hash, platform, workspace_id, chat_user_id, chat_name, expires_at)
		    VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			t, c.CodeHash, string(c.Platform), c.WorkspaceID, c.ChatUserID, c.ChatName, c.ExpiresAt.UTC())
		return err
	})
}

func (s *pgStore) RedeemCode(ctx context.Context, tenant, codeHash, userID string, now time.Time) (Link, error) {
	t := NormTenant(tenant)
	var out Link
	err := s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		var c LinkCode
		var platform string
		err := tx.QueryRow(ctx, `DELETE FROM chatops_link_codes WHERE tenant_id = $1 AND code_hash = $2
		    RETURNING platform, workspace_id, chat_user_id, chat_name, expires_at`, t, codeHash).
			Scan(&platform, &c.WorkspaceID, &c.ChatUserID, &c.ChatName, &c.ExpiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if !now.Before(c.ExpiresAt) {
			return ErrNotFound
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM chatops_links WHERE tenant_id = $1 AND platform = $2
		    AND workspace_id = $3 AND chat_user_id = $4 AND status IN ('pending','approved')`,
			t, platform, c.WorkspaceID, c.ChatUserID).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrLinked
		}
		id, err := NewID()
		if err != nil {
			return err
		}
		out = Link{TenantID: t, ID: id, Platform: Platform(platform), WorkspaceID: c.WorkspaceID, ChatUserID: c.ChatUserID,
			ChatName: c.ChatName, UserID: userID, Status: LinkPending, RequestedAt: now.UTC()}
		_, err = tx.Exec(ctx, `INSERT INTO chatops_links
		    (tenant_id, id, platform, workspace_id, chat_user_id, chat_name, user_id, status, requested_at)
		    VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8)`,
			t, out.ID, platform, out.WorkspaceID, out.ChatUserID, out.ChatName, out.UserID, out.RequestedAt)
		return err
	})
	if err != nil {
		return Link{}, err
	}
	return out, nil
}

func (s *pgStore) DecideLink(ctx context.Context, tenant, id, decidedBy string, approve bool, now time.Time) (Link, error) {
	t := NormTenant(tenant)
	var out Link
	err := s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		l, err := scanLink(tx.QueryRow(ctx, `SELECT `+linkCols+` FROM chatops_links
		    WHERE tenant_id = $1 AND id::text = $2 FOR UPDATE`, t, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		next, err := decide(l, decidedBy, approve, now)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE chatops_links SET status = $3, decided_by = $4, decided_at = $5
		    WHERE tenant_id = $1 AND id::text = $2`, t, id, string(next.Status), next.DecidedBy, next.DecidedAt); err != nil {
			return err
		}
		out = next
		return nil
	})
	if err != nil {
		return Link{}, err
	}
	return out, nil
}

var _ Store = (*pgStore)(nil)
