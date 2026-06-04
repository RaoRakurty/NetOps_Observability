package main

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"netops/backend/integration"
)

// integration_config_pg.go — per-tenant/provider integration config (migration
// 0007): sync_mode, webhook enablement + opaque token + signing secret, and the
// per-tenant external→internal state-map overrides the reconciler applies.

type integrationConfig struct {
	Tenant         string
	Provider       string
	Enabled        bool
	SyncMode       string // outbound | bidirectional
	WebhookEnabled bool
	WebhookToken   string
	WebhookSecret  string // write-only over the API
	StateMap       map[string]string
}

// Bidirectional reports whether inbound sync is configured + enabled for this row.
func (c integrationConfig) Bidirectional() bool {
	return c.Enabled && c.WebhookEnabled && c.SyncMode == "bidirectional"
}

// mappingEngine builds a per-tenant MappingEngine applying this config's state-map
// overrides on top of the shipped defaults.
func (c integrationConfig) mappingEngine() *integration.MappingEngine {
	base := integration.NewMappingEngine()
	if len(c.StateMap) == 0 {
		return base
	}
	ov := make(map[string]integration.InternalState, len(c.StateMap))
	for ext, internal := range c.StateMap {
		ov[ext] = integration.InternalState(internal)
	}
	return base.WithStateMap(ov)
}

const integrationConfigCols = `tenant_id, provider, enabled, sync_mode, webhook_enabled, webhook_token, webhook_secret, state_map`

// webhookSecretField is the Vault AAD field-id binding a webhook_secret ciphertext
// to its provider (and, via the tenant DEK, to its tenant).
func webhookSecretField(provider string) string { return "integration.webhook_secret." + provider }

// scanConfig reads one config row and decrypts the webhook_secret at rest (the
// secret is GCM-bound to tenant|provider; a dormant Vault / legacy plaintext
// passes through). Decrypt uses the row's own tenant, so platform-scope scans
// (e.g. ListBidirectionalConfigs) decrypt each row under its owner's DEK.
func (s *integrationStore) scanConfig(row pgx.Row) (integrationConfig, error) {
	var c integrationConfig
	var stateMap []byte
	err := row.Scan(&c.Tenant, &c.Provider, &c.Enabled, &c.SyncMode, &c.WebhookEnabled, &c.WebhookToken, &c.WebhookSecret, &stateMap)
	if err != nil {
		return c, err
	}
	if len(stateMap) > 0 {
		_ = json.Unmarshal(stateMap, &c.StateMap)
	}
	if c.WebhookSecret != "" {
		sec, derr := s.vault.Decrypt(c.Tenant, webhookSecretField(c.Provider), c.WebhookSecret)
		if derr != nil {
			return c, derr
		}
		c.WebhookSecret = sec
	}
	return c, nil
}

// GetConfig returns one tenant's provider config (tenant-scoped read).
func (s *integrationStore) GetConfig(ctx context.Context, tenant string, cross bool, provider string) (integrationConfig, bool, error) {
	var c integrationConfig
	var found bool
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+integrationConfigCols+` FROM integration_configs WHERE provider=$1`, provider)
		got, err := s.scanConfig(row)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		c, found = got, true
		return nil
	})
	return c, found, err
}

// ListConfigs returns all of a tenant's provider configs.
func (s *integrationStore) ListConfigs(ctx context.Context, tenant string, cross bool) ([]integrationConfig, error) {
	var out []integrationConfig
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+integrationConfigCols+` FROM integration_configs ORDER BY provider`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := s.scanConfig(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// ListBidirectionalConfigs returns all enabled, webhook-enabled, bidirectional
// configs across ALL tenants (platform scope) — the set the drift reconciler
// iterates. Webhook secret is included (the reconciler may need provider auth via
// the connector, but not the webhook secret; harmless).
func (s *integrationStore) ListBidirectionalConfigs(ctx context.Context) ([]integrationConfig, error) {
	var out []integrationConfig
	err := s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+integrationConfigCols+`
			FROM integration_configs
			WHERE enabled AND webhook_enabled AND sync_mode='bidirectional'`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := s.scanConfig(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// ConfigByToken resolves (tenant, provider, secret, …) from an opaque webhook
// token. Runs at PLATFORM scope — the webhook is unauthenticated and we don't yet
// know the tenant. Empty token never matches.
func (s *integrationStore) ConfigByToken(ctx context.Context, token string) (integrationConfig, bool, error) {
	var c integrationConfig
	var found bool
	if token == "" {
		return c, false, nil
	}
	err := s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+integrationConfigCols+` FROM integration_configs WHERE webhook_token=$1`, token)
		got, err := s.scanConfig(row)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		c, found = got, true
		return nil
	})
	return c, found, err
}

// UpsertConfig writes a tenant's provider config (platform-scope system write,
// stamps tenant_id). StateMap is serialized to jsonb.
func (s *integrationStore) UpsertConfig(ctx context.Context, c integrationConfig) error {
	sm, err := json.Marshal(c.StateMap)
	if err != nil {
		return err
	}
	if len(c.StateMap) == 0 {
		sm = []byte("{}")
	}
	// Encrypt the signing secret at rest (tenant DEK, GCM-bound to tenant|provider).
	storedSecret, err := s.vault.Encrypt(c.Tenant, webhookSecretField(c.Provider), c.WebhookSecret)
	if err != nil {
		return err
	}
	return s.db.withTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO integration_configs
   (tenant_id, provider, enabled, sync_mode, webhook_enabled, webhook_token, webhook_secret, state_map, updated_at)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now())
 ON CONFLICT (tenant_id, provider) DO UPDATE SET
   enabled=EXCLUDED.enabled, sync_mode=EXCLUDED.sync_mode,
   webhook_enabled=EXCLUDED.webhook_enabled, webhook_token=EXCLUDED.webhook_token,
   webhook_secret=EXCLUDED.webhook_secret, state_map=EXCLUDED.state_map, updated_at=now()`,
			c.Tenant, c.Provider, c.Enabled, c.SyncMode, c.WebhookEnabled, c.WebhookToken, storedSecret, sm)
		return err
	})
}
