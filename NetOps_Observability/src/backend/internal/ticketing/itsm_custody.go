// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// itsm_custody.go — at-rest custody for the per-tenant ITSM connector secrets
// (tracker 456). The five write-only secrets (ServiceNow password, Jira API
// token, PagerDuty routing key, Slack and Teams webhook URLs) are sealed with
// the secret-custody vault under the OWNING tenant's DEK before the store
// writes its blob, and opened after it reads it. The vault lives in main and is
// INJECTED here as SecretCustody (no import of internal/vault from this
// domain); a zero SecretCustody is plaintext, which is also what a dormant
// vault (no SEAL_PROVIDER) does.
//
// ENVELOPE VERSIONS. Version 2 is the plaintext era: every value in it is
// plaintext by construction (nothing sealed this store before 456). Version 3
// is written only while custody is ACTIVE and every secret in it went through
// Seal. Reading:
//   - v3: every secret goes through Open — the vault's own rules apply,
//     including VAULT_STRICT (a plaintext value in a sealed file is refused).
//   - v2 / the legacy single-object format: taken as plaintext. With custody
//     active the store is rewritten as v3 at once (one-time, idempotent: the
//     next load reads v3 and writes nothing).
// A v3 file that cannot be opened (custody removed, wrong key, tampering)
// leaves the store REFUSING to persist: a save would otherwise replace sealed
// credentials nobody could read with whatever the form held.

import (
	"errors"
	"fmt"
)

// SecretCustody seals and opens the write-only connector secrets at rest.
// Seal/Open have vault.Vault.Encrypt/Decrypt's signature; Active reports
// whether Seal really encrypts (vault.Vault.Sealed). Any nil member makes the
// whole custody plaintext passthrough.
type SecretCustody struct {
	Seal   func(tenant, fieldID, plaintext string) (string, error)
	Open   func(tenant, fieldID, stored string) (string, error)
	Active func() bool
}

func (c SecretCustody) usable() bool { return c.Seal != nil && c.Open != nil && c.Active != nil }

// active reports whether persisted secrets are sealed.
func (c SecretCustody) active() bool { return c.usable() && c.Active() }

// Vault AAD field-ids for the ITSM secrets. Stable strings: changing one makes
// existing ciphertext for that field undecryptable (AAD mismatch).
const (
	fieldITSMServiceNowPassword = "itsm.servicenow.password" // #nosec G101 -- vault AAD field-id (a config key name), not a credential value
	fieldITSMJiraAPIToken       = "itsm.jira.api_token"      // #nosec G101 -- vault AAD field-id (a config key name), not a credential value
	fieldITSMPagerDutyKey       = "itsm.pagerduty.routing_key"
	fieldITSMSlackWebhookURL    = "itsm.slack.webhook_url"
	fieldITSMTeamsWebhookURL    = "itsm.teams.webhook_url"
)

const (
	itsmFileVersionPlain  = 2 // every secret plaintext (pre-456, or custody dormant)
	itsmFileVersionSealed = 3 // every secret sealed under its tenant's DEK
)

// mapITSMSecrets applies f to each write-only secret of one tenant's config and
// returns the transformed COPY. tenant is the store key ("" = global, sealed
// under the platform DEK), which the vault binds into the AAD — a sealed value
// moved under another tenant's key does not open.
func mapITSMSecrets(tenant string, c ITSMConfig, f func(tenant, fieldID, v string) (string, error)) (ITSMConfig, error) {
	var err error
	if c.ServiceNow.Password, err = f(tenant, fieldITSMServiceNowPassword, c.ServiceNow.Password); err != nil {
		return c, fmt.Errorf("servicenow password: %w", err)
	}
	if c.Jira.APIToken, err = f(tenant, fieldITSMJiraAPIToken, c.Jira.APIToken); err != nil {
		return c, fmt.Errorf("jira api token: %w", err)
	}
	if c.PagerDuty.RoutingKey, err = f(tenant, fieldITSMPagerDutyKey, c.PagerDuty.RoutingKey); err != nil {
		return c, fmt.Errorf("pagerduty routing key: %w", err)
	}
	if c.Slack.WebhookURL, err = f(tenant, fieldITSMSlackWebhookURL, c.Slack.WebhookURL); err != nil {
		return c, fmt.Errorf("slack webhook: %w", err)
	}
	if c.Teams.WebhookURL, err = f(tenant, fieldITSMTeamsWebhookURL, c.Teams.WebhookURL); err != nil {
		return c, fmt.Errorf("teams webhook: %w", err)
	}
	return c, nil
}

// writable refuses every save while a sealed store could not be opened, before
// any setter touches the in-memory map (so a refused save changes nothing).
// Caller holds s.mu.
func (s *ITSMConfigStore) writable() error {
	if s.sealedUnreadable != nil {
		return fmt.Errorf("itsm: the stored config is sealed and could not be opened, so it is not overwritten (%w); restore secret custody and restart", s.sealedUnreadable)
	}
	return nil
}

// sealAll returns the envelope to persist: v3 with every secret sealed while
// custody is active, else v2 plaintext.
func (c SecretCustody) sealAll(cfgs map[string]ITSMConfig) (itsmConfigFile, error) {
	if !c.active() {
		return itsmConfigFile{Version: itsmFileVersionPlain, Tenants: cfgs}, nil
	}
	out := make(map[string]ITSMConfig, len(cfgs))
	for tenant, cfg := range cfgs {
		sealed, err := mapITSMSecrets(tenant, cfg, c.Seal)
		if err != nil {
			return itsmConfigFile{}, fmt.Errorf("itsm: seal tenant %q: %w", tenant, err)
		}
		out[tenant] = sealed
	}
	return itsmConfigFile{Version: itsmFileVersionSealed, Tenants: out}, nil
}

// openAll opens a v3 envelope's secrets. Any failure fails the whole load: a
// partly opened map would let a later save drop the tenants that did not open.
func (c SecretCustody) openAll(cfgs map[string]ITSMConfig) (map[string]ITSMConfig, error) {
	if !c.usable() {
		return nil, errors.New("itsm: the stored config is sealed but no secret custody is wired")
	}
	out := make(map[string]ITSMConfig, len(cfgs))
	for tenant, cfg := range cfgs {
		opened, err := mapITSMSecrets(tenant, cfg, c.Open)
		if err != nil {
			return nil, fmt.Errorf("itsm: open tenant %q: %w", tenant, err)
		}
		out[tenant] = opened
	}
	return out, nil
}
