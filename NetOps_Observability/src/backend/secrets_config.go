package main

// secrets_config.go — secret-custody (#17 phase 1c) for the PLATFORM-scoped
// config singletons (notify / OIDC / LDAP / TACACS). Each map* function applies a
// transform to that config's reversible secret fields and returns a COPY; stores
// call it with sealFn(vault) before persisting and openFn(vault) after loading.
//
// Centralizing every at-rest config secret + its Vault field-id here makes the
// reversible-secret surface auditable in one place. All use the platform DEK
// (tenant ""). A dormant Vault (or nil) passes values through unchanged, so the
// default build + running stack are untouched until SEAL_PROVIDER is set.
//
// (Copilot's API key is env-only — never persisted — so it has no entry here;
// moving env secrets into the sealed store is phase 3, not 1c.)

// Vault AAD field-ids for config secrets. Stable strings — changing one would
// make existing ciphertext for that field undecryptable (AAD mismatch).
const (
	fieldSMTPPass        = "notify.smtp.pass"  // #nosec G101 -- Vault AAD field-id (a config key name), not a credential value
	fieldTwilioAuthToken = "notify.twilio.auth_token"  // #nosec G101 -- Vault AAD field-id (a config key name), not a credential value
	fieldNtfyToken       = "notify.ntfy.token"  // #nosec G101 -- Vault AAD field-id (a config key name), not a credential value
	fieldSlackWebhookURL = "notify.slack.webhook_url"
	fieldPagerDutyKey    = "notify.pagerduty.routing_key"
	fieldOIDCSecret      = "oidc.client_secret"  // #nosec G101 -- Vault AAD field-id (a config key name), not a credential value
	fieldLDAPBindPass    = "ldap.bind_password"  // #nosec G101 -- Vault AAD field-id (a config key name), not a credential value
	fieldTACACSSecret    = "tacacs.secret"
)

// secretXform is Vault.Encrypt or Vault.Decrypt (same signature), or a passthrough.
type secretXform = func(tenant, fieldID, val string) (string, error)

func passthroughXform(_, _ string, val string) (string, error) { return val, nil }

// sealFn / openFn pick the encrypt/decrypt transform from a Vault, treating a nil
// Vault as passthrough so test stores constructed without one behave as plaintext.
func sealFn(v *Vault) secretXform {
	if v == nil {
		return passthroughXform
	}
	return v.Encrypt
}
func openFn(v *Vault) secretXform {
	if v == nil {
		return passthroughXform
	}
	return v.Decrypt
}

// mapNotify transforms the notify config's five secret fields (platform DEK).
func mapNotify(c notifyConfig, f secretXform) (notifyConfig, error) {
	var e error
	if c.SMTP.Pass, e = f("", fieldSMTPPass, c.SMTP.Pass); e != nil {
		return c, e
	}
	if c.Twilio.AuthToken, e = f("", fieldTwilioAuthToken, c.Twilio.AuthToken); e != nil {
		return c, e
	}
	if c.Ntfy.Token, e = f("", fieldNtfyToken, c.Ntfy.Token); e != nil {
		return c, e
	}
	if c.Slack.WebhookURL, e = f("", fieldSlackWebhookURL, c.Slack.WebhookURL); e != nil {
		return c, e
	}
	if c.PagerDuty.RoutingKey, e = f("", fieldPagerDutyKey, c.PagerDuty.RoutingKey); e != nil {
		return c, e
	}
	return c, nil
}

func mapOIDC(c oidcConfig, f secretXform) (oidcConfig, error) {
	var e error
	c.ClientSecret, e = f("", fieldOIDCSecret, c.ClientSecret)
	return c, e
}

func mapLDAP(c ldapConfig, f secretXform) (ldapConfig, error) {
	var e error
	c.BindPassword, e = f("", fieldLDAPBindPass, c.BindPassword)
	return c, e
}

func mapTACACS(c tacacsConfig, f secretXform) (tacacsConfig, error) {
	var e error
	c.Secret, e = f("", fieldTACACSSecret, c.Secret)
	return c, e
}
