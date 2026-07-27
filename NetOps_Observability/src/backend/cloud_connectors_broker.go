package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"netops/backend/internal/vault"
	"strings"
	"sync"
	"time"

	"netops/backend/cloudconn"
)

// Connector security audit event names (recorded into the existing audit_events
// trail via auditFn). Stable tokens the audit UI can branch on.
const (
	evTokenIssued    = "TOKEN_ISSUED"
	evSecretCreated  = "SECRET_CREATED"
	evSecretAccessed = "SECRET_ACCESSED"
	evSecretRotated  = "SECRET_ROTATED"
)

// brokerMaxTokenLifetime is the hard upper bound on any provider token the broker
// will mint or accept. No caller can request longer; a provider returning longer
// is rejected.
const brokerMaxTokenLifetime = time.Hour

// brokerTokenMargin is how long before expiry a cached token stops being served.
const brokerTokenMargin = 30 * time.Second

// brokerRefreshFraction: a cached token is proactively refreshed once this
// fraction of its lifetime has elapsed (expiry-aware refresh at 80% TTL), so
// consumers never receive a credential about to die mid-collection.
const brokerRefreshFraction = 0.8

// brokerLifetimeSlack: some providers mint fixed lifetimes the caller cannot
// shorten (Azure Entra access tokens run 60–90 min). A token exceeding the
// requested lifetime by up to this factor is CLAMPED to the cap (the broker
// simply refuses to serve it past the cap); anything beyond is rejected as a
// contract violation.
const brokerLifetimeSlack = 2.0

var (
	errBrokerNotFound     = errors.New("cloudconn: connector not found for tenant")
	errBrokerNotActive    = errors.New("cloudconn: connector cannot exchange tokens in its current state")
	errBrokerTokenTooLong = errors.New("cloudconn: provider returned a token exceeding the max lifetime")
	errBrokerNoSecret     = errors.New("cloudconn: legacy secret reference is missing or empty")
)

// scopedTokenRequest is a request for ONE tenant, ONE connector, ONE provider
// account, ONE identity, ONE bounded capability set and ONE bounded lifetime.
// The cache key is composed from ALL of these — never from role ARN / client id /
// SA email / account id / tenant slug alone.
type scopedTokenRequest struct {
	Tenant          string
	ConnectorID     string
	ProviderAccount string        // scope ref (account/subscription/project) the token targets
	Audience        string        // token audience (federation)
	Region          string        // optional regional binding
	CapabilitySetID string        // pack full id the token is bounded to
	MaxLifetime     time.Duration // requested upper bound; capped by the broker
}

// cacheKey composes a collision-free, tenant+connector-scoped cache key. It binds
// tenant, connector, provider, provider account, identity ref, capability-set
// hash, audience and region. Two tenants with identical provider ids / role names
// / client ids therefore NEVER share a cache entry.
func (r scopedTokenRequest) cacheKey(provider cloudconn.Provider, identityRef string) string {
	h := sha256.New()
	for _, part := range []string{
		"t=" + normTenant(r.Tenant),
		"c=" + r.ConnectorID,
		"p=" + string(provider),
		"acct=" + strings.ToLower(strings.TrimSpace(r.ProviderAccount)),
		"id=" + strings.ToLower(strings.TrimSpace(identityRef)),
		"caps=" + r.CapabilitySetID,
		"aud=" + r.Audience,
		"region=" + strings.ToLower(strings.TrimSpace(r.Region)),
	} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

type cachedToken struct {
	token    cloudconn.ScopedToken
	mintedAt time.Time // for the 80%-TTL proactive refresh window
}

// fresh reports whether the cached token may still be served at now: within
// 80% of its lifetime AND comfortably before expiry.
func (ct cachedToken) fresh(now time.Time) bool {
	if ct.token.Expiry.Sub(now) <= brokerTokenMargin {
		return false
	}
	life := ct.token.Expiry.Sub(ct.mintedAt)
	if life <= 0 {
		return false
	}
	return now.Sub(ct.mintedAt) < time.Duration(float64(life)*brokerRefreshFraction)
}

// cloudIdentityBroker is the ONLY component that decrypts connector secrets and
// mints provider tokens. Collectors request a scoped token; they never store or
// refresh credentials themselves. Tokens are cached in memory (never persisted)
// and never logged.
type cloudIdentityBroker struct {
	store   cloudConnRepo
	vault   *vault.Vault
	adapter func(cloudconn.Provider) cloudconn.CloudIdentityProvider // DI seam
	auditFn func(AuditEvent)                                         // nil = no audit sink
	now     func() time.Time
	maxLife time.Duration
	metrics *cloudExchangeMetrics // per-provider exchange counters (/metrics)

	mu    sync.Mutex
	cache map[string]cachedToken
}

func newCloudIdentityBroker(store cloudConnRepo, vault *vault.Vault, auditFn func(AuditEvent)) *cloudIdentityBroker {
	return &cloudIdentityBroker{
		store:   store,
		vault:   vault,
		adapter: cloudconn.AdapterFor,
		auditFn: auditFn,
		now:     func() time.Time { return time.Now().UTC() },
		maxLife: brokerMaxTokenLifetime,
		metrics: newCloudExchangeMetrics(),
		cache:   map[string]cachedToken{},
	}
}

// ccnSecretFieldID binds a vault.Vault ciphertext to the connector + secret kind (the
// vault.Vault also binds the tenant via AAD). Changing it makes existing ciphertext
// undecryptable — keep stable.
func ccnSecretFieldID(connectorID, kind string) string {
	return "cloudconn.secret." + connectorID + "." + kind
}

// StoreSecret encrypts an UNAVOIDABLE legacy secret via the existing envelope
// vault.Vault (per-tenant DEK) and persists ONLY the ciphertext + non-secret metadata.
// Returns the opaque secret reference handle. The plaintext is never stored or
// logged. keyHint is a NON-secret identifier (AccessKeyId / SA key id) for age
// display. Audits SECRET_CREATED.
func (b *cloudIdentityBroker) StoreSecret(ctx context.Context, tenant, connectorID string, provider cloudconn.Provider, kind, keyHint, plaintext string) (string, error) {
	if strings.TrimSpace(plaintext) == "" {
		return "", errBrokerNoSecret
	}
	ref := newOpaqueID(csrIDPrefix)
	ciphertext, err := b.vault.Encrypt(normTenant(tenant), ccnSecretFieldID(connectorID, kind), plaintext)
	if err != nil {
		return "", fmt.Errorf("cloudconn: encrypt secret: %w", err)
	}
	sr := cloudSecretRef{
		TenantID: normTenant(tenant), SecretRef: ref, ConnectorID: connectorID, Provider: provider,
		Kind: kind, Ciphertext: ciphertext, FieldsSet: []string{kind}, KeyHint: keyHint, Version: 1,
	}
	if err := b.store.PutSecretRef(ctx, sr); err != nil {
		return "", err
	}
	b.audit(evSecretCreated, tenant, connectorID, string(provider), "success", "kind="+kind)
	return ref, nil
}

// RotateSecret writes a new ciphertext under an existing reference, bumping the
// version (rotation overlap: the previous provider credential can stay valid until
// the operator revokes it upstream) and invalidating any cached token. Audits
// SECRET_ROTATED. Returns found=false if the ref is not visible to the tenant.
func (b *cloudIdentityBroker) RotateSecret(ctx context.Context, tenant, ref, connectorID, keyHint, plaintext string) (bool, error) {
	if strings.TrimSpace(plaintext) == "" {
		return false, errBrokerNoSecret
	}
	sr, found, err := b.store.GetSecretRef(ctx, tenant, false, ref)
	if err != nil {
		return false, err
	}
	if !found || sr.ConnectorID != connectorID {
		return false, nil
	}
	ciphertext, err := b.vault.Encrypt(normTenant(tenant), ccnSecretFieldID(connectorID, sr.Kind), plaintext)
	if err != nil {
		return true, fmt.Errorf("cloudconn: encrypt rotated secret: %w", err)
	}
	now := b.now()
	sr.Ciphertext = ciphertext
	sr.Version++
	sr.RotatedAt = &now
	if keyHint != "" {
		sr.KeyHint = keyHint
	}
	if err := b.store.PutSecretRef(ctx, sr); err != nil {
		return true, err
	}
	b.Invalidate(connectorID)
	b.audit(evSecretRotated, tenant, connectorID, string(sr.Provider), "success",
		fmt.Sprintf("kind=%s version=%d", sr.Kind, sr.Version))
	return true, nil
}

// resolveSecret decrypts the referenced legacy secret. ONLY the broker calls this.
// Audits SECRET_ACCESSED. The returned plaintext is never logged.
func (b *cloudIdentityBroker) resolveSecret(ctx context.Context, tenant string, c cloudConnector) (string, error) {
	ref := c.Identity.LegacySecretRef
	if ref == "" {
		return "", errBrokerNoSecret
	}
	sr, found, err := b.store.GetSecretRef(ctx, tenant, false, ref)
	if err != nil {
		return "", err
	}
	if !found || sr.ConnectorID != c.ConnectorID {
		return "", errBrokerNoSecret
	}
	plaintext, err := b.vault.Decrypt(normTenant(tenant), ccnSecretFieldID(c.ConnectorID, sr.Kind), sr.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("cloudconn: decrypt secret: %w", err)
	}
	b.audit(evSecretAccessed, tenant, c.ConnectorID, string(c.Provider), "success", "kind="+sr.Kind)
	return plaintext, nil
}

// TokenFor mints (or serves from cache) a short-lived, tenant+connector-scoped
// provider token. Fails closed if the connector is not visible to the tenant or
// its state cannot exchange tokens. Audits TOKEN_ISSUED on a fresh mint.
func (b *cloudIdentityBroker) TokenFor(ctx context.Context, req scopedTokenRequest) (cloudconn.ScopedToken, error) {
	c, found, err := b.store.Get(ctx, req.Tenant, false, req.ConnectorID)
	if err != nil {
		return cloudconn.ScopedToken{}, err
	}
	if !found {
		return cloudconn.ScopedToken{}, errBrokerNotFound
	}
	if !c.State.CanExchangeToken() {
		return cloudconn.ScopedToken{}, errBrokerNotActive
	}

	effLife := req.MaxLifetime
	if effLife <= 0 || effLife > b.maxLife {
		effLife = b.maxLife
	}
	identityRef := connectorIdentityRef(c)
	key := req.cacheKey(c.Provider, identityRef)

	// Serve from cache while the token is within its refresh window (80% TTL)
	// and comfortably before expiry.
	b.mu.Lock()
	if ct, ok := b.cache[key]; ok && ct.fresh(b.now()) {
		tok := ct.token
		b.mu.Unlock()
		b.metrics.recordCacheHit(c.Provider)
		return tok, nil
	}
	b.mu.Unlock()

	adapter := b.adapter(c.Provider)
	if adapter == nil {
		return cloudconn.ScopedToken{}, fmt.Errorf("cloudconn: no adapter for provider %s", c.Provider)
	}

	exReq := cloudconn.ExchangeRequest{
		Identity:        c.Identity,
		CapabilitySetID: req.CapabilitySetID,
		Scope:           cloudconn.Scope{Ref: req.ProviderAccount},
		Audience:        req.Audience,
		Region:          req.Region,
		MaxLifetime:     effLife,
	}
	// Legacy methods need the decrypted secret — resolved ONLY here, at call time.
	if c.AuthMethod.HoldsStoredSecret() {
		secret, err := b.resolveSecret(ctx, req.Tenant, c)
		if err != nil {
			return cloudconn.ScopedToken{}, err
		}
		exReq.LegacySecret = secret
	}

	exStart := b.now()
	tok, err := adapter.ExchangeCredential(ctx, exReq)
	b.metrics.recordExchange(c.Provider, err, b.now().Sub(exStart))
	if err != nil {
		// Observable failure: structured log + audit, NEVER any secret material
		// (ExchangeError is sanitized by contract; deferral sentinels are static).
		log.Printf(`{"event":"cloudconn_exchange_failed","tenant":%q,"connector":%q,"provider":%q,"error":%q}`,
			normTenant(req.Tenant), c.ConnectorID, string(c.Provider), err.Error())
		b.audit(evTokenIssued, req.Tenant, c.ConnectorID, string(c.Provider), "deny", "exchange failed: "+err.Error())
		return cloudconn.ScopedToken{}, err
	}
	now := b.now()
	// Enforce the max-lifetime cap on the returned token. Providers with fixed
	// token lifetimes the caller cannot shorten (Azure Entra: 60–90 min) are
	// CLAMPED to the cap; a token beyond the slack bound is rejected outright.
	if !tok.Expiry.IsZero() && tok.Expiry.Sub(now) > effLife+brokerTokenMargin {
		if tok.Expiry.Sub(now) > time.Duration(float64(effLife)*brokerLifetimeSlack)+brokerTokenMargin {
			log.Printf(`{"event":"cloudconn_token_lifetime_rejected","tenant":%q,"connector":%q,"provider":%q,"lifetime":%q,"cap":%q}`,
				normTenant(req.Tenant), c.ConnectorID, string(c.Provider), tok.Expiry.Sub(now).String(), effLife.String())
			return cloudconn.ScopedToken{}, errBrokerTokenTooLong
		}
		tok.Expiry = now.Add(effLife)
	}

	b.mu.Lock()
	b.cache[key] = cachedToken{token: tok, mintedAt: now}
	b.mu.Unlock()
	b.audit(evTokenIssued, req.Tenant, c.ConnectorID, string(c.Provider), "success",
		fmt.Sprintf("account=%s caps=%s ttl=%s", req.ProviderAccount, req.CapabilitySetID, effLife))
	return tok, nil
}

// Invalidate drops all cached tokens for a connector (called on disable/revoke/
// rotate so a paused connector cannot keep serving a warm token).
func (b *cloudIdentityBroker) Invalidate(connectorID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for k := range b.cache {
		// keys are opaque hashes; we cannot match by connector without the source
		// tuple, so we clear conservatively when a connector changes state. The
		// cache is a performance aid, not a source of truth — clearing is safe.
		_ = k
	}
	// Full clear keeps disable/revoke fail-closed without leaking cross-connector.
	b.cache = map[string]cachedToken{}
}

// connectorIdentityRef returns the provider-native identity reference used in the
// cache key (role ARN / client id / SA email). Never used as a cache key ALONE.
// Resolution is registry-driven (cloudconn.ProviderDescriptor.IdentityRef) — no
// per-provider switch to extend when a provider is added.
func connectorIdentityRef(c cloudConnector) string {
	return cloudconn.IdentityRefFor(c.Provider, c.Identity)
}

func (b *cloudIdentityBroker) audit(event, tenant, connectorID, provider, decision, detail string) {
	if b.auditFn == nil {
		return
	}
	b.auditFn(AuditEvent{
		Actor: "broker", Tenant: normTenant(tenant), Method: event, Path: "/cloudconn/broker/" + connectorID,
		Status: 200, Decision: decision,
		Detail: map[string]any{"event": event, "connector": connectorID, "provider": provider, "info": detail},
	})
}
