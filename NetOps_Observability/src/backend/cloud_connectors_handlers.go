// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"netops/backend/cloudconn"
)

// Connector lifecycle audit event names (emitted through the request-path audit
// middleware Detail, plus explicit records for security-relevant transitions).
const (
	evConnectorCreated   = "CONNECTOR_CREATED"
	evConnectorValidated = "TRUST_VALIDATED"
	evConnectorActivated = "CONNECTOR_ENABLED"
	evConnectorDisabled  = "CONNECTOR_DISABLED"
	evConnectorRevoked   = "CONNECTOR_REVOKED"
	evScopeChanged       = "SCOPE_CHANGED"
)

var (
	errCCNStoreOff = errors.New("cloud connectors require the postgres backend or dev in-memory store")
	errCCNNotFound = errors.New("connector not found")
)

// cloudconn.ConnectorView is the API projection — trust metadata only, NEVER a secret.
func (s *server) cloudTrustAnchor(connectorID string) cloudconn.TrustAnchor {
	return cloudconn.TrustAnchor{
		AWSPrincipalARN: os.Getenv("CLOUD_CONNECTOR_AWS_PRINCIPAL_ARN"),
		OIDCIssuer:      os.Getenv("CLOUD_CONNECTOR_OIDC_ISSUER"),
		OIDCSubject:     "correlix:connector:" + connectorID,
		OIDCAudience:    envOr("CLOUD_CONNECTOR_OIDC_AUDIENCE", ""),
	}
}

// ── collection: /api/cloud/connectors ────────────────────────────────────────

func (s *server) handleCloudConnectors(w http.ResponseWriter, r *http.Request) {
	if s.cloudConn == nil {
		writeError(w, http.StatusNotImplemented, errCCNStoreOff)
		return
	}
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		list, err := s.cloudConn.List(r.Context(), tenant, cross)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		views := make([]cloudconn.ConnectorView, 0, len(list))
		for _, c := range list {
			views = append(views, cloudconn.ToConnectorView(c))
		}
		writeJSON(w, http.StatusOK, map[string]any{"connectors": views})
	case http.MethodPost:
		s.createCloudConnectorDraft(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

type createConnectorReq struct {
	Provider    string `json:"provider"`
	DisplayName string `json:"display_name"`
}

func (s *server) createCloudConnectorDraft(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
	if !ok {
		return
	}
	tenant, _ := principalTenant(claims)
	var req createConnectorReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	provider, valid := cloudconn.ParseProvider(req.Provider)
	if !valid {
		// Registry-driven message: names exactly the providers this build offers.
		known := cloudconn.RegisteredProviders()
		toks := make([]string, 0, len(known))
		for _, p := range known {
			toks = append(toks, string(p))
		}
		writeJSONError(w, http.StatusBadRequest, "unknown provider ("+strings.Join(toks, "|")+")", "PROVIDER_INVALID")
		return
	}
	c := cloudconn.Connector{
		TenantID: tenant, ConnectorID: newOpaqueID(cloudconn.ConnectorIDPrefix), Provider: provider,
		DisplayName: strings.TrimSpace(req.DisplayName), State: cloudconn.StateDraft,
		Identity:        cloudconn.IdentityConfig{Provider: provider, TenantID: tenant},
		Scopes:          []cloudconn.Scope{},
		IdentityHealth:  cloudconn.HealthStatus{State: "unknown"},
		TelemetryHealth: cloudconn.HealthStatus{State: "unknown"},
	}
	c.Identity.ConnectorID = c.ConnectorID
	created, err := s.cloudConn.Create(r.Context(), c)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordConnectorEvent(r, claims, evConnectorCreated, created, "provider="+string(provider))
	writeJSON(w, http.StatusCreated, cloudconn.ToConnectorView(created))
}

// ── by-id subtree: /api/cloud/connectors/{id}[/action] ───────────────────────

func (s *server) handleCloudConnectorByID(w http.ResponseWriter, r *http.Request) {
	if s.cloudConn == nil {
		writeError(w, http.StatusNotImplemented, errCCNStoreOff)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/cloud/connectors/")
	parts := strings.Split(rest, "/")
	id := parts[0]
	if !strings.HasPrefix(id, cloudconn.ConnectorIDPrefix) {
		writeError(w, http.StatusBadRequest, errors.New("invalid connector id"))
		return
	}
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	switch action {
	case "":
		s.serveConnectorRoot(w, r, id)
	case "auth":
		s.serveConnectorAuth(w, r, id)
	case "scopes":
		s.serveConnectorScopes(w, r, id)
	case "org":
		s.serveConnectorOrg(w, r, id)
	case "capabilities":
		s.serveConnectorCapabilities(w, r, id)
	case "setup":
		s.serveConnectorSetup(w, r, id)
	case "validate":
		s.serveConnectorValidate(w, r, id)
	case "permissions":
		s.serveConnectorPermissions(w, r, id)
	case "discover-scopes":
		s.serveConnectorDiscover(w, r, id)
	case "activate":
		s.serveConnectorTransition(w, r, id, cloudconn.StateActive, evConnectorActivated)
	case "disable":
		s.serveConnectorTransition(w, r, id, cloudconn.StateDisabled, evConnectorDisabled)
	case "revoke":
		s.serveConnectorTransition(w, r, id, cloudconn.StateRevoked, evConnectorRevoked)
	case "secret":
		s.serveConnectorSecret(w, r, id)
	case "rotate":
		s.serveConnectorRotate(w, r, id)
	case "health":
		s.serveConnectorHealth(w, r, id)
	default:
		writeError(w, http.StatusNotFound, errors.New("unknown connector action"))
	}
}

func (s *server) loadConnector(w http.ResponseWriter, r *http.Request, id string, level int) (cloudconn.Connector, jwtClaims, bool) {
	claims, ok := s.requirePerm(w, r, "infrastructure", level)
	if !ok {
		return cloudconn.Connector{}, claims, false
	}
	tenant, cross := principalTenant(claims)
	c, found, err := s.cloudConn.Get(r.Context(), tenant, cross, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return cloudconn.Connector{}, claims, false
	}
	if !found {
		writeError(w, http.StatusNotFound, errCCNNotFound)
		return cloudconn.Connector{}, claims, false
	}
	return c, claims, true
}

func (s *server) serveConnectorRoot(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodGet:
		c, _, ok := s.loadConnector(w, r, id, LevelRead)
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, cloudconn.ToConnectorView(c))
	case http.MethodDelete:
		c, claims, ok := s.loadConnector(w, r, id, LevelWrite)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		if _, err := s.cloudConn.DeleteSecretRefs(r.Context(), tenant, cross, id); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		deleted, err := s.cloudConn.Delete(r.Context(), tenant, cross, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !deleted {
			writeError(w, http.StatusNotFound, errCCNNotFound)
			return
		}
		if s.cloudBroker != nil {
			s.cloudBroker.Invalidate(id)
		}
		s.recordConnectorEvent(r, claims, evConnectorRevoked, c, "deleted")
		writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or DELETE"))
	}
}

type selectAuthReq struct {
	Method           string `json:"method"`
	RoleARN          string `json:"role_arn"`
	AzureTenantID    string `json:"azure_tenant_id"`
	ClientID         string `json:"client_id"`
	Audience         string `json:"audience"`
	Issuer           string `json:"issuer"`
	FederatedSubject string `json:"federated_subject"`
	CertThumbprint   string `json:"cert_thumbprint"`
	ProjectNumber    string `json:"project_number"`
	WorkloadPool     string `json:"workload_pool"`
	WorkloadProvider string `json:"workload_provider"`
	ServiceAccount   string `json:"service_account"`
}

func (s *server) serveConnectorAuth(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST"))
		return
	}
	c, claims, ok := s.loadConnector(w, r, id, LevelWrite)
	if !ok {
		return
	}
	var req selectAuthReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	method, valid := cloudconn.ParseAuthMethod(req.Method)
	if !valid || !cloudconn.MethodAllowed(c.Provider, method) {
		writeJSONError(w, http.StatusBadRequest, "auth method not supported for provider", "METHOD_INVALID")
		return
	}
	// Trust metadata is stamped from the request; the TENANT is never taken from
	// the body (it stays the connector's owner). Secrets never travel here.
	c.AuthMethod = method
	c.Identity.Method = method
	c.Identity.RoleARN = strings.TrimSpace(req.RoleARN)
	c.Identity.AzureTenantID = strings.TrimSpace(req.AzureTenantID)
	c.Identity.ClientID = strings.TrimSpace(req.ClientID)
	c.Identity.Audience = strings.TrimSpace(req.Audience)
	c.Identity.Issuer = strings.TrimSpace(req.Issuer)
	c.Identity.FederatedSubject = strings.TrimSpace(req.FederatedSubject)
	c.Identity.CertThumbprint = strings.TrimSpace(req.CertThumbprint)
	c.Identity.ProjectNumber = strings.TrimSpace(req.ProjectNumber)
	c.Identity.WorkloadPool = strings.TrimSpace(req.WorkloadPool)
	c.Identity.WorkloadProvider = strings.TrimSpace(req.WorkloadProvider)
	c.Identity.ServiceAccount = strings.TrimSpace(req.ServiceAccount)

	// AWS cross-account role: mint a per-tenant+connector ExternalId if absent
	// (confused-deputy). Never derived — always framework-minted randomness.
	// Workload federation does NOT use one: AssumeRoleWithWebIdentity has no
	// ExternalId parameter; its confused-deputy protection is the role trust
	// policy's aud/sub pin on the OIDC provider.
	if c.Provider == cloudconn.ProviderAWS && method == cloudconn.AuthMethodCloudRole && c.Identity.ExternalID == "" {
		c.Identity.ExternalID = cloudconn.NewExternalID()
	}
	s.saveConnectorAndRespond(w, r, claims, c)
}

type selectScopesReq struct {
	Scopes []cloudconn.Scope `json:"scopes"`
}

func (s *server) serveConnectorScopes(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST"))
		return
	}
	c, claims, ok := s.loadConnector(w, r, id, LevelWrite)
	if !ok {
		return
	}
	var req selectScopesReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := cloudconn.ValidateScopes(c.Provider, req.Scopes); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error(), "SCOPE_INVALID")
		return
	}
	c.Scopes = req.Scopes
	s.recordConnectorEvent(r, claims, evScopeChanged, c, "scopes updated")
	s.saveConnectorAndRespond(w, r, claims, c)
}

// ── org-level (multi-account) enrollment: POST /{id}/org ─────────────────────

// orgScopeReq sets or clears the connector's org anchor. An empty type clears
// org mode (back to single-account). The TENANT never travels here (§3a.2):
// the anchor lives on the tenant-owned connector row, and every member scope
// discovered or selected under it inherits that row's tenant.
type orgScopeReq struct {
	Type         string `json:"type"` // org | ou | mgmt_group | folder — "" clears
	Ref          string `json:"ref"`
	RoleTemplate string `json:"role_template"`
}

func (s *server) serveConnectorOrg(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST"))
		return
	}
	c, claims, ok := s.loadConnector(w, r, id, LevelWrite)
	if !ok {
		return
	}
	var req orgScopeReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Type) == "" {
		c.Identity.Org = nil
		s.recordConnectorEvent(r, claims, evScopeChanged, c, "org anchor cleared")
		s.saveConnectorAndRespond(w, r, claims, c)
		return
	}
	st, _ := cloudconn.ParseScopeType(req.Type)
	anchor := cloudconn.OrgScopeAnchor{
		Type:         st,
		Ref:          strings.TrimSpace(req.Ref),
		RoleTemplate: strings.TrimSpace(req.RoleTemplate),
	}
	if err := cloudconn.ValidateOrgAnchor(c.Provider, anchor); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error(), "ORG_SCOPE_INVALID")
		return
	}
	c.Identity.Org = &anchor
	s.recordConnectorEvent(r, claims, evScopeChanged, c, "org anchor set: "+string(anchor.Type)+"="+anchor.Ref)
	s.saveConnectorAndRespond(w, r, claims, c)
}

type selectCapReq struct {
	CapabilityPack string `json:"capability_pack"`
}

func (s *server) serveConnectorCapabilities(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST"))
		return
	}
	c, claims, ok := s.loadConnector(w, r, id, LevelWrite)
	if !ok {
		return
	}
	var req selectCapReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	pack, found := cloudconn.Pack(req.CapabilityPack)
	if !found || pack.Provider != c.Provider {
		writeJSONError(w, http.StatusBadRequest, "unknown capability pack for provider", "PACK_INVALID")
		return
	}
	c.PackFullID = pack.FullID()
	s.saveConnectorAndRespond(w, r, claims, c)
}

func (s *server) serveConnectorSetup(w http.ResponseWriter, r *http.Request, id string) {
	c, _, ok := s.loadConnector(w, r, id, LevelRead)
	if !ok {
		return
	}
	pack, found := cloudconn.Pack(c.PackFullID)
	if !found {
		// Default to the provider's observer pack so setup can be previewed early.
		packs := cloudconn.PacksForProvider(c.Provider)
		if len(packs) == 0 {
			writeJSONError(w, http.StatusBadRequest, "no capability pack selected", "PACK_MISSING")
			return
		}
		pack = packs[0]
	}
	adapter := cloudconn.AdapterFor(c.Provider)
	cfg := c.Identity
	cfg.Anchor = s.cloudTrustAnchor(c.ConnectorID)
	bundle, err := adapter.SetupInstructions(cfg, pack)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, bundle)
}

// serveConnectorValidate runs the PURE configuration validation (no network),
// then — when the configuration passes — proves the trust LIVE through the
// Identity Broker (STS AssumeRole / Entra token / GCP STS exchange). It does
// NOT auto-activate. Identity health outcomes:
//   - live exchange succeeded          → "live_verified"
//   - platform identity not configured → "config_validated" (live check deferred)
//   - provider refused the exchange    → "failed" (+ live_trust_failed finding)
//
// A successful auth still never implies data is flowing — identity health stays
// SEPARATE from telemetry health.
func (s *server) serveConnectorValidate(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST"))
		return
	}
	c, claims, ok := s.loadConnector(w, r, id, LevelWrite)
	if !ok {
		return
	}
	if c.AuthMethod == "" {
		writeJSONError(w, http.StatusConflict, "select an auth method before validating", "AUTH_NOT_SET")
		return
	}
	adapter := cloudconn.AdapterFor(c.Provider)
	res := adapter.ValidateConfiguration(c.Identity)
	c.LastValidation = res
	now := time.Now().UTC()
	liveCheck := "deferred"
	if res.OK {
		c.IdentityHealth = cloudconn.HealthStatus{State: "config_validated", Detail: "configuration validated; live trust proof pending", Checked: now}
		if cloudconn.CanTransition(c.State, cloudconn.StateValidating) {
			c.State = cloudconn.StateValidating
		}
	} else {
		c.IdentityHealth = cloudconn.HealthStatus{State: "failed", Detail: "configuration has blocking findings", Checked: now}
	}
	// Persist the config-validation outcome FIRST: the broker re-reads the
	// connector (state gate + secret refs) from the store.
	saved, ok := s.persistConnector(w, r, c)
	if !ok {
		return
	}

	if res.OK && s.cloudBroker != nil {
		liveCheck, saved = s.liveTrustCheck(w, r, claims, saved, &res)
		if saved.ConnectorID == "" { // persist failed and the helper already responded
			return
		}
	}
	s.recordConnectorEvent(r, claims, evConnectorValidated, saved, "ok="+boolStr(res.OK)+" live="+liveCheck)
	writeJSON(w, http.StatusOK, map[string]any{
		"connector":  cloudconn.ToConnectorView(saved),
		"validation": res,
		"live_check": liveCheck,
	})
}

// liveTrustCheck asks the Identity Broker for a real scoped token (bounded to
// 15s) and folds the outcome into identity health + the validation findings.
// Returns the live_check marker and the re-persisted connector (zero-value
// connector when persisting failed and an error response was already written).
func (s *server) liveTrustCheck(w http.ResponseWriter, r *http.Request, claims jwtClaims, c cloudconn.Connector, res *cloudconn.ValidationResult) (string, cloudconn.Connector) {
	tenant, _ := principalTenant(claims)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	req := cloudconn.ScopedTokenRequest{
		Tenant:          tenant,
		ConnectorID:     c.ConnectorID,
		CapabilitySetID: c.PackFullID,
	}
	for _, sc := range c.Scopes {
		if sc.Type == cloudconn.ScopeRegion && req.Region == "" {
			req.Region = sc.Ref
			continue
		}
		if req.ProviderAccount == "" {
			req.ProviderAccount = sc.Ref
			if len(sc.Regions) > 0 && req.Region == "" {
				req.Region = sc.Regions[0]
			}
		}
	}

	now := time.Now().UTC()
	liveCheck := "ok"
	_, err := s.cloudBroker.TokenFor(ctx, req)
	switch {
	case err == nil:
		c.IdentityHealth = cloudconn.HealthStatus{State: "live_verified", Detail: "live trust proven: provider issued a scoped short-lived credential", Checked: now}
	case errors.Is(err, cloudconn.ErrPlatformCredentialsMissing),
		errors.Is(err, cloudconn.ErrWorkloadAssertionMissing),
		errors.Is(err, cloudconn.ErrProviderExchangeDeferred):
		liveCheck = "deferred"
		c.IdentityHealth = cloudconn.HealthStatus{State: "config_validated", Detail: "configuration validated; live check deferred: " + err.Error(), Checked: now}
	default:
		liveCheck = "failed"
		// The error surface is sanitized by contract (ExchangeError / broker
		// sentinels) — safe to persist and show as remediation.
		c.IdentityHealth = cloudconn.HealthStatus{State: "failed", Detail: "live trust check failed: " + err.Error(), Checked: now}
		res.Add(cloudconn.SeverityWarning, "live_trust_failed",
			"the provider refused to issue a credential for this identity",
			"Verify the deployed trust (role/app/pool), the ExternalId/federated subject, and the stored secret, then validate again.")
		c.LastValidation = *res
	}
	saved, ok := s.persistConnector(w, r, c)
	if !ok {
		return liveCheck, cloudconn.Connector{}
	}
	return liveCheck, saved
}

// connectorProbeToken mints (or serves cached) the broker token a live probe
// authenticates with, bounded to 20s. The deferral sentinels come back as
// ("deferred", reason); a provider refusal comes back as an error.
func (s *server) connectorProbeToken(r *http.Request, tenant string, c cloudconn.Connector) (cloudconn.ScopedToken, string, string, string, error) {
	account, region := cloudconn.DefaultScope(c)
	ctx, cancel := context.WithTimeout(r.Context(), ingestCredTimeout)
	defer cancel()
	tok, err := s.cloudBroker.TokenFor(ctx, cloudconn.ScopedTokenRequest{
		Tenant:          tenant,
		ConnectorID:     c.ConnectorID,
		ProviderAccount: account,
		Region:          region,
		CapabilitySetID: c.PackFullID,
	})
	if err != nil {
		if errors.Is(err, cloudconn.ErrPlatformCredentialsMissing) ||
			errors.Is(err, cloudconn.ErrWorkloadAssertionMissing) ||
			errors.Is(err, cloudconn.ErrProviderExchangeDeferred) {
			return cloudconn.ScopedToken{}, account, region, err.Error(), nil
		}
		return cloudconn.ScopedToken{}, account, region, "", err
	}
	return tok, account, region, "", nil
}

// serveConnectorPermissions is the LIVE permission validation (Wave 4 #13): it
// mints a scoped token through the Identity Broker and runs the provider's
// cheapest identity + per-permission dry probes (AWS GetCallerIdentity + IAM
// policy simulation, Azure RBAC permissions read, GCP testIamPermissions).
// Per-capability denials are recorded into the source-status surface the
// Ingestion Status page renders (permission_denied, per account/region scope).
// Deployments without a platform identity get an HONEST "deferred" marker.
func (s *server) serveConnectorPermissions(w http.ResponseWriter, r *http.Request, id string) {
	c, claims, ok := s.loadConnector(w, r, id, LevelWrite)
	if !ok {
		return
	}
	pack, found := cloudconn.Pack(c.PackFullID)
	if !found {
		writeJSONError(w, http.StatusBadRequest, "no capability pack selected", "PACK_MISSING")
		return
	}
	base := map[string]any{
		"capability_pack":      pack.FullID(),
		"required_permissions": pack.AllPermissions(),
	}
	if s.cloudBroker == nil {
		base["live_check"] = "deferred"
		base["note"] = "the identity broker is not available in this deployment"
		writeJSON(w, http.StatusOK, base)
		return
	}
	tenant, _ := principalTenant(claims)
	tok, account, region, deferReason, err := s.connectorProbeToken(r, tenant, c)
	if err != nil {
		// ExchangeError is sanitized by contract — safe to surface, never a secret.
		base["live_check"] = "failed"
		base["error"] = err.Error()
		writeJSON(w, http.StatusOK, base)
		return
	}
	if deferReason != "" {
		base["live_check"] = "deferred"
		base["note"] = deferReason
		writeJSON(w, http.StatusOK, base)
		return
	}
	adapter := s.cloudBroker.AdapterFor(c.Provider)
	if adapter == nil {
		writeError(w, http.StatusInternalServerError, errors.New("no adapter for provider"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), ingestCredTimeout)
	defer cancel()
	report, err := adapter.ValidateCapabilities(ctx, cloudconn.CapabilityCheckRequest{
		Identity: c.Identity,
		Pack:     pack,
		Scope:    cloudconn.Scope{Ref: account},
		Token:    tok,
	})
	switch {
	case errors.Is(err, cloudconn.ErrProviderExchangeDeferred):
		base["live_check"] = "deferred"
		base["note"] = "the live permission probe is not wired in this deployment"
	case err != nil:
		base["live_check"] = "failed"
		base["error"] = err.Error()
	default:
		base["live_check"] = "ok"
		base["report"] = report
		s.recordPermissionSourceStatus(c, pack, report, account, region)
		s.recordConnectorEvent(r, claims, "PERMISSIONS_VALIDATED", c,
			"pack="+pack.FullID()+" all_granted="+boolStr(report.AllGranted))
	}
	writeJSON(w, http.StatusOK, base)
}

// recordPermissionSourceStatus folds the per-permission report into the
// source-status store: each pack capability whose permissions include a denial
// becomes a permission_denied record on ITS source chip (per account/region
// scope detail); a fully-granted capability clears its record. Tenant and
// provider are stamped from the CONNECTOR ROW (§3a.2).
func (s *server) recordPermissionSourceStatus(c cloudconn.Connector, pack cloudconn.CapabilityPack, report cloudconn.CapabilityReport, account, region string) {
	if s.cloudSourceStatus == nil {
		return
	}
	granted := make(map[string]bool, len(report.Permissions))
	verified := make(map[string]bool, len(report.Permissions))
	for _, p := range report.Permissions {
		granted[p.Permission] = p.Granted
		verified[p.Permission] = !strings.HasPrefix(p.Detail, "unverified")
	}
	now := time.Now().UTC()
	var denied []cloudSourceStatusRecord
	for _, capa := range pack.Capabilities {
		var missing []string
		unverified := false
		for _, perm := range capa.Permissions {
			if !verified[perm] {
				unverified = true
				continue
			}
			if !granted[perm] {
				missing = append(missing, perm)
			}
		}
		rec := cloudSourceStatusRecord{
			Tenant:      c.TenantID,
			ConnectorID: c.ConnectorID,
			Provider:    strings.ToLower(string(c.Provider)),
			AccountID:   account,
			Region:      region,
			SourceType:  capa.Key,
		}
		if len(missing) == 0 {
			// Fully granted, or unverifiable — either way we may not claim a
			// denial. Unverified stays silent (unknown ≠ broken).
			_ = unverified
			s.cloudSourceStatus.ClearValidate(rec)
			continue
		}
		rec.Status = "permission_denied"
		rec.Detail = "denied: " + strings.Join(missing, ", ")
		if len(rec.Detail) > srcStatusDetailMax {
			rec.Detail = rec.Detail[:srcStatusDetailMax]
		}
		denied = append(denied, rec)
	}
	if len(denied) > 0 {
		s.cloudSourceStatus.UpsertValidate(denied, now)
	}
}

// serveConnectorDiscover is LIVE scope discovery (Wave 4 #13): the broker mints
// a scoped token and the provider probe enumerates the reachable scopes (AWS
// caller account, Azure subscriptions, GCP projects). Operator-entered scopes
// are always returned; discovery never silently widens the collection scope —
// the operator still selects what to observe.
func (s *server) serveConnectorDiscover(w http.ResponseWriter, r *http.Request, id string) {
	c, claims, ok := s.loadConnector(w, r, id, LevelWrite)
	if !ok {
		return
	}
	base := map[string]any{
		"scopes":      c.Scopes,
		"scope_types": cloudconn.ScopeTypesForProvider(c.Provider),
	}
	// ORG connector: enumeration runs against the org anchor; the discovered
	// member scopes inherit the CONNECTOR's tenant by construction (§3a — the
	// response is data on this tenant-owned row, nothing is persisted here).
	if c.Identity.Org != nil {
		base["org_scope"] = c.Identity.Org
		base["member_scope_type"] = cloudconn.MemberScopeTypeForProvider(c.Provider)
	}
	if s.cloudBroker == nil {
		base["live_check"] = "deferred"
		writeJSON(w, http.StatusOK, base)
		return
	}
	tenant, _ := principalTenant(claims)
	tok, account, _, deferReason, err := s.connectorProbeToken(r, tenant, c)
	if err != nil {
		base["live_check"] = "failed"
		base["error"] = err.Error()
		writeJSON(w, http.StatusOK, base)
		return
	}
	if deferReason != "" {
		base["live_check"] = "deferred"
		base["note"] = deferReason
		writeJSON(w, http.StatusOK, base)
		return
	}
	adapter := s.cloudBroker.AdapterFor(c.Provider)
	if adapter == nil {
		writeError(w, http.StatusInternalServerError, errors.New("no adapter for provider"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), ingestCredTimeout)
	defer cancel()
	root := cloudconn.Scope{Ref: account}
	if org := c.Identity.Org; org != nil {
		root = cloudconn.Scope{Type: org.Type, Ref: org.Ref}
	}
	discovered, err := adapter.DiscoverScopes(ctx, cloudconn.DiscoverRequest{
		Identity: c.Identity,
		Root:     root,
		Token:    tok,
	})
	switch {
	case errors.Is(err, cloudconn.ErrProviderExchangeDeferred):
		base["live_check"] = "deferred"
	case err != nil:
		base["live_check"] = "failed"
		base["error"] = err.Error()
	default:
		base["live_check"] = "ok"
		base["discovered"] = discovered
	}
	writeJSON(w, http.StatusOK, base)
}

func (s *server) serveConnectorTransition(w http.ResponseWriter, r *http.Request, id string, target cloudconn.LifecycleState, event string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST"))
		return
	}
	c, claims, ok := s.loadConnector(w, r, id, LevelWrite)
	if !ok {
		return
	}
	// A connector cannot go ACTIVE until its configuration validation succeeded.
	if target == cloudconn.StateActive && !c.LastValidation.OK {
		writeJSONError(w, http.StatusConflict, "validate the connector before activating", "NOT_VALIDATED")
		return
	}
	if !cloudconn.CanTransition(c.State, target) {
		writeJSONError(w, http.StatusConflict, "illegal transition from "+string(c.State)+" to "+string(target), "ILLEGAL_TRANSITION")
		return
	}
	c.State = target
	if target != cloudconn.StateActive {
		// Pausing/revoking clears any cached token so collection stops immediately.
		if s.cloudBroker != nil {
			s.cloudBroker.Invalidate(id)
		}
	}
	s.recordConnectorEvent(r, claims, event, c, "state="+string(target))
	s.saveConnectorAndRespond(w, r, claims, c)
}

type storeSecretReq struct {
	Kind    string `json:"kind"`
	KeyHint string `json:"key_hint"`
	Secret  string `json:"secret"`
}

func (s *server) serveConnectorSecret(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST"))
		return
	}
	c, claims, ok := s.loadConnector(w, r, id, LevelWrite)
	if !ok {
		return
	}
	if !c.AuthMethod.HoldsStoredSecret() {
		writeJSONError(w, http.StatusConflict, "this auth method does not use a stored secret (prefer federated)", "NOT_LEGACY")
		return
	}
	if s.cloudBroker == nil {
		writeError(w, http.StatusNotImplemented, errCCNStoreOff)
		return
	}
	var req storeSecretReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Secret) == "" {
		writeJSONError(w, http.StatusBadRequest, "secret is required", "SECRET_MISSING")
		return
	}
	if cloudconn.IsRootKeyHint(req.KeyHint) {
		writeJSONError(w, http.StatusBadRequest, "root/admin credentials are rejected — use a dedicated least-privilege identity", "ROOT_REJECTED")
		return
	}
	// Certificate method: validate the PEM bundle structurally BEFORE encrypting
	// (parseable, key matches cert, within validity) and cross-check/auto-fill
	// the configured thumbprint — a bad bundle fails at upload, not at the first
	// exchange. The thumbprint is non-secret (it's what the Azure portal shows).
	if c.AuthMethod == cloudconn.AuthMethodCertificate {
		thumb, terr := cloudconn.AzureCertBundleThumbprint(req.Secret, time.Now().UTC())
		if terr != nil {
			msg := "certificate bundle invalid"
			var xe *cloudconn.ExchangeError
			if errors.As(terr, &xe) && xe.Msg != "" {
				msg = "certificate bundle invalid: " + xe.Msg
			}
			writeJSONError(w, http.StatusBadRequest, msg, "CERT_BUNDLE_INVALID")
			return
		}
		if cfg := cloudconn.NormalizeAzureThumbprint(c.Identity.CertThumbprint); cfg != "" && cfg != thumb {
			writeJSONError(w, http.StatusBadRequest, "certificate bundle does not match the configured thumbprint", "CERT_THUMBPRINT_MISMATCH")
			return
		}
		if strings.TrimSpace(c.Identity.CertThumbprint) == "" {
			c.Identity.CertThumbprint = thumb
		}
		if strings.TrimSpace(req.KeyHint) == "" {
			req.KeyHint = thumb // non-secret display/age hint
		}
		if strings.TrimSpace(req.Kind) == "" {
			req.Kind = "certificate"
		}
	}
	tenant, _ := principalTenant(claims)
	ref, err := s.cloudBroker.StoreSecret(r.Context(), tenant, c.ConnectorID, c.Provider, strings.TrimSpace(req.Kind), strings.TrimSpace(req.KeyHint), req.Secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	c.Identity.LegacySecretRef = ref
	c.Identity.LegacyKeyID = strings.TrimSpace(req.KeyHint)
	// The plaintext is now encrypted in the Vault; it is never echoed back.
	s.saveConnectorAndRespond(w, r, claims, c)
}

type rotateSecretReq struct {
	KeyHint string `json:"key_hint"`
	Secret  string `json:"secret"`
}

func (s *server) serveConnectorRotate(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST"))
		return
	}
	c, claims, ok := s.loadConnector(w, r, id, LevelWrite)
	if !ok {
		return
	}
	if c.Identity.LegacySecretRef == "" || s.cloudBroker == nil {
		writeJSONError(w, http.StatusConflict, "no stored secret to rotate", "NO_SECRET")
		return
	}
	var req rotateSecretReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if cloudconn.IsRootKeyHint(req.KeyHint) {
		writeJSONError(w, http.StatusBadRequest, "root/admin credentials are rejected", "ROOT_REJECTED")
		return
	}
	tenant, _ := principalTenant(claims)
	found, err := s.cloudBroker.RotateSecret(r.Context(), tenant, c.Identity.LegacySecretRef, c.ConnectorID, strings.TrimSpace(req.KeyHint), req.Secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, errCCNNotFound)
		return
	}
	if strings.TrimSpace(req.KeyHint) != "" {
		c.Identity.LegacyKeyID = strings.TrimSpace(req.KeyHint)
		s.saveConnectorAndRespond(w, r, claims, c)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rotated": id})
}

// serveConnectorHealth returns identity + telemetry health SEPARATELY.
func (s *server) serveConnectorHealth(w http.ResponseWriter, r *http.Request, id string) {
	c, _, ok := s.loadConnector(w, r, id, LevelRead)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"state":            c.State,
		"collecting":       c.State.Collecting(),
		"identity_health":  c.IdentityHealth,
		"telemetry_health": c.TelemetryHealth,
	})
}

// ── shared helpers ────────────────────────────────────────────────────────────

func (s *server) saveConnectorAndRespond(w http.ResponseWriter, r *http.Request, claims jwtClaims, c cloudconn.Connector) {
	saved, ok := s.persistConnector(w, r, c)
	if !ok {
		return
	}
	_ = claims
	writeJSON(w, http.StatusOK, cloudconn.ToConnectorView(saved))
}

func (s *server) persistConnector(w http.ResponseWriter, r *http.Request, c cloudconn.Connector) (cloudconn.Connector, bool) {
	if !s.cloudStoreReady(w) {
		return cloudconn.Connector{}, false
	}
	// Anchor is derived at template time; never persist it.
	c.Identity.Anchor = cloudconn.TrustAnchor{}
	saved, found, err := s.cloudConn.Update(r.Context(), c, 0)
	if err != nil {
		if errors.Is(err, cloudconn.ErrVersionConflict) {
			writeJSONError(w, http.StatusConflict, "connector changed concurrently; reload", "VERSION_CONFLICT")
			return cloudconn.Connector{}, false
		}
		writeError(w, http.StatusInternalServerError, err)
		return cloudconn.Connector{}, false
	}
	if !found {
		writeError(w, http.StatusNotFound, errCCNNotFound)
		return cloudconn.Connector{}, false
	}
	return saved, true
}

// recordConnectorEvent writes a connector security event into the immutable audit
// trail. NEVER logs secrets/tokens.
func (s *server) recordConnectorEvent(r *http.Request, claims jwtClaims, event string, c cloudconn.Connector, detail string) {
	if s.audit == nil {
		return
	}
	tenant, cross := principalTenant(claims)
	s.audit.Record(AuditEvent{
		Actor: claims.Sub, Tenant: tenant, Cross: cross,
		Method: event, Path: "/api/cloud/connectors/" + c.ConnectorID, Status: 200, Decision: "allow",
		Remote: auditClientIP(r),
		Detail: map[string]any{
			"event": event, "connector": c.ConnectorID, "provider": string(c.Provider),
			"state": string(c.State), "info": detail,
		},
	})
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// ── provider catalog for the onboarding wizard: /api/cloud/providers ──────────

func (s *server) handleCloudProviderCatalog(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	type methodView struct {
		Method      cloudconn.AuthMethod `json:"method"`
		Rank        int                  `json:"rank"`
		Federated   bool                 `json:"federated"`
		Legacy      bool                 `json:"legacy"`
		Recommended bool                 `json:"recommended"`
	}
	type providerView struct {
		Provider        cloudconn.Provider         `json:"provider"`
		DisplayName     string                     `json:"display_name"`
		ShortLabel      string                     `json:"short_label"`
		SetupDocKey     string                     `json:"setup_doc_key,omitempty"`
		HasFlowLogs     bool                       `json:"has_flow_logs"`
		HasHealthLane   bool                       `json:"has_health_lane"`
		Methods         []methodView               `json:"methods"`
		ScopeTypes      []cloudconn.ScopeType      `json:"scope_types"`
		OrgScopeTypes   []cloudconn.ScopeType      `json:"org_scope_types,omitempty"`
		MemberScopeType cloudconn.ScopeType        `json:"member_scope_type,omitempty"`
		Packs           []cloudconn.CapabilityPack `json:"capability_packs"`
	}
	// Registry-driven: every registered provider descriptor is served — adding a
	// provider never edits this handler.
	descs := cloudconn.Descriptors()
	out := make([]providerView, 0, len(descs))
	for _, d := range descs {
		mv := make([]methodView, 0, len(d.AuthMethods))
		for i, m := range d.AuthMethods {
			mv = append(mv, methodView{Method: m, Rank: m.Rank(), Federated: m.IsFederated(), Legacy: m.IsLegacy(), Recommended: i == 0})
		}
		out = append(out, providerView{
			Provider: d.ID, DisplayName: d.DisplayName, ShortLabel: d.ShortLabel,
			SetupDocKey: d.SetupDocKey, HasFlowLogs: d.HasFlowLogs, HasHealthLane: d.HasHealthLane,
			Methods: mv, ScopeTypes: cloudconn.ScopeTypesForProvider(d.ID),
			OrgScopeTypes: append([]cloudconn.ScopeType(nil), d.OrgScopeTypes...), MemberScopeType: d.MemberScopeType,
			Packs: cloudconn.PacksForProvider(d.ID),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": out})
}

// cloudStoreReady reports whether durable connector storage is wired, writing a
// 501 when it is not. F-76: the in-memory fallback made `s.cloudConn == nil`
// unreachable, so credentials were accepted into RAM behind a 201. The
// constructor now returns nil off Postgres and every entry point checks here.
func (s *server) cloudStoreReady(w http.ResponseWriter) bool {
	if s.cloudConn == nil {
		writeError(w, http.StatusNotImplemented,
			errors.New("cloud connectors require the Postgres backend (STORE_BACKEND=postgres); "+
				"credentials are refused rather than held in memory"))
		return false
	}
	return true
}
