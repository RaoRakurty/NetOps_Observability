// Package main is the entry point for the NetOps Observability backend API.
//
// The binary serves a RESTful JSON API over HTTP plus a WebSocket endpoint
// for real-time event streaming. It is intentionally kept dependency-free
// (stdlib only) so the scaffold compiles in a clean Go environment without
// pulling modules from the network.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"netops/backend/alerts"
	"netops/backend/collectors"
	"netops/backend/integration"
	"netops/backend/models"
	"netops/backend/notify"
	"netops/backend/reports"
)

const version = "0.1.0-scaffold"

// server bundles the HTTP server with the long-running subsystems
// (discovery aggregator, collector pool, alert engine, notifier, user
// store for auth, and the live-events WebSocket hub).
type server struct {
	startedAt      time.Time
	discovery      *DiscoveryAggregator
	collectors     *collectors.Pool
	alerts         *alerts.Engine
	notifier       *notify.Dispatcher
	users          usersRepo
	roles          *roleStore
	tenants        *tenantStore
	apiKeys        *apiKeyStore
	refresh        *refreshStore
	snmpCreds      *snmpCredStore
	sshHosts       *sshHostStore // #20/device-ssh: TOFU host-key store for the SSH gateway
	snmpProfiles   *snmpProfileStore
	saved          savedRepo
	audit          auditRepo
	notifyCfg      *notifyConfigStore
	contactPoints  *contactPointStore
	reports        *reportScheduler
	reportPipeline *reportPipeline // async PG-backed pipeline (nil on file backend)
	incidents      incidentsRepo   // incident system of record (nil on file backend)
	incMetrics     *incidentMetrics
	integrations   *integrationStore     // integration-platform persistence (nil on file backend)
	providers      *integration.Registry // inbound provider translators (registry)
	intMetrics     *integrationMetrics   // integration-platform Prometheus counters
	vault          *Vault                // secret-custody envelope (dormant unless SEAL_PROVIDER set)
	tlsSrv         *tlsServer            // opt-in HTTPS/mTLS listener config (nil = plaintext)
	exportPolicy   *exportPolicyStore    // runtime-tunable log-export limits
	exportLimiter  *tenantRateLimiter    // per-tenant export rate limit
	copilotLimiter *tenantRateLimiter    // per-principal copilot rate limit (SR-021)
	copilotCfg     *copilotConfigStore
	netboxCfg      *netboxConfigStore // NetBox source-of-truth discovery config
	// oidc holds the live SSO provider. It is swapped atomically when an operator
	// saves config from the admin UI (oidc_config.go), and is read on the hot
	// auth path (withAuth RS256) and in the SSO handlers via oidcProvider().
	oidc        atomic.Pointer[oidcProvider]
	oidcCfg     *oidcConfigStore
	ldap        *ldapConfigStore
	tacacs      *tacacsConfigStore
	tokenPolicy *tokenPolicyStore
	secPolicy   *securityPolicyStore // #24 security-policy engine Source (catalog + per-scope overrides)
	// ITSM connectors (ServiceNow + Jira) are PER-TENANT and owned by itsmCfg
	// (itsm_config.go), which builds + hot-swaps them on save. Resolve a tenant's
	// connector via serviceNowFor()/jiraFor(); the incident-projection worker keys
	// on the incident's TenantID so a tenant's incidents only reach its own
	// ticketing. nil = not configured for that tenant.
	itsmCfg *itsmConfigStore
	hub     *Hub
}

// serviceNowFor / jiraFor resolve a tenant's live ITSM connector (nil when
// unconfigured, or before the config store is built). serviceNow()/jiraConn()
// are the global ("" tenant) shorthands used by the platform status endpoints.
func (s *server) serviceNowFor(tenant string) *notify.ServiceNow {
	if s.itsmCfg == nil {
		return nil
	}
	return s.itsmCfg.serviceNowFor(tenant)
}

func (s *server) jiraFor(tenant string) *notify.Jira {
	if s.itsmCfg == nil {
		return nil
	}
	return s.itsmCfg.jiraFor(tenant)
}

func (s *server) serviceNow() *notify.ServiceNow { return s.serviceNowFor("") }

func newServer() *server {
	// Fail closed if no JWT_SECRET is configured (SR-017) — the dev fallback is
	// public and also keys report/export links. Dev runs opt in via
	// ALLOW_DEV_SECRETS=true.
	if err := ensureSigningSecret(); err != nil {
		log.Fatalf("auth: %v", err)
	}

	// Select where the identity/saved stores persist (file by default; Postgres
	// when STORE_BACKEND=postgres). Must run before any store is constructed.
	if err := initStoreBackend(); err != nil {
		log.Fatalf("store backend: %v", err)
	}

	// Secret-custody Vault (#17). Dormant (plaintext passthrough) unless
	// SEAL_PROVIDER is set; fail closed if a configured provider can't unseal the
	// root KEK — never silently fall back to storing secrets in the clear.
	vault, err := newVault(context.Background())
	if err != nil {
		log.Fatalf("secret custody: %v", err)
	}

	// Hardened TLS for outbound calls to internal backends (#18 phase 3). Fail
	// closed: a configured-but-unloadable trust bundle aborts boot.
	if err := initBackendTransport(); err != nil {
		log.Fatalf("backend TLS: %v", err)
	}

	d := NewDiscoveryAggregator()
	d.Register(NewStaticSource(os.Getenv("STATIC_DEVICES_PATH")))
	if os.Getenv("ENABLE_SNMP_DISCOVERY") == "true" {
		d.Register(NewSNMPSource(os.Getenv("SNMP_CIDR_RANGES")))
	}
	// NetBox source-of-truth: registered always with a LIVE config getter (UI-set
	// store, env fallback). Poll is a no-op while unconfigured/disabled, so it
	// honors runtime changes from Automation → Source of Truth without a restart.
	netboxCfg := newNetboxConfigStore(envOr("NETBOX_CONFIG_FILE", "/data/netbox_config.json"), vault)
	d.Register(NewNetboxSource(netboxCfg.effective))

	// SNMP credential store is created below; capture a pointer the target
	// builder can resolve device credential_refs against (set after init).
	var snmpCredsRef *snmpCredStore

	// Feed collectors the live device inventory so they poll real targets,
	// resolving each device's SNMP credential profile to its v2c community.
	pool := collectors.NewPool(func() []collectors.Target {
		devs := d.Devices()
		out := make([]collectors.Target, 0, len(devs))
		for _, dev := range devs {
			if dev.Address == "" {
				continue
			}
			// SNMP credentials come only from UI-configured credential profiles
			// (resolved via the device's credential_ref). A v3 profile threads
			// full USM params; a v1/v2c profile threads the community. An empty
			// community falls back to the global SNMP_COMMUNITY in the poller.
			tgt := collectors.Target{
				ID:       dev.ID,
				Address:  dev.Address,
				Protocol: dev.PreferredProtocol,
			}
			if snmpCredsRef != nil && dev.CredentialRef != "" {
				if c, ok := snmpCredsRef.Resolve(dev.CredentialRef); ok {
					if c.Version == "v3" {
						tgt.SNMPVersion = 3
						tgt.V3User = c.SecurityName
						tgt.V3Level = c.SecurityLevel
						tgt.V3AuthProto = c.AuthProtocol
						tgt.V3AuthKey = c.AuthKey
						tgt.V3PrivProto = c.PrivProtocol
						tgt.V3PrivKey = c.PrivKey
						tgt.V3Context = c.Context
					} else {
						tgt.Community = c.Community
					}
				}
			}
			out = append(out, tgt)
		}
		return out
	})
	// ENABLE_SNMP_COLLECTION drives both SNMP version collectors; the v2c/v3
	// split is by per-device credential profile, not a separate toggle.
	snmpOn := os.Getenv("ENABLE_SNMP_COLLECTION") == "true"
	pool.Enable("snmpv2c", snmpOn)
	pool.Enable("snmpv3", snmpOn)
	pool.Enable("gnmi", os.Getenv("ENABLE_GNMI_COLLECTION") == "true")
	pool.Enable("netconf", os.Getenv("ENABLE_NETCONF_COLLECTION") == "true")
	pool.Enable("tunnels", os.Getenv("ENABLE_TUNNEL_DISCOVERY") == "true")
	pool.Enable("snmpmetrics", os.Getenv("ENABLE_SNMP_METRICS") == "true")
	// SNMP trap receiver (UDP/162) — passive listener that decodes v1/v2c/v3
	// traps and forwards them onto the log bus (→ netops-snmptrap-*). Off by
	// default; opt in with FEATURE_SNMP_TRAPS=true (see deployment compose).
	pool.Enable("snmptrap", os.Getenv("FEATURE_SNMP_TRAPS") == "true")

	notifier := notify.NewDispatcher()
	// Slack + PagerDuty are now UI-configurable via the notifyConfigStore (created
	// after srv exists), which seeds from FEATURE_SLACK_NOTIFICATIONS/SLACK_WEBHOOK_URL
	// and FEATURE_PAGERDUTY_NOTIFICATIONS/PAGERDUTY_KEY on first run and is then
	// editable live from the admin UI — mirroring the ITSM connectors. See
	// notify_config.go. They are intentionally NOT registered from env here.
	if os.Getenv("FEATURE_TEAMS_NOTIFICATIONS") == "true" {
		notifier.Register(notify.NewTeams(os.Getenv("TEAMS_WEBHOOK_URL")))
	}
	if os.Getenv("FEATURE_EMAIL_NOTIFICATIONS") == "true" {
		notifier.Register(
			notify.NewEmail(os.Getenv("SMTP_HOST"), os.Getenv("SMTP_FROM")).
				WithAuth(os.Getenv("SMTP_USER"), os.Getenv("SMTP_PASS")).
				WithRecipients(os.Getenv("SMTP_TO")).
				WithTLSOnConnect(os.Getenv("SMTP_TLS_ON_CONNECT") == "true"),
		)
	}
	if os.Getenv("FEATURE_TWILIO_NOTIFICATIONS") == "true" {
		notifier.Register(notify.NewTwilio(
			os.Getenv("TWILIO_ACCOUNT_SID"),
			os.Getenv("TWILIO_AUTH_TOKEN"),
			os.Getenv("TWILIO_FROM_NUMBER"),
			os.Getenv("TWILIO_TO_NUMBERS"),
		))
	}
	if os.Getenv("FEATURE_SNS_NOTIFICATIONS") == "true" {
		notifier.Register(notify.NewSNS(
			os.Getenv("AWS_ACCESS_KEY_ID"),
			os.Getenv("AWS_SECRET_ACCESS_KEY"),
			os.Getenv("AWS_REGION"),
			os.Getenv("SNS_PHONE_NUMBERS"),
			os.Getenv("SNS_TOPIC_ARN"),
		))
	}
	// ITSM connectors (ServiceNow + Jira) are built from the itsmConfigStore, which
	// seeds from the legacy FEATURE_*_NOTIFICATIONS + SERVICENOW_*/JIRA_* env on
	// first run and is then editable live from the admin UI. The store is created
	// after srv exists (it swaps connectors into srv + the notifier). See
	// itsm_config.go. Both connectors can run at once; either feeds alert
	// auto-ticketing (the notifier) and the incident-projection worker.

	engine := alerts.NewEngine(os.Getenv("RULES_FILE"), notifier)

	users, err := newUsersStore(envOr("USERS_FILE", "/data/users.json"))
	if err != nil {
		log.Fatalf("user store: %v", err)
	}
	if err := users.SeedAdmin(
		envOr("ADMIN_USERNAME", "admin"),
		os.Getenv("ADMIN_INITIAL_PASSWORD"),
	); err != nil {
		log.Printf("seed admin (non-fatal): %v", err)
	}
	// Break-glass admin recovery: when ADMIN_RESET_PASSWORD is set, force the
	// bootstrap admin's password on boot (SeedAdmin only ever seeds a *new* admin,
	// so a rotated/forgotten password otherwise locks everyone out). Unset it
	// again after recovering. Logged loudly on purpose.
	if pw := os.Getenv("ADMIN_RESET_PASSWORD"); pw != "" {
		adminUser := envOr("ADMIN_USERNAME", "admin")
		if err := users.ResetPassword(adminUser, pw); err != nil {
			log.Printf("admin password reset (non-fatal): %v", err)
		} else {
			log.Printf("SECURITY: reset password for admin %q via ADMIN_RESET_PASSWORD — unset this env now", adminUser)
		}
	}

	roles, err := newRoleStore(envOr("ROLES_FILE", "/data/roles.json"))
	if err != nil {
		log.Fatalf("role store: %v", err)
	}
	tenants, err := newTenantStore(envOr("TENANTS_FILE", "/data/tenants.json"))
	if err != nil {
		log.Fatalf("tenant store: %v", err)
	}
	apiKeys, err := newAPIKeyStore(envOr("APIKEYS_FILE", "/data/apikeys.json"))
	if err != nil {
		log.Fatalf("api key store: %v", err)
	}
	refresh, err := newRefreshStore(envOr("REFRESH_FILE", "/data/refresh_tokens.json"), refreshTokenTTL())
	if err != nil {
		log.Fatalf("refresh store: %v", err)
	}
	snmpCreds, err := newSNMPCredStore(envOr("SNMP_CREDS_FILE", "/data/snmp_credentials.json"), vault)
	if err != nil {
		log.Fatalf("snmp cred store: %v", err)
	}
	snmpCredsRef = snmpCreds // make profiles resolvable by the target builder

	saved, err := newSavedStore(envOr("SAVED_FILE", "/data/saved.json"))
	if err != nil {
		log.Fatalf("saved store: %v", err)
	}

	audit, err := newAuditStore(envOr("AUDIT_FILE", "/data/audit.json"))
	if err != nil {
		log.Fatalf("audit store: %v", err)
	}

	snmpProfiles, err := newSNMPProfileStore(envOr("SNMP_PROFILES_FILE", "/data/snmp_profiles.json"))
	if err != nil {
		log.Fatalf("snmp profile store: %v", err)
	}

	contactPoints, err := newContactPointStore(envOr("CONTACT_POINTS_FILE", "/data/contact_points.json"))
	if err != nil {
		log.Fatalf("contact point store: %v", err)
	}

	srv := &server{
		startedAt:     time.Now().UTC(),
		discovery:     d,
		collectors:    pool,
		alerts:        engine,
		notifier:      notifier,
		users:         users,
		roles:         roles,
		tenants:       tenants,
		apiKeys:       apiKeys,
		refresh:       refresh,
		snmpCreds:     snmpCreds,
		sshHosts:      newSSHHostStore(envOr("SSH_KNOWN_HOSTS_FILE", "/data/ssh_known_hosts.json")),
		snmpProfiles:  snmpProfiles,
		saved:         saved,
		audit:         audit,
		contactPoints: contactPoints,
		hub:           NewHub(),
	}
	// ITSM config store — seeds from env on first run, then admin-UI editable;
	// builds + swaps the ServiceNow/Jira connectors into srv + the notifier.
	srv.itsmCfg = newITSMConfigStore(srv, envOr("ITSM_CONFIG_FILE", "/data/itsm_config.json"))
	// Incident system (Postgres only) + its alert-ingestion hook.
	srv.incidents = newIncidentStore()
	srv.incMetrics = &incidentMetrics{}
	// Integration platform (#43): persistence is Postgres-only; the provider
	// registry (inbound translators) is always available.
	if ps, ok := backend.(*pgStore); ok {
		srv.integrations = newIntegrationStore(ps.db, vault)
	}
	srv.providers = integration.DefaultRegistry()
	srv.intMetrics = &integrationMetrics{}
	srv.vault = vault
	srv.exportPolicy = newExportPolicyStore(envOr("EXPORT_POLICY_FILE", "/data/export_policy.json"))
	srv.exportLimiter = newTenantRateLimiter()
	srv.copilotLimiter = newTenantRateLimiter()
	engine.OnFire = srv.ingestAlertIncident
	srv.reports = newReportScheduler(srv, envOr("REPORT_RUNS_FILE", "/data/report_runs.json"))
	srv.copilotCfg = newCopilotConfigStore(envOr("COPILOT_CONFIG_FILE", "/data/copilot_config.json"), vault)
	srv.netboxCfg = netboxCfg
	// UI-configurable email/SMS/push channels (registers live channels into the
	// dispatcher built above). Must come after notifier is set on srv.
	srv.notifyCfg = newNotifyConfigStore(envOr("NOTIFY_CONFIG_FILE", "/data/notify_config.json"), srv)
	srv.ldap = newLDAPConfigStore(envOr("LDAP_CONFIG_FILE", "/data/ldap_config.json"), vault)
	srv.tacacs = newTACACSConfigStore(envOr("TACACS_CONFIG_FILE", "/data/tacacs_config.json"), vault)
	srv.tokenPolicy = newTokenPolicyStore(envOr("TOKEN_POLICY_FILE", "/data/token_policy.json"), refresh)
	// Security Policy engine (#24): deterministic System→Tenant→Role→User
	// resolution of NIST-aligned controls. The store (Phase 2) is the engine's
	// persistence Source; the handlers (Phase 3, policy_http.go) expose the
	// catalog, the effective-policy/simulator view, and per-scope editing.
	srv.secPolicy = newSecurityPolicyStore(envOr("SECURITY_POLICY_FILE", "/data/security_policies.json"))
	// SSO/OIDC: runtime-configurable overlay over the env defaults. The store
	// builds the initial live provider into the atomic pointer and swaps it on
	// every admin save (see oidc_config.go).
	srv.oidcCfg = newOIDCConfigStore(envOr("OIDC_CONFIG_FILE", "/data/oidc_config.json"), srv)
	srv.oidc.Store(newOIDCProviderFromConfig(srv.oidcCfg.effective()))
	return srv
}

func main() {
	addr := envOr("LISTEN_ADDR", ":8080")
	srv := newServer()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.discovery.Start(ctx)
	srv.collectors.Start(ctx)
	srv.alerts.Start(ctx)
	// Export the device→tenant map for the ingest tier to stamp tenant_id onto
	// telemetry (#20 Phase 1). No-op unless TENANT_ENRICHMENT_DIR is set.
	srv.startTenantEnrichment(ctx)
	// Self-heal the ClickHouse tenant row policies (#20 Phase 2) in the background.
	ensureCHRowPolicies()
	// ITSM drift reconciler (#43 enhancement). No-op unless FEATURE_ITSM_RECONCILE.
	srv.startDriftReconciler(ctx)
	if os.Getenv("ENABLE_REPORT_SCHEDULER") != "false" {
		// On the Postgres backend, run the durable async pipeline (queue + workers
		// + immutable execution history). On the file backend, keep the in-process
		// scheduler so the offline/dev build still delivers scheduled reports.
		if ps, ok := backend.(*pgStore); ok {
			renderer, err := reports.NewHTMLRenderer()
			if err != nil {
				log.Fatalf("report renderer: %v", err)
			}
			srv.reportPipeline = newReportPipeline(srv,
				newPgJobQueue(ps.db, 5), newPgExecStore(ps.db), newKVArtifactStore(), renderer,
				newPgDeliveryStore(ps.db))
			srv.reportPipeline.Start(ctx)
		} else {
			srv.reports.Start(ctx)
		}
	}
	go srv.startBroadcaster(ctx.Done())
	go srv.watchAlertsForBroadcast(ctx)
	// Multi-instance cache coherence for the cached-by-design stores: refresh
	// API keys + SNMP creds from the shared backend so a revoke/rotate on another
	// replica converges here (no-op for the single-writer file backend).
	srv.startCredCacheReload(ctx)

	mux := http.NewServeMux()
	srv.routes(mux)

	handler := withCORS(withLogging(withBodyLimit(maxRequestBodyBytes(), srv.withAuth(srv.withAudit(mux)))))

	// Internal CA bootstrap (#18 phase 2). When TLS_INTERNAL_CA=true, self-issue
	// the API server + nginx client SVIDs and the CA bundle (CA key sealed by the
	// Vault) BEFORE the TLS server reads its cert paths. No-op otherwise.
	caMgr, err := bootstrapInternalCA(srv.vault)
	if err != nil {
		log.Fatalf("internal CA: %v", err)
	}

	// Opt-in TLS/mTLS (#18). Fail closed: a configured-but-broken cert/CA aborts
	// boot. Dormant (plaintext, nginx terminates ingress) when unset.
	tlsSrv, err := buildTLSServer()
	if err != nil {
		log.Fatalf("tls: %v", err)
	}
	srv.tlsSrv = tlsSrv

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MiB header cap (SR-012); default is also 1 MiB, set explicitly.
	}
	if tlsSrv != nil {
		httpSrv.TLSConfig = tlsSrv.config
		httpSrv.Handler = hsts(handler) // HSTS only when actually serving TLS
		// Count + structure-log handshake failures instead of the default logger.
		httpSrv.ErrorLog = log.New(handshakeErrLog{tlsSrv.metrics}, "", 0)
		go tlsSrv.reloader.WatchInterval(ctx, tlsSrv.interval, func(e error) {
			logError("tls", "cert reload", errf(e))
		})
		// Periodic SVID re-issue (#18 phase 4): re-mint + rewrite the API/nginx
		// certs at ~half the TTL; the reloader hot-swaps them — rotation, no restart.
		if caMgr != nil {
			go caMgr.startReissueLoop(ctx)
		}
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if tlsSrv != nil {
			log.Printf("netops-api %s listening on %s (TLS, mTLS=%v)", version, addr, tlsSrv.mtls)
			// Certs are supplied by the reloader's GetCertificate, so the file args
			// are intentionally empty.
			if err := httpSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("https server: %v", err)
			}
			return
		}
		log.Printf("netops-api %s listening on %s", version, addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()

	<-stop
	log.Println("shutdown requested")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	cancel()
	log.Println("goodbye")
}

// routes wires every HTTP handler onto the supplied mux.
//
// The path layout is stable and matches what nginx routes to
// `/api/*` from the user-facing dashboard at port 8000.
func (s *server) routes(mux *http.ServeMux) {
	mux.HandleFunc("/admin/health", s.handleHealth)
	mux.HandleFunc("/admin/readyz", s.handleReadyz)
	mux.HandleFunc("/admin/version", s.handleVersion)
	mux.HandleFunc("/api/auth/login", s.handleLogin)
	mux.HandleFunc("/api/auth/me", s.handleMe)
	mux.HandleFunc("/api/auth/change-password", s.handleChangePassword)
	mux.HandleFunc("/api/auth/password-policy", s.handlePasswordPolicy)
	mux.HandleFunc("/api/auth/refresh", s.handleRefresh)
	mux.HandleFunc("/api/auth/logout", s.handleLogout)
	mux.HandleFunc("/api/auth/osd-gate", s.handleOSDGate) // nginx auth_request target for /search
	mux.HandleFunc("/api/auth/permissions", s.handlePermissions)
	// SSO (OIDC/SAML/LDAP via Keycloak) — config + Authorization Code flow.
	mux.HandleFunc("/api/auth/sso/config", s.handleSSOConfig)
	mux.HandleFunc("/api/auth/sso/login", s.handleSSOLogin)
	mux.HandleFunc("/api/auth/sso/callback", s.handleSSOCallback)
	mux.HandleFunc("/api/auth/oidc/config", s.handleOIDCConfig)
	mux.HandleFunc("/api/notify/itsm", s.handleITSMConfig) // ServiceNow/Jira config (platform-owner)
	mux.HandleFunc("/api/auth/methods", s.handleAuthMethods)
	mux.HandleFunc("/api/auth/ldap/login", s.handleLDAPLogin)
	mux.HandleFunc("/api/auth/ldap/config", s.handleLDAPConfig)
	mux.HandleFunc("/api/auth/ldap/test", s.handleLDAPTest)
	mux.HandleFunc("/api/auth/tacacs/login", s.handleTACACSLogin)
	mux.HandleFunc("/api/auth/tacacs/config", s.handleTACACSConfig)
	mux.HandleFunc("/api/auth/tacacs/test", s.handleTACACSTest)
	mux.HandleFunc("/api/auth/token-policy", s.handleTokenPolicy)
	// Security Policy engine (#24): catalog, effective-policy/simulator, per-scope
	// override editing. Admin-gated; system-scope writes are platform-owner only.
	mux.HandleFunc("/api/policy/catalog", s.handlePolicyCatalog)
	mux.HandleFunc("/api/policy/effective", s.handlePolicyEffective)
	mux.HandleFunc("/api/policy/documents", s.handlePolicyDocuments)
	mux.HandleFunc("/api/policy/document", s.handlePolicyDocument)
	mux.HandleFunc("/api/policy/validate", s.handlePolicyValidate)
	// Identity & access (admin-gated): users, roles, tenants, API keys.
	mux.HandleFunc("/api/users", s.handleUsers)
	mux.HandleFunc("/api/users/", s.handleUserByID)
	mux.HandleFunc("/api/roles", s.handleRoles)
	mux.HandleFunc("/api/roles/", s.handleRoleByID)
	mux.HandleFunc("/api/tenants", s.handleTenants)
	mux.HandleFunc("/api/tenants/", s.handleTenantByID)
	mux.HandleFunc("/api/apikeys", s.handleAPIKeys)
	mux.HandleFunc("/api/apikeys/", s.handleAPIKeyByID)
	// SNMP credential profiles (v1/v2c/v3) — infrastructure-gated.
	mux.HandleFunc("/api/snmp/options", s.handleSNMPOptions)
	mux.HandleFunc("/api/snmp/credentials", s.handleSNMPCreds)
	mux.HandleFunc("/api/snmp/credentials/", s.handleSNMPCredByID)
	mux.HandleFunc("/api/snmp/profiles", s.handleSNMPProfiles)
	mux.HandleFunc("/api/snmp/profiles/", s.handleSNMPProfileByID)
	mux.HandleFunc("/api/devices", s.handleDevices)
	mux.HandleFunc("/api/devices/", s.handleDeviceByID)
	mux.HandleFunc("/api/collectors", s.handleCollectors)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/credentials", s.handleCredentials)
	mux.HandleFunc("/api/discovery/refresh", s.handleDiscoveryRefresh)
	mux.HandleFunc("/api/automation/netbox", s.handleNetboxConfig) // Source-of-Truth (platform-owner)
	mux.HandleFunc("/api/logs/search", s.handleLogsSearch)
	mux.HandleFunc("/api/logs/indices", s.handleLogsIndices)
	mux.HandleFunc("/api/logs/export", s.handleLogsExport)          // Mode B: whole result set (sync/async)
	mux.HandleFunc("/api/logs/export/rows", s.handleLogsExportRows) // Mode A: selected/loaded rows
	mux.HandleFunc("/api/exports/view/", s.handleExportView)        // token-authenticated (public)
	mux.HandleFunc("/api/exports/policy", s.handleExportPolicy)     // runtime export limits (admin/platform-owner)
	mux.HandleFunc("/api/exports/", s.handleExportStatus)           // async export status poll
	mux.HandleFunc("/api/flows/top", s.handleFlowsTopTalkers)
	mux.HandleFunc("/api/flows/by-proto", s.handleFlowsByProto)
	mux.HandleFunc("/api/flows/by-type", s.handleFlowsByType)
	mux.HandleFunc("/api/flows/timeseries", s.handleFlowsTimeseries)
	mux.HandleFunc("/api/tunnels", s.handleTunnels)
	mux.HandleFunc("/api/findings", s.handleFindings)
	mux.HandleFunc("/api/incidents", s.handleIncidents)     // GET list (tenant-scoped)
	mux.HandleFunc("/api/incidents/", s.handleIncidentByID) // GET {id}; POST {id}/ack|resolve|note|assign|…
	mux.HandleFunc("/api/saved", s.handleSaved)
	mux.HandleFunc("/api/saved/", s.handleSavedByID)
	mux.HandleFunc("/api/search/global", s.handleGlobalSearch)
	mux.HandleFunc("/api/reports/runs", s.handleReportRuns)
	mux.HandleFunc("/api/reports/run", s.handleReportRunNow)
	mux.HandleFunc("/api/reports/channels", s.handleReportChannels)
	mux.HandleFunc("/api/reports/executions", s.handleReportExecutions)
	mux.HandleFunc("/api/reports/executions/", s.handleReportExecutionByID)
	mux.HandleFunc("/api/reports/preview", s.handleReportPreview)
	mux.HandleFunc("/api/reports/view/", s.handleReportView) // token-authenticated (public)
	mux.HandleFunc("/api/notify/smtp", s.handleSMTPConfig)
	mux.HandleFunc("/api/notify/smtp/test", s.handleSMTPTest)
	mux.HandleFunc("/api/notify/twilio", s.handleTwilioConfig)
	mux.HandleFunc("/api/notify/twilio/test", s.handleTwilioTest)
	mux.HandleFunc("/api/notify/ntfy", s.handleNtfyConfig)
	mux.HandleFunc("/api/notify/ntfy/test", s.handleNtfyTest)
	mux.HandleFunc("/api/notify/slack", s.handleSlackConfig)
	mux.HandleFunc("/api/notify/slack/test", s.handleSlackTest)
	mux.HandleFunc("/api/notify/pagerduty", s.handlePagerDutyConfig)
	mux.HandleFunc("/api/notify/pagerduty/test", s.handlePagerDutyTest)
	mux.HandleFunc("/api/notify/contact-points", s.handleContactPoints)
	mux.HandleFunc("/api/notify/contact-points/", s.handleContactPointByID)
	mux.HandleFunc("/api/copilot/chat", s.handleCopilot)
	mux.HandleFunc("/api/copilot/config", s.handleCopilotConfig)
	mux.HandleFunc("/api/graphql", s.handleGraphQL)
	// Self-describing API + ITSM connector status.
	mux.HandleFunc("/api/openapi.json", s.handleOpenAPI)
	mux.HandleFunc("/api/itsm/servicenow", s.handleITSMServiceNow)
	mux.HandleFunc("/api/itsm/jira", s.handleITSMJira)
	// Integration platform (#43): admin config + UNAUTHENTICATED inbound webhook
	// (the more specific /webhook/ prefix wins over /api/integrations/ in the mux).
	mux.HandleFunc("/api/integrations", s.handleIntegrations)
	mux.HandleFunc("/api/integrations/reconcile", s.handleIntegrationReconcile) // exact path wins over the prefix below
	mux.HandleFunc("/api/integrations/", s.handleIntegrations)
	mux.HandleFunc("/api/integrations/webhook/", s.handleIntegrationWebhook)
	// Platform-stack self-monitoring (platform-owner only).
	mux.HandleFunc("/api/stack/health", s.handleStackHealth)
	mux.HandleFunc("/api/audit", s.handleAudit)
	// Authenticated detailed health (SR-009) — backs the in-app indicator;
	// fleet/collector detail is platform-owner-gated inside the handler.
	mux.HandleFunc("/api/health", s.handleHealthDetail)
	// Dashboard live data
	mux.HandleFunc("/api/metrics", s.handleMetricTiles)
	mux.HandleFunc("/api/metrics/query", s.handleMetricsQuery)
	mux.HandleFunc("/api/metrics/query_range", s.handleMetricsQueryRange)
	mux.HandleFunc("/api/metrics/names", s.handleMetricsNames)
	mux.HandleFunc("/api/events", s.handleEvents)
	// Prometheus scrape endpoint
	mux.HandleFunc("/metrics", s.handlePromMetrics)
}

// handleHealth (`/admin/health`, public) is a minimal liveness probe (SR-009).
// It MUST stay unauthenticated for Docker/LB/watchdog probes, so it reveals
// nothing beyond "the process is up" — no version, uptime, or fleet/collector
// inventory (those were an anonymous recon/fingerprinting surface). The detailed
// view moved to the authenticated handleHealthDetail (`/api/health`).
func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "healthy"})
}

// handleHealthDetail (`/api/health`, authenticated) backs the in-app health
// indicator. Any authenticated principal gets liveness + version + uptime; the
// fleet/collector/discovery aggregates are platform plumbing that reveal global
// fleet size, so they're gated to the platform owner (SR-009, mirroring the
// REST handleCollectors / GraphQL health gates for SR-010).
func (s *server) handleHealthDetail(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	out := map[string]any{
		"status":  "healthy",
		"version": version,
		"uptime":  time.Since(s.startedAt).String(),
	}
	if s.can(claims, ActionView, Resource{Type: ResInfraStack}) {
		out["discovery"] = s.discovery.Health()
		out["collectors"] = s.collectors.Health()
		out["alerts"] = s.alerts.Health()
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": version})
}

// handleReadyz is the readiness probe (#18 phase 4). When serving TLS it returns
// 503 if the served certificate is missing/expired/within its renewal margin, so
// a load balancer pulls this instance BEFORE it would serve a dead cert (rather
// than after clients see handshake failures). 200 otherwise.
func (s *server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if s.tlsSrv != nil {
		// Renewal margin: a cert this close to expiry should already have been
		// re-issued; if not, fail readiness loudly.
		if ok, reason := s.tlsSrv.certValid(5 * time.Minute); !ok {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "tls": reason})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

func (s *server) handleDevices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// SR-003: read requires infrastructure:read (the middleware chain only
		// authenticates; RBAC is per-handler). Tenant isolation: scoped principals
		// only see their tenant's (and shared/global) devices.
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, visibleDevices(s.discovery.Devices(), claims))
	case http.MethodPost:
		// SR-003: creating a device is a write — gate it. Previously any
		// authenticated principal (incl. read-only) could create/overwrite devices.
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		var d models.Device
		if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// A scoped principal can only create devices inside its own tenant; it
		// may not assign a device to another tenant. Cross-tenant principals may
		// set any tenant_id explicitly.
		if tenant, cross := principalTenant(claims); !cross {
			d.TenantID = tenant
		}
		s.discovery.Upsert(d)
		writeJSON(w, http.StatusCreated, d)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleDeviceByID(w http.ResponseWriter, r *http.Request) {
	// SSH gateway lives under the device path: /api/devices/{id}/ssh (opt-in,
	// dormant unless FEATURE_DEVICE_SSH). Delegate before the id parse below.
	if strings.HasSuffix(r.URL.Path, "/ssh") {
		s.handleDeviceSSH(w, r)
		return
	}
	id := r.URL.Path[len("/api/devices/"):]
	if id == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		// SR-003: read requires infrastructure:read.
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		d, ok := s.discovery.Get(id)
		// 404 (not 403) for out-of-tenant devices: don't reveal that the id
		// exists in another tenant.
		if !ok || !canSeeDevice(d, tenant, cross) {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, d)
	case http.MethodDelete:
		// SR-003: deleting a device is a write — gate it.
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		// A scoped principal may only delete a device owned by its own tenant
		// (not shared/global ones, which belong to no single tenant).
		if !cross {
			d, ok := s.discovery.Get(id)
			if !ok || deviceTenant(d) != tenant {
				http.NotFound(w, r)
				return
			}
		}
		s.discovery.Delete(id)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleCollectors(w http.ResponseWriter, r *http.Request) {
	// Collector status is a fleet-wide aggregate (shared poller engines, no
	// per-tenant breakdown), so it's platform-owner only — a tenant-scoped user
	// would otherwise learn the global fleet size. See requireCrossTenant.
	if _, ok := s.requireCrossTenant(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.collectors.Status())
}

func (s *server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	claims, _ := userFrom(r.Context())
	active := s.alerts.Active()
	// Tenant isolation: a scoped principal only sees alerts on devices it can
	// see (alerts with no device — e.g. stack-level — stay visible).
	if ids, cross := s.visibleDeviceIDs(claims); !cross {
		filtered := make([]models.Alert, 0, len(active))
		for _, a := range active {
			if a.DeviceID == "" || ids[a.DeviceID] {
				filtered = append(filtered, a)
			}
		}
		active = filtered
	}
	writeJSON(w, http.StatusOK, active)
}

func (s *server) handleRules(w http.ResponseWriter, r *http.Request) {
	// SR-004: alert rules are PLATFORM-GLOBAL (no TenantID) — they encode device
	// names/thresholds/topology and fire across every tenant. So both reading and
	// writing them is platform-owner-only, mirroring handleCollectors. (A future
	// per-tenant rule model would relax the read gate; until then a scoped tenant
	// must neither enumerate global rules nor inject one.)
	if _, ok := s.requireCrossTenant(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.alerts.Rules())
	case http.MethodPost:
		var rule alerts.Rule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		s.alerts.AddRule(rule)
		writeJSON(w, http.StatusCreated, rule)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleCredentials(w http.ResponseWriter, _ *http.Request) {
	// Scaffold: credentials live in env / external vault. Never echo secrets back.
	writeJSON(w, http.StatusOK, map[string]any{
		"netbox":     os.Getenv("NETBOX_TOKEN") != "",
		"slack":      s.notifyCfg.publicSlack().WebhookSet,
		"pagerduty":  s.notifyCfg.publicPagerDuty().RoutingSet,
		"smtp":       os.Getenv("SMTP_HOST") != "",
		"twilio":     os.Getenv("TWILIO_ACCOUNT_SID") != "",
		"aws_sns":    os.Getenv("AWS_ACCESS_KEY_ID") != "" && os.Getenv("AWS_REGION") != "",
		"opensearch": os.Getenv("OPENSEARCH_URL") != "",
		"clickhouse": os.Getenv("CLICKHOUSE_URL") != "",
		// Feature availability only — the assistant UI renders whenever the feature
		// is on, then prompts in-panel for an API key (env or UI-stored) if missing.
		"copilot":    os.Getenv("FEATURE_COPILOT") == "true",
		"device_ssh": os.Getenv("FEATURE_DEVICE_SSH") == "true",
	})
}

func (s *server) handleDiscoveryRefresh(w http.ResponseWriter, r *http.Request) {
	// SR-003: triggering a discovery scan (against the configured CIDR/Netbox) is
	// an infrastructure write; previously it had no authz at all.
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelWrite); !ok {
		return
	}
	s.discovery.RefreshNow()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "refresh scheduled"})
}

func (s *server) handlePromMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP netops_devices_total Number of known devices.\n")
	fmt.Fprintf(w, "# TYPE netops_devices_total gauge\n")
	fmt.Fprintf(w, "netops_devices_total %d\n", len(s.discovery.Devices()))
	fmt.Fprintf(w, "# HELP netops_alerts_active Currently active alerts.\n")
	fmt.Fprintf(w, "# TYPE netops_alerts_active gauge\n")
	fmt.Fprintf(w, "netops_alerts_active %d\n", len(s.alerts.Active()))
	if s.reportPipeline != nil {
		s.reportPipeline.writeMetrics(w)
	}
	if s.incMetrics != nil {
		s.incMetrics.write(w)
	}
	if s.intMetrics != nil {
		s.intMetrics.write(w)
	}
	if s.tlsSrv != nil {
		s.tlsSrv.writeTLSMetrics(w)
	}
}

// ---- helpers ----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// oidcProvider returns the current live SSO provider. It is swapped atomically
// when an operator saves OIDC config, so readers always see a consistent,
// fully-built provider without locking.
func (s *server) oidcProvider() *oidcProvider { return s.oidc.Load() }

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string) bool { return os.Getenv(key) == "true" }

// corsAllowedOrigins is the explicit cross-origin allowlist (SR-005). The SPA is
// served same-origin behind nginx on :8000, so by DEFAULT no CORS headers are
// emitted (the previous wildcard `*` let any site read API JSON if it held a
// token, and broadcast the full method surface). Set CORS_ALLOWED_ORIGINS to a
// comma-separated list only if the API must be reached from another origin.
func corsAllowedOrigins() map[string]bool {
	raw := strings.TrimSpace(os.Getenv("CORS_ALLOWED_ORIGINS"))
	if raw == "" {
		return nil
	}
	out := map[string]bool{}
	for _, o := range strings.Split(raw, ",") {
		if o = strings.TrimSpace(o); o != "" {
			out[o] = true
		}
	}
	return out
}

func withCORS(next http.Handler) http.Handler {
	allowed := corsAllowedOrigins()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		// Reflect ONLY an explicitly-allowlisted origin — never a wildcard.
		if origin != "" && allowed[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// maxRequestBodyBytes is the global per-request body backstop. nginx caps ingress
// at 50m, but in TLS/mTLS mode the Go server is reachable directly (bypassing
// nginx), and most handlers decode JSON without their own MaxBytesReader (SR-012).
// This wraps every request body so an oversized payload is refused at the reader
// rather than fully buffered into a struct. Tighter per-handler caps (copilot
// 256 KiB, login 64 KiB, the 1 MiB config handlers) still apply on top — the
// inner, smaller limit wins. Override with MAX_REQUEST_BODY_BYTES.
func maxRequestBodyBytes() int64 {
	if v := os.Getenv("MAX_REQUEST_BODY_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return 50 << 20 // 50 MiB, matching nginx client_max_body_size
}

func withBodyLimit(limit int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		logInfo("http", "request", map[string]any{
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      rw.status,
			"duration_ms": time.Since(start).Milliseconds(),
			"remote":      r.RemoteAddr,
		})
	})
}

// statusRecorder captures the response status code without altering the
// rest of the http.ResponseWriter contract.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Hijack lets the wrapped writer pass through to the underlying connection so
// the WebSocket endpoint (/api/events) can take over the socket. Without this
// the logging wrapper hides http.Hijacker and the upgrade fails with
// "server doesn't support connection hijack".
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
	}
	return hj.Hijack()
}
