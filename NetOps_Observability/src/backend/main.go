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
	"netops/backend/internal/apikey"
	"netops/backend/internal/metricval"
	"netops/backend/internal/ratelimit"
	"netops/backend/internal/seam"
	"netops/backend/internal/session"
	"netops/backend/internal/snmpcred"
	"netops/backend/internal/vault"
	"netops/backend/internal/vuln"
	"netops/backend/portintel"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"netops/backend/alerts"
	"netops/backend/chhttp"
	"netops/backend/collectors"
	"netops/backend/integration"
	"netops/backend/models"
	"netops/backend/nms"
	"netops/backend/notify"
	"netops/backend/reports"
	"netops/backend/safego"
)

const version = "0.1.0-scaffold"

// server bundles the HTTP server with the long-running subsystems
// (discovery aggregator, collector pool, alert engine, notifier, user
// store for auth, and the live-events WebSocket hub).
type server struct {
	startedAt        time.Time
	discovery        *DiscoveryAggregator
	collectors       *collectors.Pool
	alerts           *alerts.Engine
	alertEpisodes    *alertEpisodeStore
	userRules        *userRulesStore
	notifier         *notify.Dispatcher
	selfHeal         *selfHealer
	users            usersRepo
	roles            *roleStore
	tenants          tenantRepo
	orgs             *orgStore
	bindings         *bindingStore
	securitySettings *securitySettingsStore
	loginThrottle    *loginThrottle // in-memory failed-login lockout (best-effort)
	sessions         *session.Store // server-side session lifecycle (idle/absolute/revocation)
	apiKeys          *apikey.Store
	refresh          *session.RefreshStore
	snmpCreds        *snmpcred.Store
	credOverrides    *credOverrideStore // learned SNMP credential bindings (credential sentinel)
	credSentinel     *credSentinel      // self-healing credential resolution loop
	sshHosts         *sshHostStore      // #20/device-ssh: TOFU host-key store for the SSH gateway
	snmpProfiles     *snmpProfileStore
	saved            savedRepo
	audit            auditRepo
	notifyCfg        *notifyConfigStore
	contactPoints    *contactPointStore
	deviceLocations  *deviceLocationStore
	sites            *sitesStore        // internal SoT sites (default provider)
	deviceSites      *deviceSiteStore   // operator device→site bindings (intent)
	wanPolicy        *wanPolicyStore    // WAN measurement policy (operator intent) #wan-path-metrics
	systemNet        *systemNetStore    // platform DNS + NTP system settings (clock sync + URL resolution)
	backupCfg        *backupConfigStore // platform data-protection settings + DR status
	// wanIfAddr is the interface-IP registry source (deviceID → ip → ifName) for
	// the WAN endpoint projector. Defaults to collectors.FetchIfAddrMap; a DI seam
	// so the projector's tenant-filter is unit-testable without Redis (§5).
	wanIfAddr func(context.Context) (map[string]map[string]string, error)
	// wanNeighbors is the directly-connected-neighbour source (LLDP/CDP/BGP-LS
	// topology links) for deriving each WAN interface's measurement target. Defaults
	// to collectors.FetchTopologyLinks; a DI seam so target derivation is testable.
	wanNeighbors func(context.Context) ([]collectors.LLDPNeighbor, error)
	// vmRangeRaw is an optional test seam for the WAN sparkline range query
	// (query → device+ifName → value series). nil in prod = real VM query_range.
	vmRangeRaw     func(ctx context.Context, query string, start, end, step int64) (map[string][]float64, error)
	reports        *reportScheduler
	reportPipeline *reportPipeline // async PG-backed pipeline (nil on file backend)
	incidents      incidentsRepo   // incident system of record (nil on file backend)
	incMetrics     *incidentMetrics
	ticketing      ticketingStore // RCA auto-ticketing store #78 (in-memory or pg); worker+sweeper start in main() under FEATURE_RCA_TICKETING
	// ticketing invariant/contract counters (exposed on /metrics): enable attempts
	// rejected by the one-enabled-policy rule, fail-closed holds on a violated
	// invariant, and manual actions redirected off a merged object.
	tktPolicyConflicts    atomic.Int64
	tktPolicyMultiEnabled atomic.Int64
	tktMergedRedirects    atomic.Int64
	seams                 *seam.Store              // canonical seam inventory, #67 build ⑤ (nil on file backend)
	services              *pgServiceStore          // service catalog #69 §2 P2 (nil on file backend)
	cloudConn             cloudConnRepo            // multi-tenant cloud-connector framework (pg or in-memory)
	cloudBroker           *cloudIdentityBroker     // cloud identity broker: scoped short-lived provider tokens + vault secret custody
	workloadIssuer        *workloadIssuer          // platform OIDC issuer for minted workload assertions (Wave 4 #13); nil = dormant
	cloudIngestInv        *cloudIngestInventory    // per-connector inventory snapshots → per-tenant merged inventory (Wave 1 #2)
	cloudSourceStatus     *cloudSourceStatusStore  // poller-reported permission_denied/misconfigured per source (Wave 2 #4)
	topology              topologyGraphStore       // persistent topology graph #77 (in-memory or pg)
	incidentTimeline      incidentTimelineStore    // RCA Time Intelligence manual lifecycle events #84 (in-memory or pg)
	incidentTimeMetrics   incidentTimeMetricsStore // RCA Time Intelligence backfilled phase-metric snapshots #84 (in-memory or pg)
	aiFeedback            aiFeedbackStore          // Iris AI answer feedback (thumbs up/down), privacy-safe (in-memory or pg)
	applications          applicationStore         // Application Identification registry #81 P0 (in-memory or pg)
	appCatalog            *appCatalogHolder        // Application Identification IP→app resolver #81 P1 (in-memory LPM catalog)
	ngfw                  *ngfwAppResolver         // Application Identification NGFW app-id overlay #81 P-NGFW pt2 (OpenSearch-fed)
	fusion                *fusionWorker            // Application Identity Fusion Layer #81 P4 worker (opt-in via FUSION_WORKER_ENABLED)
	appOverrides          appCatalogStore          // Application Identification operator-defined overrides #81 P1c (in-memory or pg)
	cloud                 cloudStore               // Cloud App Observability inventory #81 P3A (in-memory; pg over migration 0016 next)
	bizServices           *pgBusinessServiceStore  // Business Service mapping + manual overrides #0024 (nil on file backend)
	cloudApp              *cloudAppResolver        // Cloud identity-map → appid bridge #81 P3F+1 (consumes the cloud inventory for app naming)
	// Service Path Graph (frozen contract v1, docs/design/service-path-graph-contract.md):
	// the ordered LAN→SD-WAN→carrier/cloud→application RCA spine. pathGraph is the
	// storage (PG registries + CH observation/hop streams, or in-memory on the file
	// backend); pathFacts and corrPath are the DI seams for the §3 fact base and the
	// correlation→path linkage (nil = the real inventories / ClickHouse).
	pathGraph       pathGraphStore
	pathFacts       pathFactSource
	corrPath        corrPathRef
	remotePaths     *remotePathStore      // remote-vantage traceroute pushes (POST /api/probe/paths)
	integrations    *integrationStore     // integration-platform persistence (nil on file backend)
	providers       *integration.Registry // inbound provider translators (registry)
	nms             *nmsRuntime           // NMS vendor-controller framework #95 (nil unless FEATURE_NMS_INTEGRATIONS)
	wireless        wirelessStore         // wireless canonical inventory #128 (always set: mem on file backend, PG on postgres)
	wirelessActions *wirelessActionStore  // #128 Phase 8 guarded remediation (dormant unless FEATURE_WIRELESS_ACTIONS)
	intMetrics      *integrationMetrics   // integration-platform Prometheus counters
	vault           *vault.Vault          // secret-custody envelope (dormant unless SEAL_PROVIDER set)
	tlsSrv          *tlsServer            // opt-in HTTPS/mTLS listener config (nil = plaintext)
	exportPolicy    *exportPolicyStore    // runtime-tunable log-export limits
	exportLimiter   *ratelimit.Limiter    // per-tenant export rate limit
	copilotLimiter  *ratelimit.Limiter    // per-principal copilot rate limit (SR-021)
	aiToolBudget    *aiDailyBudget        // per-tenant daily token budget for the agent loop (P2, LLM04)
	copilotCfg      *copilotConfigStore
	aiTenantCfg     *aiTenantConfigStore   // per-tenant AI entitlement + BYO provider key (P4a)
	displayPrefs    *tenantDisplayStore    // per-tenant display prefs (Wave 4 #11: time display)
	verifyCfg       *verifyConfigStore     // spec #8: per-tenant active-verification opt-in + SSH credential
	verifyRuns      *verifyRunStore        // spec #8: latest verification run per case (bounded)
	verifyLimiter   *ratelimit.Limiter     // spec #8: manual-verify per-tenant rate limit
	governance      *tenantGovernanceStore // per-tenant governance settings (Wave 4 #11: required tags, RCA window, precedence)
	cloudSLOs       *cloudSLOStore         // per-tenant SLO definitions (Wave 5 #14 slice 2)
	cloudMonitors   *cloudMonitorStore     // per-tenant cloud monitors (Wave 5 #14 slice 3)
	rcaPromotions   *rcaPromotionStore     // manual RCA-document promotions, tenant-keyed (#113 point 3)
	rcaActionItems  *rcaActionItemStore    // postmortem action-item register, tenant-keyed (postmortem Phase 1 §3/§7)
	rcaRevisions    *rcaRevisionStore      // report revision register, tenant-keyed (postmortem Phase 1 immutability)
	portStore       portintel.Store        // Port Intelligence physical-layer store (#94)
	netboxCfg       *netboxConfigStore     // NetBox source-of-truth discovery config
	discoveryCfg    *discoveryConfigStore  // SNMP subnet-discovery scan config (platform-owner)
	netboxSync      *netboxSyncer          // reconciles discovered devices INTO NetBox (write-through)
	vulns           *vuln.Feed             // #13: advisory feed for /api/vulns (lazy, mtime hot-reload)
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
	// workers is the shutdown drain group (see workerGroup below). It hangs off
	// the server so ANY subsystem that starts a goroutine from a *server method
	// can register it in one line — `s.workers.start("name", func(){…})` instead
	// of a bare `go func(){…}()` — and shutdown will then WAIT for it instead of
	// abandoning it mid-write. Never nil for a server built by newServer().
	workers *workerGroup
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

	// Recover settings orphaned by the F-63 key rename (relative -> /data/...).
	// On the Postgres backend the old relative keys worked, so repointing the
	// code stranded live per-tenant config. Copies legacy -> current where the
	// current key is empty; no-op on a fresh install. See kv_legacy_migrate.go.
	if recovered := migrateLegacyKVKeys(); len(recovered) > 0 {
		logInfo("store", "recovered settings written under pre-2026-07-21 store keys",
			map[string]any{"keys": recovered, "count": len(recovered)})
	}

	// Secret-custody Vault (#17). Dormant (plaintext passthrough) unless
	// SEAL_PROVIDER is set; fail closed if a configured provider can't unseal the
	// root KEK — never silently fall back to storing secrets in the clear.
	vaultStore, vaultWarn := vaultDeps()
	vault, err := vault.New(context.Background(), vaultStore, vaultWarn)
	if err != nil {
		log.Fatalf("secret custody: %v", err)
	}

	// Hardened TLS for outbound calls to internal backends (#18 phase 3). Fail
	// closed: a configured-but-unloadable trust bundle aborts boot.
	if err := initBackendTransport(); err != nil {
		log.Fatalf("backend TLS: %v", err)
	}

	d := NewDiscoveryAggregator()
	// Operator-created devices persist here and are seeded into the cache before
	// any source polls or the API serves a request. Without this, POST
	// /api/devices returned 201 for a device that existed only until the process
	// exited (see device_persist.go).
	d.SetStore(newDeviceStore(devicesPath()))
	d.Register(NewStaticSource(os.Getenv("STATIC_DEVICES_PATH")))
	// SNMP subnet discovery: registered always with a LIVE config getter
	// (console-set store, env bootstrap fallback) so operators can scope and
	// enable it at runtime without a restart. Poll is a no-op while disabled.
	discoveryCfg := newDiscoveryConfigStore(envOr("DISCOVERY_CONFIG_FILE", "/data/discovery_config.json"), vault)
	d.Register(NewSNMPSource(discoveryCfg.effective, d.Devices))
	// NetBox source-of-truth: registered always with a LIVE config getter (UI-set
	// store, env fallback). Poll is a no-op while unconfigured/disabled, so it
	// honors runtime changes from Automation → Source of Truth without a restart.
	netboxCfg := newNetboxConfigStore(envOr("NETBOX_CONFIG_FILE", "/data/netbox_config.json"), vault)
	d.Register(NewNetboxSource(netboxCfg.effective))

	// SNMP credential store is created below; capture a pointer the target
	// builder can resolve device credential_refs against (set after init).
	var snmpCredsRef *snmpcred.Store
	// Learned credential overrides (credential sentinel): when a device's bound
	// profile stops answering, the sentinel adopts a stored profile that does;
	// the target builder honors that resolution so polling self-heals.
	var credOverridesRef *credOverrideStore

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
				ID:      dev.ID,
				Address: dev.Address,
				// §3a.2 / F-56: the owning tenant travels with the target so a
				// collector that persists rows stamps it from the inventory,
				// never from anything the device says on the wire.
				TenantID: dev.TenantID,
				Protocol: dev.PreferredProtocol,
				// gNMI-capable devices (a gnmic subscription exists) declare it via the
				// `gnmi: "true"` label; the SNMP collector then yields gNMI-owned metric
				// families (BGP/IS-IS) to gNMI on them, staying the floor elsewhere.
				GNMICapable: strings.EqualFold(dev.Labels["gnmi"], "true"),
			}
			if snmpCredsRef != nil && dev.CredentialRef != "" {
				// The sentinel's learned override wins over the bound ref while it
				// stands (it exists only when the bound profile stopped answering).
				ref := dev.CredentialRef
				if credOverridesRef != nil {
					if ov, ok := credOverridesRef.Get(dev.ID); ok {
						ref = ov.ProfileID
					}
				}
				if c, ok := snmpCredsRef.Resolve(ref); ok {
					applyCredToTarget(&tgt, c)
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
	// Ubiquiti UniFi controller connector (device health via the controller API,
	// not device SNMP). Opt-in; needs UNIFI_URL + creds.
	pool.Enable("unifi", os.Getenv("FEATURE_UNIFI") == "true")
	// LLDP neighbour discovery (real Layer-1 topology links via SNMP LLDP-MIB) —
	// opt-in; without it the Device Topology keeps the labelled tier-inference
	// fallback. Reuses the per-device SNMP creds; UDP/161, no raw socket.
	pool.Enable("lldp", os.Getenv("ENABLE_LLDP_DISCOVERY") == "true")
	// CDP neighbour discovery (Cisco-native L2 topology) — merges with LLDP at the
	// API. Opt-in; reuses SNMP creds, UDP/161.
	pool.Enable("cdp", os.Getenv("ENABLE_CDP_DISCOVERY") == "true")
	// BGP-LS topology discovery — receive-only BGP speaker that peers with a
	// route-reflector/export speaker (BGPLS_PEERS) and ingests the IGP (IS-IS/OSPF)
	// link-state database via the Link-State AFI. Merges with LLDP/CDP at the API
	// as source_protocol=bgp_ls. Opt-in; needs a peer configured to
	// `distribute link-state`. TCP/179, no raw socket, no new dependency.
	pool.Enable("bgpls", os.Getenv("ENABLE_BGPLS_DISCOVERY") == "true")
	// SNMP trap receiver (UDP/162) — passive listener that decodes v1/v2c/v3
	// traps and forwards them onto the log bus (→ netops-snmptrap-*). Off by
	// default; opt in with FEATURE_SNMP_TRAPS=true (see deployment compose).
	pool.Enable("snmptrap", os.Getenv("FEATURE_SNMP_TRAPS") == "true")
	// Active path measurement (STAMP / RFC 8762) — opt-in. The sender probes
	// STAMP_TARGETS; the reflector responds to probes aimed at this host. Both
	// dormant by default (no targets / not enabled).
	pool.Enable("stamp-sender", os.Getenv("FEATURE_ACTIVE_PROBE") == "true")
	pool.Enable("stamp-reflector", os.Getenv("FEATURE_STAMP_REFLECTOR") == "true")
	// Path discovery (Paris-consistent traceroute, ICMP/TCP) — opt-in; traces
	// TRACEROUTE_TARGETS. Needs CAP_NET_RAW for the raw socket.
	pool.Enable("traceroute", os.Getenv("FEATURE_TRACEROUTE") == "true")
	// Service-level synthetic checks (HTTP/ICMP/TCP) — opt-in; probes the
	// SYNTHETIC_*_TARGETS lists. HTTP/TCP need no privileges; ICMP falls back
	// to raw only where CAP_NET_RAW exists (prober sidecar).
	pool.Enable("synthetics", os.Getenv("FEATURE_SYNTHETICS") == "true")
	// WAN circuit SLA — SD-WAN/BFD-style source-bound echo (ICMP, TCP-SYN
	// fallback) between WAN-interface endpoints. Targets are the circuits the
	// projector publishes to Redis. Opt-in; ICMP raw needs CAP_NET_RAW.
	pool.Enable("wan-echo", os.Getenv("FEATURE_WAN_ECHO") == "true")

	notifier := notify.NewDispatcher()
	// F-22: delivery failures used to be a bare log.Printf and nothing else.
	// Route them into the structured app log so a lost page is searchable next
	// to the alert that produced it (§10).
	notifier.SetLogger(func(level, msg string, fields map[string]any) {
		appLog.log(level, "notify", msg, fields)
	})
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
	userRules := newUserRulesStore(envOr("USER_RULES_FILE", "/data/user_rules.json"))

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
	orgs, err := newOrgStore(envOr("ORGS_FILE", "/data/orgs.json"))
	if err != nil {
		log.Fatalf("org store: %v", err)
	}
	bindings, err := newBindingStore(envOr("BINDINGS_FILE", "/data/role_bindings.json"))
	if err != nil {
		log.Fatalf("binding store: %v", err)
	}
	securitySettings, err := newSecuritySettingsStore(envOr("SECURITY_SETTINGS_FILE", "/data/security_settings.json"))
	if err != nil {
		log.Fatalf("security settings store: %v", err)
	}
	sessionKV, sessionErrf := sessionDeps()
	sessions, err := session.NewStore(envOr("SESSIONS_FILE", "/data/sessions.json"), sessionKV, sessionErrf)
	if err != nil {
		log.Fatalf("session store: %v", err)
	}
	keyLimit := apikey.DefaultRateLimit
	if v := os.Getenv("APIKEY_RATE_LIMIT_PER_MIN"); v != "" {
		if n, perr := parseIntStrict(v); perr == nil && n >= 0 {
			keyLimit = n
		}
	}
	apiKeys, err := apikey.NewStore(envOr("APIKEYS_FILE", "/data/apikeys.json"), keyLimit, TenantGlobal, platformKV{})
	if err != nil {
		log.Fatalf("api key store: %v", err)
	}
	refresh, err := session.NewRefreshStore(envOr("REFRESH_FILE", "/data/refresh_tokens.json"), refreshTokenTTL(), sessionKV)
	if err != nil {
		log.Fatalf("refresh store: %v", err)
	}
	snmpCreds, err := snmpcred.NewStore(envOr("SNMP_CREDS_FILE", "/data/snmp_credentials.json"), vault, platformKV{})
	if err != nil {
		log.Fatalf("snmp cred store: %v", err)
	}
	snmpCredsRef = snmpCreds // make profiles resolvable by the target builder
	credOverrides, err := newCredOverrideStore(envOr("CRED_OVERRIDES_FILE", "/data/credential_overrides.json"))
	if err != nil {
		log.Fatalf("credential overrides store: %v", err)
	}
	credOverridesRef = credOverrides

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

	deviceLocations, err := newDeviceLocationStore(envOr("DEVICE_LOCATIONS_FILE", "/data/device_locations.json"))
	if err != nil {
		log.Fatalf("device locations store: %v", err)
	}
	sites, err := newSitesStore(envOr("SITES_FILE", "/data/sites.json"))
	if err != nil {
		log.Fatalf("sites store: %v", err)
	}
	deviceSites, err := newDeviceSiteStore(envOr("DEVICE_SITES_FILE", "/data/device_sites.json"))
	if err != nil {
		log.Fatalf("device sites store: %v", err)
	}
	wanPolicy, err := newWanPolicyStore(envOr("WAN_POLICY_FILE", "/data/wan_policy.json"))
	if err != nil {
		log.Fatalf("wan policy store: %v", err)
	}
	contactPoints, err := newContactPointStore(envOr("CONTACT_POINTS_FILE", "/data/contact_points.json"))
	if err != nil {
		log.Fatalf("contact point store: %v", err)
	}
	systemNet, err := newSystemNetStore(envOr("SYSTEM_NETWORK_FILE", "/data/system_network.json"))
	if err != nil {
		log.Fatalf("system network store: %v", err)
	}
	backupCfg, err := newBackupConfigStore(envOr("SYSTEM_BACKUP_FILE", "/data/system_backup.json"))
	if err != nil {
		log.Fatalf("backup config store: %v", err)
	}

	srv := &server{
		startedAt:        time.Now().UTC(),
		workers:          &workerGroup{},
		discovery:        d,
		collectors:       pool,
		alerts:           engine,
		userRules:        userRules,
		notifier:         notifier,
		selfHeal:         newSelfHealer(notifier),
		users:            users,
		roles:            roles,
		tenants:          tenants,
		orgs:             orgs,
		bindings:         bindings,
		securitySettings: securitySettings,
		loginThrottle:    newLoginThrottle(),
		sessions:         sessions,
		apiKeys:          apiKeys,
		refresh:          refresh,
		snmpCreds:        snmpCreds,
		credOverrides:    credOverrides,
		credSentinel:     newCredSentinel(credOverrides, snmpCreds, d.Devices),
		sshHosts:         newSSHHostStore(envOr("SSH_KNOWN_HOSTS_FILE", "/data/ssh_known_hosts.json")),
		snmpProfiles:     snmpProfiles,
		saved:            saved,
		audit:            audit,
		contactPoints:    contactPoints,
		deviceLocations:  deviceLocations,
		sites:            sites,
		deviceSites:      deviceSites,
		wanPolicy:        wanPolicy,
		systemNet:        systemNet,
		backupCfg:        backupCfg,
		hub:              NewHub(),
		// #13 Vulnerability Management: operator-prepared advisory feed
		// (scripts/vuln-feed-prepare.py → data/vuln/, mounted ro at /data/vuln).
		vulns: vuln.NewFeed(envOr("VULN_FEED_PATH", "/data/vuln/advisories.csv"),
			func(msg string, fields map[string]any) { logWarn("vulns", msg, fields) },
			func(msg string, fields map[string]any) { logInfo("vulns", msg, fields) }),
	}
	// ITSM config store — seeds from env on first run, then admin-UI editable;
	// builds + swaps the ServiceNow/Jira connectors into srv + the notifier.
	srv.itsmCfg = newITSMConfigStore(srv, envOr("ITSM_CONFIG_FILE", "/data/itsm_config.json"))
	// RCA auto-ticketing store (#78): RLS-scoped pg repo, else in-memory. Always
	// non-nil; the outbox worker + policy sweeper start in main() only under
	// FEATURE_RCA_TICKETING (ticketing is opt-in and never blocks correlation).
	srv.ticketing = newTicketingStore()
	// Incident system (Postgres only) + its alert-ingestion hook.
	srv.incidents = newIncidentStore()
	// seam.Seam inventory (#67 build ⑤): the correlation engine's grounding targets.
	// Postgres only, like incidents; the bootstrap loop starts in main().
	srv.seams = newSeamStore()
	srv.services = newServiceStore()
	// Cloud Connector framework: tenant-safe connector store (pg or in-memory) +
	// the Identity Broker (scoped short-lived provider tokens; the ONLY component
	// that decrypts connector secrets, via the existing envelope Vault).
	srv.cloudConn = newCloudConnStore()
	srv.cloudBroker = newCloudIdentityBroker(srv.cloudConn, vault, func(e AuditEvent) {
		if srv.audit != nil {
			srv.audit.Record(e)
		}
	})
	// Platform workload OIDC issuer (Wave 4 #13): minted federated assertions
	// when CLOUD_WORKLOAD_ISSUER_URL is set; dormant (env-token fallback) otherwise.
	srv.bootstrapWorkloadIssuer(vault, os.Getenv("CLOUD_WORKLOAD_ISSUER_URL"))
	srv.cloudIngestInv = newCloudIngestInventory()          // per-tenant ingestion (Wave 1 #2)
	srv.cloudSourceStatus = newCloudSourceStatusStore()     // poller-reported source errors (Wave 2 #4)
	srv.topology = newTopologyStore()                       // persistent topology graph (#77); reconciler starts in main()
	srv.incidentTimeline = newIncidentTimelineStore()       // RCA Time Intelligence manual lifecycle events (#84)
	srv.incidentTimeMetrics = newIncidentTimeMetricsStore() // RCA Time Intelligence backfilled snapshots (#84); ticker starts in main()
	srv.aiFeedback = newAIFeedbackStore()                   // Iris AI feedback loop (privacy-safe ratings)
	srv.applications = newApplicationStore()                // Application Identification registry (#81 P0)
	srv.appCatalog = newAppCatalogHolder()                  // Application Identification IP→app resolver (#81 P1)
	srv.ngfw = newNgfwAppResolver()                         // Application Identification NGFW app-id overlay (#81 P-NGFW pt2)
	srv.appOverrides = newAppCatalogStore()                 // Application Identification operator-defined overrides (#81 P1c)
	srv.cloud = newCloudStore()                             // Cloud App Observability inventory (#81 P3A)
	srv.bizServices = newBusinessServiceStore()             // Business Service mapping + manual overrides (migration 0024)
	srv.cloudApp = newCloudAppResolver(srv.cloud)           // Cloud identity-map → appid bridge (#81 P3F+1)
	srv.pathGraph = newPathGraphStore()                     // Service Path Graph storage (contract v1); ingester starts in main()
	srv.remotePaths = newRemotePathStore()                  // remote-vantage path pushes (the LAN vantage's transport)
	if n, errs := srv.appCatalog.reload(); srv.appCatalog.feedsDir != "" {
		log.Printf("appid: loaded %d catalog prefixes from %s (%d feed errors)", n, srv.appCatalog.feedsDir, len(errs))
	}
	srv.incMetrics = &incidentMetrics{}
	// Integration platform (#43): persistence is Postgres-only; the provider
	// registry (inbound translators) is always available.
	if ps, ok := backend.(*pgStore); ok {
		srv.integrations = newIntegrationStore(ps.db, vault)
	}
	srv.providers = integration.DefaultRegistry()
	// Wireless canonical inventory (#128 Phase 1, migration 0030): PG-backed on
	// postgres (FORCE-RLS), in-memory on the file backend (dev/tests). Always
	// set — the read APIs render an empty inventory until a connector runs.
	// MUST init before the NMS runtime, which takes it as its inventory sink.
	if ps, ok := backend.(*pgStore); ok {
		srv.wireless = newPGWirelessStore(ps.db)
	} else {
		srv.wireless = newMemWirelessStore()
	}
	srv.wirelessActions = newWirelessActionStore()
	// NMS vendor-controller framework (#95 P3b): dormant unless
	// FEATURE_NMS_INTEGRATIONS=true. PG-backed on postgres (migration 0020,
	// FORCE-RLS); in-memory store on the file backend (dev).
	if nms.Enabled() {
		if ps, ok := backend.(*pgStore); ok {
			srv.nms = newNMSRuntime(newPGNMSStore(ps.db, vault))
		} else {
			// F-76: the catalog + integration list still render on a fresh
			// install, but credential writes are REFUSED rather than held as
			// plaintext in a map that dies with the process.
			srv.nms = newNMSRuntime(nonDurableNMSStore{newMemNMSStore()})
		}
		srv.nms.wireless = srv.wireless // #128: wireless-inventory sink
	}
	srv.intMetrics = &integrationMetrics{}
	srv.vault = vault
	srv.exportPolicy = newExportPolicyStore(envOr("EXPORT_POLICY_FILE", "/data/export_policy.json"))
	srv.exportLimiter = ratelimit.New()
	srv.copilotLimiter = ratelimit.New()
	srv.aiToolBudget = newAIDailyBudget()
	engine.OnFire = srv.ingestAlertIncident
	// Alert episode grouping + triage (Wave 2 #6): fold fire/resolve transitions
	// into per-tenant episodes; muted/snoozed episodes pause NOTIFICATIONS only.
	srv.alertEpisodes = newAlertEpisodeStore(envOr("ALERT_EPISODES_FILE", "/data/alert_episodes.json"))
	engine.OnTransition = srv.observeAlertTransition
	engine.SuppressNotify = srv.alertNotifySuppressed
	srv.reports = newReportScheduler(srv, envOr("REPORT_RUNS_FILE", "/data/report_runs.json"))
	srv.copilotCfg = newCopilotConfigStore(envOr("COPILOT_CONFIG_FILE", "/data/copilot_config.json"), vault)
	srv.aiTenantCfg = newAITenantConfigStore(aiTenantConfigPath(), vault)
	srv.displayPrefs = newTenantDisplayStore(tenantDisplayPath())
	// Active Verification (RCA spec item 8): per-tenant opt-in config (SSH
	// secrets vault-sealed), bounded run store, per-tenant rate limiter.
	srv.verifyCfg = newVerifyConfigStore(verifyConfigPath(), vault)
	srv.verifyRuns = newVerifyRunStore(envOr("VERIFY_RUNS_FILE", "/data/verify_runs.json"))
	srv.verifyLimiter = ratelimit.New()
	srv.governance = newTenantGovernanceStore(tenantGovernancePath())
	srv.cloudSLOs = newCloudSLOStore(cloudSLOPath())
	srv.cloudMonitors = newCloudMonitorStore(cloudMonitorsPath())
	srv.rcaPromotions = newRcaPromotionStore(rcaPromotionsPath()) // #113 point 3
	srv.rcaActionItems = newRcaActionItemStore(rcaActionItemsPath())
	srv.rcaRevisions = newRcaRevisionStore(rcaRevisionsPath())

	srv.portStore = newPortStore() // Port Intelligence #94 P5
	srv.netboxCfg = netboxCfg
	srv.discoveryCfg = discoveryCfg
	// Write-through: reconcile discovered devices INTO NetBox (the source of truth),
	// reading the deduped inventory. No-op while NetBox is disabled.
	srv.netboxSync = newNetboxSyncer(netboxCfg.effective, srv.discovery.Devices)
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
	// PBAC Phase A: ensure every existing user has its mirror role_binding so the
	// auditable artifact is complete on boot. Idempotent; behaviour-preserving.
	srv.backfillBindings()
	return srv
}

// ── goroutine safety + shutdown drain ────────────────────────────────────────

// apiPanicLogger routes a recovered goroutine panic into the structured app log,
// so the bug is as visible as the crash was (§10) — searchable next to every
// other event instead of being a container restart with no explanation.
func apiPanicLogger(name string, recovered any, stack []byte) {
	logError("panic", "goroutine panic recovered", map[string]any{
		"goroutine": name,
		"panic":     fmt.Sprint(recovered),
		"stack":     string(stack),
	})
}

// safeGo starts fn on its own goroutine with panic recovery. Nothing recovers
// panics outside net/http's per-request handler, so ANY background loop or
// per-connection pump that panics takes the whole API down for every tenant.
func safeGo(name string, fn func()) { safego.GoWith(apiPanicLogger, name, fn) }

// workerGroup tracks background workers so shutdown can WAIT for them. Without
// it, SIGTERM cancelled the root context and returned immediately: every
// in-flight Postgres/ClickHouse write (ticketing outbox, report jobs, incident
// sync) was abandoned mid-operation on every deploy.
//
// It also tracks each worker BY NAME while it runs. A drain that times out and
// says only "workers did not drain" is unactionable — the operator cannot tell
// whether a report render or a ClickHouse backfill was cut short. The names are
// the difference between an observable shutdown and a shrug (§10).
type workerGroup struct {
	wg sync.WaitGroup

	mu      sync.Mutex
	running map[string]int // worker name → live goroutines under that name
}

// start launches a tracked worker. fn must return when the root context is
// cancelled — a worker that ignores cancellation only costs the drain timeout.
//
// A nil group still runs the worker (a background loop must never be dropped
// because wiring was missed) but says so: it will NOT be drained.
func (g *workerGroup) start(name string, fn func()) {
	if g == nil {
		logWarn("shutdown", "worker started without a tracking group — it will NOT be waited for at shutdown",
			map[string]any{"worker": name})
		safeGo(name, fn)
		return
	}
	g.wg.Add(1)
	g.mark(name, 1)
	safeGo(name, func() {
		// One deferred closure so the count and the WaitGroup are released on a
		// panic too — safego recovers ABOVE this frame, so a panicking worker
		// must not leave the drain waiting on a goroutine that is already gone.
		defer func() {
			g.mark(name, -1)
			g.wg.Done()
		}()
		fn()
	})
}

// mark adjusts the live count for a worker name.
func (g *workerGroup) mark(name string, delta int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.running == nil {
		g.running = map[string]int{}
	}
	if g.running[name] += delta; g.running[name] <= 0 {
		delete(g.running, name)
	}
}

// stillRunning lists the tracked workers that have not returned yet, sorted for
// a stable log line.
func (g *workerGroup) stillRunning() []string {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	names := make([]string, 0, len(g.running))
	for n := range g.running {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// drain waits up to d for the tracked workers to return after cancellation and
// returns the names of those still running when it gave up — empty means a
// clean drain.
//
// It is bounded on purpose: a worker that ignores cancellation (or is parked on
// a slow upstream) costs exactly d and then shutdown continues, so one stuck
// loop can never hold the process open forever. What it must NOT do is exit
// quietly, which is why the caller gets the names rather than a bare bool.
func (g *workerGroup) drain(d time.Duration) []string {
	if g == nil {
		return nil
	}
	done := make(chan struct{})
	go func() {
		g.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(d):
		return g.stillRunning()
	}
}

// cancelOnlyWorkers names the background subsystems main starts through their
// OWN Start()/start*() entry points. Each of those spawns its goroutines inside
// that call and hands main no handle to wait on, so they are cancel-only: the
// root context stops them and the process then exits — they are NOT drained.
//
// This list exists so that is a stated decision instead of a silent omission,
// and so the shutdown log names precisely what was cut short. Before it, the
// drain returned "all workers finished" while collectors, discovery, the report
// pipeline and the 30-minute backfills were still mid-write to ClickHouse and
// Postgres — a shutdown that lies is the silent-failure class this release is
// closing (§10).
//
// Adopting one is a one-line change IN ITS OWN FILE: replace the internal
// `go func(){…}()` / `safeGo(name, …)` with `s.workers.start(name, …)` — the
// group hangs off *server for exactly that reason — then delete the entry here.
// Subsystems outside package main (collectors.Pool, alerts.Engine) cannot see
// this type, so they need an additive `Wait()` over their own WaitGroup, which
// main then waits on inside a tracked worker.
func cancelOnlyWorkers() []string {
	return []string{
		"alerts-engine",            // alerts.Engine.Start → go e.loop(ctx)
		"appid-catalog-refresh",    // appCatalogHolder.startRefresh
		"audit-retention",          // startAuditRetention → safego.Go
		"ch-row-policies",          // ensureCHRowPolicies (bounded retry, then exits)
		"cloud-appid-refresh",      // cloudAppResolver.startRefresh
		"cloud-inventory",          // server.startCloudInventory
		"cloud-monitor-eval",       // cloudMonitorEvaluator.Start → go e.loop(ctx)
		"collectors",               // collectors.Pool.Start → one goroutine per collector
		"cred-cache-reload",        // server.startCredCacheReload
		"discovery",                // DiscoveryAggregator.Start → per-source pollLoop + vendorLoop
		"entity-resolver-enrich",   // server.startEntityResolverEnrichment
		"fusion-worker",            // fusionWorker.start
		"incident-time-backfill",   // server.startIncidentTimeMetricsBackfill (CH writes)
		"itsm-drift-reconciler",    // server.startDriftReconciler → safeGo
		"netbox-sync",              // netboxSyncer.Start (writes INTO NetBox)
		"ngfw-appid-refresh",       // ngfwAppResolver.startRefresh
		"path-baseline-precompute", // server.startPathBaselinePrecompute (CH writes)
		"path-graph-enrich",        // server.startPathGraphEnrichment
		"path-graph-ingest",        // server.startPathGraphIngest (CH/PG writes)
		"probe-paths-enrich",       // server.startProbePathsEnrichment
		"report-pipeline",          // reportPipeline.Start → scheduler + N render workers
		"report-scheduler-file",    // reportScheduler.Start (file backend)
		"routing-direction-enrich", // server.startRoutingDirectionEnrichment
		"seam-bootstrap",           // server.startSeamBootstrap (PG writes)
		"seam-enrich",              // server.startSeamEnrichment
		"svc-flow-rollup",          // server.startSvcFlowRollup (CH writes)
		"tenant-enrichment",        // server.startTenantEnrichment
		"topology-links-enrich",    // server.startTopologyLinksEnrichment
		"topology-reconciler",      // server.startTopologyReconciler (PG writes)
		"wan-circuit-publish",      // server.startWANCircuitPublish
	}
}

// newAPIServer builds the HTTP server with a COMPLETE timeout set.
//
// Only ReadHeaderTimeout was set before, which leaves a request BODY dribblable
// forever and connections parkable indefinitely (slowloris-on-body). nginx's
// client_body_timeout covers the default deployment — but in TLS/mTLS mode this
// server is reachable directly, with nothing in front of it.
//
// The WebSocket and SSH-proxy handlers hijack their connections and manage
// their own per-read/per-write deadlines, so these values do not cap session
// length there.
func newAPIServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: durationOr("HTTP_READ_HEADER_TIMEOUT", 10*time.Second),
		// Generous: large SOT/profile imports upload over slow links.
		ReadTimeout: durationOr("HTTP_READ_TIMEOUT", 120*time.Second),
		// Must exceed the slowest upstream a handler waits on (copilot proxy, 60s).
		WriteTimeout:   durationOr("HTTP_WRITE_TIMEOUT", 180*time.Second),
		IdleTimeout:    durationOr("HTTP_IDLE_TIMEOUT", 120*time.Second),
		MaxHeaderBytes: 1 << 20, // 1 MiB header cap (SR-012); default is also 1 MiB, set explicitly.
	}
}

func main() {
	// Prober mode: a minimal, least-privilege sidecar that runs ONLY the active
	// measurement collectors (STAMP / traceroute) — the single component that
	// needs CAP_NET_RAW. No HTTP API, no DB, no auth surface. It shares the
	// traceroute path topology with the API via PROBE_PATHS_FILE on a shared
	// volume; metrics flow independently to VictoriaMetrics. Keeps the main API
	// container unprivileged.
	if os.Getenv("PROBER_ONLY") == "true" {
		runProber()
		return
	}
	addr := envOr("LISTEN_ADDR", ":8080")
	srv := newServer()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Background workers started through this group are waited for on shutdown
	// (see the drain below) instead of being abandoned mid-write. The group is
	// the server's own, so a subsystem that starts goroutines from a *server
	// method can join the drain without main having to reach into it.
	// Subsystems NOT in the group are listed by cancelOnlyWorkers().
	workers := srv.workers
	srv.discovery.Start(ctx)
	srv.netboxSync.Start(ctx)
	srv.collectors.Start(ctx)
	// Credential sentinel — self-healing SNMP credential resolution. Runs with
	// SNMP collection; CRED_AUTO_RESOLVE=false opts out (bound refs then fail
	// dark exactly as before).
	if os.Getenv("ENABLE_SNMP_COLLECTION") == "true" && os.Getenv("CRED_AUTO_RESOLVE") != "false" {
		workers.start("cred-sentinel", func() { srv.credSentinel.run(ctx) })
	}
	srv.alerts.Start(ctx)
	srv.loadUserRules() // re-feed persisted operator-created monitors (rules_user.go)
	// Per-tenant cloud monitor evaluation (Wave 5 #14 slice 3): a bounded poll
	// loop over each tenant's OWN inventory scope. CLOUD_MONITOR_EVAL_SECONDS=0
	// opts out.
	newCloudMonitorEvaluator(srv, cloudMonitorEvalInterval()).Start(ctx)
	// Export the device→tenant map for the ingest tier to stamp tenant_id onto
	// telemetry (#20 Phase 1). No-op unless TENANT_ENRICHMENT_DIR is set.
	srv.startTenantEnrichment(ctx)
	// Bounded growth for the Postgres audit trail (F-57). Opt-in and OFF by
	// default — an audit trail is evidence; only an operator decides how long
	// it is kept. No-op unless AUDIT_RETENTION_DAYS is a positive integer.
	startAuditRetention(ctx)
	// Self-heal the ClickHouse tenant row policies (#20 Phase 2) in the background.
	ensureCHRowPolicies()
	// corr_current projection drift repair (#101): detect + re-seed hot-read rows
	// whose dual-write was lost. No-op when ClickHouse is not configured.
	workers.start("corr-current-reconcile", func() { srv.corrCurrentReconcileLoop(ctx) })
	// ITSM drift reconciler (#43 enhancement). No-op unless FEATURE_ITSM_RECONCILE.
	srv.startDriftReconciler(ctx)
	// App-identity catalog hot-reload (#81 P1b). No-op unless APPID_FEEDS_DIR set.
	srv.appCatalog.startRefresh(ctx)
	// NGFW app-id overlay refresh (#81 P-NGFW pt2): aggregate firewall app-id events
	// from OpenSearch into the resolver. Harmless empty map if no firewall onboarded.
	srv.ngfw.startRefresh(ctx)
	// Cloud App Observability inventory (#81 P3A): load fixtures into the store.
	// No-op unless CLOUD_FIXTURES_DIR set (real per-tenant SDK connectors come later).
	srv.startCloudInventory(ctx)
	// Appliance self-health guard: watches disk + OpenSearch read-only blocks,
	// heals ingest after disk pressure, pages via the platform lane (self_heal.go).
	workers.start("self-heal", func() { srv.selfHeal.run(ctx) })
	// Service Path Graph ingest (contract v1): the prober's traceroutes → immutable
	// PathObservations + ordered PathHops, each hop resolved through the §3 ranked
	// resolver. Opt-in (FEATURE_PATH_GRAPH=true), dormant by default.
	srv.startPathGraphIngest(ctx)
	// …and export the resulting path graph to the shared enrichment volume
	// (/data/enrichment/path_graph.json), which is what the correlation engine's
	// NEW ranked edge-admission gate reads instead of token overlap. Same mechanism
	// as seams.json; no-op without TENANT_ENRICHMENT_DIR.
	srv.startPathGraphEnrichment(ctx)
	// Cloud identity-map → appid bridge (#81 P3F+1): index the cloud inventory's
	// (private-IP/ENI/resource → app) mappings into the shared resolver so flows/logs
	// to cloud resources name their app. Runs after the fixture load above.
	srv.cloudApp.startRefresh(ctx)
	// Application Identity Fusion worker (#81 P4): pull vendor app events → adapters →
	// observations → fuse → persist app_observations/app_identities. Opt-in + default-off
	// (FUSION_WORKER_ENABLED=true) so it never runs unasked; metrics at /api/appid/fusion/status.
	srv.fusion = newFusionWorker(openSearchSource{})
	if envOr("FUSION_WORKER_ENABLED", "") == "true" {
		srv.fusion.start(ctx)
	}
	// seam.Seam bootstrap engine (#67 build ⑤ / cloud-ingestion §4.1): auto-suggest
	// seam instances from telemetry so the grounding gate has an inventory.
	srv.startSeamBootstrap(ctx)
	// Export active seams to the enrichment dir for the correlation engine's
	// grounding gate (#67 build ⑥).
	srv.startSeamEnrichment(ctx)
	// L2/L3 adjacency export for the correlation engine's adjacency grounding (G1).
	srv.startTopologyLinksEnrichment(ctx)
	// IP→device + (device,ifIndex)→ifName export for the C7.1 EntityResolver (the
	// keystone for directed-topology direction sources C7.3–C7.5 + G2 canonicalize).
	srv.startEntityResolverEnrichment(ctx)
	// Measured forwarding paths (traceroute hop order) for the C7.4 active-path-trace
	// direction source — the highest-precedence (measured) direction signal.
	srv.startProbePathsEnrichment(ctx)
	// Computed forwarding direction (BGP-LS/IGP SPF) for the C7.5 routing source —
	// the lowest-precedence (computed) signal; empty until the LSDB has data.
	srv.startRoutingDirectionEnrichment(ctx)
	// WAN circuit SLA targets: publish the projected circuit mesh to Redis for
	// the wan-echo collector (#2). Gated by FEATURE_WAN_ECHO; no-op without Redis.
	srv.startWANCircuitPublish(ctx)
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
	// RCA auto-ticketing (#78 P3): the sweeper enqueues policy-passing correlation
	// objects → the outbox worker drains them to ServiceNow. Opt-in + default-off
	// (FEATURE_RCA_TICKETING) so external ticketing never runs unasked, and it
	// never blocks correlation. The conn resolver reads each tenant's OWN ITSM
	// connection (a tenant can only ticket via its own ServiceNow).
	if os.Getenv("FEATURE_RCA_TICKETING") == "true" {
		resolve := func(_ context.Context, tenant, system string) (ticketSystemConfig, bool, error) {
			if srv.itsmCfg == nil {
				return ticketSystemConfig{}, false, nil
			}
			cfg, ok := srv.itsmCfg.ticketSystemConfig(tenant, system)
			return cfg, ok, nil
		}
		tw := newTicketWorker(srv.ticketing, resolve)
		workers.start("ticketing-worker", func() {
			tw.Run(ctx, durationOr("RCA_TICKETING_WORKER_INTERVAL", 15*time.Second))
		})
		ts := newTicketSweeper(srv, srv.ticketing)
		workers.start("ticketing-sweeper", func() {
			ts.Run(ctx, durationOr("RCA_TICKETING_SWEEP_INTERVAL", 60*time.Second))
		})
		// Inbound state sync (#84): poll each live ticket's ServiceNow state back and
		// append the human-phase lifecycle events (acknowledged/resolved/closed/…) the
		// incident time-decomposition renders. Self-dormant when no connection is set.
		sy := newTicketStateSyncer(srv.ticketing, resolve)
		workers.start("ticketing-inbound-sync", func() {
			sy.Run(ctx, durationOr("RCA_TICKETING_INBOUND_INTERVAL", 45*time.Second))
		})
		logInfo("ticketing", "RCA auto-ticketing enabled", nil)
	}
	// Cloud signal notifications (Wave 4 #12 slice 1): page/message the owning
	// tenant when a cloud correlation object OPENS, through that tenant's OWN
	// RCA Slack/PagerDuty lanes (itsmConfigStore). Opt-in + default-off; a
	// tenant with no configured lane is an honest no-op.
	if os.Getenv("FEATURE_CLOUD_SIGNAL_NOTIFICATIONS") == "true" {
		resolveNotify := func(tenant string) []cloudNotifyTarget {
			if srv.itsmCfg == nil {
				return nil
			}
			return srv.itsmCfg.rcaNotifyTargets(tenant)
		}
		cn := newCloudNotifySweeper(srv, resolveNotify)
		workers.start("cloud-notify-sweeper", func() {
			cn.Run(ctx, durationOr("CLOUD_NOTIFY_INTERVAL", 60*time.Second))
		})
		logInfo("cloud", "cloud signal notifications enabled", nil)
	}
	// NMS controller polling (#95 P3b): each enabled integration polls on its
	// own interval; the tick only re-evaluates due-ness. Non-nil only when
	// FEATURE_NMS_INTEGRATIONS=true.
	if srv.nms != nil {
		workers.start("nms-scheduler", func() { srv.nms.Run(ctx, durationOr("NMS_POLL_TICK", 30*time.Second)) })
		logInfo("nms", "NMS integration scheduler enabled", nil)
	}
	// Active Verification auto-trigger (RCA spec item 8): watches suspected-tier
	// cases in opted-in tenants; bounded per tick, deduped per case (cooldown).
	if srv.verifyFeatureOn() {
		workers.start("verify-loop", func() { srv.verifyLoop(ctx, verifyScanInterval()) })
		logInfo("verify", "active-verification trigger enabled", nil)
	}
	workers.start("ws-broadcaster", func() { srv.startBroadcaster(ctx.Done()) })
	workers.start("ws-alert-watcher", func() { srv.watchAlertsForBroadcast(ctx) })
	// F-25: the failed-login map had no deletion path at all — a username spray
	// filled it permanently and lockout then failed OPEN for every account not
	// already tracked. The janitor is what keeps the cap reachable.
	workers.start("login-throttle-janitor", func() { srv.loginThrottle.runJanitor(ctx) })
	// Multi-instance cache coherence for the cached-by-design stores: refresh
	// API keys + SNMP creds from the shared backend so a revoke/rotate on another
	// replica converges here (no-op for the single-writer file backend).
	srv.startCredCacheReload(ctx)
	srv.startTopologyReconciler(ctx)          // #77: keep the persistent topology graph fresh
	srv.startIncidentTimeMetricsBackfill(ctx) // #84: persist phase-metric snapshots (incl. seam_type)
	// ── #69 P2 (one contiguous block): service flow rollup + PBH V1 baselines ──
	// Both opt-in + default-off. The rollup worker materializes per-service
	// per-minute flow attribution WITHOUT an MV over the policy-protected flows
	// table (svc_rollup_worker.go); the baseline precompute feeds the
	// hour-of-week tier of the path-health cascade (path_health_baselines.go).
	if os.Getenv("FEATURE_SVC_FLOW_ROLLUP") == "true" {
		srv.startSvcFlowRollup(ctx)
	}
	if os.Getenv("FEATURE_PATH_BASELINES") == "true" {
		srv.startPathBaselinePrecompute(ctx)
	}

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

	httpSrv := newAPIServer(addr, handler)
	if tlsSrv != nil {
		httpSrv.TLSConfig = tlsSrv.config
		httpSrv.Handler = hsts(handler) // HSTS only when actually serving TLS
		// Count + structure-log handshake failures instead of the default logger.
		httpSrv.ErrorLog = log.New(handshakeErrLog{tlsSrv.metrics}, "", 0)
		// Tracked (not bare safeGo): both loops select on ctx.Done and the reissue
		// loop REWRITES cert/key files — abandoning it mid-write is how a restart
		// finds a truncated key.
		workers.start("tls-cert-reloader", func() {
			tlsSrv.reloader.WatchInterval(ctx, tlsSrv.interval, func(e error) {
				logError("tls", "cert reload", errf(e))
			})
		})
		// Periodic SVID re-issue (#18 phase 4): re-mint + rewrite the API/nginx
		// certs at ~half the TTL; the reloader hot-swaps them — rotation, no restart.
		if caMgr != nil {
			workers.start("tls-svid-reissue", func() { caMgr.startReissueLoop(ctx) })
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
	logInfo("shutdown", "shutdown requested", nil)
	// Order matters: stop accepting/finish in-flight HTTP first, THEN cancel the
	// workers' context, THEN wait for them. Cancelling before the drain (and not
	// waiting at all) is what abandoned in-flight ticketing/report/incident
	// writes on every deploy.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), durationOr("HTTP_SHUTDOWN_TIMEOUT", 10*time.Second))
	defer shutdownCancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logError("shutdown", "http graceful shutdown", errf(err))
	}
	cancel()
	drainTimeout := durationOr("WORKER_DRAIN_TIMEOUT", 15*time.Second)
	if stuck := workers.drain(drainTimeout); len(stuck) > 0 {
		// Name them. "did not drain" with no names cannot be acted on, and the
		// bounded wait means shutdown continues regardless — so this line is the
		// only record that a tracked worker was cut short.
		logWarn("shutdown", "background workers did not drain before timeout — their in-flight work was cut short",
			map[string]any{"workers": stuck, "count": len(stuck), "timeout": drainTimeout.String()})
	} else {
		logInfo("shutdown", "tracked background workers drained", map[string]any{"timeout": drainTimeout.String()})
	}
	// Everything else is cancel-only: stopped by the context cancel above, never
	// waited for. Stated explicitly so the drain above is not read as "all
	// background work finished" — it never covered these (see cancelOnlyWorkers).
	if names := cancelOnlyWorkers(); len(names) > 0 {
		logInfo("shutdown", "cancel-only subsystems were signalled but NOT waited for",
			map[string]any{"subsystems": names, "count": len(names)})
	}
	// F-22: drain queued notifications last. A deploy during an incident used to
	// kill the fan-out goroutines mid-send; the pages simply never arrived.
	if srv.notifier != nil {
		if d := srv.notifier.QueueDepth(); d > 0 {
			logWarn("shutdown", "notifications still queued at shutdown", map[string]any{"queued": d})
		}
		srv.notifier.Close()
	}
	logInfo("shutdown", "goodbye", nil)
}

// runProber runs the active-measurement sidecar: only the probe collectors,
// nothing else. Targets come from env (STAMP_TARGETS / TRACEROUTE_TARGETS), so
// no device inventory / DB is needed.
func runProber() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := collectors.NewPool(nil)
	pool.Enable("stamp-sender", os.Getenv("FEATURE_ACTIVE_PROBE") == "true")
	pool.Enable("stamp-reflector", os.Getenv("FEATURE_STAMP_REFLECTOR") == "true")
	pool.Enable("traceroute", os.Getenv("FEATURE_TRACEROUTE") == "true")
	pool.Enable("synthetics", os.Getenv("FEATURE_SYNTHETICS") == "true")
	pool.Enable("wan-echo", os.Getenv("FEATURE_WAN_ECHO") == "true")
	pool.Start(ctx)
	log.Printf("netops-prober %s started (active measurement only)", version)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("prober shutdown requested")
	cancel()
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
	mux.HandleFunc("/api/auth/osd-gate", s.handleOSDGate)         // nginx auth_request target for /search + /netbox
	mux.HandleFunc("/api/auth/console-gate", s.handleConsoleGate) // SPA re-mints the embedded-console gate cookie
	// MFA (TOTP) for local accounts. /login completes the password→code challenge
	// (public); the rest are self-service (authed); mfa-reset is admin recovery.
	mux.HandleFunc("/api/auth/mfa/setup", s.handleMFASetup)
	mux.HandleFunc("/api/auth/mfa/activate", s.handleMFAActivate)
	mux.HandleFunc("/api/auth/mfa/disable", s.handleMFADisable)
	mux.HandleFunc("/api/auth/mfa/status", s.handleMFAStatus)
	mux.HandleFunc("/api/auth/mfa/login", s.handleMFALogin)
	mux.HandleFunc("/api/users/mfa-reset", s.handleMFAAdminReset)
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
	mux.HandleFunc("/api/sessions", s.handleSessions)     // admin: list live sessions
	mux.HandleFunc("/api/sessions/", s.handleSessionByID) // admin: revoke a session
	mux.HandleFunc("/api/roles", s.handleRoles)
	mux.HandleFunc("/api/roles/", s.handleRoleByID)
	mux.HandleFunc("/api/tenants", s.handleTenants)
	mux.HandleFunc("/api/tenants/", s.handleTenantByID)
	mux.HandleFunc("/api/orgs", s.handleOrgs)
	mux.HandleFunc("/api/orgs/", s.handleOrgByID)
	mux.HandleFunc("/api/onboard", s.handleOnboard)
	mux.HandleFunc("/api/onboard/snmp-config", s.handleGenerateSNMPConfig) // SNMP config generator // operator: org + first tenant (+SSO) in one audited step
	mux.HandleFunc("/api/regions", s.handleRegions)
	mux.HandleFunc("/api/regions/topology", s.handleRegionTopology)
	mux.HandleFunc("/api/bindings", s.handleBindings)
	mux.HandleFunc("/api/bindings/", s.handleBindingByID)
	mux.HandleFunc("/api/breakglass", s.handleBreakGlass)
	mux.HandleFunc("/api/breakglass/", s.handleBreakGlassByID)
	mux.HandleFunc("/api/scopes", s.handleMyScopes)
	mux.HandleFunc("/api/security-settings", s.handleSecuritySettings)
	mux.HandleFunc("/api/access/explain", s.handleAccessExplain)
	mux.HandleFunc("/api/apikeys", s.handleAPIKeys)
	mux.HandleFunc("/api/apikeys/", s.handleAPIKeyByID)
	// SNMP credential profiles (v1/v2c/v3) — infrastructure-gated.
	mux.HandleFunc("/api/snmp/options", s.handleSNMPOptions)
	mux.HandleFunc("/api/snmp/credentials", s.handleSNMPCreds)
	mux.HandleFunc("/api/snmp/credentials/", s.handleSNMPCredByID)
	mux.HandleFunc("/api/snmp/profiles", s.handleSNMPProfiles)
	mux.HandleFunc("/api/snmp/profiles/", s.handleSNMPProfileByID)
	mux.HandleFunc("/api/devices", s.handleDevices)
	// Port Intelligence (#94 P5) — enhances the Infrastructure surface (no new nav).
	mux.HandleFunc("/api/infrastructure/interfaces", s.handlePortInterfaces)
	mux.HandleFunc("/api/infrastructure/interfaces/", s.handlePortInterfaceDetail)
	mux.HandleFunc("/api/infrastructure/port-summary", s.handlePortSummary)
	mux.HandleFunc("/api/infrastructure/module-types", s.handleModuleTypes)
	mux.HandleFunc("/api/infrastructure/port-filter-options", s.handlePortFilterOptions)
	mux.HandleFunc("/api/infrastructure/port-signatures", s.handlePortSignatureCatalog)
	mux.HandleFunc("/api/devices/", s.handleDeviceByID)
	mux.HandleFunc("/api/collectors", s.handleCollectors)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/alerts/episodes", s.handleAlertEpisodes)       // tenant-scoped episode list
	mux.HandleFunc("/api/alerts/episodes/", s.handleAlertEpisodeAction) // POST {id}/(ack|assign|mute|snooze|notes)
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/credentials", s.handleCredentials)
	// Feature availability only (no credential/integration posture) — any
	// authenticated user, so gating /api/credentials to the platform owner does
	// not silently hide optional UI surfaces. See handleFeatures.
	mux.HandleFunc("/api/features", s.handleFeatures)
	mux.HandleFunc("/api/discovery/refresh", s.handleDiscoveryRefresh)
	mux.HandleFunc("/api/discovery/config", s.handleDiscoveryConfig)  // subnet-scan scope (platform-owner)
	mux.HandleFunc("/api/automation/netbox", s.handleNetboxConfig)    // Source-of-Truth config (platform-owner)
	mux.HandleFunc("/api/automation/netbox/sync", s.handleNetboxSync) // GET status / POST reconcile-now
	mux.HandleFunc("/api/logs/search", s.handleLogsSearch)
	mux.HandleFunc("/api/logs/indices", s.handleLogsIndices)
	mux.HandleFunc("/api/logs/retention", s.handleLogsRetention)    // retention floor: oldest visible log + exact total (tenant-scoped)
	mux.HandleFunc("/api/logs/export", s.handleLogsExport)          // Mode B: whole result set (sync/async)
	mux.HandleFunc("/api/logs/export/rows", s.handleLogsExportRows) // Mode A: selected/loaded rows
	mux.HandleFunc("/api/exports/view/", s.handleExportView)        // token-authenticated (public)
	mux.HandleFunc("/api/exports/policy", s.handleExportPolicy)     // runtime export limits (admin/platform-owner)
	mux.HandleFunc("/api/exports/", s.handleExportStatus)           // async export status poll
	mux.HandleFunc("/api/flows/top", s.handleFlowsTopTalkers)
	mux.HandleFunc("/api/flows/topn", s.handleFlowsTopN)
	mux.HandleFunc("/api/flows/fanout", s.handleFlowsFanout)
	mux.HandleFunc("/api/probe/paths", s.handleProbePaths)
	mux.HandleFunc("/api/geomap", s.handleGeomap)
	mux.HandleFunc("/api/sites", s.handleSites)          // internal SoT sites: GET list / POST upsert
	mux.HandleFunc("/api/sites/", s.handleSiteByID)      // /api/sites/{slug}: PUT / DELETE
	mux.HandleFunc("/api/sot/import", s.handleSoTImport) // external SoT one-way import (sites / device→site)
	// WAN circuits (#1): controller-style endpoint registry + topology policy.
	mux.HandleFunc("/api/wan/interfaces", s.handleWanInterfaces)          // per-WAN-interface table: util + circuit SLA + source
	mux.HandleFunc("/api/wan/endpoints", s.handleWanEndpoints)            // derived WAN endpoint registry (read)
	mux.HandleFunc("/api/wan/circuits", s.handleWanCircuits)              // derived circuit mesh (read)
	mux.HandleFunc("/api/wan/policy", s.handleWanPolicy)                  // topology policy: GET / PUT (intent)
	mux.HandleFunc("/api/system/network", s.handleSystemNetwork)          // platform DNS + NTP settings (GET/PUT, platform-admin)
	mux.HandleFunc("/api/system/network/test", s.handleSystemNetworkTest) // resolve + NTP-offset probe
	// RCA auto-ticketing (#78 P3): incident-policy CRUD + simulator, tenant-scoped
	// outbox/audit observability. Per-correlation ticket actions ride the
	// /api/correlations/{id}/{tickets,ticket,ticket/sync} router (correlations.go).
	mux.HandleFunc("/api/incident-policies", s.handleIncidentPolicies)
	mux.HandleFunc("/api/incident-policies/", s.handleIncidentPolicyByID)
	mux.HandleFunc("/api/tickets/outbox", s.handleTicketsOutbox)
	mux.HandleFunc("/api/tickets/audit", s.handleTicketsAudit)
	mux.HandleFunc("/api/tickets/links", s.handleTicketsLinks)
	mux.HandleFunc("/api/flows/flags", s.handleFlowsFlags)
	mux.HandleFunc("/api/flows/geo", s.handleFlowsGeo)
	mux.HandleFunc("/api/flows/by-proto", s.handleFlowsByProto)
	mux.HandleFunc("/api/flows/by-type", s.handleFlowsByType)
	mux.HandleFunc("/api/flows/timeseries", s.handleFlowsTimeseries)
	mux.HandleFunc("/api/flows/services", s.handleFlowsServices) // #69 P2: flow traffic per service
	mux.HandleFunc("/api/topology/links", s.handleTopologyLinks) // LLDP-discovered adjacencies
	mux.HandleFunc("/api/topology/view", s.handleTopologyView)   // resolved renderer-agnostic TopologyView
	mux.HandleFunc("/api/topology/graph", s.handleTopologyGraph) // persistent reconciled graph (stable ids + stale)
	mux.HandleFunc("/api/topology/cloud", s.handleCloudTopology) // in-cloud VPC/VNet→subnet→route-table→gateway network
	mux.HandleFunc("/api/tunnels", s.handleTunnels)
	mux.HandleFunc("/api/findings", s.handleFindings)
	mux.HandleFunc("/api/vulns", s.handleVulns)           // #13: device OS × advisory feed
	mux.HandleFunc("/api/compliance", s.handleCompliance) // #14: SoT drift + policy baselines

	mux.HandleFunc("/api/incidents", s.handleIncidents)     // GET list (tenant-scoped)
	mux.HandleFunc("/api/incidents/", s.handleIncidentByID) // GET {id}; POST {id}/ack|resolve|note|assign|…
	// seam.Seam inventory (#67 build ⑤): suggest→confirm→active lifecycle; the
	// correlation engine pulls ?state=active as its grounding targets.
	// Correlation Engine v2 objects — read-only inspector + replay proxy (#67).
	// Workload OIDC issuer trust material (Wave 4 #13) — anonymous BY DESIGN:
	// AWS/Azure/GCP fetch these to verify minted assertions; public keys +
	// static metadata only, never tenant data. 404 while the issuer is dormant.
	mux.HandleFunc("/.well-known/openid-configuration", s.handleWorkloadOIDCDiscovery)
	mux.HandleFunc("/.well-known/jwks.json", s.handleWorkloadJWKS)
	mux.HandleFunc("/api/correlations", s.handleCorrelations)
	mux.HandleFunc("/api/correlations/stats", s.handleCorrelationStats)                       // exact path wins over the prefix below
	mux.HandleFunc("/api/correlations/summary", s.handleCorrelationsSummary)                  // true window counts (total / tier / state) behind the page's stat chips
	mux.HandleFunc("/api/correlations/rca-reports", s.handleRcaReportsLibrary)                // #113 point 3: the management library — promoted real outages only (exact path wins over the /api/correlations/ prefix)
	mux.HandleFunc("/api/correlations/undetermined-frequency", s.handleUndeterminedFrequency) // #80 signature-governance: ranked recurring undetermined gap-shapes
	mux.HandleFunc("/api/correlations/", s.handleCorrelationByID)
	// Service Path Graph (frozen contract §7): GET /api/rca/{correlation_id}/path —
	// the ORDERED spine. The backend decides hop order; the UI never computes it.
	mux.HandleFunc("/api/rca/", s.handleRcaPath)
	mux.HandleFunc("/api/events/feed", s.handleEventsFeed)
	mux.HandleFunc("/api/paths/health", s.handlePathsHealth)
	mux.HandleFunc("/api/reliability/rollups", s.handleReliabilityRollups)                    // RCA Time Intelligence reliability rollups (#84)
	mux.HandleFunc("/api/reliability/trends", s.handleReliabilityTrends)                      // bucketed phase-metric trends (#84)
	mux.HandleFunc("/api/reliability/chronic-offenders", s.handleReliabilityChronicOffenders) // recurring-object ranking (#84)
	mux.HandleFunc("/api/reliability/time-metrics", s.handleReliabilityTimeMetrics)           // persisted phase-metric snapshots: GET (tenant) / POST backfill (platform admin) (#84)
	mux.HandleFunc("/api/health/score", s.handleHealthScore)
	mux.HandleFunc("/api/metrics/forecast", s.handleMetricsForecast)
	mux.HandleFunc("/api/services", s.handleServices)
	mux.HandleFunc("/api/services/", s.handleServiceByID)
	mux.HandleFunc("/api/applications", s.handleApplications)
	mux.HandleFunc("/api/applications/", s.handleApplicationByID)
	mux.HandleFunc("/api/appid/resolve", s.handleAppIDResolve)
	mux.HandleFunc("/api/appid/resolve/batch", s.handleAppIDResolveBatch) // #81 P3G client-side enrichment primitive
	mux.HandleFunc("/api/appid/status", s.handleAppIDStatus)
	mux.HandleFunc("/api/appid/fusion/status", s.handleFusionStatus)
	mux.HandleFunc("/api/appid/catalog", s.handleAppIDCatalog)
	mux.HandleFunc("/api/appid/catalog/", s.handleAppIDCatalogByID)
	mux.HandleFunc("/api/flows/apps", s.handleFlowsApps)
	mux.HandleFunc("/api/cloud/resources", s.handleCloudResources)
	// Wave 6 #20: single-resource read behind the permanent #/resource/cloud/{id}
	// detail page (cross-tenant / unknown id → the same 404).
	mux.HandleFunc("/api/cloud/resources/", s.handleCloudResourceByID)
	mux.HandleFunc("/api/cloud/identity-map", s.handleCloudIdentityMap)
	mux.HandleFunc("/api/cloud/apps", s.handleCloudApps)
	mux.HandleFunc("/api/cloud/attribution/coverage", s.handleCloudCoverage)
	// Cloud Network Overview roll-up (cloud-network-overview P1): provider →
	// region → VPC hierarchy + lateral seams, tenant-scoped.
	mux.HandleFunc("/api/cloud/network/overview", s.handleCloudNetworkOverview)
	// Business Service mapping + manual overrides (Azure optional-tags epic, 0024).
	mux.HandleFunc("/api/cloud/business-services", s.handleBusinessServices)
	mux.HandleFunc("/api/cloud/business-services/", s.handleBusinessServiceByID)
	mux.HandleFunc("/api/cloud/resource-mappings", s.handleResourceMappings)
	mux.HandleFunc("/api/cloud/resource-mappings/", s.handleResourceMappingByID)
	mux.HandleFunc("/api/cloud/ingestion", s.handleCloudIngestion)
	mux.HandleFunc("/api/cloud/app-rca", s.handleCloudAppRca)
	mux.HandleFunc("/api/cloud/health", s.handleCloudHealth)
	mux.HandleFunc("/api/cloud/changes", s.handleCloudChanges)
	mux.HandleFunc("/api/cloud/evidence", s.handleCloudEvidence)
	// Wave 5 #16: security-findings over the fidelity rollups, provider
	// incident/maintenance events, and the hybrid-seam telemetry read.
	mux.HandleFunc("/api/cloud/security", s.handleCloudSecurity)
	mux.HandleFunc("/api/cloud/provider-events", s.handleCloudProviderEvents)
	mux.HandleFunc("/api/cloud/seam-telemetry", s.handleCloudSeamTelemetry)
	mux.HandleFunc("/api/cloud/costs", s.handleCloudCosts)                          // daily provider-billed cost records (Wave 5 #18)
	mux.HandleFunc("/api/cloud/investigations/", s.handleCloudInvestigationChanges) // {id}/changes — change→incident correlation (Wave 4 #12)
	mux.HandleFunc("/api/cloud/service-map", s.handleCloudServiceMap)
	// Cloud metric charts (Wave 5 #14 slice 1): bounded VM query_range over the
	// caller's OWN inventory ids only (cross-tenant id → 404).
	mux.HandleFunc("/api/cloud/metrics/series", s.handleCloudMetricSeries)
	// Per-tenant SLOs / error budgets (Wave 5 #14 slice 2): defs in a tenant-
	// keyed file store, actuals measured from the status-check lane.
	mux.HandleFunc("/api/cloud/slos", s.handleCloudSLOs)
	// Per-tenant cloud monitor authoring (Wave 5 #14 slice 3).
	mux.HandleFunc("/api/cloud/monitors", s.handleCloudMonitors)
	mux.HandleFunc("/api/cloud/monitors/", s.handleCloudMonitorByID)
	// Cloud Connector framework (provider-neutral onboarding + lifecycle).
	mux.HandleFunc("/api/cloud/providers", s.handleCloudProviderCatalog)
	mux.HandleFunc("/api/cloud/connectors", s.handleCloudConnectors)
	mux.HandleFunc("/api/cloud/connectors/", s.handleCloudConnectorByID)
	// Per-tenant ingestion service surface (Wave 1 #2): the cloud-ingest poller
	// authenticates with a platform-realm ingest:cloud API key, discovers WHICH
	// connectors to poll, and obtains short-lived per-connector credentials.
	mux.HandleFunc("/api/cloud/ingest/connectors", s.handleCloudIngestConnectors)
	mux.HandleFunc("/api/cloud/ingest/connectors/", s.handleCloudIngestConnectorByID)
	mux.HandleFunc("/api/cloud/ingest/source-status", s.handleCloudIngestSourceStatus)
	mux.HandleFunc("/api/seams", s.handleSeams)
	mux.HandleFunc("/api/seams/", s.handleSeamByID)
	mux.HandleFunc("/api/seams/groups", s.handleSeamGroups)
	mux.HandleFunc("/api/seams/groups/", s.handleSeamGroupByID)
	mux.HandleFunc("/api/saved", s.handleSaved)
	mux.HandleFunc("/api/saved/", s.handleSavedByID)
	mux.HandleFunc("/api/search/global", s.handleGlobalSearch)
	// Wave 6 #20: the typed, tenant-scoped unified search (devices · cloud
	// resources · apps · accounts · correlation cases) behind the topbar/⌘K.
	mux.HandleFunc("/api/search", s.handleUnifiedSearch)
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
	// Iris AI — application-aware NOC assistant (orchestrator + governed tools).
	mux.HandleFunc("/api/ai/ask", s.handleAIAsk)
	mux.HandleFunc("/api/settings/display", s.handleDisplaySettings)
	mux.HandleFunc("/api/settings/verification", s.handleVerificationSettings) // spec #8: active-verification opt-in + read-only SSH credential
	mux.HandleFunc("/api/settings/required-tags", s.handleRequiredTagsSettings)
	mux.HandleFunc("/api/settings/rca-window", s.handleRcaWindowSettings)
	mux.HandleFunc("/api/system/backup", s.handleSystemBackup) // platform data-protection config + DR status
	mux.HandleFunc("/api/settings/attribution-precedence", s.handleAttributionPrecedenceSettings)
	mux.HandleFunc("/api/settings/seam-owners", s.handleSeamOwnersSettings) // #113: owner class → tenant's actual responsible party
	mux.HandleFunc("/api/settings/governance-audit", s.handleGovernanceAudit)
	mux.HandleFunc("/api/ai/tenant-config", s.handleAITenantConfig)
	mux.HandleFunc("/api/ai/tenants", s.handleAITenants)
	mux.HandleFunc("/api/ai/tenants/", s.handleAITenants)
	mux.HandleFunc("/api/ai/modules", s.handleAIModules)
	mux.HandleFunc("/api/ai/commands", s.handleAICommands)             // slash-command registry for the "/" menu
	mux.HandleFunc("/api/ai/commands/suggestions", s.handleAICommands) // typed-fragment suggestions
	mux.HandleFunc("/api/ai/feedback", s.handleAIFeedback)             // thumbs up/down (audited)
	mux.HandleFunc("/api/graphql", s.handleGraphQL)
	// Self-describing API + ITSM connector status.
	mux.HandleFunc("/api/openapi.json", s.handleOpenAPI)
	mux.HandleFunc("/api/itsm/servicenow", s.handleITSMServiceNow)
	mux.HandleFunc("/api/itsm/pagerduty-rca", s.handleITSMPagerDutyRCA) // #103 tenant PD paging destination
	mux.HandleFunc("/api/itsm/slack-rca", s.handleITSMSlackRCA)         // #103-E tenant Slack RCA destination
	mux.HandleFunc("/api/itsm/jira", s.handleITSMJira)
	// Integration platform (#43): admin config + UNAUTHENTICATED inbound webhook
	// (the more specific /webhook/ prefix wins over /api/integrations/ in the mux).
	mux.HandleFunc("/api/integrations", s.handleIntegrations)
	mux.HandleFunc("/api/integrations/reconcile", s.handleIntegrationReconcile) // exact path wins over the prefix below
	mux.HandleFunc("/api/integrations/", s.handleIntegrations)
	mux.HandleFunc("/api/integrations/webhook/", s.handleIntegrationWebhook)
	// NMS vendor-controller framework (#95): handlers 404 when the feature is
	// dormant (s.nms == nil), so registration is unconditional (tests included).
	mux.HandleFunc("/api/nms/connectors", s.handleNMSConnectors)
	mux.HandleFunc("/api/nms/integrations", s.handleNMSIntegrations)
	mux.HandleFunc("/api/nms/integrations/", s.handleNMSIntegrationItem)
	mux.HandleFunc("/api/nms/webhook/", s.handleNMSWebhook)
	// Wireless canonical inventory (#128 Phase 1): read-only surface, always
	// registered (empty inventory until a connector runs).
	mux.HandleFunc("/api/wireless/controllers", s.handleWirelessControllers)
	mux.HandleFunc("/api/wireless/controllers/", s.handleWirelessControllers)
	mux.HandleFunc("/api/wireless/aps", s.handleWirelessAPs)
	mux.HandleFunc("/api/wireless/aps/", s.handleWirelessAPs)
	mux.HandleFunc("/api/wireless/wlans", s.handleWirelessWLANs)
	mux.HandleFunc("/api/wireless/bssids", s.handleWirelessBSSIDs)
	// #128 Phase 8 guarded remediation: 404 unless FEATURE_WIRELESS_ACTIONS.
	mux.HandleFunc("/api/wireless/actions", s.handleWirelessActions)
	mux.HandleFunc("/api/wireless/actions/", s.handleWirelessActionItem)
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

// handleVersion reports the deployed build, including the git SHA baked in at
// image build time. See build_provenance.go for why that matters.
func (s *server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.currentBuildInfo())
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
		// F-61: this endpoint used to parse NOTHING and return the whole table —
		// `?limit=1`, `?limit=1&offset=0` and `?page_size=1` all produced the
		// byte-identical 218 KB / 512-row body. Parameters are now applied or
		// rejected by name, the page is bounded, and the TRUE fleet total rides
		// on every response (headers; ?envelope=1 for the JSON form) so a client
		// can tell a page from the whole fleet. See pagination.go.
		if err := rejectUnknownQuery(r); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		page, err := parsePage(r, deviceDefaultPage, deviceMaxPage)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		all := s.withCredActive(withDeviceType(visibleDevices(s.discovery.Devices(), claims)))
		// Wireless WLCs + APs are fleet citizens too (one LAN domain) —
		// projected read-time from the wireless store, deduped by address.
		all = append(all, s.wirelessDeviceRows(r.Context(), claims, all)...)
		// Stable order: without one, paging over a map-backed aggregator can
		// show the same device twice and never show another at all.
		sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
		rows := pageSliceOf(all, page)
		logTruncatedPage("/api/devices", page, len(rows), len(all))
		writePage(w, "devices", rows, page, len(rows), len(all))
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
		// 201 must mean the device survives a restart. Before this store existed
		// the device lived only in RAM and vanished on the next deploy.
		if err := s.discovery.Upsert(d); err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("device was not saved"))
			return
		}
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
	// Location annotation layer: /api/devices/locations (editor list) and
	// /api/devices/{id}/location (per-device get/set/clear).
	if r.URL.Path == "/api/devices/locations" {
		s.handleDeviceLocations(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/location") {
		s.handleDeviceLocation(w, r)
		return
	}
	// Operator device→site binding: /api/devices/{id}/site (get/set/clear).
	if strings.HasSuffix(r.URL.Path, "/site") {
		s.handleDeviceSite(w, r)
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
		if d.Type == "" {
			d.Type = inferDeviceType(d)
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
		// 204 must mean the device stays deleted — see F-69: this used to return
		// 204 while the owning source re-added the device within 60s.
		if err := s.discovery.Delete(id); err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("device was not deleted"))
			return
		}
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

// handleFeatures reports which OPTIONAL UI SURFACES are switched on. It carries
// no credential presence, no integration inventory and no tenant data — only
// "is this feature compiled in and enabled", which every authenticated user
// needs in order to know whether to render a button.
//
// It exists because /api/credentials used to answer this question while ALSO
// reporting the platform's integration posture; gating that endpoint to the
// platform owner (correctly, §3a rule 3) silently removed the SSH console and
// the assistant panel for everyone else. A 403 rendering as "this feature does
// not exist" is the same silent-failure class this release is fixing, so the
// answer is to split the surfaces rather than to widen the gate back.
func (s *server) handleFeatures(w http.ResponseWriter, r *http.Request) {
	if _, ok := userFrom(r.Context()); !ok {
		writeError(w, http.StatusUnauthorized, errors.New("authentication required"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"copilot":             os.Getenv("FEATURE_COPILOT") == "true",
		"device_ssh":          os.Getenv("FEATURE_DEVICE_SSH") == "true",
		"active_verification": os.Getenv("FEATURE_ACTIVE_VERIFICATION") == "true",
	})
}

func (s *server) handleCredentials(w http.ResponseWriter, r *http.Request) {
	// This reports the PLATFORM-GLOBAL integration/plumbing posture (which
	// provider credentials and feature flags the stack was started with) — not
	// per-tenant data. Per CLAUDE.md §3a rule 3 that is platform-owner surface:
	// a tenant/org admin holds administration:admin, so a scope-blind requireAdmin
	// would leak the platform's integration inventory to every tenant admin. The
	// same notify config is already requirePlatformAdmin-gated in notify_config.go.
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
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
		// Global gate only — the per-tenant opt-in rides GET /api/settings/verification.
		"active_verification": os.Getenv("FEATURE_ACTIVE_VERIFICATION") == "true",
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

	// ClickHouse write outcomes (Phase 8): the per-outcome visibility F-38/F-56
	// lacked. committed/rejected/unknown is the COMMIT-STATE axis a dashboard
	// alerts on; the by-class series names WHY (too_many_parts, schema, auth, …).
	chm := chhttp.Snapshot()
	fmt.Fprintf(w, "# HELP netops_clickhouse_write_outcomes_total ClickHouse writes by commit outcome.\n")
	fmt.Fprintf(w, "# TYPE netops_clickhouse_write_outcomes_total counter\n")
	fmt.Fprintf(w, "netops_clickhouse_write_outcomes_total{outcome=\"committed\"} %d\n", chm.Committed)
	fmt.Fprintf(w, "netops_clickhouse_write_outcomes_total{outcome=\"rejected\"} %d\n", chm.Rejected)
	fmt.Fprintf(w, "netops_clickhouse_write_outcomes_total{outcome=\"unknown\"} %d\n", chm.Unknown)
	if len(chm.ByClass) > 0 {
		fmt.Fprintf(w, "# HELP netops_clickhouse_failures_total ClickHouse failures by classification.\n")
		fmt.Fprintf(w, "# TYPE netops_clickhouse_failures_total counter\n")
		for class, n := range chm.ByClass {
			fmt.Fprintf(w, "netops_clickhouse_failures_total{class=%q} %d\n", class, n)
		}
	}
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
	if s.cloudBroker != nil {
		s.cloudBroker.metrics.write(w)
	}
	if s.hub != nil {
		fmt.Fprintf(w, "# HELP netops_ws_clients Currently connected WebSocket event clients.\n")
		fmt.Fprintf(w, "# TYPE netops_ws_clients gauge\n")
		fmt.Fprintf(w, "netops_ws_clients %d\n", s.hub.Count())
		fmt.Fprintf(w, "# HELP netops_ws_frames_dropped_total Event frames discarded because a client's send buffer was full.\n")
		fmt.Fprintf(w, "# TYPE netops_ws_frames_dropped_total counter\n")
		fmt.Fprintf(w, "netops_ws_frames_dropped_total %d\n", s.hub.Dropped())
	}
	fmt.Fprintf(w, "# HELP netops_ticketing_policy_conflicts_total Policy enables rejected because another policy is enabled for the tenant+system.\n")
	fmt.Fprintf(w, "# TYPE netops_ticketing_policy_conflicts_total counter\n")
	fmt.Fprintf(w, "netops_ticketing_policy_conflicts_total %d\n", s.tktPolicyConflicts.Load())
	fmt.Fprintf(w, "# HELP netops_ticketing_policy_multi_enabled_total Fail-closed holds because multiple enabled policies were found for one tenant+system (invariant violation).\n")
	fmt.Fprintf(w, "# TYPE netops_ticketing_policy_multi_enabled_total counter\n")
	fmt.Fprintf(w, "netops_ticketing_policy_multi_enabled_total %d\n", s.tktPolicyMultiEnabled.Load())
	fmt.Fprintf(w, "# HELP netops_ticketing_merged_redirects_total Manual ticket actions refused with the canonical id because the object was merged.\n")
	fmt.Fprintf(w, "# TYPE netops_ticketing_merged_redirects_total counter\n")
	fmt.Fprintf(w, "netops_ticketing_merged_redirects_total %d\n", s.tktMergedRedirects.Load())
	// F-25: the brute-force throttle's pressure was entirely invisible — it went
	// fail-open at its cap with no log and no metric, so "lockout: enabled" in
	// Security Settings could be a lie for months. Saturation > 0 means sign-ins
	// are being refused; evictions climbing means a spray is in progress.
	if s.loginThrottle != nil {
		fmt.Fprintf(w, "# HELP netops_login_throttle_accounts Accounts currently tracked by the failed-login throttle.\n")
		fmt.Fprintf(w, "# TYPE netops_login_throttle_accounts gauge\n")
		fmt.Fprintf(w, "netops_login_throttle_accounts %d\n", s.loginThrottle.size())
		fmt.Fprintf(w, "# HELP netops_login_throttle_evictions_total Unlocked failure records evicted (LRU) to make room at the cap — a username spray in progress.\n")
		fmt.Fprintf(w, "# TYPE netops_login_throttle_evictions_total counter\n")
		fmt.Fprintf(w, "netops_login_throttle_evictions_total %d\n", s.loginThrottle.evictions.Load())
		fmt.Fprintf(w, "# HELP netops_login_throttle_swept_total Stale failed-login records reclaimed by the janitor.\n")
		fmt.Fprintf(w, "# TYPE netops_login_throttle_swept_total counter\n")
		fmt.Fprintf(w, "netops_login_throttle_swept_total %d\n", s.loginThrottle.sweeps.Load())
		fmt.Fprintf(w, "# HELP netops_login_throttle_saturated_total Sign-ins refused because every throttle slot held a live lock (fail-closed).\n")
		fmt.Fprintf(w, "# TYPE netops_login_throttle_saturated_total counter\n")
		fmt.Fprintf(w, "netops_login_throttle_saturated_total %d\n", s.loginThrottle.saturation.Load())
	}
	// F-21: a response body that failed to encode used to be a 200 with zero
	// bytes and no trace anywhere. This counter is that trace.
	fmt.Fprintf(w, "# HELP netops_json_encode_failures_total Responses that failed to JSON-encode and were answered 500 instead of an empty 200.\n")
	fmt.Fprintf(w, "# TYPE netops_json_encode_failures_total counter\n")
	fmt.Fprintf(w, "netops_json_encode_failures_total %d\n", jsonEncodeFailures.Load())
	fmt.Fprintf(w, "# HELP netops_json_write_failures_total Response bodies that encoded but could not be written (client disconnected mid-response).\n")
	fmt.Fprintf(w, "# TYPE netops_json_write_failures_total counter\n")
	fmt.Fprintf(w, "netops_json_write_failures_total %d\n", jsonWriteFailures.Load())
	fmt.Fprintf(w, "# HELP netops_metric_nonfinite_total Metric samples dropped because the store returned NaN/±Inf.\n")
	fmt.Fprintf(w, "# TYPE netops_metric_nonfinite_total counter\n")
	fmt.Fprintf(w, "netops_metric_nonfinite_total %d\n", metricval.NonFinite())
	// F-22: alert delivery had no counter at all — a page lost to a transient
	// 502 during an incident was invisible.
	if s.notifier != nil {
		s.notifier.WriteMetrics(w)
	}
}

// ---- helpers ----------------------------------------------------------------

// jsonEncodeFailures / jsonWriteFailures make the two ways a response can fail
// to reach the client countable (§10). Package-level because writeJSON is a free
// function called from ~400 sites and threading a server through all of them
// would be a far larger change than the defect warrants; they are write-only
// atomics with no configuration, so there is no mutable global state to race on.
var (
	jsonEncodeFailures atomic.Uint64
	jsonWriteFailures  atomic.Uint64
)

// writeJSON encodes body as the response.
//
// F-21: this used to be `w.WriteHeader(status)` followed by
// `_ = json.NewEncoder(w).Encode(body)`. Encode marshals into an internal
// buffer BEFORE writing anything, so a body containing a NaN or ±Inf float
// (json: unsupported value: NaN) produced a 200 OK with
// Content-Type: application/json and ZERO BYTES — no log, no metric, at any of
// ~400 call sites. NaN reaches response structs from unguarded ParseFloat on
// VictoriaMetrics/ClickHouse values ("NaN" parses successfully), so a metric
// that goes NaN turns an endpoint into a silent empty-200 generator and the UI
// renders "no data" for a live fault.
//
// Marshalling FIRST is the whole fix: the status line is committed only once
// there is a body to send, so an encode failure can still be answered honestly
// with a 500 the caller can see.
func writeJSON(w http.ResponseWriter, status int, body any) {
	buf, err := json.Marshal(body)
	if err != nil {
		jsonEncodeFailures.Add(1)
		logError("http", "response body failed to encode — answering 500 instead of an empty 200", map[string]any{
			"err":             err.Error(),
			"body_type":       fmt.Sprintf("%T", body),
			"intended_status": status,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("{\"error\":\"response encoding failed\",\"code\":\"RESPONSE_ENCODE_FAILED\"}\n"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Trailing newline keeps the bytes identical to the previous Encoder path.
	if _, err := w.Write(append(buf, '\n')); err != nil {
		// The status line is already committed and the connection is gone, so
		// there is nothing to report to the client — but a rising counter still
		// distinguishes "clients disconnect mid-response" from "all is well".
		jsonWriteFailures.Add(1)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// writeJSONError is writeError plus a stable, machine-readable code the SPA can
// branch on (e.g. SESSION_IDLE_TIMEOUT → clear tokens + redirect to login).
func writeJSONError(w http.ResponseWriter, status int, msg, code string) {
	writeJSON(w, status, map[string]string{"error": msg, "code": code})
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

// preAuthMaxBodyBytes caps the request body on every UNAUTHENTICATED route
// (F-32).
//
// The global 50 MiB backstop is correctly placed and nothing is truly
// unbounded — but 50 MiB decoded into Go structs amplifies 3-5×, and the routes
// that can be hit with no credentials at all are the ones where that matters:
// /api/auth/refresh, /logout, /change-password, /api/auth/ldap/login and
// /api/auth/tacacs/login all decoded a body with no cap of their own, while
// /api/auth/login right next to them was correctly capped at 64 KiB. That is a
// sibling inconsistency, and closing it per-handler would only close today's
// five: capping by ROUTE CLASS means the next public route inherits the bound
// whether or not its author remembers.
//
// 256 KiB rather than 64 KiB because /api/auth/sso/callback carries a signed
// SAML/OIDC assertion, which is legitimately tens of kilobytes. Still ~200×
// tighter than the global cap.
const preAuthMaxBodyBytes int64 = 256 << 10

// isPublicPath reports whether a path is reachable without a Bearer token.
// Shares the single publicPaths list with withAuth, so the two can never drift.
func isPublicPath(p string) bool {
	for _, pub := range publicPaths {
		if p == pub {
			return true
		}
	}
	return false
}

// requestBodyLimit picks the byte cap for a request: the tight pre-auth cap for
// unauthenticated routes, the global backstop for everything else.
func requestBodyLimit(path string, global int64) int64 {
	if isPublicPath(path) && preAuthMaxBodyBytes < global {
		return preAuthMaxBodyBytes
	}
	return global
}

func withBodyLimit(limit int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, requestBodyLimit(r.URL.Path, limit))
		}
		next.ServeHTTP(w, r)
	})
}

// decodeJSONBody decodes the request body into dst under a PER-HANDLER byte cap
// (F-32). Defence in depth behind the route-class cap above: a handler that
// knows its payload is small (a token, a credential pair) should say so, so the
// bound survives the handler being reused on a non-public route.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, max int64, dst any) error {
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, max)).Decode(dst)
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		logInfo("http", "request", map[string]any{
			"method": r.Method,
			// PIPE-HIGH-2: every line this writes is shipped to OpenSearch and
			// kept for the retention window, so a capability token in the path
			// would become a searchable, replayable bearer credential. Mask it
			// here — the route survives, the credential does not.
			"path":        maskCapabilityTokenPath(r.URL.Path),
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
