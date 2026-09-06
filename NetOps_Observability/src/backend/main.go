// Package main is the entry point for the NetOps Observability backend API.
//
// The binary serves a RESTful JSON API over HTTP plus a WebSocket endpoint
// for real-time event streaming. It is intentionally kept dependency-free
// (stdlib only) so the scaffold compiles in a clean Go environment without
// pulling modules from the network.
package backend

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"path/filepath"

	"netops/backend/ai"
	"netops/backend/appid"
	"netops/backend/cloud"
	"netops/backend/cloudconn"
	// SECURITY-LANE-BEGIN
	// ENTERPRISE-ASSEMBLY-BEGIN (security_dialects)
	// The commercial hardening dialects. package main is the assembly layer and
	// the ONLY layer permitted to name both licences (licensing-gate.py check E).
	"netops/backend/enterprise/dialects"
	// ENTERPRISE-ASSEMBLY-END
	// SECURITY-LANE-END
	// ENTERPRISE-ASSEMBLY-BEGIN (security_dialects)
	// The commercial compliance-framework crosswalks. Deliberately OUTSIDE the
	// SECURITY-LANE markers: the compliance READ surface survives the producer's
	// removal, so this line goes with enterprise/, not with the lane.
	"netops/backend/enterprise/frameworks"
	// ENTERPRISE-ASSEMBLY-END
	"netops/backend/internal/apikey"
	// VMALERT-WEBHOOK-BEGIN
	"netops/backend/internal/alertwebhook"
	// VMALERT-WEBHOOK-END
	"netops/backend/internal/applog"
	"netops/backend/internal/audit"
	// BMP-BEGIN
	"netops/backend/internal/bmp"
	// BMP-END
	// CONFIG-BACKUP-BEGIN
	"netops/backend/internal/bgpdepth"
	// CONFIG-BACKUP-END
	// BGP-WATCH-BEGIN
	"netops/backend/internal/bgpwatch"
	// BGP-WATCH-END
	// SECURITY-LANE-BEGIN — used only by securityComplianceInputs, which goes
	// with internal/hardening.
	"netops/backend/internal/compliancemodel"
	// SECURITY-LANE-END
	// CONFIG-BACKUP-BEGIN
	"netops/backend/internal/configdrift"
	"netops/backend/internal/configstore"
	// CONFIG-BACKUP-END
	// DATA-PROTECTION-BEGIN
	"netops/backend/internal/dataprotect"
	"netops/backend/internal/dem"
	"netops/backend/internal/dem/experience"
	// DATA-PROTECTION-END
	"netops/backend/internal/devmon"
	"netops/backend/internal/discovery"
	// CONFIG-BACKUP-BEGIN
	"netops/backend/internal/hardening"
	// CONFIG-BACKUP-END
	"netops/backend/internal/igpmon"
	"netops/backend/internal/keycloak"
	// LICENCE-BEGIN — the central entitlement service (internal/entitlement,
	// the semantic vocabulary business code gates on) and its licence-file
	// implementation (internal/licence). Deleting this marker block, the
	// others in this file and the two packages removes the licence mechanism
	// and leaves every gate answering Community — which is the fail-closed
	// direction, not an outage.
	"netops/backend/internal/entitlement"
	"netops/backend/internal/licence"
	// LICENCE-END
	"netops/backend/internal/chschema"
	"netops/backend/internal/loginguard"
	// METERING-BEGIN — usage metering (tracker 258). A SEPARATE data contract
	// from the licence: entitlement answers "what may this customer do", this
	// answers "what did they use". Deleting this import, the METERING marker
	// blocks in this file and the package removes metering entirely — a
	// supported state in which the two Usage routes 404 and nothing else
	// changes, because nothing gates on a meter.
	"netops/backend/internal/metering"
	// METERING-END
	"netops/backend/internal/metricval"
	// PACKET-CAPTURE-BEGIN
	"netops/backend/internal/pcap"
	// PACKET-CAPTURE-END
	// DEBUG-ROUTES-BEGIN
	"netops/backend/internal/oslog"
	"netops/backend/internal/parsetrace"
	"netops/backend/internal/pipedebug"
	// DEBUG-ROUTES-END
	"netops/backend/internal/platformdb"
	"netops/backend/internal/protocoldiag"
	"netops/backend/internal/quarantine"
	"netops/backend/internal/ratelimit"
	"netops/backend/internal/registrystatus"
	"netops/backend/internal/saved"
	"netops/backend/internal/sealedfields"
	"netops/backend/internal/seam"
	"netops/backend/internal/tac"
	// SECURITY-LANE-BEGIN
	"netops/backend/internal/seclane"
	// SECURITY-LANE-END
	"math"
	"netops/backend/internal/secobs"
	"netops/backend/internal/secprofile"
	"netops/backend/internal/selfheal"
	"netops/backend/internal/session"
	"netops/backend/internal/snmpcred"
	"netops/backend/internal/ssoidp"
	"netops/backend/internal/storagemeter"
	"netops/backend/internal/tenant"
	"netops/backend/internal/ticketing"
	"netops/backend/internal/tlsprobe"
	"netops/backend/internal/vault"
	"netops/backend/internal/verify"
	"netops/backend/internal/vuln"
	"netops/backend/internal/workloadid"
	"netops/backend/internal/wsticket"
	"netops/backend/pathgraph"
	"netops/backend/policy"
	"netops/backend/portintel"
	"netops/backend/timeintel"
	"netops/backend/topology"
	"netops/backend/wireless"
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
	"netops/backend/maintenance"
	"netops/backend/models"
	"netops/backend/nms"
	"netops/backend/notify"
	"netops/backend/parsercov"
	"netops/backend/processors"
	"netops/backend/rcafeedback"
	"netops/backend/reports"
	"netops/backend/safego"
	"netops/backend/sealing"
	"netops/backend/secapi"

	"netops/backend/internal/httppage"

	"netops/backend/internal/oidc"
)

const version = "0.1.0-scaffold"

// server bundles the HTTP server with the long-running subsystems
// (discovery aggregator, collector pool, alert engine, notifier, user
// store for auth, and the live-events WebSocket hub).
type server struct {
	startedAt     time.Time
	discovery     *discovery.DiscoveryAggregator
	devStore      *discovery.DevStore // manual-device + tombstone store; Close() flushes hit recency at shutdown (ultra 9)
	collectors    *collectors.Pool
	alerts        *alerts.Engine
	alertEpisodes *alertEpisodeStore
	maintWindows  maintenance.Store // declared planned-work windows (item 121): pause notifications + stamp timeintel
	processors    processors.Store  // per-tenant pipeline processor rules (item 121): compiled into the router config
	userRules     *userRulesStore
	notifier      *notify.Dispatcher
	// pushBudgets is the process-wide, per-PUSH-SERVER outbound token-bucket
	// registry (notify/pushbudget.go). Both ntfy senders — the product
	// notification channel and the platform host-monitoring route — draw from
	// it, because ntfy.sh rate-limits per source IP and they share one.
	pushBudgets *notify.PushBudgets
	selfHeal    *selfheal.Healer
	users       usersRepo
	roles       *roleStore
	// bgpWatch is the BGP ops watchlist (item 10). It is an INTERFACE with two
	// durable backends — Postgres FORCE-RLS (migration 0035) and the tenant-keyed
	// bgpwatch.WatchFileStore — and is never nil: the watchlist, the
	// RPKI-over-watchlist view, the live-feed view and the whole alerting
	// evaluator all read a tenant's watched prefixes through it.
	bgpWatch bgpWatchStore
	bgpFetch *bgpFetcher // outbound RIPEstat/RDAP fetcher with TTL cache
	// BGP-DEPTH-BEGIN — item 10 depth (internal/bgpdepth). bgpFeed holds the
	// per-tenant bounded ring buffers + pollers and is nil unless
	// FEATURE_BGP_LIVE_FEED=true, so a flag-off deployment allocates nothing and
	// /api/bgp/feed answers an honest "not enabled". bgpASPA is the pluggable
	// ASPA source: NoASPAProvider unless BGP_ASPA_PROVIDER_URL names one, because
	// no public per-ASN ASPA API exists (see internal/bgpdepth/aspa.go).
	bgpFeed *bgpdepth.Runtime
	bgpASPA bgpdepth.ASPAProvider
	// BGP-DEPTH-END
	// BGP-WATCH-BEGIN — the watchlist EVALUATOR (internal/bgpwatch): incident
	// classes per watched prefix (#5), alerting through the notify channels and
	// the evidence bus (#10), and the bogon set (#1). bgpWatchAPI is ALWAYS
	// built — the embedded RFC/IANA bogon set is a real answer with or without
	// the evaluator — while bgpWatchEval is nil unless FEATURE_BGP_ALERTS=true,
	// so a flag-off deployment starts no worker and makes no outbound call.
	bgpWatchAPI    *bgpwatch.API
	bgpWatchEval   *bgpwatch.Evaluator
	bgpWatchPolicy bgpwatch.PolicyStore
	// BGP-WATCH-END
	// DEM-BEGIN — Digital Experience Monitoring (S17). The catalogue and the
	// HTTP surface are ALWAYS built: an operator must be able to declare targets
	// before enabling collection, and with the feature off every score says so
	// rather than rendering an empty table that reads as "all well". The
	// projector — which hands the prober its work queue — runs only under
	// FEATURE_DEM, so a flag-off deployment publishes nothing and measures
	// nothing. See docs/design/DEM_PLUMBING_2026-09-05.md.
	demTargets   dem.Catalogue
	demAPI       *dem.API
	demMetrics   *dem.Metrics
	demProjector *dem.Projector
	// demRuns holds the prober's immutable per-RUN records (tracker 253) and
	// demRunIntake drains them. Bounded, in-memory, tenant-keyed: reliability
	// is graded over a short recent window, and a restarted api grades
	// `unknown` until the rings refill rather than grading from stale history.
	demRuns      *dem.RunStore
	demRunIntake *dem.RunIntake
	// The causality layer above the catalogue (internal/dem/experience):
	// journeys, changes, evidence, hypotheses, derived experience incidents and
	// the published score. Built unconditionally for the same reason the
	// catalogue is — with collection off, every view must SAY so.
	experienceStore      experience.Store
	experienceAPI        *experience.API
	demExperienceMetrics *experience.Counters
	// DEM-END
	// Routing-protocol diagnostics (Troubleshooting item 7). Catalog + analyzer
	// are pure/immutable and always built; the collector is wired to the live
	// read-only SSH command source ONLY when FEATURE_PROTOCOL_DIAG_COLLECT=true
	// (protocol_diag_gateway.go) and stays nil otherwise — the collect endpoint
	// 503s while it is nil, and never fabricates a capture.
	protocolCatalog   *protocoldiag.Catalog
	protocolAnalyzer  *protocoldiag.Analyzer
	protocolCollector *protocoldiag.Collector
	// TAC-ROUTES-BEGIN — the TAC escalation pack (internal/tac). The service is
	// always built (its taxonomy and plans are embedded data); its live
	// COLLECTOR is wired only under the same FEATURE_PROTOCOL_DIAG_COLLECT flag
	// and the same read-only SSH custody the diagnostics collector uses, so the
	// collect route 503s honestly while it is nil.
	tacService *tac.Service
	// tacBundles is the on-disk bundle store; tacConnectors holds each tenant's
	// BYO case-connector credentials (write-only, sealed by the store).
	tacBundles    *tac.Store
	tacConnectors *ticketing.TACConnectorStore
	// tacTemplates is the per-tenant COMMAND TEMPLATE surface (tracker 250) and
	// tacTemplateStore its backing store. Both are built unconditionally: an
	// operator must be able to review and edit the command list on any
	// deployment, including one with no live SSH runner where the collection
	// itself falls back to paste.
	tacTemplates     *tac.TemplateAPI
	tacTemplateStore tac.TemplateStore
	// TAC-ROUTES-END
	tenants          tenantRepo
	orgs             *tenant.OrgStore
	bindings         *bindingStore
	securitySettings *securitySettingsStore
	loginThrottle    *loginguard.Throttle // in-memory failed-login lockout (best-effort)
	sessions         *session.Store       // server-side session lifecycle (idle/absolute/revocation)
	apiKeys          *apikey.Store
	refresh          *session.RefreshStore
	snmpCreds        *snmpcred.Store
	credOverrides    *credOverrideStore // learned SNMP credential bindings (credential sentinel)
	credSentinel     *credSentinel      // self-healing credential resolution loop
	sshHosts         *sshHostStore      // #20/device-ssh: TOFU host-key store for the SSH gateway
	snmpProfiles     *snmpProfileStore
	saved            saved.Repo
	audit            auditRepo
	notifyCfg        *notifyConfigStore
	contactPoints    *contactPointStore
	deviceLocations  *deviceLocationStore
	sites            *sitesStore      // internal SoT sites (default provider)
	deviceSites      *deviceSiteStore // operator device→site bindings (intent)
	wanPolicy        *wanPolicyStore  // WAN measurement policy (operator intent) #wan-path-metrics
	systemNet        *systemNetStore  // platform DNS + NTP system settings (clock sync + URL resolution)
	// DATA-PROTECTION-BEGIN — the whole Data Protection domain lives in
	// internal/dataprotect: the backup intent store + live DR status, the
	// netops-daily SM policy control plane, the snapshot inventory/management
	// surface, the restorability probe, the bounded operation ring and the
	// per-engine coverage table. main.go keeps only this field, the Deps
	// assembly below, the route registrations, the probe worker and the
	// /metrics delegation — no domain logic (§2).
	dataProtect *dataprotect.Service
	// DATA-PROTECTION-END
	// STORAGE-MEASUREMENT-BEGIN — MEASURED bytes on disk per store
	// (internal/storagemeter, tracker 204). Every storage and retention-pricing
	// number this platform published before it was DERIVED — a row rate times an
	// assumed bytes-per-row — and the owner directive was: measure it, or say you
	// did not. main.go keeps only this field, the Deps assembly, the route
	// registration, the sampler worker and the /metrics delegation (§2).
	storageMeter *storagemeter.Meter
	// STORAGE-MEASUREMENT-END
	// LICENCE-BEGIN — the licence mechanism. `entitlements` is the CENTRAL
	// entitlement service every commercial gate asks (entitlement.Service);
	// `licenceStore` owns the signed document at /data/api/licence.json;
	// `licenceAPI` is the platform-admin route. No safety control reads any of
	// them — isolation, RLS, authorization and core authentication (OIDC
	// included) cannot consult the entitlement service at all, which is what
	// makes "a licence problem can never weaken a safety property" a structural
	// fact rather than a promise (internal/entitlement/safety_invariant_test.go).
	licenceStore licence.Store
	entitlements *licence.Service
	licenceAPI   *licence.API
	// LICENCE-END
	// MONITORING-BEGIN — the per-device monitoring switch (C4). `devmonAPI` is
	// GET|PUT /api/devices/{id}/monitoring; the STATE it changes lives in the
	// device registry, which is also what counts it for the licence, so there
	// is one definition of "monitored" and one lock protecting it.
	devmonAPI *devmon.API
	// MONITORING-END
	// METERING-BEGIN — usage metering (tracker 258). `meteringStore` holds the
	// daily per-tenant rows, `meteringRecorder` samples hourly and owns the
	// module's metrics, `meteringKey` is this INSTALLATION's usage-report
	// signing identity (never Correlix's licence key, which does not exist on a
	// customer host), and `meteringAPI` serves the two Usage routes.
	//
	// NOTHING GATES ON ANY OF IT. No admission path reads a meter, so a
	// metering outage costs a usage report and can never refuse a device.
	meteringStore    metering.Store
	meteringRecorder *metering.Recorder
	meteringKey      *metering.ReportKey
	meteringAPI      *metering.API
	// METERING-END
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
	// Sealed Fields (#129): nil unless FEATURE_SEALED_FIELDS + key custody are
	// both present, which is what makes the reveal endpoint 501 rather than
	// pretending to be available.
	sealProvider sealing.CryptoProvider
	sealMetrics  *sealMetrics
	// F-11 quarantine observability (D6): depth/age sampler over the
	// netops-quarantine-* index + re-attribution outcome counters. nil unless
	// sealing custody is on (no custody ⇒ no quarantine stage exists).
	quarMetrics *quarantine.Metrics
	ticketing   ticketing.Store // RCA auto-ticketing store #78 (in-memory or pg); worker+sweeper start in main() under FEATURE_RCA_TICKETING
	// ticketing invariant/contract counters (exposed on /metrics): enable attempts
	// rejected by the one-enabled-policy rule, fail-closed holds on a violated
	// invariant, and manual actions redirected off a merged object.
	tktPolicyConflicts    atomic.Int64
	tktPolicyMultiEnabled atomic.Int64
	tktMergedRedirects    atomic.Int64
	seams                 *seam.Store               // canonical seam inventory, #67 build ⑤ (nil on file backend)
	services              *pgServiceStore           // service catalog #69 §2 P2 (nil on file backend)
	cloudConn             cloudconn.Repo            // multi-tenant cloud-connector framework (pg or in-memory)
	cloudBroker           *cloudconn.IdentityBroker // cloud identity broker: scoped short-lived provider tokens + vault secret custody
	workloadIssuer        *workloadIssuer           // platform OIDC issuer for minted workload assertions (Wave 4 #13); nil = dormant
	cloudIngestInv        *cloudIngestInventory     // per-connector inventory snapshots → per-tenant merged inventory (Wave 1 #2)
	cloudSourceStatus     *cloudSourceStatusStore   // poller-reported permission_denied/misconfigured per source (Wave 2 #4)
	topology              topology.GraphStore       // persistent topology graph #77 (in-memory or pg)
	incidentTimeline      timeintel.TimelineStore   // RCA Time Intelligence manual lifecycle events #84 (in-memory or pg)
	incidentTimeMetrics   incidentTimeMetricsStore  // RCA Time Intelligence backfilled phase-metric snapshots #84 (in-memory or pg)
	aiFeedback            ai.FeedbackStore          // Iris AI answer feedback (thumbs up/down), privacy-safe (in-memory or pg)
	// IRIS-MEMORY-BEGIN — IRIS Phase B investigation memory (design §3.5).
	// irisMemory is the tenant-scoped store of CONCLUDED investigations
	// (migration 0040 / file fallback); irisPending holds a conclusion in memory
	// until an operator judges it on /api/ai/feedback. Both always set.
	irisMemory  ai.InvestigationStore
	irisPending *ai.PendingInvestigations
	// IRIS-MEMORY-END
	applications appid.AppStore     // Application Identification registry #81 P0 (in-memory or pg)
	appCatalog   *appCatalogHolder  // Application Identification IP→app resolver #81 P1 (in-memory LPM catalog)
	ngfw         *ngfwAppResolver   // Application Identification NGFW app-id overlay #81 P-NGFW pt2 (OpenSearch-fed)
	fusion       *fusionWorker      // Application Identity Fusion Layer #81 P4 worker (opt-in via FUSION_WORKER_ENABLED)
	appOverrides appCatalogStore    // Application Identification operator-defined overrides #81 P1c (in-memory or pg)
	cloud        cloud.Store        // Cloud App Observability inventory #81 P3A (in-memory; pg over migration 0016 next)
	bizServices  *cloud.BizSvcStore // Business Service mapping + manual overrides #0024 (nil on file backend)
	cloudApp     *cloudAppResolver  // Cloud identity-map → appid bridge #81 P3F+1 (consumes the cloud inventory for app naming)
	// Service Path Graph (frozen contract v1, docs/design/service-path-graph-contract.md):
	// the ordered LAN→SD-WAN→carrier/cloud→application RCA spine. pathGraph is the
	// storage (PG registries + CH observation/hop streams, or in-memory on the file
	// backend); pathFacts and corrPath are the DI seams for the §3 fact base and the
	// correlation→path linkage (nil = the real inventories / ClickHouse).
	pathGraph       pathgraph.Store
	pathFacts       pathFactSource
	corrPath        corrPathRef
	remotePaths     *remotePathStore      // remote-vantage traceroute pushes (POST /api/probe/paths)
	integrations    *integration.Store    // integration-platform persistence (nil on file backend)
	providers       *integration.Registry // inbound provider translators (registry)
	nms             *nmsRuntime           // NMS vendor-controller framework #95 (nil unless FEATURE_NMS_INTEGRATIONS)
	wireless        wireless.Store        // wireless canonical inventory #128 (always set: mem on file backend, PG on postgres)
	wirelessActions *wirelessActionStore  // #128 Phase 8 guarded remediation (dormant unless FEATURE_WIRELESS_ACTIONS)
	intMetrics      *integrationMetrics   // integration-platform Prometheus counters
	vault           *vault.Vault          // secret-custody envelope (dormant unless SEAL_PROVIDER set)
	tlsSrv          *tlsServer            // opt-in HTTPS/mTLS listener config (nil = plaintext)
	tlsPeerProber   *tlsprobe.Prober      // SEC-019.1 served-cert expiry watcher (nil = plaintext baseline)
	secMetrics      *secobs.Metrics       // SEC-020.1 security-observability families (nil only if the profile itself was invalid, which aborts boot)
	transportInv    *secobs.Inventory     // SEC-001 declared-transport ledger (nil = inventory failed to load; logged at boot)
	exportPolicy    *exportPolicyStore    // runtime-tunable log-export limits
	exportLimiter   *ratelimit.Limiter    // per-tenant export rate limit
	copilotLimiter  *ratelimit.Limiter    // per-principal copilot rate limit (SR-021)
	aiToolBudget    *ai.DailyBudget       // per-tenant daily token budget for the agent loop (P2, LLM04)
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
	// Operator verdict feedback on RCA cases (Project 2 P7) — the
	// false-positive-rate instrument. PG (migration 0036, tenant_iso FORCE-RLS)
	// under the Postgres backend, tenant-keyed file store otherwise.
	rcaFeedback        rcafeedback.Store
	rcaFeedbackMetrics *rcafeedback.Metrics
	// Security (CTEM) read API + its control-plane state (Project 3 P3-API).
	// The findings themselves live in OpenSearch (netops-secfindings-<seg>-*,
	// SECURITY_FINDINGS_STORE_DECISION 2026-08-28); only rule enablement and
	// saved views are relational — PG (migration 0037, tenant_iso FORCE-RLS)
	// under the Postgres backend, tenant-keyed file store otherwise.
	secAPI         *secapi.API
	secStore       secapi.Store
	secFindMetrics *secapi.Metrics
	// SEC-FRAMEWORKS-BEGIN
	// Which compliance frameworks a tenant has opted into (owner, 2026-09-03:
	// compliance is analyzed per customer requirement, not run for everybody).
	// PG under the Postgres backend (migration 0042, tenant_iso FORCE-RLS),
	// tenant-keyed file store otherwise.
	secFrameworks secapi.FrameworkStore
	// SEC-FRAMEWORKS-END
	// Parser coverage (programme A6, parsercov/): platform-admin engine parser
	// stats + the caller's own unrecognized log shapes. Handlers live in the
	// subpackage; only the wiring is here (§2, the secapi precedent).
	parserCov        *parsercov.API
	parserCovMetrics *parsercov.Metrics
	// DEBUG-ROUTES-BEGIN
	// Pipeline debugger (docs/design/PIPELINE_DEBUGGER_2026-09-04.md). The
	// handlers live in internal/pipedebug over injected seams; only the wiring
	// is here (§2, the secapi precedent), and it is deletable as a unit —
	// removing the five DEBUG-ROUTES marker blocks in this file (import, this
	// struct hunk, the newServer wiring, the four mux registrations and the
	// debugDeps builder), the three in logs.go / correlation/main.py, and the
	// internal/pipedebug package removes the whole feature and nothing else.
	debugAPI *pipedebug.API
	// debugRing is the bounded, per-marker in-memory log buffer that serves a
	// trace's `api` stage WITHOUT reading the applogs index — a debugger must
	// not depend on the pipeline it is debugging.
	debugRing *pipedebug.Ring
	// debugAPILevel owns this process's runtime log level with the auto-revert
	// armed HERE, so a module never stays at debug because a caller died.
	debugAPILevel *pipedebug.LevelSwitch
	// debugParseFilter is the runtime PARSER decision-trace switch
	// (internal/parsetrace). It is the collectors' process-wide default, joined
	// to the debug ring at boot: a record carrying a cx_debug marker is traced
	// unconditionally, and an operator arms it by needle for a REAL record.
	debugParseFilter *parsetrace.Filter
	// DEBUG-ROUTES-END
	// SECURITY-LANE-BEGIN — P3-EMIT removable module; see internal/seclane's
	// package doc, "REMOVAL RULE". nil unless FEATURE_SECURITY_LANE=true.
	securityLane *seclane.Lane
	// SECURITY-LANE-END
	// CONFIG-BACKUP-BEGIN — P3-CFG removable module (internal/configstore +
	// internal/configdrift). All nil unless FEATURE_CONFIG_BACKUP=true.
	configBackup *configstore.Manager   // capture runtime + scheduler
	configAPI    *configstore.API       // /api/devices/{id}/config/* subtree
	configDrift  *configdrift.Evaluator // sync badge + ConfigDrift bus signal
	// CONFIG-BACKUP-END
	// PACKET-CAPTURE-BEGIN — removable module (internal/pcap). Both nil unless
	// FEATURE_PACKET_CAPTURE=true. A PCAP is customer payload, so this module is
	// dormant by default and answers 404 when off (see internal/pcap's doc.go).
	packetCapture *pcap.Manager // bounded on-device capture runtime
	pcapAPI       *pcap.API     // /api/devices/{id}/pcap* subtree
	// PACKET-CAPTURE-END
	// BMP-BEGIN — the BGP Monitoring Protocol receiver (internal/bmp,
	// frontend-wave item 10). nil unless FEATURE_BMP=true: with the flag off
	// no TCP port is bound, no worker starts, and all three routes answer 404.
	// A router PUSHES its RIB-In to us; we configure nothing on any device.
	bmpAPI *bmp.API
	// BMP-END
	// VMALERT-WEBHOOK-BEGIN — the DELIVERY layer for the vmalert evaluator
	// (internal/alertwebhook). vmalert ran with -notifier.blackhole: rules
	// fired and nothing was ever delivered to a human (a 3h correlation outage
	// on 2026-09-02 went unnoticed with 13 alerts standing firing). This is the
	// Alertmanager-v2 receiver its notifier POSTs to, fanning alerts into the
	// existing notify.Dispatcher channels.
	//
	// vmalertWebhook is nil unless VMALERT_WEBHOOK_TOKEN is set — fail-closed:
	// an unauthenticated alert fan-out is never served, and the route is not
	// registered at all. vmalertWebhookMetrics is built UNCONDITIONALLY so
	// /metrics always carries netops_alert_webhook_enabled: "nothing was
	// delivered because nothing fired" and "nothing was delivered because the
	// receiver was never wired" must be distinguishable.
	vmalertWebhook        http.HandlerFunc
	vmalertWebhookMetrics *alertwebhook.Metrics
	// VMALERT-WEBHOOK-END
	// igpAPI serves the read-only OSPF/IS-IS monitoring subtree
	// /api/protocols/{ospf|isis}/{adjacencies,summary,health} (internal/igpmon).
	// It is always on — it collects nothing and reads only telemetry the
	// platform already has. A nil value (construction refused an incomplete
	// Deps) answers 404 on every route rather than reading unscoped.
	igpAPI       *igpmon.API
	rcaRevisions *rcaRevisionStore     // report revision register, tenant-keyed (postmortem Phase 1 immutability)
	rcaClock     func() time.Time      // DI seam for the RCA generation clock (nil = wall clock) — deterministic re-render tests inject it
	portStore    portintel.Store       // Port Intelligence physical-layer store (#94)
	netboxCfg    *netboxConfigStore    // NetBox source-of-truth discovery config
	discoveryCfg *discoveryConfigStore // SNMP subnet-discovery scan config (platform-owner)
	netboxSync   *netboxSyncer         // reconciles discovered devices INTO NetBox (write-through)
	vulns        *vuln.Feed            // #13: advisory feed for /api/vulns (lazy, mtime hot-reload)
	// oidc holds the live SSO provider. It is swapped atomically when an operator
	// saves config from the admin UI (oidc_config.go), and is read on the hot
	// auth path (withAuth RS256) and in the SSO handlers via oidcProvider().
	oidc    atomic.Pointer[oidcProvider]
	ssoTxns *ssoTxnStore // server-side single-use login transactions (state → nonce + PKCE verifier)
	// wsTickets: one-time, scope-bound WebSocket tickets. A browser cannot set
	// an Authorization header on a WebSocket, and putting the session JWT in the
	// URL wrote a reusable privileged credential into the nginx access log.
	wsTickets   *wsticket.Store
	oidcCfg     *oidcConfigStore
	ssoIdPCfg   *ssoidp.Store    // desired-state SSO identity providers (internal/ssoidp)
	kc          *keycloak.Client // admin client for the bundled Keycloak broker (env-derived)
	ldap        *ldapConfigStore
	tacacs      *tacacsConfigStore
	tokenPolicy *tokenPolicyStore
	secPolicy   *policy.SecurityStore // #24 security-policy engine Source (catalog + per-scope overrides)
	// ITSM connectors (ServiceNow + Jira) are PER-TENANT and owned by itsmCfg
	// (itsm_config.go), which builds + hot-swaps them on save. Resolve a tenant's
	// connector via serviceNowFor()/jiraFor(); the incident-projection worker keys
	// on the incident's TenantID so a tenant's incidents only reach its own
	// ticketing. nil = not configured for that tenant.
	itsmCfg *itsmConfigStore
	hub     *Hub
	// timeIntelInvalidRows counts pick rows that failed validation (ultra #3).
	// They are PERMANENTLY unprocessable — the watermark advances past them so
	// they can never wedge the pass, and this series is the only trace they leave.
	timeIntelInvalidRows atomic.Int64
	// timeIntelRescanFailures / timeIntelRescanSkips (ultra #5): a failed
	// phase-1 re-scan no longer blocks the mark-advancing forward phase — it is
	// counted here, and a ClickHouse-refused re-scan additionally moves the
	// re-scan floor forward (a bounded skip past a deterministically failing
	// region — progress over completeness, loudly).
	timeIntelRescanFailures atomic.Int64
	timeIntelRescanSkips    atomic.Int64
	// timeIntelPassMu serializes backfill passes (ultra #6): the ticker pass and
	// the POST /time-metrics manual pass must never interleave. TryLock, never
	// Lock — a pass that finds another in flight yields instead of queueing.
	timeIntelPassMu sync.Mutex
	// timeIntelCursorMu guards the watermark WRITE path and its generation:
	// a ?reset bumps timeIntelCursorGen under this mutex, and every in-pass
	// cursor save re-checks its own generation under the same mutex — so a save
	// from a pass that predates the reset is discarded, never clobbering it.
	timeIntelCursorMu  sync.Mutex
	timeIntelCursorGen int64
	// timeIntelRescanFloor is the ultra-#5 bounded-skip floor (guarded by
	// timeIntelPassMu — only pass code touches it). Zero = no active skip.
	timeIntelRescanFloor time.Time
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
	return s.itsmCfg.ServiceNowFor(tenant)
}

func (s *server) jiraFor(tenant string) *notify.Jira {
	if s.itsmCfg == nil {
		return nil
	}
	return s.itsmCfg.JiraFor(tenant)
}

func newServer() *server {
	// Fail closed if no JWT_SECRET is configured (SR-017) — the dev fallback is
	// public and also keys report/export links. Dev runs opt in via
	// ALLOW_DEV_SECRETS=true.
	if err := ensureSigningSecret(); err != nil {
		log.Fatalf("auth: %v", err)
	}

	// PRODUCTION SECURITY VALIDATOR (Security v1). Evaluates the deployment's
	// security controls and, in the production profile, REFUSES TO START on any
	// fatal finding. Lower profiles report the same findings without blocking,
	// so an operator sees what production would refuse before they get there.
	// There is deliberately no global bypass — the profile IS the escape hatch.
	if err := runSecurityValidator(); err != nil {
		log.Fatal(err)
	}

	// Select where the identity/saved stores persist (file by default; Postgres
	// when STORE_BACKEND=postgres). Must run before any store is constructed.
	if err := initStoreBackend(); err != nil {
		log.Fatalf("store backend: %v", err)
	}
	// One-time file→Postgres cutover for the collections whose Postgres target
	// is a DOMAIN table (dem targets, iris memory, config versions/drift, the
	// security control plane, the BGP watchlist, metering, …). The blob-shaped
	// collections are imported inside NewPGStore; these cannot be, because
	// internal/platformdb must not import the packages that import it — so the
	// composition root injects them. A failure ABORTS THE BOOT: a half-imported
	// control plane that comes up looks exactly like a complete one.
	if err := importDomainCollections(); err != nil {
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

	// Sealed Fields (#129): reversible masking. Dormant unless
	// FEATURE_SEALED_FIELDS=true; fail closed when it is on but key custody is
	// not, rather than accepting seal rules that would not encrypt.
	sealProvider, err := sealedfields.Init(vault, vaultWarn)
	if err != nil {
		log.Fatalf("sealed fields: %v", err)
	}

	// Hardened TLS for outbound calls to internal backends (#18 phase 3). Fail
	// closed: a configured-but-unloadable trust bundle aborts boot.
	if err := initBackendTransport(); err != nil {
		log.Fatalf("backend TLS: %v", err)
	}
	// The collectors' mesh egress (ClickHouse inserts, VictoriaMetrics pushes
	// and queries, the Vector ingest lanes) rides the same hardened client.
	// The factory defers to the transport at call time, so the post-CA
	// re-initialization below is picked up without re-wiring.
	collectors.SetMeshHTTPClient(backendHTTPClient)

	d := discovery.NewDiscoveryAggregator()
	// Operator-created devices persist here and are seeded into the cache before
	// any source polls or the API serves a request. Without this, POST
	// /api/devices returned 201 for a device that existed only until the process
	// exited (see device_persist.go).
	devStore := newDeviceStore(devicesPath())
	d.SetStore(devStore)
	d.Register(discovery.NewStaticSource(os.Getenv("STATIC_DEVICES_PATH")))
	// SNMP subnet discovery: registered always with a LIVE config getter
	// (console-set store, env bootstrap fallback) so operators can scope and
	// enable it at runtime without a restart. Poll is a no-op while disabled.
	discoveryCfg := newDiscoveryConfigStore(envOr("DISCOVERY_CONFIG_FILE", "/data/discovery_config.json"), vault)
	d.Register(newSNMPSourceFromStore(discoveryCfg, d.Devices))
	// NetBox source-of-truth: registered always with a LIVE config getter (UI-set
	// store, env fallback). Poll is a no-op while unconfigured/disabled, so it
	// honors runtime changes from Automation → Source of Truth without a restart.
	netboxCfg := newNetboxConfigStore(envOr("NETBOX_CONFIG_FILE", "/data/netbox_config.json"), vault)
	d.Register(discovery.NewNetboxSource(netboxCfg.effective, func(msg string, fields map[string]any) { logWarn("discovery", msg, fields) }))

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
			// MONITORING-BEGIN — collect only from devices monitoring is ON
			// for (owner decision C4, 2026-09-05). This is what makes the
			// licence count mean something: the ceiling counts MONITORED
			// devices, and this line is the reason that number is the set the
			// platform actually spends telemetry, storage and correlation on.
			// A discovered candidate nobody enabled is inventory, not load.
			//
			// The flag is stamped by the device registry (internal/discovery),
			// which owns the one definition — nothing here re-derives it.
			if !dev.Monitored {
				continue
			}
			// MONITORING-END
			// SNMP credentials come only from UI-configured credential profiles
			// (resolved via the device's credential_ref). A v3 profile threads
			// full USM params; a v1/v2c profile threads the community. An empty
			// community falls back to the global SNMP_COMMUNITY in the poller.
			tgt := collectors.Target{
				ID: dev.ID,
				// The stored name (raw sysName for scan devices) rides along so
				// the trap receiver's NAT-surviving sysName rescue can match a
				// trap's sysName varbind against what the device actually
				// reports — the derived id (sanitized + addr-hash) never can.
				Name:    dev.Name,
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
					snmpcred.ApplyCredToTarget(&tgt, c)
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
	// Digital Experience checks (S17) — the catalogue-driven ICMP/TCP/DNS/HTTP
	// runner. Targets arrive as the api-published work queue, so this collector
	// is inert (0 targets, honestly reported) until an operator declares one.
	pool.Enable("dem", envBool(dem.EnvFeatureFlag))
	// WAN circuit SLA — SD-WAN/BFD-style source-bound echo (ICMP, TCP-SYN
	// fallback) between WAN-interface endpoints. Targets are the circuits the
	// projector publishes to Redis. Opt-in; ICMP raw needs CAP_NET_RAW.
	pool.Enable("wan-echo", os.Getenv("FEATURE_WAN_ECHO") == "true")

	notifier := notify.NewDispatcher()
	// F-22: delivery failures used to be a bare log.Printf and nothing else.
	// Route them into the structured app log so a lost page is searchable next
	// to the alert that produced it (§10).
	notifier.SetLogger(func(level, msg string, fields map[string]any) {
		applog.Log(level, "notify", msg, fields)
	})
	// Slack, PagerDuty, Teams and SNS are now UI-configurable via the
	// notifyConfigStore (created after srv exists), which seeds from
	// FEATURE_SLACK_NOTIFICATIONS/SLACK_WEBHOOK_URL,
	// FEATURE_PAGERDUTY_NOTIFICATIONS/PAGERDUTY_KEY,
	// FEATURE_TEAMS_NOTIFICATIONS/TEAMS_WEBHOOK_URL and
	// FEATURE_SNS_NOTIFICATIONS/AWS_*+SNS_* on first run and is then editable
	// live from the admin UI — mirroring the ITSM connectors. See
	// notify_config.go. They are intentionally NOT registered from env here: a
	// second, env-only registration would shadow the stored channel config and
	// silently keep paging a webhook the operator had already removed in the UI.
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
	// ITSM connectors (ServiceNow + Jira) are built from the itsmConfigStore, which
	// seeds from the legacy FEATURE_*_NOTIFICATIONS + SERVICENOW_*/JIRA_* env on
	// first run and is then editable live from the admin UI. The store is created
	// after srv exists (it swaps connectors into srv + the notifier). See
	// itsm_config.go. Both connectors can run at once; either feeds alert
	// auto-ticketing (the notifier) and the incident-projection worker.

	// SEC-010: rule evaluation reaches VictoriaMetrics through the hardened
	// backend client (mesh-CA verify + URL-userinfo credentials). Lazy — the
	// transport is rebuilt after the internal CA bootstrap, and clientFn picks
	// that up on the next evaluation.
	alerts.SetHTTPClientFunc(func() *http.Client { return backendHTTPClient(8 * time.Second) })
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
	// Item 121: mirror allowed mutations onto the corr_signals spine so the
	// event feed's "what changed" includes operator/API actions. No-op without
	// ClickHouse; the trail above stays the durable record either way.
	audit = newAuditSignalBridge(audit)

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
	// MONITORING-BEGIN — per-device monitoring decisions (owner decision C4,
	// 2026-09-05): which devices Correlix collects from, and therefore which
	// ones the licence counts.
	//
	// Attached to the registry BEFORE any source polls or the API serves, so a
	// decision made yesterday is in force before the ceiling is asked about it
	// — exactly the reason SetStore is called where it is.
	//
	// Tenant scoping is by construction, not by convention: the records live in
	// the §3a tenantKV primitive keyed (tenant, device id), and the tenant is
	// stamped from the DEVICE's own owner (server-side state), never from a
	// request body (§3a rule 2).
	deviceMonitoring, err := newDeviceMonitorStore(envOr("DEVICE_MONITORING_FILE", "/data/device_monitoring.json"))
	if err != nil {
		log.Fatalf("device monitoring store: %v", err)
	}
	d.SetMonitorStore(deviceMonitoring)
	// MONITORING-END
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
	backupCfg, err := dataprotect.NewFileConfigStore(envOr("SYSTEM_BACKUP_FILE", "/data/system_backup.json"))
	if err != nil {
		log.Fatalf("backup config store: %v", err)
	}

	srv := &server{
		startedAt:        time.Now().UTC(),
		workers:          &workerGroup{},
		discovery:        d,
		devStore:         devStore,
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
		loginThrottle:    loginguard.NewThrottle(func(msg string, fields map[string]any) { logWarn("auth", msg, fields) }),
		sessions:         sessions,
		apiKeys:          apiKeys,
		refresh:          refresh,
		snmpCreds:        snmpCreds,
		credOverrides:    credOverrides,
		// MONITORING-BEGIN — the credential sentinel probes devices over SNMP to
		// learn which profile answers, so it must see only the devices
		// monitoring is on for: probing one nobody enabled is collection the
		// licence does not count (C4).
		credSentinel: newCredSentinel(credOverrides, snmpCreds, monitoredOnly(d.Devices)),
		// MONITORING-END
		sshHosts:        newSSHHostStore(envOr("SSH_KNOWN_HOSTS_FILE", "/data/ssh_known_hosts.json")),
		snmpProfiles:    snmpProfiles,
		saved:           saved,
		audit:           audit,
		contactPoints:   contactPoints,
		deviceLocations: deviceLocations,
		sites:           sites,
		deviceSites:     deviceSites,
		wanPolicy:       wanPolicy,
		systemNet:       systemNet,
		hub:             NewHub(),
		// #13 Vulnerability Management: operator-prepared advisory feed
		// (scripts/vuln-feed-prepare.py → data/vuln/, mounted ro at /data/vuln).
		vulns: vuln.NewFeed(envOr("VULN_FEED_PATH", "/data/vuln/advisories.csv"),
			func(msg string, fields map[string]any) { logWarn("vulns", msg, fields) },
			func(msg string, fields map[string]any) { logInfo("vulns", msg, fields) }),
	}
	// DATA-PROTECTION-BEGIN — the Data Protection domain (internal/dataprotect).
	// Built here, after srv exists, because every seam it takes is a method on
	// *server (the platform-admin gate, the audit sink, the OpenSearch caller).
	srv.dataProtect = dataprotect.New(srv.dataProtectDeps(backupCfg))
	// DATA-PROTECTION-END
	// STORAGE-MEASUREMENT-BEGIN — built here for the same reason: every seam it
	// takes (the OpenSearch caller, the ClickHouse worker lane, the VM query, the
	// admin gate) is a method on *server, and every env switch it reads is
	// resolved ONCE below and travels in Deps as a value.
	srv.storageMeter = storagemeter.New(srv.storageMeterDeps())
	// STORAGE-MEASUREMENT-END
	// LICENCE-BEGIN — built here, after srv exists, because the gate, the audit
	// sink and the usage counters are all methods on *server.
	//
	// Construction NEVER fails and never touches the disk: a missing licence is
	// the supported Community state, and an unreadable one must not be able to
	// stop the api. The first State() call loads and, if the file is corrupt,
	// reports Community plus a loud reason.
	srv.licenceStore = licence.NewFileStore(envOr("LICENCE_FILE", licence.DefaultPath), licence.FileStoreOptions{})
	srv.entitlements = licence.NewService(srv.licenceStore)
	// The durable "since when are you over" register (owner decision,
	// 2026-09-05: "record overage_since and let the order form decide"). It
	// lives beside the licence, fails soft — a register that cannot be written
	// costs the start time and nothing else — and encodes no window, no
	// countdown and no consequence, because those are order-form terms.
	srv.entitlements.SetOverageTracker(licence.NewOverageTracker(
		licence.OveragePathFor(srv.licenceStore.Path()),
		func(msg string, err error) {
			if err != nil {
				logWarn("licence", msg, errf(err))
				return
			}
			logWarn("licence", msg, nil)
		}))
	srv.licenceAPI = licence.New(srv.licenceDeps())
	// The MONITORED-DEVICE ceiling. Injected rather than read by the aggregator,
	// so internal/discovery keeps knowing nothing about licensing: it asks
	// "may one more device be monitored?" and honours the answer.
	//
	// It gates COLLECTION, never DISCOVERY (owner decision C4, 2026-09-05):
	// finding a device costs no allowance and is never refused, so a /24 sweep
	// that turns up 500 devices creates 500 inventory rows and uses 0 of 25.
	// What consumes an entitlement is the transition to monitored — the first
	// time Correlix is told to collect from a device — which is why this one
	// closure covers every path there is: the monitoring switch, the manual
	// create, and a source reporting a device that would default to monitored.
	srv.discovery.SetMonitorGate(func(current int) error {
		return entitlement.CheckCeiling(srv.entitlements, entitlement.CeilingDevices, current)
	})
	srv.logLicenceState()
	// LICENCE-END
	// METERING-BEGIN — usage metering (tracker 258). Built here, after srv
	// exists, because every seam it takes is a method on *server: the sampler
	// reads the monitored set, the tenant register and the watchlist; the read
	// gate is the licence page's gate.
	//
	// Construction NEVER fails and never touches the disk. The Postgres backend
	// is used when it is active (migration 0046, FORCE-RLS), the file backend
	// otherwise — the same selection the DEM catalogue and the security control
	// plane make.
	srv.meteringStore = newMeteringStore()
	srv.meteringKey = metering.NewReportKey(
		metering.ReportKeyPathFor(srv.licenceStore.Path()),
		func(msg string, err error) {
			if err != nil {
				logWarn("metering", msg, errf(err))
				return
			}
			logWarn("metering", msg, nil)
		})
	srv.meteringRecorder = metering.NewRecorder(srv.meteringStore, srv.meteringSample,
		func(msg string, err error) {
			if err != nil {
				logWarn("metering", msg, errf(err))
				return
			}
			logWarn("metering", msg, nil)
		})
	srv.meteringAPI = metering.New(srv.meteringDeps())
	// METERING-END
	// MONITORING-BEGIN — the monitoring switch's route. Built here, after srv
	// exists, because every seam it takes is a method on *server (the two
	// permission gates, the device-visibility rule, the audit sink) — the same
	// reason the licence and data-protection modules are built here.
	srv.devmonAPI = devmon.New(srv.devmonDeps())
	// MONITORING-END
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
	srv.cloudBroker = cloudconn.NewIdentityBroker(srv.cloudConn, vault, func(event, tenant, connectorID, provider, decision, detail string) {
		if srv.audit != nil {
			srv.audit.Record(AuditEvent{
				Actor: "broker", Tenant: tenant, Method: event, Path: "/cloudconn/broker/" + connectorID,
				Status: 200, Decision: decision,
				Detail: map[string]any{"event": event, "connector": connectorID, "provider": provider, "info": detail},
			})
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
	// IRIS-MEMORY-BEGIN
	srv.irisMemory = newIrisInvestigationStore()    // Iris investigation memory (migration 0040 / file fallback)
	srv.irisPending = ai.NewPendingInvestigations() // concluded-but-unjudged buffer (in memory, bounded, never persisted)
	// IRIS-MEMORY-END
	srv.applications = newApplicationStore()      // Application Identification registry (#81 P0)
	srv.appCatalog = newAppCatalogHolder()        // Application Identification IP→app resolver (#81 P1)
	srv.ngfw = newNgfwAppResolver()               // Application Identification NGFW app-id overlay (#81 P-NGFW pt2)
	srv.appOverrides = newAppCatalogStore()       // Application Identification operator-defined overrides (#81 P1c)
	srv.cloud = newCloudStore()                   // Cloud App Observability inventory (#81 P3A)
	srv.bizServices = newBusinessServiceStore()   // Business Service mapping + manual overrides (migration 0024)
	srv.cloudApp = newCloudAppResolver(srv.cloud) // Cloud identity-map → appid bridge (#81 P3F+1)
	srv.pathGraph = newPathGraphStore()           // Service Path Graph storage (contract v1); ingester starts in main()
	srv.remotePaths = newRemotePathStore()        // remote-vantage path pushes (the LAN vantage's transport)
	if n, errs := srv.appCatalog.Reload(); srv.appCatalog.FeedsDir() != "" {
		log.Printf("appid: loaded %d catalog prefixes from %s (%d feed errors)", n, srv.appCatalog.FeedsDir(), len(errs))
	}
	srv.incMetrics = &incidentMetrics{}
	srv.sealMetrics = &sealMetrics{}
	// SEC-020.1: the security-observability families. The validator re-runs
	// here (pure env/file reads) so the finding counts ride /metrics for the
	// life of the process — a boot log line is not a queryable posture.
	// A missing inventory is loud but non-fatal: the api must still boot on
	// images built before the inventory was baked in.
	if rep, repErr := evaluateSecurityPosture(); repErr == nil {
		inv, invErr := secobs.LoadInventory(transportInventoryPath())
		if invErr != nil {
			logError("security", "transport inventory unavailable — declared-edge metrics and the transport-posture view degrade to probe-only", errf(invErr))
		}
		srv.transportInv = inv
		srv.secMetrics = secobs.NewMetrics(inv, rep.Fatal, rep.Warn, rep.Info, nil)
	}
	// nil unless FEATURE_SEALED_FIELDS + real key custody are BOTH present, which
	// is what makes the reveal endpoint answer 501 instead of pretending.
	srv.sealProvider = sealProvider
	if sealProvider != nil {
		// F-11 D6: the quarantine index only exists on deployments with sealing
		// custody, so the depth/age families follow the same boundary.
		srv.quarMetrics = quarantine.NewMetrics(openSearch, nil)
	}
	// Integration platform (#43): persistence is Postgres-only; the provider
	// registry (inbound translators) is always available.
	if ps, ok := platformdb.ActivePG(); ok {
		srv.integrations = integration.NewStore(ps.DB(), vault)
	}
	srv.providers = integration.DefaultRegistry()
	// Wireless canonical inventory (#128 Phase 1, migration 0030): PG-backed on
	// postgres (FORCE-RLS), in-memory on the file backend (dev/tests). Always
	// set — the read APIs render an empty inventory until a connector runs.
	// MUST init before the NMS runtime, which takes it as its inventory sink.
	if ps, ok := platformdb.ActivePG(); ok {
		srv.wireless = wireless.NewPGStore(ps.DB())
	} else {
		srv.wireless = wireless.NewMemStore()
	}
	srv.wirelessActions = newWirelessActionStore()
	// BGP Operations (item 10): the watchlist is DURABLE ON BOTH BACKENDS —
	// Postgres (migration 0035, tenant_iso FORCE-RLS) when it is active, the
	// tenant-keyed JSON register otherwise, exactly as the alert policy store
	// below picks its backend. Never nil: a nil store used to mean the whole
	// alerting evaluator saw no prefixes on every single-box install. A corrupt
	// file still SERVES (empty watchlist) but says so — a watchlist that failed
	// to load must never look like one a tenant never wrote. The fetcher is
	// store-independent and always available.
	if ps, ok := platformdb.ActivePG(); ok {
		srv.bgpWatch = newBGPWatchStore(ps.DB())
	} else {
		fs := bgpwatch.NewWatchFileStore(envOr(bgpwatch.EnvWatchlistFile, "/data/bgp_watchlist.json"))
		if err := fs.LoadErr(); err != nil {
			logError("bgp", "the BGP watchlist file could not be read — the watchlist starts EMPTY and NO watched prefix will be evaluated until it is re-added or the file is repaired",
				map[string]any{"err": err.Error()})
		}
		srv.bgpWatch = fs
	}
	srv.bgpFetch = newBGPFetcher()
	// BGP-DEPTH-BEGIN — depth wiring (item 10). The ASPA provider is always
	// present but is the honest no-op unless an operator configured a real one.
	// The live feed runtime is built only under its flag; Stop() is registered
	// with the server's shutdown hooks so pollers never outlive the process.
	srv.bgpASPA = bgpdepth.NewASPAProvider(os.Getenv(bgpdepth.EnvASPAProviderURL), srv.bgpFetch, time.Now)
	if envBool(bgpdepth.EnvFeatureFlag) {
		srv.bgpFeed = bgpdepth.NewRuntime(srv.bgpFetch, bgpdepth.Options{
			Enabled: true,
			// The first poll's window. The producer polls an ARCHIVE that has
			// been measured hours behind real time, so a window shorter than
			// that lag buffers nothing forever; the package clamps a bad value
			// rather than honouring one that would silence the feed.
			Lookback: durationOr(bgpdepth.EnvFeedLookback, bgpdepth.DefaultFeedLookback),
			Log: func(msg string, fields map[string]any) {
				logInfo("bgp-feed", msg, fields)
			},
			// Screen what a poll just appended for bogons immediately; the
			// evaluator's own tick still sweeps the ring, so this is a latency
			// improvement and never the only path (the register dedupes).
			OnUpdates: srv.bgpWatchNoteFeedUpdates,
		})
		logInfo("bgp-feed", "near-live BGP update feed enabled (RIPEstat poller; RIS Live is WebSocket-only and no websocket module is on the §6 allowlist)", map[string]any{
			"ring_size": bgpdepth.RingSize, "max_pollers": bgpdepth.MaxPollers,
			"lookback": srv.bgpFeed.Lookback().String(),
		})
	}
	// BGP-DEPTH-END
	// BGP-WATCH-BEGIN — the watchlist evaluator + its HTTP surface. The policy
	// store and the bogon set are always built (both are cheap and both are
	// useful with the evaluator off); the evaluator itself only under
	// FEATURE_BGP_ALERTS. Construction failure is LOUD, never silently dormant.
	srv.bgpWatchPolicy = newBGPAlertPolicyStore()
	bgpBogons := bgpwatch.NewBogonSet()
	if eval, err := srv.buildBGPWatch(srv.bgpWatchPolicy, bgpBogons); err != nil {
		logError("bgp-watch", "BGP alerting could not be constructed — NO watchlist alert will be raised", errf(err))
	} else {
		srv.bgpWatchEval = eval
	}
	if api, err := srv.buildBGPWatchAPI(srv.bgpWatchPolicy, bgpBogons, srv.bgpWatchEval); err != nil {
		logError("bgp-watch", "the BGP alerts/bogons routes could not be wired — they will answer 404", errf(err))
	} else {
		srv.bgpWatchAPI = api
	}
	// BGP-WATCH-END
	// DEM-BEGIN — the experience target catalogue + its HTTP surface. Both are
	// built unconditionally (see the field block); construction failure is LOUD,
	// never silently dormant, because a nil API answers 404 and a 404 on the
	// experience page is indistinguishable from "nothing is wrong".
	srv.demMetrics = dem.NewMetrics()
	srv.demRuns = dem.NewRunStore()
	srv.demTargets = newDEMStore()
	if api, err := srv.buildDEMAPI(srv.demTargets); err != nil {
		logError("dem", "the Digital Experience routes could not be wired — they will answer 404 and no experience score will be served", errf(err))
	} else {
		srv.demAPI = api
	}
	srv.demExperienceMetrics = experience.NewCounters()
	srv.experienceStore = newExperienceStore()
	if api, err := srv.buildExperienceAPI(srv.experienceStore, srv.demTargets); err != nil {
		logError("dem", "the Digital Experience causality routes could not be wired — they will answer 404, and a 404 on the experience screen is indistinguishable from 'nothing is wrong'", errf(err))
	} else {
		srv.experienceAPI = api
	}
	if envBool(dem.EnvFeatureFlag) {
		if pr, err := dem.NewProjector(srv.demTargets, demPublisher{},
			durationOr(dem.EnvProjectInterval, dem.DefaultProjectInterval), srv.demMetrics,
			func(m string, f map[string]any) { logWarn("dem", m, f) }); err != nil {
			logError("dem", "the experience work-queue projector could not be built — the prober will receive NO targets and measure nothing", errf(err))
		} else {
			srv.demProjector = pr
		}
		if ri, err := dem.NewRunIntake(demRunFetcher{}, srv.demRuns,
			dem.DefaultRunIntakeInterval, srv.demMetrics,
			func(m string, f map[string]any) { logWarn("dem", m, f) }); err != nil {
			logError("dem", "the experience run-record intake could not be built — every check will grade as ungraded and no experience incident will reach a high severity", errf(err))
		} else {
			srv.demRunIntake = ri
		}
	}
	// DEM-END
	// PROTOCOL-DIAG-BEGIN — Routing-protocol diagnostics (Troubleshooting item
	// 7): the catalog + signatures are a pure, always-available library (they
	// never touch a device). The LIVE collect transport is opt-in and
	// default-OFF: unless FEATURE_PROTOCOL_DIAG_COLLECT=true the collector stays
	// nil and the collect endpoint returns an honest 503 rather than fabricating
	// a capture. When the flag is on, buildProtocolDiagCollector wires the
	// read-only SSH command source (protocol_diag_gateway.go) — same ssh client,
	// same pinned host-key TOFU custody and same sealed credentials as config
	// capture and the operator terminal.
	srv.protocolCatalog = protocoldiag.DefaultCatalog()
	srv.protocolAnalyzer = protocoldiag.DefaultAnalyzer()
	if err := srv.buildProtocolDiagCollector(); err != nil {
		// Fail LOUD, not silently dormant: the operator asked for live collect.
		logError("protocol-diag", "live collect transport could not be wired — collect stays 503", errf(err))
	}
	// PROTOCOL-DIAG-END
	// TAC-ROUTES-BEGIN — the escalation pack. A failure here means the EMBEDDED
	// taxonomy/plan data did not load, which the package's own test would have
	// caught; it is logged loudly and leaves every /tac route answering an
	// honest 503 rather than taking the api down.
	if err := srv.buildTACService(); err != nil {
		logError("tac", "TAC escalation catalog could not be built — the escalation routes will answer 503", errf(err))
	}
	// TAC-ROUTES-END
	// NMS vendor-controller framework (#95 P3b): dormant unless
	// FEATURE_NMS_INTEGRATIONS=true. PG-backed on postgres (migration 0020,
	// FORCE-RLS); in-memory store on the file backend (dev).
	if nms.Enabled() {
		if ps, ok := platformdb.ActivePG(); ok {
			srv.nms = newNMSRuntime(nms.NewPGStore(ps.DB(), vault))
		} else {
			// F-76: the catalog + integration list still render on a fresh
			// install, but credential writes are REFUSED rather than held as
			// plaintext in a map that dies with the process.
			srv.nms = newNMSRuntime(nms.NewNonDurableStore())
		}
		srv.nms.SetWirelessStore(srv.wireless) // #128: wireless-inventory sink
	}
	// TRACKER 256 — wireless controllers and access points are DEVICES, and one
	// entitlement each when Correlix is collecting from them. Registering them
	// as an ordinary discovery source is the whole mechanism: from here the
	// single monitored-device definition (internal/devmon) decides, the same
	// dedupe collapses a controller SNMP also found into one device, and the
	// same ceiling gate is asked at the transition — no second counter exists.
	//
	// Registered here rather than beside the other sources because it needs the
	// wireless store and the NMS integration list, both built above; still
	// before discovery.Start(), which copies the source set once.
	if srv.wireless != nil {
		srv.discovery.Register(wireless.NewDeviceSource(srv.wireless, srv.wirelessActiveTenants, 0))
	}
	srv.intMetrics = &integrationMetrics{}
	srv.vault = vault
	srv.exportPolicy = newExportPolicyStore(envOr("EXPORT_POLICY_FILE", "/data/export_policy.json"))
	srv.exportLimiter = ratelimit.New()
	srv.copilotLimiter = ratelimit.New()
	srv.aiToolBudget = ai.NewDailyBudget()
	engine.OnFire = srv.ingestAlertIncident
	// Alert episode grouping + triage (Wave 2 #6): fold fire/resolve transitions
	// into per-tenant episodes; muted/snoozed episodes pause NOTIFICATIONS only.
	srv.alertEpisodes = newAlertEpisodeStore(envOr("ALERT_EPISODES_FILE", "/data/alert_episodes.json"))
	// Maintenance windows (item 121): a covering window pauses notifications for
	// newly-firing alerts and stamps timeintel snapshots as planned maintenance.
	srv.maintWindows = newMaintenanceWindowStore()
	// Per-tenant pipeline processor rules (item 121): structured redact/drop/set
	// shaping compiled into the router's processors.yaml by the config writer.
	srv.processors = newProcessorStore()
	engine.OnTransition = srv.observeAlertTransition
	engine.SuppressNotify = srv.alertNotifySuppressed
	// DURABLE notified set (alerts/notifystate.go). Without it every api
	// restart re-paged every still-firing alert, because the engine's "already
	// notified" record lived only in memory — two deploys inside an hour on
	// 2026-09-03 produced exactly that burst. Tenant derivation is the same
	// device→tenant rule the episode fold uses (§3a): never the alert's labels.
	engine.TenantOf = srv.alertTenant
	if st, err := alerts.NewNotifyStateStore(envOr("ALERT_NOTIFY_STATE_FILE", "/data/alert_notify_state.json")); err != nil {
		// NOT fatal: the worst case is the pre-existing behaviour (one
		// duplicate notification per still-firing alert). Loud, though — a
		// silently empty store would look identical to a clean boot (§10).
		logError("alerts", "the notified-alert state could not be loaded — still-firing alerts may be re-notified once after this restart", errf(err))
	} else if n := engine.SetNotifyState(st); n > 0 {
		logInfo("alerts", "restored the notified-alert state across the restart", map[string]any{
			"restored": n,
			"note":     "still-firing alerts will NOT be re-notified; anything that cleared while down resolves on the first tick",
		})
	}
	srv.reports = newReportScheduler(srv, envOr("REPORT_RUNS_FILE", "/data/report_runs.json"))
	srv.copilotCfg = newCopilotConfigStore(envOr("COPILOT_CONFIG_FILE", "/data/copilot_config.json"), vault)
	srv.aiTenantCfg = newAITenantConfigStore(aiTenantConfigPath(), vault)
	srv.displayPrefs = newTenantDisplayStore(tenantDisplayPath())
	// Active Verification (RCA spec item 8): per-tenant opt-in config (SSH
	// secrets vault-sealed), bounded run store, per-tenant rate limiter.
	srv.verifyCfg = verify.NewConfigStore(verifyConfigPath(), vault)
	srv.verifyRuns = verify.NewRunStore(envOr("VERIFY_RUNS_FILE", "/data/verify_runs.json"))
	srv.verifyLimiter = ratelimit.New()
	srv.governance = newTenantGovernanceStore(tenantGovernancePath())
	srv.cloudSLOs = newCloudSLOStore(cloudSLOPath())
	srv.cloudMonitors = newCloudMonitorStore(cloudMonitorsPath())
	srv.rcaPromotions = newRcaPromotionStore(rcaPromotionsPath()) // #113 point 3
	srv.rcaActionItems = newRcaActionItemStore(rcaActionItemsPath())
	srv.rcaFeedback = newRcaFeedbackStore()           // Project 2 P7 operator verdicts (migration 0036 / file fallback)
	srv.rcaFeedbackMetrics = rcafeedback.NewMetrics() // netops_rca_feedback_total{verdict}
	srv.secStore = newSecurityControlPlaneStore()     // Project 3 P3-API (migration 0037 / file fallback)
	// SEC-FRAMEWORKS-BEGIN
	srv.secFrameworks = newSecurityFrameworkStore() // per-tenant framework opt-in (migration 0042 / file fallback)
	// SEC-FRAMEWORKS-END
	srv.secFindMetrics = secapi.NewMetrics()           // netops_security_findings_queries_total{op}
	srv.secAPI = secapi.New(srv.securityAPIDeps())     // handlers over injected seams (§5)
	srv.parserCovMetrics = parsercov.NewMetrics()      // netops_parser_coverage_* counters
	srv.parserCov = parsercov.New(srv.parserCovDeps()) // handlers over injected seams (§5)
	// DEBUG-ROUTES-BEGIN
	// The ring is installed as the applog OBSERVER, so any log line carrying a
	// `cx_debug=<ulid>` marker is retained in memory for the trace that owns it.
	// Off-path cost when no trace is running is one map lookup per log line; the
	// ring itself is bounded at pipedebug.RingCapacity lines.
	srv.debugRing = pipedebug.NewRing()
	applog.SetObserver(func(level, component, msg string, fields map[string]any) {
		marker := pipedebug.MarkerIn(msg, fields)
		if marker == "" {
			return
		}
		srv.debugRing.Append(marker, pipedebug.RingLine{
			Level: level, Component: component, Msg: msg, Fields: fields,
		})
	})
	srv.debugAPILevel = pipedebug.NewLevelSwitch(pipedebug.ModuleAPI, func(l pipedebug.Level) error {
		applog.SetLevel(string(l))
		return nil
	})
	// The collectors' parse hook and the debug ring are joined HERE, and only
	// here: internal/parsetrace knows nothing about the debugger's HTTP surface
	// and internal/pipedebug knows nothing about the SNMP decoder, so neither
	// imports the other (§2 — no hidden coupling). A decision line lands in the
	// ring under the record's marker AND in the structured application log, so
	// it survives whether the reader is `correlix-debug` or `docker logs api`.
	srv.debugParseFilter = parsetrace.Default()
	srv.debugParseFilter.SetSink(func(marker, component, msg string, fields map[string]any) {
		srv.debugRing.Append(marker, pipedebug.RingLine{
			Level: "debug", Component: component, Msg: msg, Fields: fields,
		})
		applog.Debug(component, msg, fields)
	})
	srv.debugAPI = pipedebug.New(srv.debugDeps()) // handlers over injected seams (§5)
	// DEBUG-ROUTES-END
	srv.rcaRevisions = newRcaRevisionStore(rcaRevisionsPath())

	srv.portStore = newPortStore() // Port Intelligence #94 P5
	srv.netboxCfg = netboxCfg
	srv.discoveryCfg = discoveryCfg
	// Write-through: reconcile discovered devices INTO NetBox (the source of truth),
	// reading the deduped inventory. No-op while NetBox is disabled.
	srv.netboxSync = newNetboxSyncer(netboxCfg.effective, srv.discovery.Devices)
	// UI-configurable email/SMS/push channels (registers live channels into the
	// dispatcher built above). Must come after notifier is set on srv.
	// The SHARED per-push-server budget (notify/pushbudget.go). Built BEFORE the
	// notify config store, because that store's apply() constructs the product
	// ntfy channel and the channel must be born holding the shared bucket — a
	// channel wired without one is a sender the page reserve cannot see.
	// The knobs keep the PLATFORM_ALERTS_PUSH_BUDGET* names; their scope is now
	// the server host, shared across the product and platform routes.
	srv.pushBudgets = notify.NewPushBudgets(
		alertwebhook.ParseCount(os.Getenv(alertwebhook.EnvPushBudget),
			alertwebhook.DefaultPushBudget, alertwebhook.EnvPushBudget, alertWebhookLog),
		alertwebhook.ParseCount(os.Getenv(alertwebhook.EnvPushBudgetPageReserve),
			alertwebhook.DefaultPageReserve, alertwebhook.EnvPushBudgetPageReserve, alertWebhookLog),
		nil)
	srv.notifier.SetPushBudgets(srv.pushBudgets)
	srv.notifyCfg = newNotifyConfigStore(envOr("NOTIFY_CONFIG_FILE", "/data/notify_config.json"), srv)
	// VMALERT-WEBHOOK-BEGIN — the vmalert delivery path. Must come after the
	// notifier is on srv (it is the fan-out target).
	srv.vmalertWebhookMetrics = alertwebhook.NewMetrics()
	if token := strings.TrimSpace(os.Getenv(alertwebhook.EnvToken)); token == "" {
		// LOUD, not silent (§10): with no shared secret the receiver stays
		// unregistered, which means vmalert's alerts go nowhere again — the
		// exact condition this module exists to end. Name the variable so the
		// fix is one line away.
		logWarn("alertwebhook", "vmalert alert delivery is DISABLED: "+alertwebhook.EnvToken+" is unset — "+
			"vmalert rules will fire and nothing will be delivered to any notification channel", map[string]any{
			"env":      alertwebhook.EnvToken,
			"endpoint": alertwebhook.AlertsPath,
		})
	} else {
		hostRoute, hostServer := platformAlertsHostRoute()
		h, err := alertwebhook.Handler(alertwebhook.Deps{
			Dispatcher: srv.notifier,
			HostRoute:  hostRoute,
			// The SHARED bucket, keyed by the server this route actually talks
			// to. Without it this route's page reserve could not see the
			// product channel's traffic against the same ntfy server — the
			// 2026-09-03 defect.
			Budgets:    srv.pushBudgets,
			HostServer: hostServer,
			Token:      token,
			Cooldown:   alertwebhook.ParseCooldown(os.Getenv(alertwebhook.EnvCooldown), alertWebhookLog),
			// Noise + rate-limit control (2026-09-03): the warning tier is
			// summarized into one push per window instead of buzzing per alert,
			// and the outbound budget reserves capacity so a chronic warning can
			// never spend the token a page needs. Env is read HERE and the
			// values injected — the package stays env-free.
			WarningDigestInterval: alertwebhook.ParseDigestInterval(os.Getenv(alertwebhook.EnvWarningDigestInterval), alertWebhookLog),
			PushBudget: alertwebhook.ParseCount(os.Getenv(alertwebhook.EnvPushBudget),
				alertwebhook.DefaultPushBudget, alertwebhook.EnvPushBudget, alertWebhookLog),
			PageReserve: alertwebhook.ParseCount(os.Getenv(alertwebhook.EnvPushBudgetPageReserve),
				alertwebhook.DefaultPageReserve, alertwebhook.EnvPushBudgetPageReserve, alertWebhookLog),
			Metrics: srv.vmalertWebhookMetrics,
			Log:     alertWebhookLog,
		})
		if err != nil {
			logError("alertwebhook", "vmalert webhook receiver could not be built — NO vmalert alert will be delivered", errf(err))
		} else {
			srv.vmalertWebhook = h
		}
	}
	// VMALERT-WEBHOOK-END
	srv.ldap = newLDAPConfigStore(envOr("LDAP_CONFIG_FILE", "/data/ldap_config.json"), vault)
	srv.tacacs = newTACACSConfigStore(envOr("TACACS_CONFIG_FILE", "/data/tacacs_config.json"), vault)
	srv.tokenPolicy = newTokenPolicyStore(envOr("TOKEN_POLICY_FILE", "/data/token_policy.json"), refresh)
	// Security Policy engine (#24): deterministic System→Tenant→Role→User
	// resolution of NIST-aligned controls. The store (Phase 2) is the engine's
	// persistence Source; the handlers (Phase 3, policy_http.go) expose the
	// catalog, the effective-policy/simulator view, and per-scope editing.
	srv.secPolicy = policy.NewSecurityStore(envOr("SECURITY_POLICY_FILE", "/data/security_policies.json"), platformKV{}, logError)
	// SSO/OIDC: runtime-configurable overlay over the env defaults. The store
	// builds the initial live provider into the atomic pointer and swaps it on
	// every admin save (see oidc_config.go).
	srv.oidcCfg = newOIDCConfigStore(envOr("OIDC_CONFIG_FILE", "/data/oidc_config.json"), srv)
	srv.oidc.Store(oidc.NewProviderFromConfig(srv.oidcCfg.effective(), jwksTTL()))
	srv.ssoTxns = newSSOTxnStore()
	srv.wsTickets = wsticket.NewStore()
	// GUI-configurable SSO (Keycloak side): the desired-state IdP store plus the
	// admin client that reconciles it into the bundled broker (internal/ssoidp +
	// internal/keycloak; HTTP boundary + apply path in oidc_config.go). Env is
	// read HERE (wiring layer) and injected; the packages stay env-free.
	ssoSeal, ssoOpen := ssoIdPSecretXforms(vault)
	srv.ssoIdPCfg = ssoidp.NewStore(envOr("SSO_IDP_CONFIG_FILE", "/data/sso_idp_config.json"), ssoidp.Deps{
		Seal:               ssoSeal,
		Open:               ssoOpen,
		RoleValid:          func(role string) bool { _, ok := srv.roles.Get(role); return ok },
		AllowPlatformOwner: func() bool { return os.Getenv("FEDERATION_ALLOW_PLATFORM_OWNER") == "true" },
		Errorf:             logError,
	})
	srv.kc = keycloak.New(keycloak.Config{
		BaseURL:       envOr("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080/auth"),
		AdminUser:     os.Getenv("KEYCLOAK_ADMIN"),
		AdminPassword: os.Getenv("KEYCLOAK_ADMIN_PASSWORD"),
		Realm:         envOr("KEYCLOAK_REALM", "correlix"),
	})
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
		"discovery",                // discovery.DiscoveryAggregator.Start → per-source pollLoop + vendorLoop
		"entity-resolver-enrich",   // server.startEntityResolverEnrichment
		"fusion-worker",            // fusionWorker.start
		"incident-time-backfill",   // server.startIncidentTimeMetricsBackfill (CH writes)
		"itsm-drift-reconciler",    // server.startDriftReconciler → safeGo
		"netbox-sync",              // netboxSyncer.Start (writes INTO NetBox)
		"ngfw-appid-refresh",       // ngfwAppResolver.startRefresh
		"path-baseline-precompute", // server.startPathBaselinePrecompute (CH writes)
		"path-graph-enrich",        // server.startPathGraphEnrichment
		"path-graph-ingest",        // server.startPathGraphIngest (CH/PG writes)
		"pipeline-processors",      // server.startProcessorsConfigWriter (ticker + mutation kicks)
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

// newTicketingStore picks the backend: an RLS-scoped pg repository under
// STORE_BACKEND=postgres, else an in-memory store. Always non-nil.
func newTicketingStore() ticketing.Store {
	if ps, ok := platformdb.ActivePG(); ok {
		return ticketing.NewPGStore(ps.DB())
	}
	return ticketing.NewMemStore()
}

// newPathGraphStore picks the backend: pg registries + ClickHouse streams under
// STORE_BACKEND=postgres, else in-memory (with env-tunable retention).
func newPathGraphStore() pathgraph.Store {
	if ps, ok := platformdb.ActivePG(); ok {
		return pathgraph.NewPGCHStore(ps.DB(), chSeam{})
	}
	st := pathgraph.NewMemStoreWithRetention(envInt("PATH_GRAPH_MEM_RETENTION", pathgraph.DefaultObsRetention))
	st.SetInfof(func(msg string, fields map[string]any) { logInfo("pathgraph", msg, fields) })
	return st
}

// chSeam adapts main's ClickHouse plumbing to pathgraph.CH. Exec preserves the
// no-ClickHouse-configured → no-op semantics the purge relied on.
type chSeam struct{}

func (chSeam) InsertJSON(ctx context.Context, table, scope string, rows []map[string]any) error {
	return chInsertJSON(ctx, table, scope, rows)
}
func (chSeam) Select(ctx context.Context, scope, sql, comment string) ([]map[string]any, error) {
	return chSelect(ctx, scope, sql, comment)
}
func (chSeam) Exec(sql string) error {
	base := envOr("CLICKHOUSE_URL", "")
	if base == "" {
		return nil
	}
	if msg := chExecErr(base, sql); msg != "" {
		return errors.New(msg)
	}
	return nil
}

// newCloudStore picks the backend: RLS-scoped pg under STORE_BACKEND=postgres,
// else in-memory (both enforce §3a tenant isolation in the store itself).
func newCloudStore() cloud.Store {
	if ps, ok := platformdb.ActivePG(); ok {
		return cloud.NewPGStore(ps.DB())
	}
	return cloud.NewMemStore()
}

// newCloudConnStore picks the connector-credential backend: only the RLS-scoped
// pg repository qualifies — credentials must not live only in RAM.
func newCloudConnStore() cloudconn.Repo {
	if ps, ok := platformdb.ActivePG(); ok {
		return cloudconn.NewPGStore(ps.DB())
	}
	logWarn("cloud", "cloud connectors disabled: durable storage required", map[string]any{
		"reason": "STORE_BACKEND is not postgres; credentials would live only in RAM",
	})
	return nil
}

// newBusinessServiceStore: Business Service Observability is Postgres-only
// (nil on the file backend — handlers 503 with a clear message).
func newBusinessServiceStore() *cloud.BizSvcStore {
	if ps, ok := platformdb.ActivePG(); ok {
		return cloud.NewBizSvcStore(ps.DB())
	}
	return nil
}

// newApplicationStore picks the Applications registry backend EXPLICITLY
// (tracker 245). There is no file implementation for this registry, and the old
// "else in-memory" fallback made that invisible: on the file backend — the
// packaged default at the time — an operator could create an application, see
// it listed, and lose it on the next api restart, with nothing in the API or the
// Registries page able to say why.
//
// The three cases are now closed:
//   - postgres → the RLS-scoped durable store (the authoritative backend);
//   - memory   → the ephemeral store, reachable ONLY by an explicit
//     STORE_BACKEND=memory (a development/test mode that says so);
//   - file     → nil. The registry is UNSUPPORTED on this backend and the
//     handlers refuse with 501 + a machine-readable code instead of
//     acknowledging writes nothing durable will keep.
//
// A nil store is never a Postgres-outage state: a configured-postgres process
// fails its boot when the database is unreachable (initStoreBackend), so a
// running api on the postgres backend always has the pg store — an outage
// AFTER boot surfaces as 503 from the handlers, never as a silent switch to
// another backend.
func newApplicationStore() appid.AppStore {
	switch platformdb.Kind() {
	case platformdb.KindPostgres:
		ps, ok := platformdb.ActivePG()
		if !ok {
			// Unreachable in practice (Kind and active are set together); a
			// wrong answer here would resurrect the silent-fallback bug, so it
			// is loud and unsupported rather than quietly ephemeral.
			logError("store", "applications registry unavailable: postgres backend selected but no pg store is active", nil)
			return nil
		}
		logInfo("store", "applications registry storage", map[string]any{
			"backend": platformdb.KindPostgres, "persistent": true,
		})
		return appid.NewPGAppStore(ps.DB())
	case platformdb.KindMemory:
		logWarn("store", "applications registry storage is EPHEMERAL — records are lost on restart", map[string]any{
			"backend": platformdb.KindMemory, "persistent": false,
		})
		return appid.NewMemAppStore()
	default:
		logWarn("store", "applications registry unavailable", map[string]any{
			"configured_backend": platformdb.Kind(), "reason": "backend_not_supported",
		})
		return nil
	}
}

// newIncidentTimelineStore picks the incident-timeline backend: RLS-scoped pg
// under STORE_BACKEND=postgres, else in-memory.
func newIncidentTimelineStore() timeintel.TimelineStore {
	if ps, ok := platformdb.ActivePG(); ok {
		return timeintel.NewPGTimelineStore(ps.DB())
	}
	return timeintel.NewMemTimelineStore()
}

// devicesPath resolves the manual-device store location (env-overridable).
func devicesPath() string {
	if p := strings.TrimSpace(os.Getenv("DEVICES_STORE_PATH")); p != "" {
		return p
	}
	return "/data/devices.json"
}

// MONITORING-BEGIN — the composition-root adapters for the per-device
// monitoring switch (C4). Wiring only: the POLICY is internal/devmon and the
// STATE is internal/discovery, and neither knows this file exists.

// monitoredOnly narrows a device-list source to the devices Correlix collects
// from. Anything that REACHES a device on a schedule reads through this, so a
// device nobody enabled is never probed — the licence counts the monitored set,
// and the monitored set is what the platform must actually touch.
func monitoredOnly(all func() []models.Device) func() []models.Device {
	return func() []models.Device {
		devs := all()
		out := make([]models.Device, 0, len(devs))
		for _, d := range devs {
			if d.Monitored {
				out = append(out, d)
			}
		}
		return out
	}
}

// devmonGate adapts the platform's permission gate to the monitoring module's
// seam. Monitoring is device state, so it takes exactly the gate the device
// routes take — infrastructure:read to look, infrastructure:write to change —
// and reports the caller's tenant scope so the module can 404 a device the
// caller may not see.
func (s *server) devmonGate(w http.ResponseWriter, r *http.Request, level int) (devmon.Principal, bool) {
	claims, ok := s.requirePerm(w, r, "infrastructure", level)
	if !ok {
		return devmon.Principal{}, false
	}
	tenant, cross := principalTenant(claims)
	return devmon.Principal{Subject: claims.Sub, Tenant: tenant, CrossTenant: cross}, true
}

// deviceMonitorStore persists the monitoring decisions on the §3a tenant-scoped
// kv primitive, and adapts it to the registry's MonitorStore seam.
//
// The primitive is default-closed by construction: records are keyed
// (tenant, device id) and there is no unscoped list except the one the REGISTRY
// takes at boot to seed itself — the same platform-wide read DeviceStore.Devices
// already performs, and for the same reason (the registry is the platform's
// device state, not one tenant's view of it).
type deviceMonitorStore struct{ kv *tenantKV[devmon.Record] }

func newDeviceMonitorStore(path string) (*deviceMonitorStore, error) {
	kv, err := newTenantKV[devmon.Record](path,
		func(r devmon.Record) string { return r.TenantID },
		func(r devmon.Record) string { return r.DeviceID })
	if err != nil {
		return nil, err
	}
	return &deviceMonitorStore{kv: kv}, nil
}

// MonitorRecords is the boot-time seed (see the type comment).
func (s *deviceMonitorStore) MonitorRecords() []devmon.Record { return s.kv.All("", true) }

// PutMonitor persists one decision. The caller (the registry) has already
// stamped the owning tenant from the device record.
func (s *deviceMonitorStore) PutMonitor(rec devmon.Record) error { return s.kv.Upsert(rec) }

// DeleteMonitor removes a device's decision, scoped to the tenant that owns it —
// never cross-tenant, so a delete can only ever reach the record it was asked
// about. An absent record is not an error: the caller is deleting the device and
// the decision is already gone.
func (s *deviceMonitorStore) DeleteMonitor(tenant, deviceID string) error {
	s.kv.Delete(tenant, false, deviceID)
	return nil
}

// MONITORING-END

// newDeviceStore wires the manual-device store onto the platform kv + logger.
// When the active backend supports per-record persistence (both production
// backends do), the store gets the prefix capability and writes O(1) records
// per Put/Remove instead of the whole fleet (GA scale P0); otherwise it keeps
// the whole-blob path.
func newDeviceStore(path string) *discovery.DevStore {
	if _, ok := platformdb.ActivePrefix(); ok {
		return discovery.NewDevStore(path, platformPrefixKV{}, logError)
	}
	return discovery.NewDevStore(path, platformKV{}, logError)
}

// newSavedStore selects the saved-objects backend: RLS-scoped pg under
// STORE_BACKEND=postgres, else the file store on the platform kv.
func newSavedStore(path string) (saved.Repo, error) {
	if ps, ok := platformdb.ActivePG(); ok {
		return saved.NewPGStore(ps.DB(), logError), nil
	}
	return saved.NewFileStore(path, platformKV{})
}

// newTopologyStore picks the graph-store backend: RLS-scoped pg under
// STORE_BACKEND=postgres, else in-memory.
func newTopologyStore() topology.GraphStore {
	if ps, ok := platformdb.ActivePG(); ok {
		return topology.NewPGStore(ps.DB())
	}
	return topology.NewMemStore()
}

// newAIFeedbackStore picks the copilot-feedback backend: RLS-scoped pg under
// STORE_BACKEND=postgres, else in-memory.
func newAIFeedbackStore() ai.FeedbackStore {
	if ps, ok := platformdb.ActivePG(); ok {
		return ai.NewPGFeedbackStore(ps.DB())
	}
	return ai.NewMemFeedbackStore()
}

// newSelfHealer wires the ingest self-healer onto env config + the platform
// mTLS-aware HTTP client and structured logs.
func newSelfHealer(notifier *notify.Dispatcher) *selfheal.Healer {
	clearPct := 90
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv("SELF_HEAL_CLEAR_PCT"))); err == nil && v > 0 && v < 100 {
		clearPct = v
	}
	return selfheal.NewHealer(notifier, selfheal.Config{
		OSURL:    envOr("OPENSEARCH_URL", "http://opensearch:9200"),
		DiskPath: envOr("SELF_HEAL_DISK_PATH", "/data"),
		ClearPct: clearPct,
		Enabled:  strings.ToLower(strings.TrimSpace(os.Getenv("SELF_HEAL"))) != "false",
		HTTP:     backendHTTPClient,
		Infof:    logInfo,
		Errorf:   logError,
	})
}

// initStoreBackend selects the store backend from STORE_BACKEND; env stays
// here, the machinery lives in internal/platformdb.
//
// DEFAULTS (tracker 245). New normal installations are generated with
// STORE_BACKEND=postgres — that is the PRODUCT default, written explicitly by
// scripts/install.py into deployment/docker/.env. The BINARY's unset default
// stays "file" on purpose: an existing install whose configuration is lost or
// not yet migrated must keep reading the registry data it already has on the
// data volume, not silently start serving an empty Postgres. An unset variable
// is therefore "the historical compatibility backend", never "guess postgres".
//
// There is NO failover between backends: the selection is made once, here, and
// holds for the life of the process. A configured-postgres deployment whose
// database is unreachable fails its boot loudly (below) rather than writing
// authoritative state into files or RAM that nothing would ever reconcile.
func initStoreBackend() error {
	platformdb.SetLoggers(logInfo, logWarn, logError)
	switch strings.ToLower(strings.TrimSpace(os.Getenv("STORE_BACKEND"))) {
	case "", "file":
		platformdb.UseFile()
		// Anchor RELATIVE store keys (the vault's wrapped-keys file) on the
		// data volume — unanchored they resolved against the distroless CWD
		// and sealing custody could not persist on the file backend at all
		// (CI tls-boot find, 2026-08-12).
		platformdb.SetFileRoot(envOr("DATA_DIR", "/data"))
		logInfo("store", "state backend selected", map[string]any{
			"backend": platformdb.KindFile, "persistent": true,
		})
		return nil
	case "postgres", "postgresql", "pg":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := platformdb.UsePostgres(ctx, os.Getenv("DATABASE_URL")); err != nil {
			return err
		}
		logInfo("store", "state backend selected", map[string]any{
			"backend": platformdb.KindPostgres, "persistent": true,
		})
		return nil
	case "memory", "mem":
		// Explicit ephemeral mode: development and tests only. It is never a
		// fallback and never a packaged default — reaching it takes deliberately
		// setting STORE_BACKEND=memory, and it says so on every boot.
		platformdb.UseMemory()
		logWarn("store", "state backend is EPHEMERAL — nothing persists across a restart (STORE_BACKEND=memory)",
			map[string]any{"backend": platformdb.KindMemory, "persistent": false})
		return nil
	default:
		// A typo (STORE_BACKEND=postgress) must abort, never silently select
		// file or memory: a misconfigured persistent deployment that comes up on
		// the wrong backend is exactly the failure tracker 245 closes.
		return fmt.Errorf("unknown STORE_BACKEND %q (want postgres|file|memory)", os.Getenv("STORE_BACKEND"))
	}
}

// importDomainCollections is the WIRING for the one-time file→Postgres import
// of every collection whose Postgres target is a normalized DOMAIN table.
//
// It is a list, not logic: each entry names the collection, the file under
// IMPORT_FILE_STATE_DIR, and the owning package's own Count/Import pair. The
// mechanism (the at-most-once marker, the skipped-populated decision, the
// row-count verification, the fail-the-boot contract) lives in
// platformdb.ImportCollections; the ROW SHAPE lives in the owning package,
// which is the only place that knows it.
//
// The file names are the stores' DEFAULT basenames. A deployment that moved a
// store with its own env knob is out of scope by construction — the same
// contract the blob-key importer has always had, and it is stated in
// docs/DEPLOY_POSTGRES_APPSTATE.md rather than guessed at here.
//
// No-op unless IMPORT_FILE_STATE_DIR is set AND the Postgres backend is active.
func importDomainCollections() error {
	dir := strings.TrimSpace(os.Getenv("IMPORT_FILE_STATE_DIR"))
	if dir == "" {
		return nil
	}
	ps, ok := platformdb.ActivePG()
	if !ok {
		return nil // file/memory backend: the files ARE the store
	}
	// Bounded like every other boot step (§9). Generous, because this runs once,
	// before the listener opens, over an install's whole durable state.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	return platformdb.ImportCollections(ctx, dir, domainImportCollections(ps.DB()))
}

// domainImportCollections is the list itself, split from the wiring above so a
// guard test can inspect it without a database: no collection name may collide
// with a blob-key basename (they would share an import marker and the second
// one would silently never run).
func domainImportCollections(db *platformdb.DB) []platformdb.Collection {
	return []platformdb.Collection{
		{
			Name: "dem_targets", File: "dem_targets.json",
			Count:  func(c context.Context) (int, error) { return dem.CountRows(c, db) },
			Import: func(c context.Context, raw []byte) (int, error) { return dem.ImportFile(c, db, raw) },
		},
		{
			Name: "dem_experience", File: "dem_experience.json",
			Count:  func(c context.Context) (int, error) { return experience.CountRows(c, db) },
			Import: func(c context.Context, raw []byte) (int, error) { return experience.ImportFile(c, db, raw) },
		},
		{
			Name: "iris_investigations", File: "iris_investigations.json",
			Count:  func(c context.Context) (int, error) { return ai.CountInvestigationRows(c, db) },
			Import: func(c context.Context, raw []byte) (int, error) { return ai.ImportInvestigationFile(c, db, raw) },
		},
		{
			Name: "config_backup_versions", File: "config_backup_versions.json",
			Count:  func(c context.Context) (int, error) { return configstore.CountRows(c, db) },
			Import: func(c context.Context, raw []byte) (int, error) { return configstore.ImportFile(c, db, raw) },
		},
		{
			Name: "config_drift_state", File: "config_drift_state.json",
			Count:  func(c context.Context) (int, error) { return configdrift.CountRows(c, db) },
			Import: func(c context.Context, raw []byte) (int, error) { return configdrift.ImportFile(c, db, raw) },
		},
		{
			Name: "security_control_plane", File: "security_control_plane.json",
			Count:  func(c context.Context) (int, error) { return secapi.CountControlPlaneRows(c, db) },
			Import: func(c context.Context, raw []byte) (int, error) { return secapi.ImportControlPlaneFile(c, db, raw) },
		},
		{
			Name: "security_frameworks", File: "security_frameworks.json",
			Count:  func(c context.Context) (int, error) { return secapi.CountFrameworkRows(c, db) },
			Import: func(c context.Context, raw []byte) (int, error) { return secapi.ImportFrameworkFile(c, db, raw) },
		},
		{
			Name: "bgp_watchlist", File: "bgp_watchlist.json",
			Count:  func(c context.Context) (int, error) { return bgpwatch.CountWatchlistRows(c, db) },
			Import: func(c context.Context, raw []byte) (int, error) { return bgpwatch.ImportWatchlistFile(c, db, raw) },
		},
		{
			Name: "bgp_alert_policy", File: "bgp_alert_policy.json",
			Count:  func(c context.Context) (int, error) { return bgpwatch.CountPolicyRows(c, db) },
			Import: func(c context.Context, raw []byte) (int, error) { return bgpwatch.ImportPolicyFile(c, db, raw) },
		},
		{
			Name: "maintenance_windows", File: "maintenance_windows.json",
			Count:  func(c context.Context) (int, error) { return maintenance.CountRows(c, db) },
			Import: func(c context.Context, raw []byte) (int, error) { return maintenance.ImportFile(c, db, raw) },
		},
		{
			Name: "pcap_captures", File: "pcap_captures.json",
			Count:  func(c context.Context) (int, error) { return pcap.CountRows(c, db) },
			Import: func(c context.Context, raw []byte) (int, error) { return pcap.ImportFile(c, db, raw) },
		},
		{
			Name: "pipeline_processors", File: "pipeline_processors.json",
			Count:  func(c context.Context) (int, error) { return processors.CountRows(c, db) },
			Import: func(c context.Context, raw []byte) (int, error) { return processors.ImportFile(c, db, raw) },
		},
		{
			Name: "rca_feedback", File: "rca_feedback.json",
			Count:  func(c context.Context) (int, error) { return rcafeedback.CountRows(c, db) },
			Import: func(c context.Context, raw []byte) (int, error) { return rcafeedback.ImportFile(c, db, raw) },
		},
		{
			Name: "tac_templates", File: "tac_templates.json",
			Count:  func(c context.Context) (int, error) { return tac.CountTemplateRows(c, db) },
			Import: func(c context.Context, raw []byte) (int, error) { return tac.ImportTemplateFile(c, db, raw) },
		},
		{
			// The metering history lives BESIDE the licence, under /data/api —
			// one operational object an operator copies out whole. It is the one
			// collection whose file is not at the top of the import dir.
			Name: "metering_daily", File: "api/metering.json",
			Count:  func(c context.Context) (int, error) { return metering.CountRows(c, db) },
			Import: func(c context.Context, raw []byte) (int, error) { return metering.ImportFile(c, db, raw) },
		},
	}
}

// Run is the backend entrypoint: cmd/api/main.go calls it. It owns flag/env
// resolution, wiring and the serve loop — /cmd stays logic-free (§2).
func Run() {
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
	// OS-VERSION SOURCE LADDER — wired here, before the discovery loops start,
	// so the first enrichment tick already has its rungs (see vulns_http.go).
	srv.buildOSVersionLadder()
	srv.discovery.Start(ctx)
	srv.netboxSync.Start(ctx)
	srv.collectors.Start(ctx)
	// Credential sentinel — self-healing SNMP credential resolution. Runs with
	// SNMP collection; CRED_AUTO_RESOLVE=false opts out (bound refs then fail
	// dark exactly as before).
	if os.Getenv("ENABLE_SNMP_COLLECTION") == "true" && os.Getenv("CRED_AUTO_RESOLVE") != "false" {
		workers.start("cred-sentinel", func() { srv.credSentinel.Run(ctx) })
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
	srv.startProcessorsConfigWriter(ctx) // item 121: rules → router processors.yaml
	// Bounded growth for the Postgres audit trail (F-57). Opt-in and OFF by
	// default — an audit trail is evidence; only an operator decides how long
	// it is kept. No-op unless AUDIT_RETENTION_DAYS is a positive integer and
	// the Postgres backend is active (the file backend self-bounds).
	if ps, ok := platformdb.ActivePG(); ok && ps != nil {
		// The platform-global config changes keep their own, longer floor under
		// the general horizon (tracker 235) — the same policy the file backend's
		// retained trail uses, so the two backends promise the same thing.
		audit.StartRetention(ctx, ps.DB(),
			audit.ParseRetentionDays(os.Getenv("AUDIT_RETENTION_DAYS")),
			audit.ParseTrailPolicy(os.Getenv(audit.EnvTrailDays), os.Getenv(audit.EnvTrailMaxEvents)).Days)
	}
	// Self-heal the ClickHouse tenant row policies (#20 Phase 2) in the background.
	ensureCHRowPolicies()
	// corr_current projection drift repair (#101): detect + re-seed hot-read rows
	// whose dual-write was lost. No-op when ClickHouse is not configured.
	workers.start("corr-current-reconcile", func() { srv.corrCurrentReconcileLoop(ctx) })
	// ITSM drift reconciler (#43 enhancement). No-op unless FEATURE_ITSM_RECONCILE.
	srv.startDriftReconciler(ctx)
	// App-identity catalog hot-reload (#81 P1b). No-op unless APPID_FEEDS_DIR set.
	srv.appCatalog.StartRefresh(ctx, time.Duration(envInt("APPID_REFRESH_MINUTES", 360))*time.Minute)
	// NGFW app-id overlay refresh (#81 P-NGFW pt2): aggregate firewall app-id events
	// from OpenSearch into the resolver. Harmless empty map if no firewall onboarded.
	srv.ngfw.startRefresh(ctx)
	// Cloud App Observability inventory (#81 P3A): load fixtures into the store.
	// No-op unless CLOUD_FIXTURES_DIR set (real per-tenant SDK connectors come later).
	srv.startCloudInventory(ctx)
	// Appliance self-health guard: watches disk + OpenSearch read-only blocks,
	// heals ingest after disk pressure, pages via the platform lane (self_heal.go).
	workers.start("self-heal", func() { srv.selfHeal.Run(ctx) })
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
	srv.cloudApp.StartRefresh(ctx)
	// Application Identity Fusion worker (#81 P4): pull vendor app events → adapters →
	// observations → fuse → persist app_observations/app_identities. Opt-in + default-off
	// (FUSION_WORKER_ENABLED=true) so it never runs unasked; metrics at /api/appid/fusion/status.
	srv.fusion = newFusionWorker(openSearchSource{})
	if envOr("FUSION_WORKER_ENABLED", "") == "true" {
		srv.fusion.start(ctx)
	}
	// BGP-WATCH-BEGIN — the BGP watchlist evaluator (tracker #5/#10): per
	// tenant, on a bounded jittered ticker, classifying each watched prefix and
	// emitting notifications + evidence on the TRANSITIONS. Opt-in and
	// default-off (FEATURE_BGP_ALERTS=true); with the flag off nothing was
	// constructed above and no worker starts here.
	if srv.bgpWatchEval != nil {
		eval := srv.bgpWatchEval
		workers.start("bgp-watch", func() { eval.Run(ctx) })
	}
	// BGP-WATCH-END
	// CONFIG-BACKUP-BEGIN — Config Backup & Drift (P3-CFG): capture over the SSH
	// gateway → sealed, content-addressed version store → drift verdict →
	// ConfigDrift finding onto netops.security. Opt-in and default-off; with the
	// flag off NOTHING is constructed, started or routed.
	if envBool(configstore.EnvFeatureFlag) {
		if err := srv.buildConfigBackup(); err != nil {
			// Fail LOUD, not silently dormant: the operator asked for backups.
			logError("config.backup", "config backup could not be started — NO device configurations will be captured", errf(err))
		} else {
			workers.start("config-backup", func() { srv.configBackup.Run(ctx) })
		}
	}
	// CONFIG-BACKUP-END
	// SECURITY-LANE-BEGIN — Security evidence producer (Project 3, P3-EMIT):
	// hardening + vendor-advisory + threat detections → secbus.FromFinding →
	// netops.security, per tenant, on a bounded jittered ticker. Opt-in and
	// default-off (FEATURE_SECURITY_LANE=true); with the flag off NOTHING is
	// constructed, started or routed.
	//
	// ORDER IS LOAD-BEARING, and this is where it was got wrong (lab, 2026-09-03).
	// securityLaneDeps() RESOLVES Deps.ConfigSource ONCE, here, by calling
	// configHardeningSource() — which reads s.configDrift. This block used to sit
	// ABOVE the CONFIG-BACKUP block that assigns that field, so the lane captured
	// a nil ConfigSource on every boot and every §5e hardening rule reported
	// "running-config unavailable — control not assessed (fail-closed)" even
	// though the lab spines each had a captured, unsealable running-config on
	// file. The lane MUST be constructed after every module whose value it
	// injects; keep it BELOW config backup.
	if envBool(seclane.EnvFeatureFlag) {
		lane, err := seclane.New(srv.securityLaneDeps())
		if err != nil {
			// Fail LOUD, not silently dormant: the operator asked for the lane.
			logError("security.lane", "security evidence lane could not be constructed — NOTHING will be emitted",
				errf(err))
		} else {
			srv.securityLane = lane
			workers.start("security-lane", func() { lane.Run(ctx) })
		}
	}
	// SECURITY-LANE-END
	// PACKET-CAPTURE-BEGIN — Packet Capture: bounded, per-interface, on-device
	// capture over the SSH gateway → sealed capture store. There is NO scheduler
	// and NO worker: every capture is an explicit, audited operator action.
	// Opt-in and default-off; with the flag off NOTHING is constructed or routed.
	if envBool(pcap.EnvFeatureFlag) {
		if err := srv.buildPacketCapture(); err != nil {
			// Fail LOUD, not silently dormant: the operator asked for capture.
			logError("pcap", "packet capture could not be started — NO captures will be possible", errf(err))
		}
	}
	// PACKET-CAPTURE-END
	// SNAPSHOT-RESTORABILITY-BEGIN — the nightly restorability probe. It
	// RESTORES the smallest index out of the newest SUCCESS snapshot into a
	// disposable probe-* index and compares doc counts, then deletes it. This is
	// the only thing in the platform that can distinguish "a snapshot exists"
	// from "a snapshot can be restored" — the distinction the 2026-08-27
	// incident turned on. Bounded, jittered off the 01:30 snapshot window, and
	// killable with SNAPSHOT_PROBE_ENABLED=false (in which case the metric says
	// so rather than reporting a fake pass).
	workers.start("snapshot-restorability-probe", func() { srv.dataProtect.StartRestorabilityProbe(ctx) })
	// STORAGE-MEASUREMENT-BEGIN — the sampler. The /metrics scrape formats this
	// worker's CACHE and never probes a store itself: a scrape that runs
	// `system.parts` is a scrape that times out under load.
	workers.start("storage-measurement-sampler", func() { srv.storageMeter.RunSampler(ctx) })
	// STORAGE-MEASUREMENT-END
	// METERING-BEGIN — the hourly usage snapshot (tracker 258). It takes one
	// reading immediately and then every hour: immediately, because otherwise
	// the staleness rule spends its first hour unable to tell "just booted" from
	// "stopped recording". It joins the drain group, so a snapshot in flight at
	// shutdown finishes its write instead of being abandoned mid-file.
	//
	// A failed snapshot is counted and logged, never fatal: metering gates
	// nothing, so an hour missing from a roll-up costs a usage report some
	// precision and costs collection nothing at all.
	workers.start("metering-snapshot", func() {
		srv.meteringRecorder.Run(ctx, durationOr("METERING_INTERVAL", metering.DefaultInterval))
	})
	// METERING-END
	// DEM-BEGIN — publish the prober's experience work queue. Only under
	// FEATURE_DEM (the projector is nil otherwise), and the published entry
	// carries a short TTL so a prober that loses the api stops measuring a stale
	// list rather than measuring deleted targets forever.
	if srv.demProjector != nil {
		workers.start("dem-target-projector", func() { srv.demProjector.Run(ctx) })
	}
	// …and drain the run records the prober publishes back on the same channel
	// (tracker 253). Without this every check grades `unknown`, and an ungraded
	// check can never raise a high-severity experience incident.
	if srv.demRunIntake != nil {
		workers.start("dem-run-intake", func() { srv.demRunIntake.Run(ctx) })
	}
	// DEM-END
	// SNAPSHOT-RESTORABILITY-END
	// BMP-BEGIN — BGP Monitoring Protocol receiver (internal/bmp): a TCP
	// listener a router pushes its Adj-RIB-In to. READ-ONLY toward the network —
	// it accepts a feed and configures nothing on any device. Opt-in and
	// default-off; with the flag off NO port is bound, no goroutine starts and
	// the three read routes answer 404.
	if envBool(bmp.EnvFeatureFlag) {
		api, err := srv.buildBMP()
		if err != nil {
			// Fail LOUD, not silently dormant: the operator asked for the feed.
			logError("bmp", "BMP receiver could not be constructed — NO router feed will be received", errf(err))
		} else {
			srv.bmpAPI = api
			// TRACKED worker (not a fire-and-forget goroutine): shutdown WAITS
			// for the receiver, and Listener.Run closes the bound socket and
			// every live connection when ctx is cancelled.
			workers.start("bmp-receiver", func() { srv.bmpAPI.Run(ctx) })
		}
	}
	// BMP-END
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
		if ps, ok := platformdb.ActivePG(); ok {
			renderer, err := reports.NewHTMLRenderer()
			if err != nil {
				log.Fatalf("report renderer: %v", err)
			}
			srv.reportPipeline = newReportPipeline(srv,
				reports.NewPGJobQueue(ps.DB(), 5), reports.NewPGExecStore(ps.DB()), newKVArtifactStore(), renderer,
				reports.NewPGDeliveryStore(ps.DB()))
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
		resolve := func(_ context.Context, tenant, system string) (ticketing.SystemConfig, bool, error) {
			if srv.itsmCfg == nil {
				return ticketing.SystemConfig{}, false, nil
			}
			cfg, ok := srv.itsmCfg.SystemConfigFor(tenant, system)
			return cfg, ok, nil
		}
		tw := ticketing.NewWorker(srv.ticketing, resolve, func(msg string, fields map[string]any) { logWarn("ticketing", msg, fields) }, func(msg string, fields map[string]any) { logError("ticketing", msg, fields) })
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
		sy := ticketing.NewStateSyncer(srv.ticketing, resolve)
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
			return rcaNotifyTargets(srv.itsmCfg, tenant)
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
	workers.start("login-throttle-janitor", func() { srv.loginThrottle.RunJanitor(ctx) })
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
	// The CA has now written the trust bundle (and the API/nginx SVIDs), so the
	// internal-backend transport can be built for real. On the first boot of a
	// TLS-enabled deployment the earlier call deferred (backend_client.go);
	// this one fails closed exactly as it always did.
	if err := initBackendTransport(); err != nil {
		log.Fatalf("backend TLS (post-CA): %v", err)
	}

	// Opt-in TLS/mTLS (#18). Fail closed: a configured-but-broken cert/CA aborts
	// boot. Dormant (plaintext, nginx terminates ingress) when unset.
	tlsSrv, err := buildTLSServer()
	if err != nil {
		log.Fatalf("tls: %v", err)
	}
	srv.tlsSrv = tlsSrv

	// SEC-019.1: served-certificate expiry prober. The 2026-08-05 incident:
	// disk SVIDs were fresh (the reissue loop works) while clickhouse and
	// postgres SERVED expired copies loaded at their last start — invisible
	// until every client failed. Watch the wire, not the disk. Dormant on
	// the plaintext baseline, active whenever the internal mesh is
	// configured; a malformed endpoint override fails boot (a typo that
	// silently un-watches an endpoint is this feature's own failure mode).
	if os.Getenv("TLS_INTERNAL_CA") == "true" ||
		strings.TrimSpace(envOr("TLS_BACKEND_CA_FILE", os.Getenv("TLS_CLIENT_CA_FILE"))) != "" {
		prober, err := tlsprobe.New(os.Getenv("TLS_PROBE_ENDPOINTS"),
			func(msg string, fields map[string]any) { logWarn("tls", msg, fields) })
		if err != nil {
			log.Fatalf("tls peer prober: %v", err)
		}
		srv.tlsPeerProber = prober
	}

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
	}
	// Periodic SVID re-issue (#18 phase 4): re-mint + rewrite the API/nginx/mesh
	// certs at ~half the TTL. This is gated on the CA being active (caMgr != nil),
	// NOT on THIS API serving TLS (tlsSrv != nil) — the two are independent env
	// conditions. When TLS_INTERNAL_CA=true but the API sits behind a TLS-
	// terminating nginx (no TLS_CERT_FILE, so tlsSrv == nil), the CA still mints
	// SVIDs for nginx/clickhouse/postgres at boot; nesting the reissue loop under
	// tlsSrv left those certs un-renewed, so the whole mesh expired at the SVID
	// TTL (~24h) with no rotation. The loop rewrites the cert FILES on disk; each
	// consumer reloads its own.
	if caMgr != nil {
		workers.start("tls-svid-reissue", func() { caMgr.startReissueLoop(ctx) })
	}
	if srv.tlsPeerProber != nil {
		workers.start("tls-peer-probe", func() { srv.tlsPeerProber.Run(ctx) })
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
	// BGP-DEPTH-BEGIN — the feed's pollers run on their own contexts (they are
	// started lazily per tenant, long after this ctx was built), so they need an
	// explicit stop or they would keep making outbound calls during shutdown.
	if srv.bgpFeed != nil {
		srv.bgpFeed.Stop()
	}
	// BGP-DEPTH-END
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
	// Ultra 9: the device store persists tombstone hit-recency on a TTL-derived
	// cadence; the shutdown flush drains the last un-persisted window, so a
	// restart never mistakes a continuously-hit suppression for an expired one.
	// After the worker drain above, the pollers that record hits have stopped.
	srv.devStore.Close()
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

	// Same mesh-client seam as the API process: the prober's probe-event
	// forwarders POST to the Vector ingest tier, which SEC-013 moves behind
	// TLS. Fail closed like the API does — a prober that silently downgraded
	// to a bare client would recreate the 2026-08-05 defect on its lane.
	if err := initBackendTransport(); err != nil {
		log.Fatalf("prober backend TLS: %v", err)
	}
	collectors.SetMeshHTTPClient(backendHTTPClient)

	pool := collectors.NewPool(nil)
	pool.Enable("stamp-sender", os.Getenv("FEATURE_ACTIVE_PROBE") == "true")
	pool.Enable("stamp-reflector", os.Getenv("FEATURE_STAMP_REFLECTOR") == "true")
	pool.Enable("traceroute", os.Getenv("FEATURE_TRACEROUTE") == "true")
	pool.Enable("synthetics", os.Getenv("FEATURE_SYNTHETICS") == "true")
	pool.Enable("dem", envBool(dem.EnvFeatureFlag))
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
	// Security v1: read-only posture feed for the Security page (platform admin).
	mux.HandleFunc("/admin/security/posture", s.handleSecurityPosture)
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
	mux.HandleFunc("/api/auth/sso/idp", s.handleSSOIdPList)  // platform admin: configured IdPs + Keycloak ping
	mux.HandleFunc("/api/auth/sso/idp/", s.handleSSOIdPItem) // platform admin: {alias} CRUD + {alias}/test probe
	mux.HandleFunc("/api/notify/itsm", s.handleITSMConfig)   // ServiceNow/Jira config (platform-owner)
	mux.HandleFunc("/api/auth/methods", s.handleAuthMethods)
	mux.HandleFunc("/api/auth/ldap/login", s.handleLDAPLogin)
	// LICENCE-BEGIN — LDAP is in the owner's LOCKED Enterprise set. Only the
	// CONFIGURATION routes are gated, never /api/auth/ldap/login: core
	// authentication must stay reachable at every licence state, and gating a
	// login path would mean a lapsed licence could lock people out. An
	// unlicensed deployment cannot ENABLE or CHANGE LDAP; one that already has
	// it configured keeps signing in while the operator sorts the licence out.
	// Local accounts and OIDC are core and are never gated at all.
	mux.HandleFunc("/api/auth/ldap/config", s.licenceFeature(entitlement.FeatureLDAP, s.handleLDAPConfig))
	mux.HandleFunc("/api/auth/ldap/test", s.licenceFeature(entitlement.FeatureLDAP, s.handleLDAPTest))
	// LICENCE-END
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
	// BGP Operations (item 10): tenant watchlist + remote-API data spine.
	mux.HandleFunc("/api/bgp/watchlist", s.handleBGPWatchlist)
	mux.HandleFunc("/api/bgp/resource", s.handleBGPResource)
	// BGP-DEPTH-BEGIN — item 10 depth: RPKI, ASPA (honest), geofeed, the AS-path
	// graph and the near-live update feed. Registered individually so each stays
	// visible to the route-isolation ledger; /api/bgp/rpki and /api/bgp/feed are
	// the per-tenant ones (watchlist-driven), the rest are public routing facts.
	mux.HandleFunc("/api/bgp/rpki", s.handleBGPRPKI)
	mux.HandleFunc("/api/bgp/aspa", s.handleBGPASPA)
	mux.HandleFunc("/api/bgp/geofeed", s.handleBGPGeofeed)
	mux.HandleFunc("/api/bgp/aspath-graph", s.handleBGPASPathGraph)
	mux.HandleFunc("/api/bgp/feed", s.handleBGPFeed)
	// BGP-DEPTH-END
	// BGP-WATCH-BEGIN — alerting (#10), the incident classes behind it (#5) and
	// the bogon listing (#1). All three are per-tenant DATA and are registered
	// individually so each stays visible to the route-isolation ledger; a nil
	// bgpWatchAPI (construction refused) answers 404 on all three.
	mux.HandleFunc("/api/bgp/alerts", s.bgpWatchAPI.HandleAlerts)
	mux.HandleFunc("/api/bgp/alerts/config", s.bgpWatchAPI.HandleAlertConfig)
	mux.HandleFunc("/api/bgp/bogons", s.bgpWatchAPI.HandleBogons)
	// DEM-BEGIN — Digital Experience Monitoring (S17). Per-tenant data: the
	// module scopes every read and write to ONE concrete tenant and answers 404
	// for another tenant's target id.
	//
	// Registered UNCONDITIONALLY, and through *server methods rather than
	// bound method values on s.demAPI: a bound method value captures the
	// pointer AT REGISTRATION TIME, so a surface assembled after routes() runs
	// (which is what a test harness does) would be permanently unreachable. The
	// module's handlers nil-check their receiver and answer 404, so a
	// construction failure is a 404 and never an unscoped read.
	//
	// Registered as LITERALS, not as the dem.*Path constants: the route
	// isolation ledger's scanner reads these strings out of this file, and a
	// route it cannot see is a route nobody classified.
	// TestDEMRouteLiteralsMatchTheModuleConstants pins that they still agree.
	mux.HandleFunc("/api/dem/targets", s.handleDEMTargets)
	mux.HandleFunc("/api/dem/targets/", s.handleDEMTargetItem) // GET|PUT|DELETE {id}
	mux.HandleFunc("/api/dem/experience", s.handleDEMExperience)
	// The causality surface (internal/dem/experience). Same registration
	// discipline as above: literals so the isolation ledger's scanner can see
	// them, *server methods so a surface assembled after routes() runs is still
	// reachable, and a nil surface answers 404 rather than reading unscoped.
	mux.HandleFunc("/api/dem/overview", s.handleDEMOverview)
	mux.HandleFunc("/api/dem/incidents", s.handleDEMIncidents)
	mux.HandleFunc("/api/dem/incidents/", s.handleDEMIncidentItem) // {id}[/evidence|/timeline|/path]
	mux.HandleFunc("/api/dem/journeys", s.handleDEMJourneys)
	mux.HandleFunc("/api/dem/journeys/", s.handleDEMJourneyItem) // GET|PUT|DELETE {id}
	mux.HandleFunc("/api/dem/synthetics/coverage", s.handleDEMCoverage)
	mux.HandleFunc("/api/dem/changes", s.handleDEMChanges)
	mux.HandleFunc("/api/dem/data-health", s.handleDEMDataHealth)
	// DEM-END
	// BGP-WATCH-END
	// Routing-protocol diagnostics (Troubleshooting item 7).
	mux.HandleFunc("/api/troubleshoot/protocol-diagnostics/catalog", s.handleProtocolDiagCatalog)
	mux.HandleFunc("/api/troubleshoot/protocol-diagnostics/analyze", s.handleProtocolDiagAnalyze)
	mux.HandleFunc("/api/troubleshoot/protocol-diagnostics/collect", s.handleProtocolDiagCollect)
	// The "Send to TAC" bundle. The handler, its validation path and its tests
	// have always existed and the file header + openapi.go have always
	// documented the route — it was simply never registered, so a documented
	// endpoint 404'd (QA 2026-09-03, D-12). Registering it is the honest fix:
	// the alternative (deleting the documentation) would take away the only way
	// to export a capture no signature could explain, which is the case the
	// feature exists for.
	mux.HandleFunc("/api/troubleshoot/protocol-diagnostics/export", s.handleProtocolDiagExport)
	// TAC-ROUTES-BEGIN — the TAC escalation pack (protocol_diagnostics.go,
	// internal/tac). Each route is registered INDIVIDUALLY so it stays visible
	// to the route-isolation ledger; a nil tacService (embedded data failed to
	// load) answers 503 on all six. The {id} wildcard is matched ahead of the
	// broader "/api/incidents/" prefix by the mux's own specificity rule.
	mux.HandleFunc("/api/incidents/{id}/tac", s.handleTACState)
	mux.HandleFunc("/api/incidents/{id}/tac/classify", s.handleTACClassify)
	mux.HandleFunc("/api/incidents/{id}/tac/plan", s.handleTACPlan)
	mux.HandleFunc("/api/incidents/{id}/tac/collect", s.handleTACCollect)
	mux.HandleFunc("/api/incidents/{id}/tac/bundle", s.handleTACBundle)
	mux.HandleFunc("/api/incidents/{id}/tac/case", s.handleTACCase)
	// The vendor-coverage view behind Iris → Knowledge: version-pinned reference
	// data, identical for every tenant, revealing no tenant's devices.
	mux.HandleFunc("/api/troubleshoot/tac/knowledge", s.handleTACKnowledge)
	// The per-tenant COMMAND TEMPLATES (tracker 250): the sets a NOC admin saves
	// per vendor dialect and loads into the review step. Registered as LITERALS,
	// not as the tac.*Path constants, because the route-isolation ledger's
	// scanner reads these strings out of this file and a route it cannot see is
	// a route nobody classified. The two literal leaves are registered ahead of
	// the {id} pattern for the reader's benefit only — net/http already gives a
	// literal segment precedence over a wildcard.
	mux.HandleFunc("/api/tac/templates", s.handleTACTemplates)
	mux.HandleFunc("/api/tac/templates/defaults", s.handleTACTemplateDefaults)
	mux.HandleFunc("/api/tac/templates/validate", s.handleTACTemplateValidate)
	mux.HandleFunc("/api/tac/templates/", s.handleTACTemplateItem) // GET|PUT|DELETE {id}
	// TAC-ROUTES-END
	// IGP-MONITORING-BEGIN — OSPF/IS-IS advanced monitoring (Project 4 D item
	// 11, internal/igpmon). READ-ONLY over telemetry the platform already
	// collects; every response carries an honest coverage block. Each route is
	// registered individually so it stays visible to the route-isolation ledger;
	// a nil igpAPI (construction refused) answers 404 on all six.
	if api, err := s.buildIGPMon(); err != nil {
		logError("igpmon", "OSPF/IS-IS monitoring could not be wired — the routes will answer 404", errf(err))
	} else {
		s.igpAPI = api
	}
	igp := s.igpAPI.Handler()
	mux.HandleFunc("/api/protocols/ospf/adjacencies", igp)
	mux.HandleFunc("/api/protocols/ospf/summary", igp)
	mux.HandleFunc("/api/protocols/ospf/health", igp)
	mux.HandleFunc("/api/protocols/isis/adjacencies", igp)
	mux.HandleFunc("/api/protocols/isis/summary", igp)
	mux.HandleFunc("/api/protocols/isis/health", igp)
	// IGP-MONITORING-END
	// BMP-BEGIN — the live BGP feed (internal/bmp). Each route is registered
	// individually so it stays visible to the route-isolation ledger; a nil
	// bmpAPI (FEATURE_BMP off, or construction refused) answers 404 on all
	// three, so a flag-off deployment does not even enumerate the feature.
	bmpH := s.bmpAPI.Handler()
	mux.HandleFunc("/api/bgp/bmp/sessions", bmpH)
	mux.HandleFunc("/api/bgp/bmp/updates", bmpH)
	mux.HandleFunc("/api/bgp/bmp/stats", bmpH)
	// BMP-END
	// VMALERT-WEBHOOK-BEGIN — the vmalert delivery path (internal/alertwebhook).
	// SUBTREE pattern: vmalert's -notifier.url is an Alertmanager BASE url and
	// the notifier appends /api/v2/alerts, so the real request is
	// POST /api/internal/vmalert/api/v2/alerts. The handler pins that exact
	// suffix and 404s everything else in the subtree.
	//
	// Registered ONLY when the receiver was built (VMALERT_WEBHOOK_TOKEN set):
	// fail-closed, so an unconfigured stack exposes no unauthenticated fan-out
	// and the mux answers 404 rather than enumerating the feature.
	if s.vmalertWebhook != nil {
		mux.HandleFunc("/api/internal/vmalert/", s.handleVMAlertWebhook)
	}
	// VMALERT-WEBHOOK-END
	// VRF-IFACES-BEGIN — per-device interfaces grouped by routing instance
	// (frontend-wave item 4, internal/ifgroup). READ-ONLY over telemetry the
	// platform already collects, in the DEVICE's own dialect (VRF /
	// routing-instance / VPRN / VPN instance). The route is more specific than
	// the "/api/devices/" subtree above it, so ServeMux prefers it; a failed
	// build leaves the route unregistered and "/api/devices/" answers 404 for
	// the path, which is the same dormant, never-unscoped outcome.
	if api, err := s.buildIfGroup(); err != nil {
		logError("ifgroup", "interfaces-by-routing-instance could not be wired — the route will answer 404", errf(err))
	} else {
		mux.HandleFunc("/api/devices/{id}/interfaces/by-vrf", api.Handler())
	}
	// VRF-IFACES-END
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
	mux.HandleFunc("/api/alerts/episodes", s.handleAlertEpisodes)                     // tenant-scoped episode list
	mux.HandleFunc("/api/alerts/episodes/", s.handleAlertEpisodeAction)               // POST {id}/(ack|assign|mute|snooze|notes)
	mux.HandleFunc("/api/alerts/maintenance-windows", s.handleMaintenanceWindows)     // tenant-scoped planned-work windows (item 121)
	mux.HandleFunc("/api/alerts/maintenance-windows/", s.handleMaintenanceWindowByID) // GET|PUT|DELETE {id}
	mux.HandleFunc("/api/pipeline/processors", s.handleProcessors)                    // per-tenant processor rules (item 121)
	mux.HandleFunc("/api/pipeline/processors/", s.handleProcessorByID)                // GET|PUT|DELETE {id} · POST preview
	mux.HandleFunc("/api/quarantine", s.handleQuarantineList)                         // F-11 D5: sealed-quarantine metadata list (platform-owner)
	mux.HandleFunc("/api/quarantine/reattribute", s.handleQuarantineReattribute)      // F-11 D5: unseal + re-inject (platform-owner + sensitive_data:admin)
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

	// ── Security (CTEM) — Project 3 P3-API ──────────────────────────────────
	// Read surface over the per-tenant findings index plus the small mutable
	// control-plane state. Exact paths are registered BEFORE the /findings/
	// prefix so facets/trend win over the by-id route (net/http's ServeMux
	// prefers the longest registered pattern, and an exact path beats a prefix).
	// Every route is tenant-scoped through secapi's oslog.TenantIndexPattern +
	// oslog.TenantFilter chokepoint pair; see security_findings_isolation_test.go.
	// LICENCE-BEGIN — the findings LANE is the Team capability in the owner's
	// LOCKED commercial set (2026-09-04). Gated at the mux, not inside secapi,
	// for two reasons: the gate is a commercial concern and secapi is a read
	// API that must not learn about licensing, and the tenant-isolation tests
	// call these handlers DIRECTLY — so isolation keeps being tested at full
	// strength, licensed or not.
	//
	// Refusal is the structured 402 the SPA renders as an upgrade card, never a
	// broken page and never an empty list that reads as "you are clean".
	// Everything else on the security surface — posture, exposure stories,
	// hardening rules, frameworks, compliance, views — is UNGATED: the owner
	// locked "security findings", and the rest of the tiering plan is a
	// proposal, not a decision.
	mux.HandleFunc("/api/security/findings", s.licenceFeature(entitlement.FeatureSecurityFindings, s.secAPI.HandleFindings))
	mux.HandleFunc("/api/security/findings/facets", s.licenceFeature(entitlement.FeatureSecurityFindings, s.secAPI.HandleFacets))
	mux.HandleFunc("/api/security/findings/trend", s.licenceFeature(entitlement.FeatureSecurityFindings, s.secAPI.HandleTrend))
	mux.HandleFunc("/api/security/findings/", s.licenceFeature(entitlement.FeatureSecurityFindings, s.secAPI.HandleFindingByID))
	// LICENCE-END
	mux.HandleFunc("/api/security/posture", s.secAPI.HandlePosture)
	mux.HandleFunc("/api/security/exposure-stories", s.secAPI.HandleExposureStories)
	mux.HandleFunc("/api/security/exposure-stories/", s.handleSecurityExposureStory)
	mux.HandleFunc("/api/security/rules", s.secAPI.HandleRules)
	// SEC-FRAMEWORKS-BEGIN
	// Per-tenant compliance framework selection (GET|PUT) and the scorecards
	// that follow from it. Both are per-tenant DATA: the read is scoped by the
	// same index-pattern + tenant-clause chokepoint, and the write takes the
	// per-tenant administration gate with the owner stamped from the token.
	mux.HandleFunc("/api/security/frameworks", s.secAPI.HandleFrameworks)
	mux.HandleFunc("/api/security/compliance", s.secAPI.HandleCompliance)
	// SEC-FRAMEWORKS-END
	mux.HandleFunc("/api/security/views", s.secAPI.HandleViews)
	mux.HandleFunc("/api/security/views/", s.secAPI.HandleViews)
	// DEBUG-ROUTES-BEGIN
	// Pipeline debugger (design §4). requirePlatformAdmin on all four — a trace
	// reads one tenant's telemetry out of the shared stores and a log-level
	// change is stack-wide plumbing, so a tenant admin's full
	// administration:admin must NOT reach them (§3a rule 3). Every route is
	// audited by the withAudit chokepoint (all four are mutating or carry an
	// explicit pdAudit-style record) and body-capped inside the handlers.
	mux.HandleFunc("/api/debug/trace", s.debugAPI.HandleTrace)
	mux.HandleFunc("/api/debug/trace/", s.debugAPI.HandleTraceStatus)
	mux.HandleFunc("/api/debug/loglevel", s.debugAPI.HandleLogLevel)
	mux.HandleFunc("/api/debug/parsemarker", s.debugAPI.HandleParseMarker)
	mux.HandleFunc("/api/debug/stage/", s.debugAPI.HandleStage)
	// The session routes (W3, the in-GUI viewer) read the debugger's own output
	// directory: the index, one session, one MODULE LOG FILE and the redacted,
	// checksummed bundle. Same gate and the same audit as the rest of the
	// family, and for the same reason twice over — a module log file can carry
	// a tenant's own log line, so it is platform-admin material and every read
	// of one is recorded.
	mux.HandleFunc("/api/debug/sessions", s.debugAPI.HandleSessions)
	mux.HandleFunc("/api/debug/sessions/", s.debugAPI.HandleSession)
	// DEBUG-ROUTES-END
	// SECURITY-LANE-BEGIN
	s.registerSecurityLaneRoutes(mux)
	// SECURITY-LANE-END
	// CONFIG-BACKUP-BEGIN
	if s.configDrift != nil {
		mux.HandleFunc("/api/config/drift", s.configDrift.HandleDriftList)
	}
	// CONFIG-BACKUP-END
	// Parser coverage (A6). /api/admin/parser/stats is platform-GLOBAL plumbing
	// (whole-process engine counters, not a tenant's rows) and takes the
	// platform-admin gate; the two /api/telemetry routes are per-tenant DATA,
	// read through oslog.TenantIndexPattern + TenantFilter. The propose route
	// APPLIES NOTHING — it returns a drafted catalog row as text.
	mux.HandleFunc("/api/admin/parser/stats", s.parserCov.HandleStats)
	mux.HandleFunc("/api/telemetry/unrecognized", s.parserCov.HandleUnrecognized)
	mux.HandleFunc("/api/telemetry/unrecognized/", s.parserCov.HandlePropose)

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
	mux.HandleFunc("/api/correlations/feedback/summary", s.handleRcaFeedbackSummary)          // Project 2 P7: windowed false-positive rate for the caller's tenant (exact path wins over the /api/correlations/ prefix)
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
	// Which backend actually holds each registry's records, and can it serve
	// (tracker 245). The Registries page renders from this instead of assuming.
	mux.HandleFunc("/api/registries/status", s.handleRegistriesStatus)
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
	mux.HandleFunc("/api/notify/teams", s.handleTeamsConfig)
	mux.HandleFunc("/api/notify/teams/test", s.handleTeamsTest)
	mux.HandleFunc("/api/notify/sns", s.handleSNSConfig)
	mux.HandleFunc("/api/notify/sns/test", s.handleSNSTest)
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
	mux.HandleFunc("/api/system/backup", s.dataProtect.HandleConfig)           // platform data-protection config + DR status
	mux.HandleFunc("/api/system/backup/snapshots", s.dataProtect.HandlePolicy) // #150: SM policy view/control (platform admin)
	// DATA-PROTECTION-BEGIN — the enterprise Data Protection surface
	// (internal/dataprotect). All platform-GLOBAL: requirePlatformAdmin,
	// writes audited on BOTH outcomes, category "platform" in
	// route_isolation_test.go.
	//
	// The subtree pattern is load-bearing: "/api/system/backup/snapshots" stays
	// the EXACT policy route above, and the trailing-slash pattern below owns
	// list/create/delete/restore/verify beneath it. ServeMux prefers the exact
	// match, so the #150 policy GET/PUT is untouched.
	mux.HandleFunc("/api/system/backup/coverage", s.dataProtect.HandleCoverage)
	mux.HandleFunc("/api/system/backup/snapshots/", s.dataProtect.HandleSnapshotOps)
	// STORAGE-MEASUREMENT-BEGIN — the literal path, so the route-isolation ledger
	// and the coverage guard can both see it (they scan this file's source).
	// Registered as a CLOSURE, not as the method value `s.storageMeter.
	// HandleMeasured`: a method value binds the receiver at REGISTRATION time,
	// so a meter rebuilt or replaced after the router is assembled (which is
	// exactly what the isolation test does, and what a future re-wire would do)
	// would be silently ignored while the route still answered.
	mux.HandleFunc("/api/system/storage/measured", func(w http.ResponseWriter, r *http.Request) {
		s.storageMeter.HandleMeasured(w, r)
	})
	// STORAGE-MEASUREMENT-END
	mux.HandleFunc("/api/system/backup/operations", s.dataProtect.HandleOperations)
	mux.HandleFunc("/api/system/backup/operations/", s.dataProtect.HandleOperationByID)
	// DATA-PROTECTION-END
	// LICENCE-BEGIN — the platform-admin Licence surface. Platform-GLOBAL:
	// requirePlatformAdmin (a tenant/org admin holds full administration:admin,
	// so a scope-blind requireAdmin here would let any tenant read the
	// customer's commercial terms and install a licence for the whole platform —
	// CLAUDE.md 3a rule 3), writes audited on BOTH outcomes, category "platform"
	// in route_isolation_test.go.
	mux.HandleFunc("/api/system/licence", s.licenceAPI.Handle)
	// LICENCE-END
	// METERING-BEGIN — the Usage surface (tracker 258). Both are per-tenant
	// READS: a tenant/org admin sees their OWN usage, the platform owner sees
	// every tenant plus the installation row, and `?tenant=` may only NARROW —
	// a scoped caller naming another tenant gets 404, never a 403 that would
	// confirm the other tenant exists. Cross-org proof:
	// metering_isolation_test.go.
	mux.HandleFunc("/api/system/licence/usage", s.meteringAPI.HandleUsage)
	mux.HandleFunc("/api/system/licence/usage/report", s.meteringAPI.HandleReport)
	// METERING-END
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
	// SEC-021.1: read-only transport posture (tenant-scoped; platform rows
	// require the platform identity) + the exportable posture report.
	mux.HandleFunc("/api/security/transport-posture", s.handleTransportPosture)
	mux.HandleFunc("/api/security/transport-posture/export", s.handleTransportPostureExport)
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
	// Sealed Fields edge key delivery (#129). Registered ONLY when sealing is
	// enabled, so a deployment without the feature has no key-serving route at
	// all — not even one that answers 501. Stack-internal credential required;
	// see internal/sealedfields/edgekeys.go for why this is not a public route.
	if s.sealProvider != nil {
		// SEC-018.1: on a TLS deployment only the vector-router's workload
		// identity may fetch keys (sealingEdgeCaller); plaintext baseline
		// keeps the stack-internal token. Every served fetch is audited with
		// tenant + caller identity — never the key.
		mux.HandleFunc(sealedfields.EdgeKeyPath, sealedfields.EdgeKeyHandler(
			func() sealing.CryptoProvider { return s.sealProvider },
			s.sealingEdgeCaller,
			// Only mint an edge DEK for a REAL tenant (canonical id) or one of the
			// engine's reserved scopes — never an arbitrary string.
			s.edgeKeyScopeResolver(),
			func(r *http.Request, tenant string) {
				logInfo("sealing", "edge key served", map[string]any{
					"tenant": tenant, "peer": sealingEdgePeer(r),
				})
			},
		))
	}
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
// ── Security v1: production validator wiring ────────────────────────────────
// The RULES live in internal/secprofile (pure + unit-tested, so CI can evaluate
// a candidate configuration without standing the stack up). What follows is
// only wiring — read the profile, evaluate the real environment, log every
// finding, abort in production — which is what this entrypoint file is for.

// securityProfile resolves SECURITY_PROFILE. An unrecognized value is fatal —
// silently treating "prod" as lab would disable every production check.
func securityProfile() (secprofile.Profile, error) {
	return secprofile.ParseProfile(os.Getenv("SECURITY_PROFILE"))
}

// transportInventoryPath resolves the SEC-001 inventory: the env override,
// else the image-baked copy (Dockerfile.backend), else the repo checkout
// relative to src/backend (developer `go run`). Returning the image path when
// nothing exists keeps the error message pointed at the canonical location.
func transportInventoryPath() string {
	if p := strings.TrimSpace(os.Getenv("TRANSPORT_INVENTORY_PATH")); p != "" {
		return p
	}
	const baked = "/transport-inventory.yaml"
	if _, err := os.Stat(baked); err == nil {
		return baked
	}
	repo := filepath.Join("..", "..", "docs", "security", "transport-inventory.yaml")
	if _, err := os.Stat(repo); err == nil {
		return repo
	}
	return baked
}

// evaluateSecurityPosture runs the rule set against the live environment.
func evaluateSecurityPosture() (secprofile.Report, error) {
	p, err := securityProfile()
	if err != nil {
		return secprofile.Report{}, err
	}
	return secprofile.Evaluate(p, os.Getenv, func(path string) bool {
		_, statErr := os.Stat(path)
		return statErr == nil
	}), nil
}

// runSecurityValidator is called at boot. It returns an error only when the
// deployment must NOT start.
func runSecurityValidator() error {
	rep, err := evaluateSecurityPosture()
	if err != nil {
		return err
	}
	for _, f := range rep.Findings {
		fields := map[string]any{
			"rule": f.Rule, "control": f.Control, "component": f.Component,
			"source": f.Source, "observed": f.Observed, "required": f.Required,
			"remedy": f.Remedy, "profile": string(rep.Profile),
		}
		switch f.Severity {
		case secprofile.Fatal:
			// Fatal-class findings are logged as errors in EVERY profile: a lab
			// operator should be able to see exactly what production will refuse.
			logError("security", "security control not satisfied", fields)
		case secprofile.Warn:
			logWarn("security", "security control not satisfied", fields)
		default:
			logInfo("security", "declared security exception", fields)
		}
	}
	logInfo("security", "security posture evaluated", map[string]any{
		"profile": string(rep.Profile), "fatal": rep.Fatal, "warn": rep.Warn, "info": rep.Info,
		"blocking": rep.Blocking(),
	})
	if rep.Blocking() {
		return &securityRefusal{rep: rep}
	}
	return nil
}

// securityRefusal renders the operator-facing boot refusal.
type securityRefusal struct{ rep secprofile.Report }

func (e *securityRefusal) Error() string { return e.rep.Error() }

// handleSecurityPosture (GET /admin/security/posture) is the read-only feed for
// the security posture page. Platform-admin gated: it enumerates which controls
// are NOT satisfied, which is operational intelligence, not tenant data.
//
// It reports what the validator ACTUALLY EVALUATED — the UI must never compute
// "secure" on its own, and anything unverifiable is reported as such rather
// than assumed green.
func (s *server) handleSecurityPosture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	rep, err := evaluateSecurityPosture()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// probeObservations maps the SEC-019.1 prober snapshot into the posture
// package's injected shape. nil when the mesh is on the plaintext baseline.
func (s *server) probeObservations() map[string]secobs.ProbeObservation {
	if s.tlsPeerProber == nil {
		return nil
	}
	res := s.tlsPeerProber.Results()
	out := make(map[string]secobs.ProbeObservation, len(res))
	for name, r := range res {
		out[name] = secobs.ProbeObservation{OK: r.OK, NotAfter: r.NotAfter, CheckedAt: r.CheckedAt}
	}
	return out
}

// transportPostureRows builds the posture table and stamps each destination's
// SPIFFE identity from the workload registry (the trust domain is config, so
// the stamping lives here, not in the pure package).
func (s *server) transportPostureRows() []secobs.PostureRow {
	rows := secobs.BuildPosture(s.transportInv, s.probeObservations(), nil)
	td := envOr("TLS_TRUST_DOMAIN", "netops")
	registered := make(map[string]bool, len(workloadid.Registry))
	for _, e := range workloadid.Registry {
		registered[e.Service] = true
	}
	for i := range rows {
		if registered[rows[i].Destination] {
			rows[i].Identity = "spiffe://" + td + "/ns/default/sa/" + rows[i].Destination
		}
	}
	return rows
}

// handleTransportPosture (GET /api/security/transport-posture) — SEC-021.1
// read-only posture view. Two scopes, default-closed:
//   - platform owner: every hop (declared vs observed vs drift) + the boot
//     validator report. Platform-global operational intelligence, so the gate
//     is the platform identity, not tenant-scoped administration:admin
//     (CLAUDE.md §3a.3 — a tenant admin holds administration:admin too).
//   - tenant admin: ONLY the device trust-domain lanes their fleet rides, plus
//     their own device count. No workload/operator/public hops, no validator
//     internals — those enumerate platform attack surface.
func (s *server) handleTransportPosture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.transportInv == nil {
		// Inventory failed to load at boot (already logged). An empty table
		// pretending to be posture is worse than a loud 503.
		writeError(w, http.StatusServiceUnavailable, errors.New("transport inventory unavailable on this deployment"))
		return
	}
	rows := s.transportPostureRows()
	if isPlatformOwner(claims) {
		rep, err := evaluateSecurityPosture()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"scope":     "platform",
			"generated": time.Now().UTC(),
			"rows":      rows,
			"validator": rep,
		})
		return
	}
	// Tenant view. visibleDevices applies the caller's tenant scope (and
	// ignores as_tenant for non-owners via claims), so the count is the
	// caller's fleet, never another tenant's.
	devices := visibleDevices(s.discovery.Devices(), claims)
	writeJSON(w, http.StatusOK, map[string]any{
		"scope":        "tenant",
		"generated":    time.Now().UTC(),
		"device_lanes": secobs.DeviceLaneRows(rows),
		"device_count": len(devices),
	})
}

// handleTransportPostureExport (GET /api/security/transport-posture/export)
// renders the customer-facing posture report (SEC-021.1): every Correlix-owned
// path with its declared/observed transport and peer identity, then a clearly
// separated section for device lanes that are NOT authenticated, with the
// declared reason. Platform-admin only — the full table enumerates internal
// attack surface. Reuses the report renderers (html/xlsx; pdf arrives with the
// report pipeline's sidecar when configured).
func (s *server) handleTransportPostureExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	claims, ok := s.requirePlatformAdmin(w, r)
	if !ok {
		return
	}
	if s.transportInv == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("transport inventory unavailable on this deployment"))
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "html"
	}
	rend := previewRenderer(format)
	if rend == nil {
		writeError(w, http.StatusBadRequest, errors.New("unknown export format"))
		return
	}
	rows := s.transportPostureRows()
	var owned, deviceLanes []secobs.PostureRow
	for _, row := range rows {
		if row.TrustDomain == "device" {
			deviceLanes = append(deviceLanes, row)
		} else {
			owned = append(owned, row)
		}
	}
	ownedHeader, ownedCells := secobs.PostureTable(owned, nil)
	devHeader, devCells := secobs.PostureTable(deviceLanes, nil)
	now := time.Now().UTC()
	vm := reports.ViewModel{
		ReportID:    "transport-posture",
		ReportName:  "Transport Security Posture",
		Kind:        "security-posture",
		TenantID:    TenantGlobal,
		GeneratedAt: now,
		Description: "Declared vs observed transport for every platform path (SEC-021.1). Observation source: the served-certificate probe; 'not probed' means exactly that, never 'assumed secure'.",
		Summary:     fmt.Sprintf("%d paths declared; %d device lanes carry declared exceptions or protocol-native security", len(owned), len(deviceLanes)),
		Sections: []reports.Section{
			{Title: "Correlix-owned paths", Header: ownedHeader, Rows: ownedCells},
			{Title: "Device lanes (NOT cryptographically authenticated unless protocol-native)", Header: devHeader, Rows: devCells,
				Note: "Device-facing lanes carry the transport the device protocol supports. A lane listed with a declared exception is plaintext by explicit, owner-accepted decision — the reason and age are in the table. No claim of cryptographic authenticity is made for any device lane (HLD §6.6)."},
		},
	}
	art, err := rend.Render(r.Context(), vm)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if s.audit != nil {
		tenant, cross := principalTenant(claims)
		s.audit.Record(AuditEvent{
			Actor: claims.Sub, Tenant: tenant, Cross: cross,
			Method: "EXPORT", Path: "/api/security/transport-posture/export",
			Status: http.StatusOK, Decision: "allow", Remote: auditClientIP(r),
			Detail: map[string]any{
				secobs.SecEventKey: secobs.SecEventPostureExport,
				"format":           format, "edges": len(rows),
			},
		})
	}
	w.Header().Set("Content-Type", art.ContentType)
	if format != "html" {
		w.Header().Set("Content-Disposition", `attachment; filename="transport-posture.`+format+`"`)
	}
	_, _ = w.Write(art.Bytes) // best-effort: status committed; a failed write means the client is gone
}

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
		if err := httppage.RejectUnknownQuery(r); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		page, err := httppage.Parse(r, deviceDefaultPage, deviceMaxPage)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		all := s.withCredActive(withDeviceType(visibleDevices(s.discovery.Devices(), claims)))
		// Wireless WLCs + APs are fleet citizens too (one LAN domain). The ones
		// an enabled integration polls are already in `all` — the registry holds
		// them (wireless.DeviceSource) so the licence counts them; this adds the
		// REMAINDER, the inventory nothing is polling, marked not monitored with
		// its reason rather than dropped from the fleet (tracker 256).
		all = append(all, s.wirelessDeviceRows(r.Context(), claims, all)...)
		// Stable order: without one, paging over a map-backed aggregator can
		// show the same device twice and never show another at all.
		sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
		rows := httppage.SliceOf(all, page)
		httppage.LogTruncated("/api/devices", page, len(rows), len(all))
		httppage.Write(w, "devices", rows, page, len(rows), len(all))
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
		// F-8: an id-less create used to persist a device keyed "" — the API
		// returned 201 and DELETE /api/devices/{id} can never express the empty
		// id, so the row was unaddressable forever. Derive the id server-side
		// (the ScanDeviceID convention every discovered device already follows)
		// and refuse a device that offers nothing to derive from.
		if strings.TrimSpace(d.ID) == "" {
			d.ID = discovery.ScanDeviceID(d.Name, d.Address)
		}
		if d.ID == "" {
			writeError(w, http.StatusBadRequest,
				errors.New("device requires an id, name, or address"))
			return
		}
		// TRACKER 181: RESOLVE BEFORE PERSISTING. This used to Upsert first and
		// only then ask what became of the record, so a create that dedupe
		// absorbed still wrote its own row — a SHADOW: invisible to
		// GET /api/devices (which shows the merged survivor), still addressable
		// by DELETE, and it resurfaced the moment the absorber was deleted. Two
		// overlapping scale runs left 1,000 of them, unlistable by any
		// prefix-scoped cleanup. CreateOrResolve does the check and the write
		// under one lock and declines to write an absorbed create, so GET and
		// DELETE agree about what exists.
		//
		// 201 still means the device survives a restart (it is persisted before
		// we answer) — before that store existed it lived only in RAM and
		// vanished on the next deploy.
		//
		// TRACKER 161: 201 must also mean the REQUESTED identity actually
		// exists. Cross-source dedupe merges records that share an identity
		// token (management IP, serial, or normalized name), so a create can be
		// absorbed into an existing device and stop existing as its own row.
		// This handler used to answer 201 and echo the caller's own object back
		// regardless, which is a false success: the device is not retrievable
		// under the name the caller chose, and — because the tenant-enrichment
		// export writes the SURVIVOR's name — every event bearing the absorbed
		// name is unattributable forever. Measured 2026-08-19: 73 devices
		// re-provisioned onto addresses held by stale records lost the merge,
		// and 22% of a qualification burst went unattributed while the API had
		// reported 1000 successful creates.
		//
		// The merge itself is right (same IP usually is the same device). What
		// changes is that the caller is TOLD, and always receives the identity
		// that actually survived.
		// LICENCE-BEGIN — the MONITORED-DEVICE ceiling (Community: 25). The
		// monitored device is the priced unit, so this is the gate the whole
		// per-device pricing model rests on.
		//
		// The check is NOT made here. It is made inside the registry, in the
		// same hold of the lock as the write, because that is the only place
		// the two can be atomic: a count taken here and a write performed there
		// lets two concurrent creates at 24 of 25 both see a free slot. The
		// registry asks the ceiling exactly when this write turns a device that
		// is NOT monitored into one that is — so a re-POST of an existing
		// monitored device (re-onboarding a fleet, adding a credential ref or a
		// gnmi label to a device already counted) is never refused, and a
		// create absorbed by cross-source dedupe writes nothing and consumes
		// nothing.
		//
		// A manually created device is monitored by default: someone asking the
		// platform to add a device is asking it to collect from that device.
		// Devices found by subnet DISCOVERY are not — see internal/devmon.
		canonical, kept, err := s.discovery.CreateOrResolve(d)
		if err != nil {
			// The ceiling refusal is the structured 402 the SPA renders as an
			// upgrade card. Checked before the generic 500 so a commercial
			// limit never reaches an operator as "device was not saved".
			if entitlement.WriteRefusal(w, err) {
				return
			}
			writeError(w, http.StatusInternalServerError, errors.New("device was not saved"))
			return
		}
		// LICENCE-END
		if !kept {
			log.Printf("device create absorbed by dedupe: requested=%s canonical=%s "+
				"(shared identity token) — no row written, caller told 200, not 201",
				d.ID, canonical.ID)
			w.Header().Set("X-Device-Requested-Id", d.ID)
			w.Header().Set("X-Device-Canonical-Id", canonical.ID)
			// 200, not 201: nothing was created under the requested identity.
			writeJSON(w, http.StatusOK, canonical)
			return
		}
		w.Header().Set("X-Device-Canonical-Id", canonical.ID)
		writeJSON(w, http.StatusCreated, canonical)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleDeviceByID(w http.ResponseWriter, r *http.Request) {
	// SSH gateway lives under the device path: /api/devices/{id}/ssh (opt-in,
	// dormant unless FEATURE_DEVICE_SSH). Delegate before the id parse below.
	if strings.HasSuffix(r.URL.Path, "/ssh-ticket") {
		s.handleDeviceSSHTicket(w, r)
		return
	}
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
	// MONITORING-BEGIN — the monitoring switch: /api/devices/{id}/monitoring
	// (get/set). Dispatched here rather than registered on the mux for the same
	// reason the config-backup subtree is: it lives under /api/devices/ and
	// inherits that route's tenant classification.
	if _, ok := devmon.Path(r.URL.Path); ok {
		s.devmonAPI.Handle(w, r)
		return
	}
	// MONITORING-END
	// CONFIG-BACKUP-BEGIN
	if s.configAPI != nil && s.configAPI.ServeDeviceSubroute(w, r) {
		return
	}
	// CONFIG-BACKUP-END
	// PACKET-CAPTURE-BEGIN
	if s.pcapAPI != nil && s.pcapAPI.ServeDeviceSubroute(w, r) {
		return
	}
	// PACKET-CAPTURE-END
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
		// item 121: the per-tenant pipeline processor editor. The API itself is
		// always up (rules persist regardless); the flag gates UI visibility and
		// signals that the router is actually consuming the generated config.
		"processors": os.Getenv("FEATURE_PROCESSORS") == "true",
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

func (s *server) handlePromMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP netops_devices_total Number of known devices.\n")
	fmt.Fprintf(w, "# TYPE netops_devices_total gauge\n")
	fmt.Fprintf(w, "netops_devices_total %d\n", len(s.discovery.Devices()))
	// MONITORING-BEGIN — the LICENSED unit beside the inventory total, so a
	// dashboard can show both and an operator can see the gap between what has
	// been discovered and what is being collected from (C4). Emitted every
	// scrape, including as a zero: a series that vanishes is indistinguishable
	// from a scrape failure.
	fmt.Fprintf(w, "# HELP netops_monitored_devices_total Devices Correlix is configured to collect from — the unit the licence device ceiling counts.\n")
	fmt.Fprintf(w, "# TYPE netops_monitored_devices_total gauge\n")
	fmt.Fprintf(w, "netops_monitored_devices_total %d\n", s.discovery.MonitoredCount())
	fmt.Fprintf(w, "# HELP netops_monitoring_withheld_devices_total Devices that would be monitored but are not, because the licence ceiling is full.\n")
	fmt.Fprintf(w, "# TYPE netops_monitoring_withheld_devices_total gauge\n")
	fmt.Fprintf(w, "netops_monitoring_withheld_devices_total %d\n", s.discovery.MonitoringWithheldCount())
	// MONITORING-END
	fmt.Fprintf(w, "# HELP netops_alerts_active Currently active alerts.\n")
	fmt.Fprintf(w, "# TYPE netops_alerts_active gauge\n")
	fmt.Fprintf(w, "netops_alerts_active %d\n", len(s.alerts.Active()))

	// Registry storage posture (tracker 245). A registry whose storage cannot
	// serve is invisible from the outside — the API answers honestly, but only
	// to whoever asks. Emitted EVERY scrape, including as a zero, so "storage
	// unavailable" is alertable and a vanished series still means a scrape
	// failure rather than health. One cheap pool ping per scrape.
	storageOK, _ := platformdb.Health(r.Context())
	fmt.Fprintf(w, "# HELP netops_registry_storage_available Whether the configured storage for a registry can serve (1) or not (0).\n")
	fmt.Fprintf(w, "# TYPE netops_registry_storage_available gauge\n")
	for _, st := range registrystatus.Build(registrySpecs(), platformdb.Kind(), storageOK, "").Registries {
		v := 0
		if st.Available {
			v = 1
		}
		fmt.Fprintf(w, "netops_registry_storage_available{registry=%q,configured_backend=%q,persistence=%q} %d\n",
			st.Registry, st.ConfiguredBackend, st.Persistence, v)
	}

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
	if s.sealMetrics != nil {
		s.sealMetrics.write(w)
	}
	if s.quarMetrics != nil {
		s.quarMetrics.Write(w)
	}
	if s.incMetrics != nil {
		s.incMetrics.write(w)
	}
	if s.rcaFeedbackMetrics != nil {
		s.rcaFeedbackMetrics.Write(w)
	}
	if s.secFindMetrics != nil {
		s.secFindMetrics.Write(w)
	}
	// SNAPSHOT-RESTORABILITY-BEGIN — the DR proof series. Rendered from CACHED
	// state only: the metrics handler never makes a blocking OpenSearch call
	// (the nightly probe worker refreshes the cache). 0 on
	// netops_opensearch_snapshot_restorable means NOT PROVEN restorable, and
	// "never probed" is deliberately the same 0 as "the probe failed" — an
	// unproven backup and a disproven one are the same operational state, which
	// is the whole lesson of 2026-08-27.
	s.dataProtect.Metrics().Write(w)
	// SNAPSHOT-RESTORABILITY-END
	// STORAGE-MEASUREMENT-BEGIN — netops_storage_bytes_measured{store,tenant},
	// the per-store measured/not-measured gauge and the staleness gauge, all
	// rendered from the sampler's cache. A store that was NOT measured emits no
	// bytes series at all: a zero-byte gauge and an unmeasured store must not
	// look the same, which is the presentation bug this was filed about.
	s.storageMeter.Metrics().Write(w)
	// STORAGE-MEASUREMENT-END
	// SECURITY-LANE-BEGIN
	if s.securityLane != nil {
		s.securityLane.Metrics().Write(w)
	}
	// SECURITY-LANE-END
	// CONFIG-BACKUP-BEGIN
	if s.configBackup != nil {
		s.configBackup.Metrics().Write(w)
	}
	if s.configDrift != nil {
		s.configDrift.Metrics().Write(w)
	}
	// CONFIG-BACKUP-END
	// PACKET-CAPTURE-BEGIN
	if s.packetCapture != nil {
		s.packetCapture.Metrics().Write(w)
	}
	// PACKET-CAPTURE-END
	// OS-VERSION LADDER — how many version probes ran, by rung and outcome. It
	// is the only place an operator can see that (say) every gnmi rung is
	// reporting itself unavailable, which is the difference between "these
	// devices have no version source" and "we never wired one".
	if s.discovery != nil {
		s.discovery.WriteOSVersionMetrics(w)
	}
	// LICENCE-BEGIN — emitted on every deployment including Community, so
	// "no licence" is a VALUE (the 36500-day sentinel) and never a gap in the
	// series. A vanished series must mean a scrape failure, not a state change.
	s.entitlements.WriteMetrics(w, time.Now().UTC())
	// The ceiling/usage/soft/overage families the 80/90/100 % soft-overage rules
	// divide. This call is ALSO what records the overage episode's start time,
	// so the number on a dashboard and the `overage_since` on the Licence page
	// come from one observation and cannot disagree.
	s.entitlements.WriteUsageMetrics(w, s.licenceUsage(r.Context()), time.Now().UTC())
	// LICENCE-END
	// METERING-BEGIN — the usage-metering series. Rendered from atomics the
	// hourly recorder already updated, so the scrape never blocks on a store,
	// and emitted even when nothing is wired (as zeros) so a vanished series
	// means a scrape failure rather than "we are fine".
	s.meteringRecorder.WriteMetrics(w)
	// METERING-END
	// IGP-MONITORING-BEGIN
	s.igpAPI.Metrics().Write(w) // nil-safe on both the API and the counter set
	// IGP-MONITORING-END
	// BMP-BEGIN
	s.bmpAPI.Metrics().Write(w) // nil-safe on both the API and the counter set
	// BMP-END
	// VMALERT-WEBHOOK-BEGIN — always written, even when the receiver is off, so
	// netops_alert_webhook_enabled distinguishes "nothing fired" from "the
	// delivery path was never wired".
	s.vmalertWebhookMetrics.Write(w) // nil-safe
	// VMALERT-WEBHOOK-END
	// DEBUG-ROUTES-BEGIN — ALWAYS written, with zeros when nothing is raised.
	// scripts/stack-watchdog.sh's DEBUG_LEVEL_STUCK class is the only layer that
	// survives this process being wedged, and it can see nothing but /metrics.
	// If these gauges were omitted while nothing was raised, "the check could
	// not run" and "the check passed" would look identical to it — the exact
	// inversion the 2026-09-02 post-mortem is about.
	if s.debugAPILevel != nil {
		fmt.Fprint(w, pipedebug.RenderMetrics(
			map[pipedebug.Module]pipedebug.LevelReader{pipedebug.ModuleAPI: s.debugAPILevel},
			s.debugParseFilter))
	}
	// DEBUG-ROUTES-END
	// BGP-WATCH-BEGIN
	if s.bgpWatchEval != nil {
		s.bgpWatchEval.Metrics().Write(w)
	}
	// The feed's PROCESS-WIDE counters belong here and only here: the per-tenant
	// API body carries the caller's own ring/poll tally instead (§3a — an
	// aggregate over every tenant is other tenants' activity).
	if s.bgpFeed != nil {
		s.bgpFeed.WriteMetrics(w)
	}
	// BGP-WATCH-END
	if s.parserCovMetrics != nil {
		s.parserCovMetrics.Write(w)
	}
	if s.intMetrics != nil {
		s.intMetrics.write(w)
	}
	if s.tlsSrv != nil {
		s.tlsSrv.writeTLSMetrics(w)
	}
	if s.tlsPeerProber != nil {
		s.tlsPeerProber.WriteMetrics(w)
	}
	if s.demMetrics != nil {
		s.demMetrics.Write(w)
	}
	if s.secMetrics != nil {
		s.secMetrics.Write(w)
	}
	if s.cloudBroker != nil {
		s.cloudBroker.Metrics().Write(w)
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
	// Backfill pass integrity (ultra 3/5). invalid_rows > 0 means the pick
	// returned rows that can never be folded — the watermark advanced past them
	// and this counter is their only trace. rescan_failures > 0 means a phase-1
	// re-scan died without blocking the forward phase; rescan_skips climbing
	// means a region behind the mark is being skipped as deterministically
	// unreadable and reconcile-repaired rows there may go unsnapshotted.
	fmt.Fprintf(w, "# HELP netops_timeintel_invalid_rows_total Backfill pick rows that failed validation — permanently unprocessable; the watermark advanced past them.\n")
	fmt.Fprintf(w, "# TYPE netops_timeintel_invalid_rows_total counter\n")
	fmt.Fprintf(w, "netops_timeintel_invalid_rows_total %d\n", s.timeIntelInvalidRows.Load())
	fmt.Fprintf(w, "# HELP netops_timeintel_rescan_failures_total Backfill phase-1 re-scans that failed; the forward (mark-advancing) phase still ran.\n")
	fmt.Fprintf(w, "# TYPE netops_timeintel_rescan_failures_total counter\n")
	fmt.Fprintf(w, "netops_timeintel_rescan_failures_total %d\n", s.timeIntelRescanFailures.Load())
	fmt.Fprintf(w, "# HELP netops_timeintel_rescan_skips_total Bounded forward moves of the re-scan floor past a ClickHouse-refused region behind the watermark.\n")
	fmt.Fprintf(w, "# TYPE netops_timeintel_rescan_skips_total counter\n")
	fmt.Fprintf(w, "netops_timeintel_rescan_skips_total %d\n", s.timeIntelRescanSkips.Load())
	// F-25: the brute-force throttle's pressure was entirely invisible — it went
	// fail-open at its cap with no log and no metric, so "lockout: enabled" in
	// Security Settings could be a lie for months. Saturation > 0 means sign-ins
	// are being refused; evictions climbing means a spray is in progress.
	if s.loginThrottle != nil {
		fmt.Fprintf(w, "# HELP netops_login_throttle_accounts Accounts currently tracked by the failed-login throttle.\n")
		fmt.Fprintf(w, "# TYPE netops_login_throttle_accounts gauge\n")
		fmt.Fprintf(w, "netops_login_throttle_accounts %d\n", s.loginThrottle.Size())
		fmt.Fprintf(w, "# HELP netops_login_throttle_evictions_total Unlocked failure records evicted (LRU) to make room at the cap — a username spray in progress.\n")
		fmt.Fprintf(w, "# TYPE netops_login_throttle_evictions_total counter\n")
		fmt.Fprintf(w, "netops_login_throttle_evictions_total %d\n", s.loginThrottle.Evictions())
		fmt.Fprintf(w, "# HELP netops_login_throttle_swept_total Stale failed-login records reclaimed by the janitor.\n")
		fmt.Fprintf(w, "# TYPE netops_login_throttle_swept_total counter\n")
		fmt.Fprintf(w, "netops_login_throttle_swept_total %d\n", s.loginThrottle.Sweeps())
		fmt.Fprintf(w, "# HELP netops_login_throttle_saturated_total Sign-ins refused because every throttle slot held a live lock (fail-closed).\n")
		fmt.Fprintf(w, "# TYPE netops_login_throttle_saturated_total counter\n")
		fmt.Fprintf(w, "netops_login_throttle_saturated_total %d\n", s.loginThrottle.Saturations())
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
		_, _ = w.Write([]byte("{\"error\":\"response encoding failed\",\"code\":\"RESPONSE_ENCODE_FAILED\"}\n")) // last-resort constant payload; the client is gone if this fails
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

// ---------------------------------------------------------------------------
// Package-wide helpers (Phase-2 Wave 0b consolidation, 2026-07-29).
//
// Each of these used to live in the file that first needed it — which pinned
// that file in the root, because a file cannot be extracted while it hosts
// helpers the whole package calls. They live with the composition root now;
// per the §2 no-utils-package rule they stay in main rather than forming a
// shared package.
// ---------------------------------------------------------------------------

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

// secEnvDuration reads a positive integer-seconds env var, clamped to [min,max].
func secEnvDuration(key string, def, lo, hi int) time.Duration {
	v := def
	if s := strings.TrimSpace(os.Getenv(key)); s != "" {
		if n, err := parseIntStrict(s); err == nil {
			v = n
		}
	}
	if v < lo {
		v = lo
	}
	if v > hi {
		v = hi
	}
	return time.Duration(v) * time.Second
}

// orDefault returns s unless blank, else def.
func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// corr builds the correlation fields stamped on every pipeline log line so a
// single `grep execution_id` reconstructs a report's whole lifecycle.
func corr(execID, tenant, scheduleID, jobID, workerID string) map[string]any {
	m := map[string]any{"execution_id": execID, "tenant_id": tenant, "schedule_id": scheduleID}
	if jobID != "" {
		m["job_id"] = jobID
	}
	if workerID != "" {
		m["worker_id"] = workerID
	}
	return m
}

func merge(a, b map[string]any) map[string]any {
	out := make(map[string]any, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func errf(err error) map[string]any { return map[string]any{"error": err.Error()} }

// ---- small JSON/value helpers (ClickHouse FORMAT JSON yields any-typed cells) ----

func asStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", x)
	}
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func asFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		// ClickHouse can hand back a non-finite float directly (nan/inf in a
		// JSON number position); sanitise it here too, not just the string form.
		return metricval.Sanitize(x)
	case string:
		// F-21: ParseFloat("NaN") succeeds and the NaN lands in a health-score
		// response field, where it (a) fails the JSON encode for the entire
		// response and (b) compares false against every threshold above.
		return metricval.FiniteOrZero(x)
	}
	return 0
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x == "1" || x == "true"
	}
	return false
}

// affectedDevices extracts device names from the affected field, which is a
// {"devices":[...],"paths":[...]} object (string-encoded or already parsed).
func affectedDevices(v any) []string {
	parse := func(m map[string]any) []string {
		var out []string
		if ds, ok := m["devices"].([]any); ok {
			for _, e := range ds {
				if s := asStr(e); s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	}
	switch x := v.(type) {
	case map[string]any:
		return parse(x)
	case string:
		if strings.TrimSpace(x) == "" {
			return nil
		}
		var m map[string]any
		if json.Unmarshal([]byte(x), &m) == nil {
			return parse(m)
		}
	}
	return nil
}

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

// VMALERT-WEBHOOK-BEGIN — the vmalert delivery path (internal/alertwebhook).

// alertWebhookLog adapts the package's injected LogFunc onto the structured
// app log (§10). The receiver NEVER passes a credential in these fields.
func alertWebhookLog(level, msg string, fields map[string]any) {
	applog.Log(level, "alertwebhook", msg, fields)
}

// platformAlertsHostRoute builds the HOST-MONITORING push destination for
// PLATFORM self-health alerts (owner decision, 2026-09-03: "Correlix alerts
// should be alerted to the host monitoring").
//
// Env is read HERE, in the wiring layer, and the built sender is injected — the
// package stays env-free (the seclane/configstore precedent). The topic
// defaults to the external watchdog's own topic, which is already passed into
// this container so notify_config.go can REFUSE it for PRODUCT alerting: the
// platform's self-health alerts and the watchdog's death notice belong on the
// same phone channel, while a tenant-facing channel still may not point at it.
//
// Returns a nil interface (never a typed nil) when no topic is configured, so
// the receiver counts the misconfiguration instead of dereferencing it.
// It returns the sender and the SERVER it is aimed at; the server is the key
// into the shared per-server push budget (notify/pushbudget.go) and is safe to
// log — unlike the topic, which is a credential.
func platformAlertsHostRoute() (alertwebhook.HostPusher, string) {
	topic := strings.TrimSpace(os.Getenv(alertwebhook.EnvHostTopic))
	source := alertwebhook.EnvHostTopic
	if topic == "" {
		topic = strings.TrimSpace(os.Getenv(alertwebhook.EnvWatchdogTopic))
		source = alertwebhook.EnvWatchdogTopic
	}
	if topic == "" {
		// LOUD, not silent (§10): with no topic the stack keeps every alert to
		// itself, which is the failure mode the whole delivery path exists to
		// end. Name both variables so the fix is one line away.
		logWarn("alertwebhook", "platform self-health alerts will NOT reach the host-monitoring phone channel: neither "+
			alertwebhook.EnvHostTopic+" nor "+alertwebhook.EnvWatchdogTopic+" is set", map[string]any{
			"route": alertwebhook.RouteHostMonitoring,
			"env":   alertwebhook.EnvHostTopic,
		})
		return nil, ""
	}
	server := strings.TrimSpace(firstNonEmpty(os.Getenv(alertwebhook.EnvHostServer), os.Getenv(alertwebhook.EnvProductNtfyServer)))
	token := strings.TrimSpace(firstNonEmpty(os.Getenv(alertwebhook.EnvHostToken), os.Getenv(alertwebhook.EnvProductNtfyToken)))
	// The TOPIC is never logged — knowing it is enough to read every alert
	// published to it and to publish forgeries (§8).
	logInfo("alertwebhook", "platform self-health alerts route to the host-monitoring push channel",
		alertwebhook.HostRouteLogFields(server, token != "", source))
	// NO budget is attached to this sender on purpose: the receiver takes the
	// token at ENQUEUE (internal/alertwebhook/hostroute.go), so attaching one
	// here would spend two tokens per push. Both draw from the SAME shared
	// bucket for this server.
	return notify.NewNtfy(server, topic, token), server
}

// handleVMAlertWebhook serves the Alertmanager-v2 receiver vmalert POSTs to.
//
// The route is registered only when the receiver was built, so a nil handler
// here should be unreachable; it answers 404 anyway rather than panicking —
// fail-closed is cheaper than a nil deref in the process that is supposed to
// notice outages.
func (s *server) handleVMAlertWebhook(w http.ResponseWriter, r *http.Request) {
	if s.vmalertWebhook == nil {
		http.NotFound(w, r)
		return
	}
	s.vmalertWebhook(w, r)
}

// VMALERT-WEBHOOK-END

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

// ── Parser coverage wiring (programme A6) ───────────────────────────────────
//
// parsercov holds no ambient authority: which permission each abstract gate
// maps onto, which transports it gets and where the replicas are all arrive
// here, explicitly (the secapi precedent).

// parserCovAuthz maps parsercov's abstract gates onto this platform's RBAC and
// resolves the caller's tenant scope.
//
// GATE CHOICE (§3a rule 3 — "pick the right gate"):
//   - STATS is requirePlatformAdmin. Parser counters are process-wide facts
//     about the whole fleet's parser, not one tenant's rows. A scope-blind
//     requireAdmin would be satisfied by a tenant admin's full
//     administration:admin — a privilege leak, not a convenience.
//   - WRITE (drafting a catalog proposal) is alerts:write: a proposal is
//     detection-content working state, and it APPLIES NOTHING.
//   - READ is infrastructure:read, the same gate every other log surface uses;
//     the tenant filter is applied on top.
func (s *server) parserCovAuthz(w http.ResponseWriter, r *http.Request, gate parsercov.Gate) (parsercov.Principal, bool) {
	var claims jwtClaims
	var ok bool
	switch gate {
	case parsercov.GateStats:
		claims, ok = s.requirePlatformAdmin(w, r)
	case parsercov.GateWrite:
		claims, ok = s.requirePerm(w, r, "alerts", LevelWrite)
	default:
		claims, ok = s.requirePerm(w, r, "infrastructure", LevelRead)
	}
	if !ok {
		return parsercov.Principal{}, false
	}
	tenant, cross := principalTenant(claims)
	keys, _ := s.visibleDeviceKeys(claims)
	addrs, _ := s.visibleDeviceAddrs(claims)
	return parsercov.Principal{
		Tenant: tenant, Cross: cross, Subject: claims.Sub,
		DeviceKeys: keys, DeviceAddrs: addrs,
	}, true
}

// parserCovDeps assembles the injected collaborators. Called AFTER
// parserCovMetrics is set, so the API never captures a nil counter set.
func (s *server) parserCovDeps() parsercov.Deps {
	return parsercov.Deps{
		Authz:  s.parserCovAuthz,
		Search: openSearch,
		// The fetcher carries the internal-mTLS transport and its own response
		// cap; the 10s client timeout is the outer bound on a slow replica.
		Fetch: parsercov.NewFetcher(backendHTTPClient(10 * time.Second)),
		// Replica topology is CONFIGURATION, not discovery: the endpoints are
		// TLS-verified by name on the hardened deployment, so an unset
		// CORRELATION_REPLICA_URLS correctly falls back to the single
		// CORRELATION_URL rather than fanning out over resolved IPs.
		Replicas: func(context.Context) []string {
			return parsercov.ReplicaList(
				envOr("CORRELATION_URL", "http://correlation:8000"),
				os.Getenv(parsercov.EnvReplicaURLs))
		},
		Metrics:    s.parserCovMetrics,
		Audit:      s.securityAudit,
		WriteJSON:  writeJSON,
		WriteError: writeError,
		LogWarn:    func(msg string, f map[string]any) { logWarn("parsercov", msg, f) },
		MaxLines:   envInt(parsercov.EnvMaxLines, parsercov.DefaultMaxLines),
	}
}

// DEBUG-ROUTES-BEGIN
// ── Pipeline debugger wiring (design PIPELINE_DEBUGGER_2026-09-04 §4) ───────
//
// internal/pipedebug holds NO ambient authority: the gate, the store clients,
// the injection sockets, the sidecar transport and the clock all arrive here,
// explicitly (the secapi/parsercov precedent). Deleting this function, the four
// other DEBUG-ROUTES marker blocks in this file and the internal/pipedebug
// package removes the debugger without touching anything else.

// debugAuthz is the ONE gate for every debug route.
//
// GATE CHOICE (§3a rule 3). requirePlatformAdmin, never requireAdmin: a trace
// reads a tenant's telemetry back out of the SHARED stores, and a log-level
// change is stack-wide plumbing that affects every tenant's service. A tenant
// or org admin holds full administration:admin, so a scope-blind requireAdmin
// here would be a privilege leak, not a convenience.
func (s *server) debugAuthz(w http.ResponseWriter, r *http.Request) (pipedebug.Principal, bool) {
	claims, ok := s.requirePlatformAdmin(w, r)
	if !ok {
		return pipedebug.Principal{}, false
	}
	tenant, cross := principalTenant(claims)
	return pipedebug.Principal{Subject: claims.Sub, Tenant: tenant, Cross: cross}, true
}

// debugUIHost adapts *server to pipedebug.UIQueryHost — the seam stage 10 runs
// the SPA's own queries over.
//
// It is an ADAPTER, not logic: every method forwards to the api surface the SPA
// itself calls, so the tenant clause, the visibility policy and the ClickHouse
// row policy exercised by a trace are the production ones. Re-implementing any
// of them here is the drift this seam exists to prevent.
type debugUIHost struct{ s *server }

func (h debugUIHost) LogsScope(r *http.Request, signal string) (string, []any, []any, bool, bool) {
	return h.s.logsScope(r, signal)
}

func (h debugUIHost) SyntheticExclusion() map[string]any { return syntheticDebugExclusion() }

func (h debugUIHost) SearchOpenSearch(method, path string, body any) (*http.Response, error) {
	return openSearch(method, path, body)
}

func (h debugUIHost) IndexPatternFor(signal, tenant string, cross bool) string {
	return oslog.TenantIndexPattern(signal, tenant, cross)
}

func (h debugUIHost) ServeFlowsTopTalkers(w http.ResponseWriter, r *http.Request) {
	h.s.handleFlowsTopTalkers(w, r)
}

func (h debugUIHost) ServeMetricsQueryRange(w http.ResponseWriter, r *http.Request) {
	h.s.handleMetricsQueryRange(w, r)
}

// debugDeps assembles the injected collaborators.
func (s *server) debugDeps() pipedebug.Deps {
	client := backendHTTPClient(20 * time.Second)
	corrURL := envOr("CORRELATION_URL", "http://correlation:8000")
	sidecar, err := pipedebug.SidecarBase(
		os.Getenv(pipedebug.EnvSidecarURL), corrURL,
		envInt(pipedebug.EnvSidecarPort, pipedebug.DefaultSidecarPort))
	if err != nil {
		// MISCONFIGURED is not the same as NOT CONFIGURED (§10): an unusable
		// CORRELATION_URL is an operator mistake, and it must be named at boot
		// rather than surfacing later as "the bus stage is not observable".
		logError("pipedebug", "cannot derive the correlation debug sidecar URL — the Kafka peek and the correlation log-level control will report as unavailable", map[string]any{"err": err.Error()})
	}
	// UNSET IS THE SHIPPED DEFAULT: with no token the bus peek and the
	// correlation log-level control report "not observable / not switchable"
	// WITH THE REASON, rather than being silently open on the internal network
	// (§3 — no implicit trust between services).
	token := os.Getenv(pipedebug.EnvSidecarToken)

	return pipedebug.Deps{
		Authz:          s.debugAuthz,
		Search:         openSearch,
		OSIndexPattern: oslog.TenantIndexPattern,
		CHSelect:       chSelect,
		CHScopeFor: func(p pipedebug.Principal) string {
			if p.Cross {
				return "__all__"
			}
			if p.Tenant == "" {
				return "__none__"
			}
			return p.Tenant
		},
		VictoriaExport: pipedebug.NewVictoriaExport(client,
			envOr("VICTORIA_URL", envOr("METRICS_URL", "http://victoria:8428"))),
		KafkaPeek:    pipedebug.NewKafkaPeek(client, sidecar, token),
		CorrLogLevel: pipedebug.NewCorrLogLevel(client, sidecar, token),
		CorrHealth:   pipedebug.NewCorrHealth(client, strings.TrimRight(corrURL, "/")),
		SetAPILevel:  s.debugAPILevel.Set,
		// Vector is deliberately NOT wired: it reads VECTOR_LOG at process start
		// and exposes no log-level mutation on its API, so there is nothing
		// honest to call. The handler answers with pipedebug.VectorLevelReason,
		// which names the substitute (`vector tap`) instead of faking a switch.
		VectorLogLevel: nil,
		InjectSyslog: func(ctx context.Context, frame string) error {
			return pipedebug.NewUDPInjector(
				envOr(pipedebug.EnvSyslogTarget, pipedebug.DefaultSyslogTarget),
				5*time.Second)(ctx, []byte(frame))
		},
		InjectTrap: pipedebug.NewUDPInjector(
			envOr(pipedebug.EnvTrapTarget, pipedebug.DefaultTrapTarget), 5*time.Second),
		// The flow probe goes to the STACK's own goflow2 listener, exactly as
		// the syslog and trap probes go to the stack's own receivers. There is
		// deliberately no gNMI counterpart: a gNMI update originates on the
		// device, so the seam that would be needed to fake one does not exist.
		InjectFlow: pipedebug.NewUDPInjector(
			envOr(pipedebug.EnvFlowTarget, pipedebug.DefaultFlowTarget), 5*time.Second),
		ParseFilter: s.debugParseFilter,
		UIQueryRun:  pipedebug.NewUIQueryRun(debugUIHost{s: s}),
		Ring:        s.debugRing,
		// Where a GUI-started trace writes its §3 session directory, and where
		// the session routes read from. Inside the api's OWN data volume by
		// default: it is the one directory this container is guaranteed to be
		// able to create 0700 and write. The host-side CLI keeps writing its
		// own data/debug on the host — an operator who wants both in one place
		// mounts that directory and sets DEBUG_SESSION_ROOT to the mount.
		SessionRoot: envOr(pipedebug.EnvSessionRoot, filepath.Join(envOr("DATA_DIR", "/data"), "debug")),
		// The read side of /api/debug/loglevel reports a LIVE reading only for
		// the switch this process owns. Every other module is reported as the
		// last change requested through this api, labelled as such — a guessed
		// level is how a module left at debug goes unnoticed.
		LevelReaders: map[pipedebug.Module]pipedebug.LevelReader{pipedebug.ModuleAPI: s.debugAPILevel},
		Audit:        s.debugAudit,
		WriteJSON:    writeJSON,
		WriteError:   writeError,
		Now:          func() time.Time { return time.Now().UTC() },
	}
}

// debugAudit records a debug action into the immutable trail with the
// `sensitive` tag — the pdAudit shape, so the two operator-initiated features
// that touch tenant telemetry read identically in the compliance view.
func (s *server) debugAudit(r *http.Request, tenant, action string, detail map[string]any) {
	if s.audit == nil {
		return
	}
	claims, _ := userFrom(r.Context())
	_, cross := principalTenant(claims)
	if detail == nil {
		detail = map[string]any{}
	}
	detail["action"] = action
	detail["sensitive"] = true
	s.audit.Record(AuditEvent{
		Actor: claims.Sub, Tenant: tenant, Cross: cross,
		Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Decision: "allow",
		Remote: auditClientIP(r), Detail: detail,
	})
}

// DEBUG-ROUTES-END

// ── Security (CTEM) API wiring — Project 3 P3-API ───────────────────────────
//
// The handlers live in package secapi (a real compiler-enforced boundary, §2);
// what belongs HERE is the wiring: which permission each of its abstract gates
// maps onto, which transports it gets, and how one route delegates to an
// existing handler. secapi holds no ambient authority of its own — everything
// below is handed to it explicitly.

// newSecurityControlPlaneStore selects the Postgres register under the Postgres
// backend (migration 0037, tenant_iso FORCE-RLS), else the tenant-keyed file
// store so the default build works unchanged (the rcafeedback precedent).
func newSecurityControlPlaneStore() secapi.Store {
	if ps, ok := platformdb.ActivePG(); ok {
		return secapi.NewPGStore(ps.DB())
	}
	fs := secapi.NewFileStore(envOr("SECURITY_CONTROL_PLANE_FILE", "/data/security_control_plane.json"))
	if err := fs.LoadErr(); err != nil {
		// The store still SERVES (the shipped catalog defaults + no saved
		// views) rather than refusing to boot over a preferences file — but a
		// tenant whose disabled rules did not load must not silently see the
		// full catalog as if it had configured nothing (§10).
		logError("security", "security control-plane state could not be read — serving the SHIPPED rule defaults and NO saved views; a tenant's stored rule state is NOT applied",
			map[string]any{"err": err.Error()})
	}
	return fs
}

// SEC-FRAMEWORKS-BEGIN
// newSecurityFrameworkStore selects the Postgres register under the Postgres
// backend (migration 0042, tenant_iso FORCE-RLS), else the tenant-keyed file
// store so the default build works unchanged (the secStore precedent).
func newSecurityFrameworkStore() secapi.FrameworkStore {
	if ps, ok := platformdb.ActivePG(); ok {
		return secapi.NewFrameworkPGStore(ps.DB())
	}
	fs := secapi.NewFrameworkFileStore(envOr("SECURITY_FRAMEWORK_STATE_FILE", "/data/security_frameworks.json"))
	if err := fs.LoadErr(); err != nil {
		// The store still SERVES (the shipped default framework set) rather
		// than refusing to boot over a preferences file — but a tenant whose
		// HIPAA/PCI selection did not load must not be shown the defaults as
		// though it had chosen them (§10 no silent failures).
		logError("security", "security framework selection could not be read — serving the SHIPPED default framework set; a tenant's stored selection is NOT applied",
			map[string]any{"err": err.Error()})
	}
	return fs
}

// SEC-FRAMEWORKS-END

// securityAuthz maps secapi's abstract gates onto this platform's RBAC modules
// and resolves the caller's tenant scope.
//
// GATE CHOICE (§3a rule 3 — "pick the right gate"):
//   - READ is infrastructure:read, the SAME gate /api/compliance and
//     /api/correlations already use. Security findings are per-tenant OPERATOR
//     data about the tenant's own devices, not platform plumbing.
//   - WRITE (saved views) is infrastructure:write: a saved filter set is
//     operator working state, not administration.
//   - ADMIN (rule enablement) is administration:write — the per-tenant config
//     gate ticketing/contact points already use. It is deliberately NOT
//     requirePlatformAdmin/requireCrossTenant: which detections a tenant runs
//     is that TENANT's configuration, and a platform-global gate would put it
//     out of the tenant's own reach while a scope-blind admin gate would put it
//     in every other tenant's. The tenant filter is applied on top either way.
func (s *server) securityAuthz(w http.ResponseWriter, r *http.Request, gate secapi.Gate) (secapi.Principal, bool) {
	module, level := "infrastructure", LevelRead
	switch gate {
	case secapi.GateWrite:
		module, level = "infrastructure", LevelWrite
	case secapi.GateAdmin:
		module, level = "administration", LevelWrite
	case secapi.GateRead:
		// the default above
	}
	claims, ok := s.requirePerm(w, r, module, level)
	if !ok {
		return secapi.Principal{}, false
	}
	tenant, cross := principalTenant(claims)
	keys, _ := s.visibleDeviceKeys(claims)
	addrs, _ := s.visibleDeviceAddrs(claims)
	return secapi.Principal{
		Tenant: tenant, Cross: cross, Subject: claims.Sub,
		DeviceKeys: keys, DeviceAddrs: addrs,
	}, true
}

// securityRegistryDevices is the CTEM funnel's `scope`: how many devices the
// caller's tenant actually OWNS, from the same visibility rule every inventory
// surface uses. It is the registry, not the set of devices that happen to carry
// findings — that distinction is the whole point of reporting `unassessed`.
func (s *server) securityRegistryDevices(r *http.Request) int {
	claims, ok := userFrom(r.Context())
	if !ok || s.discovery == nil {
		return 0
	}
	return len(visibleDevices(s.discovery.Devices(), claims))
}

// securityAudit records an accepted security control-plane write (the
// auditManualEdit shape: deny-by-default writes are audited, reads are not).
func (s *server) securityAudit(r *http.Request, tenant, action string, detail map[string]any) {
	if s.audit == nil {
		return
	}
	claims, _ := userFrom(r.Context())
	_, cross := principalTenant(claims)
	if detail == nil {
		detail = map[string]any{}
	}
	detail["action"] = action
	s.audit.Record(AuditEvent{
		Actor: claims.Sub, Tenant: tenant, Cross: cross,
		Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Decision: "allow",
		Remote: auditClientIP(r), Detail: detail,
	})
}

// securityAPIDeps assembles the injected collaborators. Called AFTER secStore /
// secFindMetrics are set, so the API never captures a nil store.
func (s *server) securityAPIDeps() secapi.Deps {
	return secapi.Deps{
		Authz:           s.securityAuthz,
		Search:          openSearch,
		ExposureStories: s.securityExposureStories,
		RegistryDevices: s.securityRegistryDevices,
		Store:           s.secStore,
		// SEC-FRAMEWORKS-BEGIN
		FrameworkStore: s.secFrameworks,
		// SEC-FRAMEWORKS-END
		// SECURITY-LANE-BEGIN
		// The ONLY producer-derived input the compliance view takes. It sits in
		// the SECURITY-LANE markers (not the SEC-FRAMEWORKS ones) because it is
		// the one line that goes when internal/hardening does: with it removed
		// the field is nil, secapi falls back to the seed catalog, and the
		// framework selection + scorecards keep answering.
		ComplianceInputs: securityComplianceInputs,
		// SECURITY-LANE-END
		// ENTERPRISE-ASSEMBLY-BEGIN (security_dialects)
		// The crosswalks for the frameworks beyond the default two are a
		// commercial add-on module (enterprise/frameworks). This is the ONLY
		// place that names it: secapi takes the packs as data and never learns
		// about licensing, exactly as the security lane takes the dialect packs.
		FrameworkCrosswalks: s.licensedFrameworkCrosswalks,
		// ENTERPRISE-ASSEMBLY-END
		Metrics:    s.secFindMetrics,
		Audit:      s.securityAudit,
		WriteJSON:  writeJSON,
		WriteError: writeError,
	}
}

// ENTERPRISE-ASSEMBLY-BEGIN (security_dialects)
// licensedFrameworkCrosswalks is the compliance-framework half of the
// `security_dialects` entitlement, whose locked scope is "device-hardening
// dialects beyond the default set, AND compliance frameworks beyond the default
// two". NIST SP 800-53 Rev5 and CIS Controls v8.1 are CORE and are not gated
// here — their crosswalks live in Apache-2.0 internal/compliancemodel and this
// function never sees them.
//
// It is a FUNCTION, not a slice computed once at start-up, because entitlement
// is live state: installing or letting a licence lapse must change what the
// next request is scored against without a restart — the same reason
// licenceDialectAllowed is a predicate.
//
// Degradation is honest and is the projection's job, not this function's: an
// enabled framework whose crosswalk this deployment does not carry gets a
// scorecard with a NULL score and a sentence saying so
// (compliancemodel.NotLicensedCoverage), never a silent disappearance from the
// page and never a 0 % that would read as total failure.
func (s *server) licensedFrameworkCrosswalks() []compliancemodel.FrameworkPack {
	if !entitlement.Entitled(s.entitlements, entitlement.FeatureSecurityDialects) {
		return nil
	}
	return frameworks.Packs()
}

// ENTERPRISE-ASSEMBLY-END

// SECURITY-LANE-BEGIN
// securityComplianceInputs adapts the shipped hardening catalogue into the
// producer-derived half of the compliance view: the rule→control mapping the
// framework projection composes onto the owned control catalog, and the
// published CIS device benchmarks with the section each rule cites.
//
// It lives HERE, in the wiring, because internal/hardening is a removable module
// and secapi is a read API that must survive its deletion
// (security_lane_removability_test.go). Deleting the SECURITY-LANE block that
// carries it leaves secapi.Deps.ComplianceInputs nil, which is a SUPPORTED
// state: the frameworks endpoint then serves the catalogue with no benchmark
// list and says so, and the scorecards project the legacy compliance checks
// only.
//
// A rule contributes at the honest "supports" strength (§5d): one config-audit
// check evidences a control without fully demonstrating it.
func securityComplianceInputs() secapi.ComplianceInputs {
	// No DialectPacks, deliberately: this projects the rule CONCEPTS and their
	// control/benchmark provenance, all of which are Apache-2.0 core and the
	// same whichever dialects are installed. Only the per-vendor detection
	// differs, and nothing here reads it.
	hc := hardening.DefaultCatalog()

	labels := map[string]string{}
	benchmarks := make([]secapi.BenchmarkView, 0, 8)
	for _, b := range hardening.Benchmarks() {
		labels[b.ID] = b.Label()
		benchmarks = append(benchmarks, secapi.BenchmarkView{
			ID: b.ID, Title: b.Title, Version: b.Version, Platform: b.Platform,
			SectionsVerified: b.SectionsVerified, Note: b.Note,
		})
	}

	mappings := make([]compliancemodel.ControlMapping, 0, 64)
	controls := map[string][]string{}
	ids := make([]string, 0, 64)
	add := func(id string, tags []string) {
		ids = append(ids, id)
		controls[id] = tags
		if len(tags) > 0 {
			mappings = append(mappings, compliancemodel.ControlMapping{
				Check: id, Controls: secapi.SupportsControls(tags),
			})
		}
	}
	for _, r := range hc.Rules() {
		add(r.ID, r.Controls)
	}
	for _, p := range hc.Probes() {
		add(p.ID, p.Controls)
	}
	sort.Strings(ids)

	citations := make([]secapi.BenchmarkCitation, 0, 64)
	for _, id := range ids {
		for _, ref := range hardening.BenchmarkSections(id) {
			citations = append(citations, secapi.BenchmarkCitation{
				RuleID: id, BenchmarkID: ref.BenchmarkID, Section: ref.Section, Title: ref.Title,
				Label:    labels[ref.BenchmarkID] + " §" + ref.Section + " " + ref.Title,
				Controls: append([]string(nil), controls[id]...),
			})
		}
	}
	return secapi.ComplianceInputs{Mappings: mappings, Benchmarks: benchmarks, Citations: citations}
}

// registerSecurityLaneRoutes registers the producer lane's two operator
// surfaces — ONLY when the lane is on. A flag-off deployment answers 404 rather
// than advertising a dormant surface (and a 404 is also what a would-be prober
// gets, so the feature's presence is not enumerable).
func (s *server) registerSecurityLaneRoutes(mux *http.ServeMux) {
	if s.securityLane == nil {
		return
	}
	mux.HandleFunc("/api/security/lane/status", s.securityLane.HandleStatus)
	mux.HandleFunc("/api/security/scan", s.securityLane.HandleScan)
}

// securityLaneDeps assembles the P3-EMIT producer lane's injected collaborators
// (internal/seclane holds NO ambient authority — everything below is handed to
// it explicitly, the secapi precedent). Deleting this function, the four other
// SECURITY-LANE marker blocks in this file and internal/seclane removes the
// security PRODUCER without touching anything else; see the seclane package doc.
func (s *server) securityLaneDeps() seclane.Deps {
	return seclane.Deps{
		Now:          func() time.Time { return time.Now().UTC() },
		Interval:     durationOr(seclane.EnvScanInterval, seclane.DefaultScanInterval),
		MaxFindings:  envInt(seclane.EnvMaxFindings, seclane.DefaultMaxFindings),
		GlobalTenant: TenantGlobal,

		Tenants: s.securityLaneTenants,
		Devices: s.securityLaneDevices,
		// LICENCE-BEGIN — the hardening dialect gate (§4 "dialect registry").
		// The lane forwards it to the engine and knows nothing about licensing.
		DialectAllowed: s.licenceDialectAllowed,
		// LICENCE-END
		// ENTERPRISE-ASSEMBLY-BEGIN (security_dialects)
		// The dialects beyond the core one are a commercial add-on module
		// (enterprise/dialects). This is the ONLY place that names it: the lane
		// takes the packs as data, and internal/hardening never learns where
		// they came from. Deleting enterprise/ means deleting this line and the
		// import — the lane then evaluates the core dialect and reports every
		// other platform NotApplicable, never a false Pass.
		Dialects: dialects.Packs(),
		// ENTERPRISE-ASSEMBLY-END
		RuleStates: func(ctx context.Context, tenant string) (map[string]bool, error) {
			if s.secStore == nil {
				return nil, errors.New("security control-plane store unavailable")
			}
			// cross=false ALWAYS: a worker pass is scoped to one tenant, and a
			// cross-tenant read here would let one tenant's stored state reach
			// another tenant's scan (§3a).
			return s.secStore.RuleStates(ctx, tenant, false)
		},
		Seams: s.securityLaneSeams,

		// Transport: the same Vector bus-bridge produce path every other Go
		// producer uses (no Kafka client in the backend, §6 allowlist).
		Publish: func(ctx context.Context, topic string, recs []seclane.Record) (int, error) {
			out := make([]proxyRecord, 0, len(recs))
			for _, r := range recs {
				out = append(out, proxyRecord{Key: r.Key, Value: r.Value})
			}
			return produceJSON(ctx, topic, out)
		},
		Search: openSearch,
		CHQuery: func(ctx context.Context, scope, sql string) ([]map[string]any, error) {
			return chSelect(ctx, scope, sql, "worker:security-lane-flows")
		},

		// Vendor advisories: the OFFLINE feed is the canonical, credential-free
		// provider (§5g air-gap path). ConfigSource is the sealed config store
		// when FEATURE_CONFIG_BACKUP is on; nil while it is off — the hardening
		// lane then reports every rule UNASSESSED rather than falsely clear.
		AdvisoryFeed: s.vulns,
		ConfigSource: s.configHardeningSource(), // P3-CFG: sealed config store (nil while FEATURE_CONFIG_BACKUP is off)
		ParseSoftware: func(vendor, osStr, osVersion string) (string, string) {
			osi := collectors.ResolveDeviceOS(vendor, osStr, osVersion)
			return osi.Product, osi.Version
		},

		Authz:      s.securityAuthz,
		Audit:      s.securityAudit,
		WriteJSON:  writeJSON,
		WriteError: writeError,
		LogWarn:    func(msg string, f map[string]any) { logWarn("security.lane", msg, f) },
		LogError:   func(msg string, f map[string]any) { logError("security.lane", msg, f) },
		Scrub:      scrubLogValue,
		TenantSeg:  seclane.TenantSeg,
		Spool: seclane.NewFileSpool(
			envOr(seclane.EnvDeadLetterFile, seclane.DefaultDeadLetterFile),
			seclane.DeadLetterMaxBytes,
			func() time.Time { return time.Now().UTC() },
			seclane.TenantSeg, scrubLogValue),
	}
}

// securityLaneTenants lists the tenant ids the producer scans. Untagged/global
// devices are deliberately NOT scanned: a finding with no owning tenant has no
// one to attribute it to, and stamping one would be inventing provenance (§10).
func (s *server) securityLaneTenants() []string {
	if s.tenants == nil {
		return nil
	}
	out := make([]string, 0, 8)
	for _, t := range s.tenants.List() {
		id := normTenant(t.ID)
		if id == "" || id == TenantGlobal || t.Status == TenantStatusSuspended {
			continue
		}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// securityLaneDevices returns ONE tenant's own devices (§3a: the inventory row's
// tenant is the authority — this path has no request body at all).
func (s *server) securityLaneDevices(tenant string) []seclane.Device {
	if s.discovery == nil {
		return nil
	}
	want := normTenant(tenant)
	all := s.discovery.Devices()
	out := make([]seclane.Device, 0, len(all))
	for _, d := range all {
		if deviceTenant(d) != want {
			continue
		}
		// MONITORING-BEGIN — assess only devices monitoring is on for: the
		// security lane's evidence comes from the same collection the licence
		// counts, so an unmonitored device has nothing to assess FROM (C4).
		if !d.Monitored {
			continue
		}
		// MONITORING-END
		out = append(out, seclane.Device{
			ID: d.ID, Name: d.Name, Address: d.Address,
			Vendor: d.Vendor, OS: d.OS, OSVersion: d.OSVersion, Model: d.Model,
			TenantID: deviceTenant(d),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// securityLaneSeams projects ONE tenant's ACTIVE seam inventory for the
// seam-aware exposure probes. An error propagates so the evaluator fails CLOSED
// (StatusUnknown) — it must never read an unreadable seam model as "not
// exposed". A deployment with no seam store (file backend) has no seam data,
// which is the same honest non-verdict.
func (s *server) securityLaneSeams(ctx context.Context, tenant string) ([]seclane.SeamRow, error) {
	if s.seams == nil {
		return nil, nil
	}
	list, err := s.seams.List(ctx, normTenant(tenant), false, "active", "")
	if err != nil {
		return nil, err
	}
	out := make([]seclane.SeamRow, 0, len(list))
	for _, sm := range list {
		out = append(out, seclane.SeamRow{
			SeamID: sm.SeamID, SeamType: sm.SeamType,
			OnPrem: sm.Endpoints["on_prem"], Interface: sm.Endpoints["interface"],
		})
	}
	return out, nil
}

// SECURITY-LANE-END

// DATA-PROTECTION-BEGIN — the internal/dataprotect wiring.
//
// The module owns the whole domain; what stays here is the Deps assembly plus
// the four adapters that need the *server receiver to reach platform plumbing:
// the platform-admin gate, the audit repo, the shared OpenSearch client and the
// structured loggers. Every concrete value the module needs is resolved from
// the environment HERE, once, so nothing inside the package reads os.Getenv
// (and the documented-env-switch guard still sees every literal).

// dataProtectDeps assembles the Data Protection module's dependencies.
func (s *server) dataProtectDeps(cfg dataprotect.ConfigStore) dataprotect.Deps {
	return dataprotect.Deps{
		Search:    dataProtectSearch{s: s},
		Audit:     dataProtectAudit{s: s},
		Authz:     s.dataProtectGate,
		Log:       dataProtectLog{},
		Config:    cfg,
		WriteJSON: writeJSON,
		Go:        safeGo,
		// Read lazily through the *server: the config-backup module is built
		// AFTER newServer returns (main() gates it on FEATURE_CONFIG_BACKUP),
		// so a value captured here would always report the module off.
		DeviceConfigs: dataProtectDeviceConfigs{s: s},

		Repository:             dataprotect.DefaultRepository,
		OpsFile:                envOr("SNAPSHOT_OPS_FILE", "/data/snapshot_operations.json"),
		VerifyFile:             envOr("SNAPSHOT_VERIFY_FILE", "/data/snapshot_verify.json"),
		BackupReportPath:       envOr("BACKUP_REPORT", "/data/backup-report.json"),
		RestoreDrillReportPath: envOr("RESTORE_DRILL_REPORT", "/data/restore-drill.report.json"),
		// The BUNDLE drill's report (scripts/backup-drill.sh). Distinct from the
		// live-store canary drill above: this one proves an actual bundle
		// ARTIFACT restores, which is what an operator holds after losing the
		// host. The host dir data/api is the api's /data mount, so the script's
		// default and this default name the same file from the two sides.
		BackupDrillReportPath: envOr("BACKUP_DRILL_REPORT", "/data/backup-drill.report.json"),
		// Optional second `fs` snapshot repository on a separately mounted path
		// (tracker 225a). Empty = not configured, which is the shipped default
		// and is reported as a deployment fact rather than as a fault.
		SecondaryRepository: strings.TrimSpace(os.Getenv("OPENSEARCH_SNAPSHOT_REPO2")),
		// Default ON: a platform that silently stops proving its backups is the
		// failure the probe closes, so only an explicit "false" disables it.
		ProbeEnabled:  envOr("SNAPSHOT_PROBE_ENABLED", "true") == "true",
		ProbeInterval: snapshotProbeInterval(),
	}
}

// storageMeterDatabase is the ClickHouse database whose `system.parts` rows are
// measured. The literal 'netops' is what every other SQL string in this
// codebase already names (internal/chschema); it is a const here so the size
// query and the schema queries cannot drift apart silently.
const storageMeterDatabase = "netops"

// storageMeterLog adapts the package's variadic key/value logger onto this
// platform's structured logger. Odd trailing keys are kept (as a key with an
// empty value) rather than dropped — a log line that silently loses a field is
// the observability failure §10 forbids.
func storageMeterLog(msg string, kv ...any) {
	fields := make(map[string]any, len(kv)/2+1)
	for i := 0; i < len(kv); i += 2 {
		key := fmt.Sprint(kv[i])
		if i+1 < len(kv) {
			fields[key] = kv[i+1]
		} else {
			fields[key] = ""
		}
	}
	logInfo("storage.measure", msg, fields)
}

// STORAGE-MEASUREMENT-BEGIN — the Deps assembly for internal/storagemeter
// (tracker 204). Every seam is bound to the client the rest of the api ALREADY
// uses, never a second one: the package holds no URL, no credential and no TLS
// config, and it reads no environment at all. Each env switch below is resolved
// here, once, and travels as a value.
func (s *server) storageMeterDeps() storagemeter.Deps {
	return storagemeter.Deps{
		Now:  func() time.Time { return time.Now().UTC() },
		Log:  storageMeterLog,
		Gate: s.storageMeterGate,

		// The SAME OpenSearch request path the log search and Data Protection
		// use (backend_client.go), so a transport or credential change lands in
		// one place. `_cat/indices` needs `indices:monitor/stats`, which the
		// api's service role gained with this change — an installation whose
		// security config has not been re-applied gets the node-level fallback
		// and is TOLD that it did.
		OpenSearch: func(ctx context.Context, path string, out any) error {
			return s.osDo(ctx, http.MethodGet, path, nil, out, 20*time.Second)
		},
		// The SAME index-pattern algebra the log search uses (§3a.4: one
		// derivation of what a caller may name, not two).
		CatPattern:  oslog.TenantCatPattern,
		IndexTenant: indexTenantSegment,

		// The cross-tenant WORKER lane: system.parts is cluster metadata with no
		// tenant column, so no row policy can scope it and the narrowing lives
		// in the SQL storagemeter builds (and is pinned by its own test).
		ClickHouse: func(ctx context.Context, sql string) ([]map[string]any, error) {
			return chWorkerQueryTuned(ctx, chWorkerRead{SQL: sql, Tag: "worker:storage-measure"})
		},
		Database: storageMeterDatabase,

		// UNSCOPED on purpose: vm_data_size_bytes is VictoriaMetrics' own
		// self-metric and carries no tenant label. storagemeter calls this only
		// on the platform path and refuses to derive a per-tenant share.
		Victoria: func(ctx context.Context, promql string) ([]storagemeter.VMSample, error) {
			samples, err := s.vmInstant(ctx, promql)
			if err != nil {
				return nil, err
			}
			out := make([]storagemeter.VMSample, 0, len(samples))
			for _, sm := range samples {
				out = append(out, storagemeter.VMSample{Labels: sm.Labels, Value: sm.Value})
			}
			return out, nil
		},

		Postgres: storageMeterPGSize,

		Dir:      storagemeter.WalkDir,
		DataRoot: envOr("DATA_DIR", "/data"),
	}
}

// storageMeterGate binds the READ gate (§3a rule 1 — scope by the principal,
// default-closed). Deliberately requireAdmin + principalTenant rather than
// requirePlatformAdmin: a tenant admin may see ITS OWN bytes (that is its own
// data), and the cross-tenant grant is what widens the view to every tenant.
// The tenant is taken from the token and from nowhere else — this route reads
// no tenant selector at all, so there is no `as_tenant` to ignore.
func (s *server) storageMeterGate(w http.ResponseWriter, r *http.Request) (storagemeter.Principal, bool) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return storagemeter.Principal{}, false
	}
	tenant, cross := principalTenant(claims)
	if cross {
		// The platform owner's tenant is the GLOBAL pseudo-tenant, which is not
		// a storage scope. A cross-tenant read carries no tenant at all, so the
		// value can never be mistaken for a narrowing.
		tenant = ""
	}
	return storagemeter.Principal{Subject: claims.Sub, Tenant: tenant, CrossTenant: cross}, true
}

// indexTenantSegment recovers the tenant segment from a per-tenant OpenSearch
// index name. It is the INVERSE of the naming vector-router writes and
// oslog.TenantIndexPattern reads: netops-<signal>-<tenant>-<date>. A name that
// does not match is reported as platform-owned rather than attributed to a
// guess — bytes belonging to nobody is a fact; bytes attributed to the wrong
// tenant is a §3a leak.
func indexTenantSegment(index string) (string, bool) {
	rest, ok := strings.CutPrefix(index, "netops-")
	if !ok {
		return "", false
	}
	// <signal>-<tenant>-<date>: the date is the last segment, the signal the
	// first, and everything between them is the tenant segment (which may
	// itself contain hyphens, since IndexTenantSeg maps illegal characters to
	// "-").
	parts := strings.Split(rest, "-")
	if len(parts) < 3 {
		return "", false
	}
	seg := strings.Join(parts[1:len(parts)-1], "-")
	if seg == "" {
		return "", false
	}
	return seg, true
}

// storageMeterPGSize measures the application database, or says why it cannot.
// "This installation runs the file backend" is a DEPLOYMENT FACT, not a
// failure, and the two must not render alike.
func storageMeterPGSize(ctx context.Context) (int64, []storagemeter.Component, bool, string, error) {
	ps, active := platformdb.ActivePG()
	if !active {
		return 0, nil, false,
			"this installation does not use the PostgreSQL app-state backend (STORE_BACKEND is not `postgres`), so there is no application database to size",
			nil
	}
	total, rels, err := ps.DB().DatabaseSize(ctx)
	if err != nil {
		if errors.Is(err, platformdb.ErrNoPool) {
			return 0, nil, false,
				"the PostgreSQL backend is selected but no pool is open, so no size could be read",
				nil
		}
		return 0, nil, false, "", err
	}
	comps := make([]storagemeter.Component, 0, len(rels))
	for _, r := range rels {
		comps = append(comps, storagemeter.Component{Name: r.Name, BytesOnDisk: r.Bytes})
	}
	return total, comps, true, "", nil
}

// STORAGE-MEASUREMENT-END

// snapshotProbeInterval is the minimum spacing between restorability probes.
// An unparseable value falls back to the shipped 24h and SAYS SO — a silently
// ignored cadence is the class of switch the env-docs guard exists to catch.
func snapshotProbeInterval() time.Duration {
	if v := strings.TrimSpace(os.Getenv("SNAPSHOT_PROBE_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
		logWarn("backup.probe", "SNAPSHOT_PROBE_INTERVAL unparseable — falling back to 24h",
			map[string]any{"value": v})
	}
	return dataprotect.DefaultProbeInterval
}

// dataProtectGate binds the PLATFORM-admin gate (§3a rule 3): a tenant/org
// admin holds full administration:admin, so a scope-blind requireAdmin here
// would hand every tenant the platform's backup posture and the ability to
// delete its restore points.
func (s *server) dataProtectGate(w http.ResponseWriter, r *http.Request) (dataprotect.Principal, bool) {
	claims, ok := s.requirePlatformAdmin(w, r)
	if !ok {
		return dataprotect.Principal{}, false
	}
	return dataprotect.Principal{Subject: claims.Sub}, true
}

// dataProtectSearch adapts the shared OpenSearch client (backend_client.go) to
// dataprotect.OpenSearch — the module's ONLY route to the cluster.
type dataProtectSearch struct{ s *server }

func (a dataProtectSearch) Do(ctx context.Context, method, path string, body []byte, out any, timeout time.Duration) error {
	return a.s.osDo(ctx, method, path, body, out, timeout)
}

// dataProtectAudit adapts the platform audit repo. The request envelope
// (method, path, client IP) is filled HERE so the module never has to know how
// this platform derives a client address behind its proxy.
type dataProtectAudit struct{ s *server }

func (a dataProtectAudit) Record(r *http.Request, ev dataprotect.AuditRecord) {
	a.s.audit.Record(AuditEvent{
		Actor: ev.Actor, Method: r.Method, Path: r.URL.Path,
		Status: ev.Status, Decision: ev.Decision, Remote: auditClientIP(r),
		Detail: ev.Detail,
	})
}

// dataProtectLog adapts the structured loggers (§10).
type dataProtectLog struct{}

func (dataProtectLog) Info(component, msg string, fields map[string]any) {
	logInfo(component, msg, fields)
}
func (dataProtectLog) Warn(component, msg string, fields map[string]any) {
	logWarn(component, msg, fields)
}
func (dataProtectLog) Error(component, msg string, fields map[string]any) {
	logError(component, msg, fields)
}

// dataProtectDeviceConfigs reports the config-backup module's coverage facts.
// ok=false means the module is OFF, which the coverage table renders as
// "not_applicable" with a reason — never as a measurement failure.
type dataProtectDeviceConfigs struct{ s *server }

func (a dataProtectDeviceConfigs) Facts() (dataprotect.DeviceConfigFacts, bool) {
	facts := dataprotect.DeviceConfigFacts{
		FeatureFlagEnv:  configstore.EnvFeatureFlag,
		IntervalEnv:     configstore.EnvInterval,
		KeepVersionsEnv: configstore.EnvKeepVersions,
		KeepVersions:    configBackupKeepVersions(),
	}
	if a.s == nil || a.s.configBackup == nil {
		return facts, false
	}
	facts.Interval = a.s.configBackup.Interval()
	if m := a.s.configBackup.Metrics(); m != nil {
		snap := m.Snapshot()
		facts.Versions, facts.Failed, facts.Pruned = snap["versions_total"], snap["runs_failed"], snap["pruned_total"]
		facts.HasCounters = true
	}
	return facts, true
}

// configBackupKeepVersions mirrors the config-backup module's own clamp so the
// number the coverage table shows is the number that applies.
func configBackupKeepVersions() int {
	keep := configstore.DefaultKeepVersions
	if v := strings.TrimSpace(os.Getenv(configstore.EnvKeepVersions)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			keep = n
		}
	}
	switch {
	case keep < 2:
		keep = 2
	case keep > 500:
		keep = 500
	}
	return keep
}

// DATA-PROTECTION-END

// LICENCE-BEGIN — the internal/licence + internal/entitlement wiring.
//
// Deleting this block, the other LICENCE marker blocks in this file and in
// bgp_ops.go / identity_handlers.go / oidc_config.go / org_handlers.go, and the
// two packages, removes the licence mechanism entirely. That is a SUPPORTED
// state, and a deliberately boring one: every gate then answers Community —
// 25 devices, 5 watched prefixes, no commercial feature — because the gates
// are nil-safe and fail CLOSED. Nothing breaks, nothing opens up.
//
// Nothing here is reachable from a safety control. Isolation, RLS,
// authorization, integrity and core authentication (OIDC included) do not
// consult the entitlement service, and a test asserts they cannot
// (internal/entitlement/safety_invariant_test.go). The worst outcome of a bug
// in this wiring is a customer who paid for a capability not getting it — a
// support ticket, never a breach.

// licenceDeps assembles the platform-admin Licence route's injected
// collaborators. internal/licence holds NO ambient authority: it reads no
// environment and reaches nothing it was not handed (the internal/dataprotect
// precedent).
func (s *server) licenceDeps() licence.Deps {
	return licence.Deps{
		Store:       s.licenceStore,
		Service:     s.entitlements,
		Gate:        s.licenceGate,
		ReadGate:    s.licenceReadGate,
		Audit:       licenceAudit{s},
		Usage:       s.licenceUsage,
		UsageNotes:  s.licenceUsageNotes,
		TenantUsage: s.licenceTenantUsage,
		// The over-ceiling device list — the "which devices are over" half of
		// the honest-degradation rule. Provider view only (the module drops it
		// from the tenant projection).
		OverCeilingDevices: s.licenceOverCeilingDevices,
		Now:                func() time.Time { return time.Now().UTC() },
		WriteJSON:          writeJSON,
		WriteError:         writeError,
	}
}

// MONITORING-BEGIN

// devmonDeps assembles the monitoring switch's injected collaborators.
//
// One function, shared by the composition root and by the tests, so what the
// tests exercise IS the wiring the process runs — a second, test-only Deps
// literal is how a gate ends up proven in a fixture and missing in production.
// internal/devmon holds no ambient authority: it reads no environment and
// reaches nothing it was not handed (the internal/licence precedent).
func (s *server) devmonDeps() devmon.Deps {
	return devmon.Deps{
		Registry: s.discovery,
		ReadGate: func(w http.ResponseWriter, r *http.Request) (devmon.Principal, bool) {
			return s.devmonGate(w, r, LevelRead)
		},
		WriteGate: func(w http.ResponseWriter, r *http.Request) (devmon.Principal, bool) {
			return s.devmonGate(w, r, LevelWrite)
		},
		CanSee: canSeeDevice,
		Audit: func(r *http.Request, ev devmon.AuditRecord) {
			if s.audit == nil {
				return
			}
			claims, _ := userFrom(r.Context())
			tenant, cross := principalTenant(claims)
			s.audit.Record(AuditEvent{
				Actor: ev.Actor, Tenant: tenant, Cross: cross,
				Method: r.Method, Path: r.URL.Path, Status: ev.Status,
				Decision: ev.Decision, Remote: auditClientIP(r), Detail: ev.Detail,
			})
		},
		// A ceiling refusal reaches the module as an opaque error; this is the
		// only place that knows it is a licence matter and renders the 402.
		Refusal:    entitlement.WriteRefusal,
		WriteJSON:  writeJSON,
		WriteError: writeError,
	}
}

// MONITORING-END

// licenceGate binds the PLATFORM-admin gate (§3a rule 3) for every WRITE.
// Installing or replacing the licence is platform-global commercial plumbing:
// a tenant/org admin holds full administration:admin, so a scope-blind
// requireAdmin here would let any tenant license the whole platform.
//
// requirePlatformAdmin resolves the platform owner, who is cross-tenant by
// construction, so the principal it returns carries Cross=true — which is also
// what makes the module's fail-closed ReadGate fallback serve the PROVIDER view
// rather than an empty tenant projection.
func (s *server) licenceGate(w http.ResponseWriter, r *http.Request) (licence.Principal, bool) {
	claims, ok := s.requirePlatformAdmin(w, r)
	if !ok {
		return licence.Principal{}, false
	}
	return licence.Principal{Subject: claims.Sub, Tenant: TenantGlobal, CrossTenant: true}, true
}

// licenceReadGate binds the READ gate: administration:admin, at whatever scope
// the caller holds it (§3a rule 1 — scope by the principal, default-closed).
//
// A tenant/org admin is ADMITTED here and gets their own tenant's projection;
// the platform owner is cross-tenant and gets the provider view. The narrowing
// selector (`as_tenant` / X-Acting-Tenant) is already applied to the claims by
// the auth middleware and can only NARROW, so a scoped caller cannot use it to
// read another tenant's usage — principalTenant ignores it for a non-owner.
func (s *server) licenceReadGate(w http.ResponseWriter, r *http.Request) (licence.Principal, bool) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return licence.Principal{}, false
	}
	tenant, cross := principalTenant(claims)
	return licence.Principal{Subject: claims.Sub, Tenant: tenant, CrossTenant: cross}, true
}

// licenceAudit adapts the platform audit repo. The request envelope (method,
// path, client IP) is filled HERE so the module never has to know how this
// platform derives a client address behind its proxy.
type licenceAudit struct{ s *server }

func (a licenceAudit) Record(r *http.Request, ev licence.AuditRecord) {
	if a.s == nil || a.s.audit == nil {
		return
	}
	a.s.audit.Record(AuditEvent{
		Actor: ev.Actor, Method: r.Method, Path: r.URL.Path,
		Status: ev.Status, Decision: ev.Decision, Remote: auditClientIP(r),
		Detail: ev.Detail,
	})
}

// licenceUsage measures the ENFORCED ceilings for the admin page's usage bars.
//
// A ceiling this function omits is NOT MEASURED and the page says exactly that
// — it is never rendered as a reassuring zero. Only the two decided ceilings
// are measured, because those are the only two anything enforces; showing a bar
// for a limit that does not bite would be theatre (licenceUsageNotes says so on
// the page).
//
// Both counts are PLATFORM-WIDE, deliberately: a licence covers the deployment,
// not a tenant's view of it, and counting through the caller's tenant filter
// would let a second tenant's devices escape the ceiling.
func (s *server) licenceUsage(ctx context.Context) licence.Usage {
	u := licence.Usage{}
	if s.discovery != nil {
		// MONITORED devices, deduplicated — the licensed unit (owner decision
		// C4, 2026-09-05), and exactly the set the collector pool polls.
		//
		// Inventory size is deliberately NOT this number. A deployment that has
		// discovered five hundred devices and enabled twelve is using twelve of
		// its allowance, and a bar reading "500 of 25" would be a lie about what
		// the licence covers. What the inventory holds beyond that is shown as
		// the discovered count on the Devices page, and the devices whose
		// monitoring the ceiling itself withheld are listed by
		// licenceUsageNotes — nothing is hidden, and nothing is deleted.
		u[entitlement.CeilingDevices] = s.discovery.MonitoredCount()
	}
	if s.bgpWatch != nil {
		if n, err := s.watchedPrefixCount(ctx, TenantGlobal, true); err == nil {
			u[entitlement.CeilingWatchedPrefixes] = n
		}
		// On error the key is simply absent — "we could not measure this" and
		// "there are none" are different facts and only one of them is
		// reassuring.
	}
	return u
}

// licenceTenantUsage measures the ceilings for ONE tenant — the numbers the
// tenant projection shows beside the shared ceilings — plus the reason for
// every ceiling it does not measure.
//
// ISOLATION (§3a rule 1). Every count here is taken through the SAME tenant
// filter the rest of the API uses, with cross=false always: canSeeDevice for the
// fleet, the watchlist store's own (tenant, cross) read for prefixes. A tenant
// therefore never sees a number that includes another tenant's rows, and never
// the platform-wide total — which would itself disclose the size of everyone
// else's estate.
//
// UNMEASURABLE IS SAID OUT LOUD. Only the two ENFORCED ceilings can carry a
// number at all (licence_routes_test.go pins that an un-enforced ceiling never
// shows usage as if it bit), and two of the rest cannot be counted per tenant
// even in principle: the withheld-at-the-ceiling devices have no owner yet, and
// the Iris method catalog ships with the platform and is identical for every
// tenant. Each says so rather than showing a reassuring zero.
func (s *server) licenceTenantUsage(ctx context.Context, tenant string) (licence.Usage, map[string]string) {
	u := licence.Usage{}
	notes := map[string]string{}
	for _, n := range entitlement.CeilingNames() {
		if !entitlement.Enforced(n) {
			notes[n] = "carried in the licence but not enforced by this build"
		}
	}
	notes[entitlement.CeilingTenants] = "carried in the licence but not enforced by this build; it counts the tenants on the whole installation, which is the provider's number, not yours"
	notes[entitlement.CeilingSkills] = "carried in the licence but not enforced by this build; the Iris method catalog ships with the platform and is the same for every tenant"

	if s.discovery == nil {
		notes[entitlement.CeilingDevices] = "the device registry is not available"
	} else {
		// Only the MONITORED devices THIS tenant owns — the same unit the
		// platform bar counts, through the same visibility filter the rest of
		// the API uses. A device the tenant has discovered but not enabled is
		// not on this bar, because it consumes nothing.
		n := 0
		for _, d := range s.discovery.Devices() {
			if d.Monitored && canSeeDevice(d, tenant, false) {
				n++
			}
		}
		u[entitlement.CeilingDevices] = n
	}

	if s.bgpWatch == nil {
		notes[entitlement.CeilingWatchedPrefixes] = "the BGP watchlist is not available"
	} else if n, err := s.watchedPrefixCount(ctx, tenant, false); err == nil {
		u[entitlement.CeilingWatchedPrefixes] = n
	} else {
		notes[entitlement.CeilingWatchedPrefixes] = "the BGP watchlist could not be read"
	}
	return u, notes
}

// licenceOverCeilingDevices lists the monitored devices beyond the licensed
// allowance, most recently enabled first.
//
// It is the device-granular half of "over-ceiling state is LISTED" (owner
// decision, 2026-09-05). None of these devices is disabled, hidden or deleted,
// and nothing here chooses which devices a licence covers — the ordering is
// presentational and the page says so verbatim (licence.OverCeilingNoteText).
//
// The reason carried per device is deliberately the SAME sentence for all of
// them: they are in one state, not ranked.
func (s *server) licenceOverCeilingDevices(_ context.Context) []licence.OverCeilingDevice {
	if s.discovery == nil || s.entitlements == nil {
		return nil
	}
	limit, _ := s.entitlements.Ceiling(entitlement.CeilingDevices)
	rows := s.discovery.MonitoredOverCeiling(limit)
	if len(rows) == 0 {
		return nil
	}
	reason := fmt.Sprintf("monitored and beyond the licensed allowance of %d %s — still being collected from; nothing has been disabled, hidden or deleted",
		limit, entitlement.CeilingLabel(entitlement.CeilingDevices))
	out := make([]licence.OverCeilingDevice, 0, len(rows))
	for _, r := range rows {
		out = append(out, licence.OverCeilingDevice{
			DeviceID: r.DeviceID, TenantID: r.TenantID, Name: r.Name, Reason: reason,
		})
	}
	return out
}

// licenceUsageNotes explains, per ceiling, why the page shows no number.
func (s *server) licenceUsageNotes(_ context.Context) map[string]string {
	notes := map[string]string{}
	for _, n := range entitlement.CeilingNames() {
		if !entitlement.Enforced(n) {
			notes[n] = "carried in the licence but not enforced by this build"
		}
	}
	if s.discovery == nil {
		notes[entitlement.CeilingDevices] = "the device registry is not available"
	} else if limit, _ := s.entitlements.Ceiling(entitlement.CeilingDevices); entitlement.SoftCeiling(entitlement.CeilingDevices, s.entitlements.Tier()) &&
		entitlement.Exceeds(s.discovery.MonitoredCount(), limit) {
		// The SOFT case: nothing was withheld because nothing is refused on a
		// paid tier. The bar reads over 100 % and the honest line beside it is
		// what that means commercially, not operationally.
		notes[entitlement.CeilingDevices] = fmt.Sprintf(
			"%d monitored device(s) above the allowance. This ceiling does not block on your tier — every device is still being collected from, "+
				"nothing has been disabled or deleted, and the overage is recorded for true-up; the devices concerned are listed below",
			s.discovery.MonitoredCount()-limit)
	} else if n := s.discovery.MonitoringWithheldCount(); n > 0 {
		// The honest half of the ceiling: these devices are in the inventory,
		// nothing about them was deleted or hidden, and Correlix is simply not
		// collecting from them because the licence is full. Saying so beside a
		// bar reading "25 of 25" is the difference between a limit and a
		// mystery.
		notes[entitlement.CeilingDevices] = fmt.Sprintf(
			"%d more device(s) are in the inventory and would be monitored, but the ceiling is full — "+
				"they are still discovered, still visible and nothing has been deleted; "+
				"raise the licence or turn monitoring off elsewhere to start collecting from them", n)
	}
	if s.bgpWatch == nil {
		notes[entitlement.CeilingWatchedPrefixes] = "the BGP watchlist is not available"
	}
	return notes
}

// licenceFeature wraps a handler in the central entitlement gate.
//
// This is the `requireFeature("...")` of the design's §4 table. It asks the
// SEMANTIC question — Entitled(FeatureX) — and never compares a tier, so a
// licence that grants a capability outside its usual bundle (a trial, a
// contractual exception) works with no special case.
//
// READ AND WRITE ARE DIFFERENT QUESTIONS (owner decision, 2026-09-05). After a
// licence lapses past its grace period, "paid-only creation/configuration
// actions become unavailable, existing data stays viewable/exportable". So the
// METHOD picks the gate, and nothing else does:
//
//	GET, HEAD          → RequireRead. A customer whose Team licence lapsed can
//	                     still open, search and export the findings they have.
//	everything else    → Require. Creating or configuring more is refused with
//	                     the 402, carrying licence_state: post_grace.
//
// The method is the right discriminator here rather than a per-route table
// because every route this wraps follows the HTTP contract already: its GET
// reads and its PUT/POST/DELETE write. A future route that mutated on GET would
// be a bug in that route, not in this rule — and would be caught by the
// enumeration test in licence_routes_test.go, which drives BOTH verbs against
// every wrapped route.
//
// Nothing about this widens a lapsed licence: RequireRead admits only features
// the lapsed document actually granted (State.LapsedFeatures). A capability
// nobody ever bought stays refused in every phase.
//
// Order matters: the licence check runs BEFORE the handler, so an unlicensed
// caller never reaches the domain code, and AFTER nothing — in particular it
// does not replace the handler's own authorization. A 402 means "your licence
// does not include this"; a 401/403 still means "you may not do this", and the
// two are different answers to different questions. Wrapping never removes a
// permission check; it only ever adds a commercial one on top.
func (s *server) licenceFeature(f entitlement.Feature, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gate := entitlement.Require
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			gate = entitlement.RequireRead
		}
		if err := gate(s.entitlements, f); err != nil {
			entitlement.WriteRefusal(w, err)
			return
		}
		next(w, r)
	}
}

// METERING-BEGIN — the internal/metering wiring (tracker 258).
//
// Deleting this block, the other METERING marker blocks in this file and the
// package removes usage metering entirely. That is a SUPPORTED state and a
// boring one: the two Usage routes stop being registered, the four metering
// series stop being emitted, and NOTHING else changes — because nothing in the
// product gates on a meter. Metering observes; it never admits and never
// refuses.
//
// The division of labour is the one internal/licence set: this file holds the
// integration seam (backend selection, the sampler that reads the platform's
// own state, the gate mapping) and internal/metering holds the data contract.
// The package reads no environment and reaches nothing it was not handed.

// newMeteringStore picks the metering backend, exactly as the DEM catalogue and
// the security control plane do: Postgres (migration 0046, FORCE-RLS) when it
// is active, the file store otherwise.
//
// A corrupt file still SERVES (an empty history) but says so — a history that
// failed to load must never look like one nobody has written to, because the
// visible consequence of both is an empty chart.
func newMeteringStore() metering.Store {
	if ps, ok := platformdb.ActivePG(); ok {
		return metering.NewPGStore(ps.DB())
	}
	fs := metering.NewFileStore(envOr(metering.EnvFile, metering.DefaultFile))
	if err := fs.LoadErr(); err != nil {
		logError("metering", "the usage history could not be read — it starts EMPTY and the recorded past will not be in a usage report until the file is repaired or removed",
			map[string]any{"err": err.Error()})
	}
	return fs
}

// meteringDeps assembles the Usage routes' injected collaborators.
func (s *server) meteringDeps() metering.Deps {
	return metering.Deps{
		Store:    s.meteringStore,
		Key:      s.meteringKey,
		Recorder: s.meteringRecorder,
		// The SAME read gate the Licence page uses: administration:admin at
		// whatever scope the caller holds it, with the tenant resolved by
		// principalTenant. A tenant/org admin gets their own tenant's usage; the
		// platform owner gets every tenant's plus the installation row. The
		// narrowing selector is applied to the claims by the auth middleware and
		// can only ever NARROW.
		ReadGate:   s.meteringReadGate,
		Audit:      meteringAudit{s},
		Licence:    s.meteringLicence,
		Now:        func() time.Time { return time.Now().UTC() },
		WriteJSON:  writeJSON,
		WriteError: writeError,
	}
}

// meteringReadGate binds the READ gate (§3a rule 1 — scope by the principal,
// default-closed).
func (s *server) meteringReadGate(w http.ResponseWriter, r *http.Request) (metering.Principal, bool) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return metering.Principal{}, false
	}
	tenant, cross := principalTenant(claims)
	if cross {
		// The platform owner's tenant is the GLOBAL pseudo-tenant, which is not
		// a metering row key. A cross-tenant read carries no tenant at all, so
		// the value can never be mistaken for a narrowing.
		tenant = ""
	}
	return metering.Principal{Subject: claims.Sub, Tenant: tenant, CrossTenant: cross}, true
}

// meteringAudit adapts the platform audit repo for the report download. The
// request envelope (method, path, client IP) is filled HERE so the module never
// has to know how this platform derives a client address behind its proxy.
type meteringAudit struct{ s *server }

func (a meteringAudit) Record(r *http.Request, ev metering.AuditRecord) {
	if a.s == nil || a.s.audit == nil {
		return
	}
	a.s.audit.Record(AuditEvent{
		Actor: ev.Actor, Method: r.Method, Path: r.URL.Path,
		Status: ev.Status, Decision: ev.Decision, Remote: auditClientIP(r),
		Detail: ev.Detail,
	})
}

// meteringLicence is the entitlement context a usage report is read against.
// The commercial identity is supplied only for the PLATFORM scope; the module
// drops it again for a tenant, so a wiring mistake here cannot leak it.
func (s *server) meteringLicence(_ context.Context, cross bool) metering.ReportLicence {
	out := metering.ReportLicence{Devices: entitlement.Unlimited}
	if s.entitlements == nil {
		return out
	}
	st := s.entitlements.State()
	out.Tier = string(st.Tier)
	limit, _ := s.entitlements.Ceiling(entitlement.CeilingDevices)
	out.Devices = limit
	if cross {
		out.Customer, out.LicenceID = st.Customer, st.LicenceID
	}
	return out
}

// meteringSample takes ONE reading of everything this installation can honestly
// measure, for every tenant plus the installation itself.
//
// TWO RULES GOVERN EVERY LINE BELOW, and they are why this function is long
// rather than clever:
//
//  1. THE PRIMARY METER COMES FROM CONFIGURATION. Monitored devices are counted
//     from the monitored set — a device with at least one collector enabled —
//     and never from recent telemetry (owner decision, 2026-09-05). A device
//     that stopped answering still counts, so an outage never moves the number
//     a customer is billed on.
//  2. A METER WITH NO COUNTER IS RECORDED AS not_measured WITH ITS REASON,
//     never as a zero. Every branch that cannot produce a number says why, in a
//     sentence an operator can act on.
//
// SCOPE. Tenant rows carry that tenant's own numbers; the installation row
// carries the platform-wide totals and the meters that describe the deployment
// (tenant and org counts, the configured retention windows, the pipeline
// counters). The two are not addends: a device nobody has assigned to a tenant
// is platform-owned and appears only in the installation total, so the tenant
// rows can sum to less than it.
func (s *server) meteringSample(ctx context.Context) map[string][]metering.Reading {
	out := map[string][]metering.Reading{}
	inst := metering.ScopeInstallation
	add := func(tenant string, r metering.Reading) { out[tenant] = append(out[tenant], r) }

	// Every known tenant gets a row even with nothing on it, so a tenant that
	// monitored nothing this month appears in the report as a zero rather than
	// as a gap somebody has to explain.
	tenants := []string{}
	if s.tenants != nil {
		for _, t := range s.tenants.List() {
			id := strings.ToLower(strings.TrimSpace(t.ID))
			if id == "" || id == TenantGlobal {
				continue
			}
			tenants = append(tenants, id)
			out[id] = nil
		}
	}

	s.meterDevices(out, add, inst, tenants)
	s.meterRegistry(add, inst)
	s.meterWatchlist(ctx, add, inst, tenants)
	s.meterRetention(add, inst)
	s.meterAITokens(add, inst, tenants)
	s.meterTelemetry(ctx, add, inst, tenants)
	return out
}

// meterDevices records the PRIMARY meter from the monitored set.
func (s *server) meterDevices(out map[string][]metering.Reading, add func(string, metering.Reading), inst string, tenants []string) {
	if s.discovery == nil {
		const why = "the device registry is not available on this build, so no device count was taken"
		add(inst, metering.NotMeasured(metering.MeterMonitoredDevicesUnique, inst, why))
		add(inst, metering.NotMeasured(metering.MeterMonitoredDevicesPeak, inst, why))
		add(inst, metering.NotMeasured(metering.MeterMonitoredWithheld, inst, why))
		return
	}
	all := []string{}
	byTenant := map[string][]string{}
	for _, d := range s.discovery.Devices() {
		if !d.Monitored {
			// Discovery does not consume the monitoring allowance: an inventory
			// row nobody enabled is not a metered device.
			continue
		}
		all = append(all, d.ID)
		if t := deviceTenant(d); t != "" {
			byTenant[t] = append(byTenant[t], d.ID)
		}
	}
	add(inst, metering.Unique(metering.MeterMonitoredDevicesUnique, inst, all))
	add(inst, metering.Measured(metering.MeterMonitoredDevicesPeak, inst, float64(len(all))))
	add(inst, metering.Measured(metering.MeterMonitoredWithheld, inst, float64(s.discovery.MonitoringWithheldCount())))
	for _, t := range tenants {
		ids := byTenant[t]
		add(t, metering.Unique(metering.MeterMonitoredDevicesUnique, t, ids))
		add(t, metering.Measured(metering.MeterMonitoredDevicesPeak, t, float64(len(ids))))
	}
	// A tenant that owns monitored devices but is not in the register still gets
	// its row: dropping it would lose devices from the per-tenant breakdown
	// while leaving them in the installation total, which is exactly the kind of
	// silent disagreement a signed report must not contain.
	known := map[string]bool{}
	for _, t := range tenants {
		known[t] = true
	}
	for t, ids := range byTenant {
		if known[t] {
			continue
		}
		if _, seen := out[t]; !seen {
			out[t] = nil
		}
		add(t, metering.Unique(metering.MeterMonitoredDevicesUnique, t, ids))
		add(t, metering.Measured(metering.MeterMonitoredDevicesPeak, t, float64(len(ids))))
	}
}

// meterRegistry records the tenant and org counts. Installation scope only:
// how many tenants an installation has is the provider's number.
func (s *server) meterRegistry(add func(string, metering.Reading), inst string) {
	if s.tenants == nil {
		add(inst, metering.NotMeasured(metering.MeterTenants, inst, "the tenant register is not available on this build"))
	} else {
		add(inst, metering.Measured(metering.MeterTenants, inst, float64(len(s.tenants.List()))))
	}
	if s.orgs == nil {
		add(inst, metering.NotMeasured(metering.MeterOrgs, inst, "the organisation register is not available on this build"))
		return
	}
	add(inst, metering.Measured(metering.MeterOrgs, inst, float64(len(s.orgs.List()))))
}

// meterWatchlist records the watched-prefix count, per tenant and platform-wide.
func (s *server) meterWatchlist(ctx context.Context, add func(string, metering.Reading), inst string, tenants []string) {
	const unavailable = "the BGP watchlist is not available on this build"
	if s.bgpWatch == nil {
		add(inst, metering.NotMeasured(metering.MeterWatchedPrefixes, inst, unavailable))
		for _, t := range tenants {
			add(t, metering.NotMeasured(metering.MeterWatchedPrefixes, t, unavailable))
		}
		return
	}
	const unreadable = "the BGP watchlist could not be read when this sample was taken"
	if n, err := s.watchedPrefixCount(ctx, TenantGlobal, true); err == nil {
		add(inst, metering.Measured(metering.MeterWatchedPrefixes, inst, float64(n)))
	} else {
		add(inst, metering.NotMeasured(metering.MeterWatchedPrefixes, inst, unreadable))
	}
	for _, t := range tenants {
		if n, err := s.watchedPrefixCount(ctx, t, false); err == nil {
			add(t, metering.Measured(metering.MeterWatchedPrefixes, t, float64(n)))
		} else {
			add(t, metering.NotMeasured(metering.MeterWatchedPrefixes, t, unreadable))
		}
	}
}

// meterRetention records the CONFIGURED retention windows — what the operator
// asked for, not what happens to be on disk.
//
// The api applies the ClickHouse TTLs itself (clickhouse_policies.go), so those
// three numbers are authoritative here. The log window is the one the
// opensearch-init bootstrap applies from the same env value. The metric window
// is a VictoriaMetrics process flag the api cannot see, and says so rather than
// reporting a default it did not verify.
func (s *server) meterRetention(add func(string, metering.Reading), inst string) {
	ch := chschema.RetentionConfig()
	add(inst, metering.Measured(metering.MeterRetentionFlows, inst, float64(ch.Flows)))
	add(inst, metering.Measured(metering.MeterRetentionFindings, inst, float64(ch.Findings)))
	add(inst, metering.Measured(metering.MeterRetentionCorrelation, inst, float64(chschema.CorrRetentionConfig().History)))

	if raw := strings.TrimSpace(os.Getenv("OPENSEARCH_LOG_RETENTION_DAYS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
			add(inst, metering.Measured(metering.MeterRetentionLogs, inst, float64(n)))
		} else {
			add(inst, metering.NotMeasured(metering.MeterRetentionLogs, inst,
				"OPENSEARCH_LOG_RETENTION_DAYS is set to something that is not a whole number of days, so the configured window could not be read"))
		}
	} else {
		add(inst, metering.NotMeasured(metering.MeterRetentionLogs, inst,
			"the log retention window is applied by the opensearch-init bootstrap from OPENSEARCH_LOG_RETENTION_DAYS, which is not set in this process"))
	}
	add(inst, metering.NotMeasured(metering.MeterRetentionMetrics, inst,
		"the metric retention window is a VictoriaMetrics start-up flag (VICTORIA_RETENTION) that this process cannot read; the value on the compose file is the one in force"))
}

// meterAITokens records provider spend from the budget that already counts it.
func (s *server) meterAITokens(add func(string, metering.Reading), inst string, tenants []string) {
	// Input and output are NOT separable: the budget keeps one combined chars/4
	// estimate, because its job is a spend ceiling rather than accounting. Two
	// fabricated halves would be worse than one honest whole.
	const split = "the provider budget meters one combined estimate for a spend ceiling, not separate input and output tokens"
	for _, t := range tenants {
		add(t, metering.NotMeasured(metering.MeterAITokensInput, t, split))
		add(t, metering.NotMeasured(metering.MeterAITokensOutput, t, split))
	}
	if s.aiToolBudget == nil {
		const why = "no hosted AI provider is configured on this installation, so no tokens are being charged"
		add(inst, metering.NotMeasured(metering.MeterAITokens, inst, why))
		for _, t := range tenants {
			add(t, metering.NotMeasured(metering.MeterAITokens, t, why))
		}
		return
	}
	used := s.aiToolBudget.UsedByTenant()
	total := 0
	for _, n := range used {
		total += n
	}
	add(inst, metering.Counted(metering.MeterAITokens, inst, float64(total)))
	for _, t := range tenants {
		add(t, metering.Counted(metering.MeterAITokens, t, float64(used[t])))
	}
}

// meterTelemetry records the DIAGNOSTIC meters from counters the platform
// already keeps in its metrics store.
//
// These exist because they are useful, NOT because anything is charged for
// them: on-premises ingestion is deliberately not metered for money (the
// commercial strategy is explicit — "Correlix is not paying for the customer's
// disks, network or compute"). Every query below is a read of a counter that is
// already being scraped; a query that returns nothing is recorded as
// not_measured with the reason, never as a zero.
func (s *server) meterTelemetry(ctx context.Context, add func(string, metering.Reading), inst string, tenants []string) {
	// One hour of interval, matching the snapshot cadence, so the day's sum is
	// the day's total.
	//
	// read returns the value and, when there is none, the REASON — and the two
	// no-value cases are kept apart deliberately (§10). "the metrics store did
	// not answer" is a broken dependency an operator can fix; "the counter has
	// no series" is a pipeline that is not running or not scraped. Reporting one
	// sentence for both would render an outage as a normal empty state, which is
	// the exact confusion this package refuses to create with a zero.
	const storeDown = "the metrics store did not answer when this sample was taken, so the counter could not be read"
	read := func(query, absent string) (float64, string) {
		samples, err := s.vmInstant(ctx, query)
		if err != nil {
			return 0, storeDown
		}
		if len(samples) == 0 {
			return 0, absent
		}
		return samples[0].Value, ""
	}
	counter := func(meter, query, absent string) {
		v, why := read(query, absent)
		if why != "" {
			add(inst, metering.NotMeasured(meter, inst, why))
			return
		}
		add(inst, metering.Counted(meter, inst, math.Max(0, v)))
	}

	counter(metering.MeterMetricSamples, `sum(increase(vm_rows_inserted_total[1h]))`,
		"the time-series store publishes no ingestion counter on this installation")
	counter(metering.MeterMetricSeries, `sum(vm_cache_entries{type="storage/hour_metric_ids"})`,
		"the time-series store publishes no active-series counter on this installation")
	counter(metering.MeterLogRecords, `sum(increase(vector_component_sent_events_total{component_id=~"opensearch_syslog|opensearch_applogs"}[1h]))`,
		"no log sink reported anything in the last hour, so there is no counter to read — not a count of zero")
	counter(metering.MeterFlowRecords, `sum(increase(vector_component_sent_events_total{component_id=~"clickhouse_flows|opensearch_flows"}[1h]))`,
		"no flow sink reported anything in the last hour, so there is no counter to read — not a count of zero")
	add(inst, metering.NotMeasured(metering.MeterTraceSpans, inst,
		"no distributed-tracing pipeline is configured on this installation, so no spans are accepted and none are counted"))

	// Processor in/out is measured at the pipeline's edges — what entered and
	// what was kept — because that is the ratio the number is FOR: a customer
	// who filters noise should see the ratio fall.
	const pipeAbsent = "the telemetry pipeline published no source/sink counter for the last hour"
	pin, whyIn := read(`sum(increase(vector_component_received_events_total{component_kind="source"}[1h]))`, pipeAbsent)
	pout, whyOut := read(`sum(increase(vector_component_sent_events_total{component_kind="sink"}[1h]))`, pipeAbsent)
	if whyIn != "" {
		add(inst, metering.NotMeasured(metering.MeterProcessorInput, inst, whyIn))
	} else {
		add(inst, metering.Counted(metering.MeterProcessorInput, inst, math.Max(0, pin)))
	}
	if whyOut != "" {
		add(inst, metering.NotMeasured(metering.MeterProcessorOutput, inst, whyOut))
	} else {
		add(inst, metering.Counted(metering.MeterProcessorOutput, inst, math.Max(0, pout)))
	}
	switch {
	case whyIn != "":
		add(inst, metering.NotMeasured(metering.MeterProcessorRatio, inst, whyIn))
	case whyOut != "":
		add(inst, metering.NotMeasured(metering.MeterProcessorRatio, inst, whyOut))
	case pin <= 0:
		add(inst, metering.NotMeasured(metering.MeterProcessorRatio, inst,
			"nothing entered the pipeline in the last hour, so there is no ratio to state — a ratio over zero input is undefined, not 0"))
	default:
		add(inst, metering.Counted(metering.MeterProcessorRatio, inst, math.Max(0, pout/pin)))
	}

	// Experience checks carry the tenant that owns the target, so this one is
	// measurable per tenant as well as platform-wide.
	byTenant := map[string]float64{}
	total := 0.0
	demWhy := ""
	samples, err := s.vmInstant(ctx, `sum by (tenant) (count_over_time(dem_probe_success[1h]))`)
	if err != nil {
		demWhy = storeDown
	} else {
		for _, sm := range samples {
			byTenant[strings.ToLower(strings.TrimSpace(sm.Labels["tenant"]))] += sm.Value
			total += sm.Value
		}
	}
	if demWhy != "" {
		add(inst, metering.NotMeasured(metering.MeterDEMChecks, inst, demWhy))
	} else {
		add(inst, metering.Counted(metering.MeterDEMChecks, inst, math.Max(0, total)))
	}
	for _, t := range tenants {
		if demWhy != "" {
			add(t, metering.NotMeasured(metering.MeterDEMChecks, t, demWhy))
			continue
		}
		add(t, metering.Counted(metering.MeterDEMChecks, t, math.Max(0, byTenant[t])))
	}
}

// METERING-END

// SECURITY-LANE-BEGIN — this function alone, inside the LICENCE block, carries
// BOTH markers. It is licence policy (which dialects this deployment may
// evaluate) expressed in the security producer's vocabulary, so it must come
// out with EITHER module: delete the security lane and this goes with it
// (leaving seclane.Deps.DialectAllowed unset, which allows every dialect and is
// a supported state); delete the licence mechanism and it goes too (the gate
// simply stops being applied). Its test lives in licence_dialect_gate_test.go,
// which the removal recipe in security_lane_removability_test.go names.
//
// licenceDialectAllowed is the hardening dialect gate (§4 "dialect registry").
//
// The CORE set is cisco-iosxe — the primary, fully-bound dialect that
// internal/hardening documents as such — and it is available at every tier.
// Everything beyond it (juniper, nokia, arista, srlinux) is the "multi-vendor
// dialects" line in the owner's LOCKED Enterprise set.
//
// Degradation is honest and is the ENGINE's job, not this function's: a device
// on an unlicensed dialect gets one coverage finding saying so
// (hardening.RuleDialectNotLicensed), never an empty result that would read as
// "this device is clean".
func (s *server) licenceDialectAllowed(v hardening.Vendor) bool {
	if v == hardening.VendorCiscoIOSXE || v == hardening.VendorUnknown {
		return true
	}
	return entitlement.Entitled(s.entitlements, entitlement.FeatureSecurityDialects)
}

// SECURITY-LANE-END

// watchedPrefixCount counts watched PREFIXES in one scope — the unit the
// Community ceiling of 5 is expressed in.
//
// The SCOPE is the caller's to choose, and the two callers choose differently
// for the same reason:
//
//   - ENFORCEMENT and the provider's usage bar pass (TenantGlobal, true). A
//     licence covers the deployment, so counting through one tenant's view
//     would let a second tenant's prefixes escape the ceiling.
//   - The TENANT PROJECTION passes the caller's own tenant with cross=false, so
//     the store's own filter — not this function — keeps that number to that
//     tenant's rows (§3a rule 4).
//
// What it deliberately does NOT count, in either scope, is "watchlist entries":
// a WatchEntry is a prefix OR an ASN, and counting ASNs against a PREFIX
// ceiling would silently make the free tier smaller than the number on the
// pricing page.
//
// Nothing here is returned to a caller either way: the rows are counted and
// discarded, so the platform-wide read crosses no boundary in the direction
// that matters.
func (s *server) watchedPrefixCount(ctx context.Context, tenant string, cross bool) (int, error) {
	if s.bgpWatch == nil {
		return 0, errors.New("bgp watchlist unavailable")
	}
	rows, err := s.bgpWatch.List(ctx, tenant, cross)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range rows {
		if e.Kind == "prefix" {
			n++
		}
	}
	return n, nil
}

// logLicenceState writes the boot line.
//
// With no licence this is INFO, not a warning: Community is the free tier and
// the funnel, a normal supported state, and a platform that scolds an operator
// for not having paid yet is a platform nobody evaluates twice. A licence that
// is installed but REFUSED is a different matter and goes out as a warning,
// because that operator has lost a tier they are paying for and needs to know.
func (s *server) logLicenceState() {
	st := s.licenceStore.State()
	switch {
	case st.LoadError != "":
		logWarn("licence", "licence: "+st.Summary(), map[string]any{
			"source": string(st.Source), "path": s.licenceStore.Path(), "error": st.LoadError,
		})
	case st.Degraded:
		logWarn("licence", "licence: "+st.Summary(), map[string]any{
			"source": string(st.Source), "tier": string(st.Tier),
			"licensed_tier": string(st.LicensedTier), "degraded": true,
		})
	default:
		logInfo("licence", "licence: "+st.Summary(), map[string]any{
			"source": string(st.Source), "tier": string(st.Tier), "in_grace": st.InGrace,
		})
	}
}

// LICENCE-END

// CONFIG-BACKUP-BEGIN

// configVersionStore selects the version register: normalized PG rows under
// STORE_BACKEND=postgres (migration 0038, tenant_iso FORCE-RLS), else the file
// register. Same selector shape as newSecurityControlPlaneStore.
func (s *server) configVersionStore() configstore.Store {
	if ps, ok := platformdb.ActivePG(); ok {
		return configstore.NewPGStore(ps.DB())
	}
	return configstore.NewFileStore(envOr("CONFIG_BACKUP_VERSIONS_FILE", "/data/config_backup_versions.json"))
}

func (s *server) configDriftStore() configdrift.StateStore {
	if ps, ok := platformdb.ActivePG(); ok {
		return configdrift.NewPGStore(ps.DB())
	}
	return configdrift.NewFileStore(envOr("CONFIG_DRIFT_STATE_FILE", "/data/config_drift_state.json"))
}

// configSealer adapts the secret-custody vault to configstore.Sealer. Marker is
// the vault's own version prefix, so the blob store can prove a value is sealed
// before it ever reaches the disk.
type configSealer struct{ v *vault.Vault }

func (c configSealer) Seal(tenant, fieldID, plaintext string) (string, error) {
	return c.v.Encrypt(tenant, fieldID, plaintext)
}
func (c configSealer) Open(tenant, fieldID, sealed string) (string, error) {
	return c.v.Decrypt(tenant, fieldID, sealed)
}
func (c configSealer) Active() bool   { return c.v.Sealed() }
func (c configSealer) Marker() string { return vault.VersionPrefix }

// configDeviceOwner resolves a device's OWNING tenant from the inventory row —
// the §3a rule 2 authority the hardening ConfigSource keys on.
func (s *server) configDeviceOwner(deviceID string) (string, bool) {
	if s.discovery == nil {
		return "", false
	}
	d, ok := s.discovery.Get(deviceID)
	if !ok {
		return "", false
	}
	return deviceTenant(d), true
}

// configBackupTenants lists the tenants the scheduler sweeps (the
// securityLaneTenants rule: no global tenant, no suspended tenant).
func (s *server) configBackupTenants() []string {
	if s.tenants == nil {
		return nil
	}
	out := make([]string, 0, 8)
	for _, t := range s.tenants.List() {
		id := normTenant(t.ID)
		if id == "" || id == TenantGlobal || t.Status == TenantStatusSuspended {
			continue
		}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// configBackupDevices returns ONE tenant's own devices (§3a: the inventory row's
// tenant is the authority; this path has no request body at all).
func (s *server) configBackupDevices(tenant string) []configstore.Device {
	if s.discovery == nil {
		return nil
	}
	want := normTenant(tenant)
	all := s.discovery.Devices()
	out := make([]configstore.Device, 0, len(all))
	for _, d := range all {
		if deviceTenant(d) != want {
			continue
		}
		// MONITORING-BEGIN — capture only from devices monitoring is on for.
		// A configuration sweep logs into the device over SSH on a schedule;
		// that is monitoring, and doing it to a device nobody enabled would
		// collect from a device the licence does not count (C4).
		if !d.Monitored {
			continue
		}
		// MONITORING-END
		out = append(out, configstore.Device{
			ID: d.ID, Name: d.Name, Address: d.Address,
			Vendor: d.Vendor, OS: d.OS, Model: d.Model, TenantID: deviceTenant(d),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *server) configLookupDevice(deviceID string) (configstore.Device, bool) {
	if s.discovery == nil {
		return configstore.Device{}, false
	}
	d, ok := s.discovery.Get(deviceID)
	if !ok {
		return configstore.Device{}, false
	}
	return configstore.Device{
		ID: d.ID, Name: d.Name, Address: d.Address,
		Vendor: d.Vendor, OS: d.OS, Model: d.Model, TenantID: deviceTenant(d),
	}, true
}

// configAuthz maps the module's gates onto the RBAC model: reads are
// infrastructure:read, capture/golden are infrastructure:write. Config backup is
// per-tenant DATA, so it is requirePerm + a tenant filter, NOT a platform gate.
func (s *server) configAuthz(w http.ResponseWriter, r *http.Request, gate configstore.Gate) (configstore.Principal, bool) {
	level := LevelRead
	if gate == configstore.GateWrite {
		level = LevelWrite
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", level)
	if !ok {
		return configstore.Principal{}, false
	}
	tenant, cross := principalTenant(claims)
	return configstore.Principal{Tenant: tenant, Cross: cross, Subject: claims.Sub}, true
}

func (s *server) configDriftAuthz(w http.ResponseWriter, r *http.Request, _ configdrift.Gate) (configdrift.Principal, bool) {
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return configdrift.Principal{}, false
	}
	tenant, cross := principalTenant(claims)
	return configdrift.Principal{Tenant: tenant, Cross: cross, Subject: claims.Sub}, true
}

// configAudit is the securityAudit shape for API actions. A configuration READ
// passes detail["sensitive"]=true from the module itself.
func (s *server) configAudit(r *http.Request, tenant, action string, detail map[string]any) {
	if s.audit == nil {
		return
	}
	claims, _ := userFrom(r.Context())
	_, cross := principalTenant(claims)
	if detail == nil {
		detail = map[string]any{}
	}
	detail["action"] = action
	s.audit.Record(AuditEvent{
		Actor: claims.Sub, Tenant: tenant, Cross: cross,
		Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Decision: "allow",
		Remote: auditClientIP(r), Detail: detail,
	})
}

// configCaptureAudit records a SCHEDULED capture — there is no request behind
// it, so the actor is the worker identity rather than a borrowed principal.
func (s *server) configCaptureAudit(tenant, deviceID, action string, detail map[string]any) {
	if s.audit == nil {
		return
	}
	if detail == nil {
		detail = map[string]any{}
	}
	detail["action"] = action
	detail["device"] = deviceID
	s.audit.Record(AuditEvent{
		Time: time.Now().UTC(), Actor: "system:config-backup", Tenant: tenant,
		Method: "WORKER", Path: "/api/devices/" + deviceID + "/config/backup",
		Status: http.StatusOK, Decision: "allow", Detail: detail,
	})
}

// configGateway binds capture to the SAME SSH client and the SAME host-key TOFU
// custody the operator terminal uses: HostKeyCheck IS device_ssh.go's pinned
// fingerprint store, so a device whose key changed is refused identically on
// both paths. Credentials are a least-privilege, read-only account whose
// password/key are sealed at rest like every other reversible secret (§8).
func (s *server) configGateway() *configstore.SSHGateway {
	return &configstore.SSHGateway{
		Credentials: func(context.Context, configstore.Device) (configstore.Credential, error) {
			user := os.Getenv(configstore.EnvSSHUser)
			pw, err := s.vault.Decrypt("", "configstore.capture.password", os.Getenv(configstore.EnvSSHPassword))
			if err != nil {
				return configstore.Credential{}, err
			}
			key, err := s.vault.Decrypt("", "configstore.capture.key", os.Getenv(configstore.EnvSSHKey))
			if err != nil {
				return configstore.Credential{}, err
			}
			if user == "" || (pw == "" && key == "") {
				return configstore.Credential{}, errors.New("no config-capture credential configured (set CONFIG_BACKUP_SSH_USER and CONFIG_BACKUP_SSH_PASSWORD or _KEY)")
			}
			return configstore.Credential{Username: user, Password: pw, PrivateKey: key}, nil
		},
		HostKeyCheck: s.sshHosts.check,
		DialTimeout:  sshDialTimeout(),
		Port:         envInt(configstore.EnvSSHPort, 22),
		OnHostKey: func(dev configstore.Device, fp string, first bool) {
			if first {
				logInfo("config.backup", "device host key pinned on first capture", map[string]any{
					"device": dev.ID, "fingerprint": fp})
			}
		},
	}
}

// buildConfigBackup CONSTRUCTS the drift evaluator, then the capture manager
// over it, and stores all three on the server. Order matters: the manager's
// drift observers ARE the evaluator's methods.
//
// It is a builder, not a launcher, and its name says so: the only goroutine this
// module runs is the scheduler, started by the VISIBLE workers.start(
// "config-backup", …) beside the call — so it is drained on shutdown like every
// other tracked worker, and cancelOnlyWorkers() correctly does not list it.
func (s *server) buildConfigBackup() error {
	versions := s.configVersionStore()
	sealer := configSealer{v: s.vault}
	blobs, err := configstore.NewFileBlobStore(envOr(configstore.EnvDir, configstore.DefaultDir), sealer.Marker())
	if err != nil {
		return err
	}
	open := func(v configstore.Version) (string, error) {
		sealed, gerr := blobs.Get(v.BlobRef)
		if gerr != nil {
			return "", gerr
		}
		return sealer.Open(configstore.NormTenant(v.TenantID), configstore.BlobField(v.DeviceID, v.SHA), sealed)
	}
	drift, err := configdrift.New(configdrift.Deps{
		Now:      func() time.Time { return time.Now().UTC() },
		Store:    s.configDriftStore(),
		Versions: versions,
		Open:     open,
		// The same Vector bus-bridge produce path every other Go producer uses
		// (no Kafka client in the backend, §6 allowlist). The retry ladder itself
		// lives in internal/secbus and is REUSED, never re-implemented.
		Publish: func(ctx context.Context, topic string, recs []configdrift.Record) (int, error) {
			out := make([]proxyRecord, 0, len(recs))
			for _, r := range recs {
				out = append(out, proxyRecord{Key: r.Key, Value: r.Value})
			}
			return produceJSON(ctx, topic, out)
		},
		// Spool is deliberately nil: the drift VERDICT is already durable in the
		// state row and the version row, so an unplaceable bus copy is counted
		// (netops_config_drift_lost_total) and logged rather than duplicating
		// seclane's dead-letter ladder — which would also break seclane's
		// removal recipe by making main.go's seclane import load-bearing here.
		Devices: func(tenant string) []configdrift.DeviceRef {
			refs := []configdrift.DeviceRef{}
			for _, d := range s.configBackupDevices(tenant) {
				refs = append(refs, configdrift.DeviceRef{ID: d.ID, Name: d.Name, TenantID: d.TenantID})
			}
			return refs
		},
		Metrics:    configdrift.NewMetrics(),
		Authz:      s.configDriftAuthz,
		WriteJSON:  writeJSON,
		WriteError: writeError,
		LogWarn:    func(m string, f map[string]any) { logWarn("config.drift", m, f) },
		LogError:   func(m string, f map[string]any) { logError("config.drift", m, f) },
		Scrub:      scrubLogValue,
	})
	if err != nil {
		return err
	}
	mgr, err := configstore.New(configstore.Deps{
		Now:          func() time.Time { return time.Now().UTC() },
		Tenants:      s.configBackupTenants,
		Devices:      s.configBackupDevices,
		LookupDevice: s.configLookupDevice,
		Gateway:      s.configGateway(),
		Sealer:       sealer,
		Blobs:        blobs,
		Store:        versions,
		Metrics:      configstore.NewMetrics(),
		OnCapture:    drift.Observe,
		OnFailure:    drift.OnFailure,
		Authz:        s.configAuthz,
		Audit:        s.configAudit,
		AuditCapture: s.configCaptureAudit,
		WriteJSON:    writeJSON,
		WriteError:   writeError,
		LogWarn:      func(m string, f map[string]any) { logWarn("config.backup", m, f) },
		LogError:     func(m string, f map[string]any) { logError("config.backup", m, f) },
		Scrub:        scrubLogValue,
		Interval:     durationOr(configstore.EnvInterval, configstore.DefaultInterval),
		KeepVersions: envInt(configstore.EnvKeepVersions, configstore.DefaultKeepVersions),
	})
	if err != nil {
		return err
	}
	s.configDrift, s.configBackup = drift, mgr
	s.configAPI = configstore.NewAPI(mgr, drift.StatusFor)
	return nil
}

// configHardeningSource is the seam internal/seclane's Deps.ConfigSource takes.
// nil while config backup is off, which keeps the hardening lane's honest
// "control not assessed (fail-closed)" verdicts.
//
// CALL-ORDER CONTRACT (the lab defect of 2026-09-03): this resolves s.configDrift
// EAGERLY and its result is captured once, in seclane.Deps. It therefore returns
// nil for any caller that runs before buildConfigBackup has assigned that field —
// which is exactly what happened when newServer constructed the security lane
// above the CONFIG-BACKUP block: every §5e rule reported the config unavailable
// while two lab spines had a sealed running-config on file. The nil answer stays
// EAGER on purpose (a lazily-resolving source would be an unsynchronized read of
// s.configDrift from the lane's goroutine, i.e. a data race); the ordering is
// asserted in newServer instead, and the SECURITY-LANE block carries the note.
func (s *server) configHardeningSource() hardening.ConfigSource {
	if s.configDrift == nil {
		return nil
	}
	return s.configDrift.HardeningSource(s.configDeviceOwner)
}

// CONFIG-BACKUP-END

// PACKET-CAPTURE-BEGIN

// pcapStore selects the capture register: normalized PG rows under
// STORE_BACKEND=postgres (migration 0039, tenant_iso FORCE-RLS), else the file
// register. Same selector shape as configVersionStore.
func (s *server) pcapStore() pcap.Store {
	if ps, ok := platformdb.ActivePG(); ok {
		return pcap.NewPGStore(ps.DB())
	}
	return pcap.NewFileStore(envOr(pcap.EnvMetaFile, "/data/pcap_captures.json"))
}

// pcapSealer adapts the secret-custody vault to pcap.Sealer. The marker is the
// vault's own version prefix, so the blob store can prove a value is sealed
// before it ever reaches the disk — the property that matters most here,
// because the value is customer payload.
type pcapSealer struct{ v *vault.Vault }

func (c pcapSealer) Seal(tenant, fieldID, plaintext string) (string, error) {
	return c.v.Encrypt(tenant, fieldID, plaintext)
}
func (c pcapSealer) Open(tenant, fieldID, sealed string) (string, error) {
	return c.v.Decrypt(tenant, fieldID, sealed)
}
func (c pcapSealer) Active() bool   { return c.v.Sealed() }
func (c pcapSealer) Marker() string { return vault.VersionPrefix }

// pcapLookupDevice resolves ONE device id for the HTTP path. The inventory row's
// tenant is the §3a rule 2 authority; this path reads no tenant from a request.
func (s *server) pcapLookupDevice(deviceID string) (pcap.Device, bool) {
	if s.discovery == nil {
		return pcap.Device{}, false
	}
	d, ok := s.discovery.Get(deviceID)
	if !ok {
		return pcap.Device{}, false
	}
	return pcap.Device{
		ID: d.ID, Name: d.Name, Address: d.Address,
		Vendor: d.Vendor, OS: d.OS, Model: d.Model, TenantID: deviceTenant(d),
	}, true
}

// pcapAuthz maps the module's gates onto the RBAC model. Packet capture is
// per-tenant DATA, so it is requirePerm + a tenant filter, NOT a platform gate.
// The gate SPLIT is the deliberate part: listing captures is infrastructure:read,
// but STARTING one, DOWNLOADING one (a reveal of customer payload) and DELETING
// one are infrastructure:write — a PCAP download must never be a read-level act.
func (s *server) pcapAuthz(w http.ResponseWriter, r *http.Request, gate pcap.Gate) (pcap.Principal, bool) {
	level := LevelRead
	if gate == pcap.GateWrite {
		level = LevelWrite
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", level)
	if !ok {
		return pcap.Principal{}, false
	}
	tenant, cross := principalTenant(claims)
	return pcap.Principal{Tenant: tenant, Cross: cross, Subject: claims.Sub}, true
}

// pcapAudit is the securityAudit shape for capture actions. The module itself
// passes detail["sensitive"]=true on every start, fetch and download: a capture
// contains real payload, and a reveal of it is never anonymous.
func (s *server) pcapAudit(r *http.Request, tenant, action string, detail map[string]any) {
	if s.audit == nil {
		return
	}
	claims, _ := userFrom(r.Context())
	_, cross := principalTenant(claims)
	if detail == nil {
		detail = map[string]any{}
	}
	detail["action"] = action
	s.audit.Record(AuditEvent{
		Actor: claims.Sub, Tenant: tenant, Cross: cross,
		Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Decision: "allow",
		Remote: auditClientIP(r), Detail: detail,
	})
}

// pcapRuntimeAudit records the moment packet payload left a device — the
// capture runtime has no request behind it, so the actor is the worker identity
// and the capture row carries the operator who asked for it.
func (s *server) pcapRuntimeAudit(tenant, deviceID, action string, detail map[string]any) {
	if s.audit == nil {
		return
	}
	if detail == nil {
		detail = map[string]any{}
	}
	detail["action"] = action
	detail["device"] = deviceID
	s.audit.Record(AuditEvent{
		Time: time.Now().UTC(), Actor: "system:packet-capture", Tenant: tenant,
		Method: "WORKER", Path: "/api/devices/" + deviceID + "/pcap",
		Status: http.StatusOK, Decision: "allow", Detail: detail,
	})
}

// pcapGateway binds capture to the SAME SSH client and the SAME host-key TOFU
// custody the operator terminal and config capture use: HostKeyCheck IS
// device_ssh.go's pinned fingerprint store, so a device whose key changed is
// refused identically on all three paths. Credentials are a least-privilege
// account whose password/key are sealed at rest like every other reversible
// secret (§8).
func (s *server) pcapGateway() *pcap.SSHGateway {
	return &pcap.SSHGateway{
		Credentials: func(context.Context, pcap.Device) (pcap.Credential, error) {
			user := os.Getenv(pcap.EnvSSHUser)
			pw, err := s.vault.Decrypt("", "pcap.capture.password", os.Getenv(pcap.EnvSSHPassword))
			if err != nil {
				return pcap.Credential{}, err
			}
			key, err := s.vault.Decrypt("", "pcap.capture.key", os.Getenv(pcap.EnvSSHKey))
			if err != nil {
				return pcap.Credential{}, err
			}
			if user == "" || (pw == "" && key == "") {
				return pcap.Credential{}, errors.New("no packet-capture credential configured (set PCAP_SSH_USER and PCAP_SSH_PASSWORD or _KEY)")
			}
			return pcap.Credential{Username: user, Password: pw, PrivateKey: key}, nil
		},
		HostKeyCheck: s.sshHosts.check,
		DialTimeout:  sshDialTimeout(),
		Port:         envInt(pcap.EnvSSHPort, 22),
		OnHostKey: func(dev pcap.Device, fp string, first bool) {
			if first {
				logInfo("pcap", "device host key pinned on first capture", map[string]any{
					"device": dev.ID, "fingerprint": fp})
			}
		},
	}
}

// buildPacketCapture CONSTRUCTS the capture manager and its HTTP surface. There
// is no worker to start AT ALL: a capture is always an explicit, audited
// operator action, never a scheduled sweep — the design's "capturing customer
// traffic is high-privilege" rule made structural. Each capture's own bounded
// goroutine is spawned by the manager for the life of that one capture and is
// bounded by the request's duration cap, so there is nothing here for the
// shutdown drain or cancelOnlyWorkers() to name.
func (s *server) buildPacketCapture() error {
	sealer := pcapSealer{v: s.vault}
	blobs, err := pcap.NewFileBlobStore(envOr(pcap.EnvDir, "/data/packet-captures"), sealer.Marker())
	if err != nil {
		return err
	}
	mgr, err := pcap.New(pcap.Deps{
		Now:          func() time.Time { return time.Now().UTC() },
		LookupDevice: s.pcapLookupDevice,
		Gateway:      s.pcapGateway(),
		// The per-vendor capture commands live in the Vendor Profile registry
		// (capture.pcap_start_cmd / pcap_stop_cmd / pcap_cleanup_cmd /
		// pcap_remote_path / pcap_supports_filter), so onboarding a platform is
		// "author a profile", not "edit an engine". This is the swap point the
		// CommandTable seam exists for.
		Commands:     pcap.NewProfileCommandTable(),
		Sealer:       sealer,
		Blobs:        blobs,
		Store:        s.pcapStore(),
		Metrics:      pcap.NewMetrics(),
		Authz:        s.pcapAuthz,
		Audit:        s.pcapAudit,
		AuditRuntime: s.pcapRuntimeAudit,
		WriteJSON:    writeJSON,
		WriteError:   writeError,
		LogWarn:      func(m string, f map[string]any) { logWarn("pcap", m, f) },
		LogError:     func(m string, f map[string]any) { logError("pcap", m, f) },
		Scrub:        scrubLogValue,
		Keep:         envInt(pcap.EnvKeep, pcap.DefaultKeep),
	})
	if err != nil {
		return err
	}
	s.packetCapture = mgr
	s.pcapAPI = pcap.NewAPI(mgr)
	return nil
}

// PACKET-CAPTURE-END

// handleSecurityExposureStory serves GET /api/security/exposure-stories/{id} by
// DELEGATING to the correlation detail handler — an Exposure Story IS a
// correlation object, so it must render identically and, more importantly,
// inherit that handler's ownership pre-read verbatim (loadCorrSlice reads at
// chTenantScope and answers 404 on zero rows, so another tenant's id is never
// confirmed). Re-implementing the lookup here is exactly how the 2026-08-04
// {id}/replay cross-tenant leak happened: a second path to the same object
// that forgot the check.
func (s *server) handleSecurityExposureStory(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/security/exposure-stories/")
	clone := r.Clone(r.Context())
	clone.URL.Path = "/api/correlations/" + id
	s.handleCorrelationByID(w, clone)
}
