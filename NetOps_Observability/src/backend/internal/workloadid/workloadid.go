// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package workloadid is the SEC-003.3 workload identity registry: the single
// authoritative table of which compose service holds which SPIFFE identity in
// the correlix mesh, encoded as data so guards can enforce completeness.
//
// The SPIFFE identity string stays EXACTLY as the internal CA has always
// emitted it — spiffe://<trust-domain>/ns/default/sa/<service> (owner steer
// §0a: no new identity scheme; SPIRE/zone variants remain drop-ins later).
// Issuance is table-driven and ADDITIVE: when TLS_SERVICE_CERT_ROOT is set,
// the CA (src/backend/tls_ca.go) mints every row's SVID under
// <root>/<service>/<service>.{crt,key} at boot and rotates it with the
// existing TTL/2 loop — but nothing consumes a cert until that service's own
// SEC epic switches it on. That decoupling lets Phases 3–5 land per-component
// with the stack green in between.
//
// Two guards keep the table honest (workloadid_test.go):
//   - every compose service appears EXACTLY ONCE across Registry + Exempt
//     (a new service fails CI until someone decides its identity),
//   - no duplicate services, no wildcard DNS, servers declare dialled names.
package workloadid

// Entry describes one workload's identity material.
type Entry struct {
	// Service is the compose service name; it is also the SPIFFE SA name and
	// the on-disk directory name under TLS_SERVICE_CERT_ROOT.
	Service string
	// DNS holds the names peers actually dial (compose DNS). Non-empty DNS
	// implies a server (or dual-role) certificate; client-only rows leave it
	// empty. Never a wildcard.
	DNS []string
	// Client/Server select the EKUs the leaf carries.
	Client, Server bool
}

// Registry is the v1 identity table (SEC-003.3 step 1, encoded as data).
// Server rows carry the DNS names their clients dial; pure producers and
// pollers are client-only.
var Registry = []Entry{
	// Already minted before the registry existed (kept here so the table is
	// the single source of truth; tls_ca.go keeps their historical env-var
	// paths working):
	{Service: "api", DNS: []string{"api", "localhost"}, Client: true, Server: true},
	{Service: "nginx", Client: true},                                             // pure client toward the api; its PUBLIC server cert is the ingress cert, never an SVID
	{Service: "victoria", DNS: []string{"victoria"}, Client: true, Server: true}, // client: scrapes the api; server: TLS-native option later
	{Service: "vmauth", DNS: []string{"vmauth"}, Server: true},                   // SEC-010: the authenticating TLS front for VictoriaMetrics

	// Stores — servers their clients verify by compose DNS name.
	// SEC-006 broker listener. Client too (2026-08-06): the broker's DN is the
	// KAFKA_SUPER_USERS principal, and after the SEC-007.2 default-deny flip
	// every admin-plane operation (dynamic keystore re-set in rotate-tls,
	// consumer-group diagnostics, kafka-init topic creation) must authenticate
	// on MTLS:9094 — a serverAuth-only leaf cannot act as that client
	// (broker rejects it with certificate_unknown; proven on the lab). Same
	// both-EKU precedent as opensearch below.
	{Service: "kafka", DNS: []string{"kafka"}, Client: true, Server: true},
	{Service: "opensearch", DNS: []string{"opensearch"}, Client: true, Server: true}, // SEC-008: node cert needs BOTH EKUs — the security plugin uses it for transport-layer mutual auth between nodes
	{Service: "clickhouse", DNS: []string{"clickhouse"}, Server: true},               // SEC-009
	{Service: "postgres", DNS: []string{"postgres"}, Server: true},                   // SEC-011
	{Service: "redis", DNS: []string{"redis"}, Server: true},                         // SEC-012 (Valkey; compose name is redis)

	// Application services.
	{Service: "correlation", DNS: []string{"correlation"}, Client: true, Server: true}, // SEC-013: serves the api, consumes the bus/stores

	// Bus producers/consumers and ingest actors — client identities (SEC-006/007/013).
	{Service: "vector-aggregator", DNS: []string{"vector-aggregator"}, Client: true, Server: true}, // server: the ingest lanes it terminates (SEC-013)
	{Service: "vector-router", Client: true},
	{Service: "goflow2", Client: true},
	{Service: "gnmic", Client: true},
	{Service: "prober", Client: true},
	{Service: "syslog-ng", Client: true}, // its forward hop into vector (SEC-014.1)
	{Service: "kafka-exporter", Client: true},
	{Service: "cloud-ingest", Client: true}, // SEC-013: mTLS to the ingest lanes; task #9: mTLS kafka producer
	{Service: "vmalert", Client: true},      // queries victoria via vmauth once SEC-010 lands

	// Ops/UI tier behind nginx — server identities so their inner hops can be
	// meshed later without re-deciding identity.
	{Service: "grafana", DNS: []string{"grafana"}, Server: true},
	{Service: "opensearch-dashboards", DNS: []string{"opensearch-dashboards"}, Server: true},
	{Service: "frontend", DNS: []string{"frontend"}, Server: true},
	{Service: "keycloak", DNS: []string{"keycloak"}, Server: true},
	{Service: "netbox", DNS: []string{"netbox"}, Server: true},
	{Service: "gotenberg", DNS: []string{"gotenberg"}, Server: true},
	{Service: "netbox-postgres", DNS: []string{"netbox-postgres"}, Server: true},
	{Service: "cadvisor", DNS: []string{"cadvisor"}, Server: true},           // scrape target
	{Service: "node-exporter", DNS: []string{"node-exporter"}, Server: true}, // scrape target
}

// Exempt lists compose services that deliberately get NO workload identity,
// each with the reason on record. A service must be in exactly one of the two
// tables — the guard fails the build otherwise, which is the ratchet: adding
// a service forces an explicit identity decision.
var Exempt = map[string]string{
	"kafka-init":               "one-shot volume-format job; no listener, no steady-state network peer",
	"opensearch-init":          "one-shot template/ISM applier; runs and exits",
	"opensearch-security-init": "one-shot securityadmin bootstrap; authenticates with the ADMIN cert (minted via TLS_OS_ADMIN_CERT_DIR, deliberately not a registry row — it is a credential, not a workload)",
	"secrets-seal":             "custody sidecar reachable ONLY via a host-private unix socket (never TCP); an SVID would imply a network surface it must never have",
	"telegraf":                 "profiles:[legacy] — does not run (SEC-001.2)",
	"mock-nms":                 "lab fixture, excluded from customer bundles (declared in the transport inventory)",
	"mock-servicenow":          "lab fixture, excluded from customer bundles (declared in the transport inventory)",
}
