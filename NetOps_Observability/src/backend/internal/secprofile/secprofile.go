// Package secprofile is the production security validator: the control that
// turns Correlix's security posture from a set of features into a property of
// the deployment.
//
// The problem it solves is the one the security review found repeatedly — the
// platform HAS strong controls (internal CA, mTLS, sealed secrets, row
// policies) and ships with nearly all of them switched off. Documentation
// cannot fix that; only something executable can. So:
//
//	lab / development  → findings are advisory (logged, never fatal)
//	staging            → new violations are loud
//	production         → any FATAL finding ABORTS BOOT
//
// Every finding names the exact control, the component, where the value came
// from, what was observed, what is required, and how to fix it — because an
// error an operator cannot act on is only marginally better than silence.
//
// Deliberately NOT provided: a global "ignore security errors" switch. A
// deployment that needs an exception makes it narrow, owned and expiring at the
// individual rule level, never by disabling the validator.
package secprofile

import (
	"fmt"
	"sort"
	"strings"
)

// Profile is the deployment posture. Unknown values are rejected rather than
// defaulted, so a typo cannot silently downgrade production to lab.
type Profile string

const (
	Lab         Profile = "lab"
	Development Profile = "development"
	Staging     Profile = "staging"
	Production  Profile = "production"
)

// ParseProfile resolves the configured profile. An empty value means lab (the
// shipped default, and the only one that tolerates plaintext); anything
// unrecognized is an error — never a silent fallback.
func ParseProfile(v string) (Profile, error) {
	switch p := Profile(strings.ToLower(strings.TrimSpace(v))); p {
	case "":
		return Lab, nil
	case Lab, Development, Staging, Production:
		return p, nil
	default:
		return "", fmt.Errorf("unknown SECURITY_PROFILE %q — expected one of: lab, development, staging, production", v)
	}
}

// Severity is what a violation MEANS for this profile.
type Severity string

const (
	// Fatal aborts boot in production. In lower profiles it is reported.
	Fatal Severity = "fatal"
	// Warn is reported everywhere and never aborts. Used for controls that are
	// desirable but whose absence is not a security hole by itself.
	Warn Severity = "warn"
	// Info records a deliberate, declared exception (e.g. a lab plaintext lane)
	// so it is visible rather than invisible.
	Info Severity = "info"
)

// Finding is one evaluated rule. The field set is the operator contract: it
// must be possible to act on a finding without reading the source.
type Finding struct {
	Rule      string   `json:"rule"`      // stable id, e.g. "TLS-001"
	Control   string   `json:"control"`   // the security control at stake
	Component string   `json:"component"` // which part of the stack
	Source    string   `json:"source"`    // where the value came from (env var, file)
	Observed  string   `json:"observed"`  // what we found (never a secret value)
	Required  string   `json:"required"`  // what production requires
	Remedy    string   `json:"remedy"`    // how to fix it, or the runbook
	Severity  Severity `json:"severity"`
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s (%s): %s — observed %s, required %s. Fix: %s",
		f.Rule, f.Control, f.Component, f.Source, f.Observed, f.Required, f.Remedy)
}

// Report is the machine-readable result. It is also what the read-only security
// posture page renders, so the UI never computes "secure" independently — it
// shows what the validator actually evaluated.
type Report struct {
	Profile  Profile   `json:"profile"`
	Findings []Finding `json:"findings"`
	// Fatal is the count of findings that ABORT BOOT in production. It is
	// reported for every profile so a lab operator can see what production
	// would refuse, before they get there.
	Fatal int `json:"fatal"`
	Warn  int `json:"warn"`
	Info  int `json:"info"`
}

// Blocking reports whether this report must stop a production boot.
func (r Report) Blocking() bool { return r.Profile == Production && r.Fatal > 0 }

// Error renders the operator-facing refusal. One finding per line, because a
// wall of prose at 3am is worse than a list.
func (r Report) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "security profile %q refuses to start — %d fatal finding(s):\n", r.Profile, r.Fatal)
	for _, f := range r.Findings {
		if f.Severity == Fatal {
			fmt.Fprintf(&b, "  - %s\n", f)
		}
	}
	b.WriteString("\nThese are deployment configuration problems, not code problems.\n")
	b.WriteString("There is deliberately NO global override: fix the control, or run a lower SECURITY_PROFILE.\n")
	return b.String()
}

// Env is the value source. Injected rather than read from os.Getenv directly so
// the rules are unit-testable without mutating process state.
type Env func(key string) string

// Evaluate runs every rule and returns the report. Pure: no I/O beyond the
// injected lookups, so CI can evaluate a candidate configuration without
// standing the stack up.
func Evaluate(p Profile, env Env, fileExists func(string) bool) Report {
	rep := Report{Profile: p}
	for _, rule := range rules {
		if f, violated := rule(env, fileExists); violated {
			rep.Findings = append(rep.Findings, f)
		}
	}
	sort.Slice(rep.Findings, func(i, j int) bool {
		if rep.Findings[i].Severity != rep.Findings[j].Severity {
			return sevRank(rep.Findings[i].Severity) < sevRank(rep.Findings[j].Severity)
		}
		return rep.Findings[i].Rule < rep.Findings[j].Rule
	})
	for _, f := range rep.Findings {
		switch f.Severity {
		case Fatal:
			rep.Fatal++
		case Warn:
			rep.Warn++
		default:
			rep.Info++
		}
	}
	return rep
}

func sevRank(s Severity) int {
	switch s {
	case Fatal:
		return 0
	case Warn:
		return 1
	default:
		return 2
	}
}

// rule reports a Finding when the control is NOT satisfied.
type rule func(env Env, fileExists func(string) bool) (Finding, bool)

// plaintextURL reports whether a configured URL is plaintext http://.
func plaintextURL(v string) bool {
	v = strings.TrimSpace(strings.ToLower(v))
	return v != "" && strings.HasPrefix(v, "http://")
}

// rules is the production fail-closed rule set (ADR-SEC-008 V1–V16). Each rule
// is independent and names its own remedy.
var rules = []rule{
	// ── Transport: the API's own listener ─────────────────────────────────────
	func(env Env, fx func(string) bool) (Finding, bool) {
		cert, key := env("TLS_CERT_FILE"), env("TLS_KEY_FILE")
		if cert != "" && key != "" {
			return Finding{}, false
		}
		return Finding{
			Rule: "TLS-001", Control: "API serves TLS", Component: "api",
			Source: "TLS_CERT_FILE / TLS_KEY_FILE", Observed: "unset (plaintext listener)",
			Required: "both set", Remedy: "enable the internal CA (TLS_INTERNAL_CA=true) or supply certs; docs/runbooks/tls-mtls.md",
			Severity: Fatal,
		}, true
	},
	func(env Env, fx func(string) bool) (Finding, bool) {
		if env("TLS_CLIENT_CA_FILE") != "" {
			return Finding{}, false
		}
		return Finding{
			Rule: "TLS-002", Control: "API requires client certificates (mTLS)", Component: "api",
			Source: "TLS_CLIENT_CA_FILE", Observed: "unset (any client accepted)",
			Required: "trust bundle path", Remedy: "set TLS_CLIENT_CA_FILE; the internal CA writes it at boot",
			Severity: Fatal,
		}, true
	},
	func(env Env, fx func(string) bool) (Finding, bool) {
		// mTLS without an identity allowlist authenticates but does not
		// authorize: ANY certificate the CA signed is accepted, including one
		// issued to a different service. tlsconfig/verify.go:62-64.
		if env("TLS_CLIENT_CA_FILE") == "" {
			return Finding{}, false // TLS-002 already covers it
		}
		if env("TLS_CLIENT_ALLOWED_URIS") != "" || env("TLS_CLIENT_ALLOWED_DNS") != "" {
			return Finding{}, false
		}
		return Finding{
			Rule: "TLS-003", Control: "mTLS peer identity is allowlisted", Component: "api",
			Source: "TLS_CLIENT_ALLOWED_URIS / _DNS", Observed: "empty (any CA-signed cert accepted)",
			Required: "the exact caller identity, e.g. spiffe://<domain>/ns/default/sa/nginx",
			Remedy:   "set TLS_CLIENT_ALLOWED_URIS — authentication without authorization is not a boundary",
			Severity: Fatal,
		}, true
	},
	// ── Key custody ───────────────────────────────────────────────────────────
	func(env Env, fx func(string) bool) (Finding, bool) {
		if env("SEAL_PROVIDER") != "" {
			return Finding{}, false
		}
		return Finding{
			Rule: "SEC-001", Control: "secrets are sealed at rest", Component: "vault",
			Source: "SEAL_PROVIDER", Observed: "unset (plaintext passthrough)",
			Required: "a sealing provider (swtpm/TPM/HSM/KMS)",
			Remedy:   "set SEAL_PROVIDER and start the 'seal' profile; docs/design/secret-custody.md",
			Severity: Fatal,
		}, true
	},
	func(env Env, fx func(string) bool) (Finding, bool) {
		// The specific foot-gun: an internal CA with no custody writes a 10-year
		// root key in cleartext. Enforced in code too (tls_ca.go seal gate);
		// duplicated here so CI catches the config BEFORE it reaches a host.
		if env("TLS_INTERNAL_CA") != "true" || env("SEAL_PROVIDER") != "" {
			return Finding{}, false
		}
		return Finding{
			Rule: "SEC-002", Control: "internal CA key is sealed", Component: "api",
			Source: "TLS_INTERNAL_CA + SEAL_PROVIDER", Observed: "CA enabled with no sealing provider",
			Required: "SEAL_PROVIDER set whenever TLS_INTERNAL_CA=true",
			Remedy:   "set SEAL_PROVIDER — the CA root can mint an identity for every service and must not sit in cleartext",
			Severity: Fatal,
		}, true
	},
	func(env Env, fx func(string) bool) (Finding, bool) {
		if env("ALLOW_DEV_SECRETS") != "true" {
			return Finding{}, false
		}
		return Finding{
			Rule: "SEC-003", Control: "no development secret fallbacks", Component: "platform",
			Source: "ALLOW_DEV_SECRETS", Observed: "true",
			Required: "unset", Remedy: "unset ALLOW_DEV_SECRETS and provide real secrets (JWT_SECRET, SEAL_PROVIDER)",
			Severity: Fatal,
		}, true
	},
	func(env Env, fx func(string) bool) (Finding, bool) {
		if strings.TrimSpace(env("JWT_SECRET")) != "" {
			return Finding{}, false
		}
		return Finding{
			Rule: "SEC-004", Control: "session signing key is configured", Component: "api",
			Source: "JWT_SECRET", Observed: "unset (dev fallback would be used)",
			Required: "a generated secret", Remedy: "install.py generates it; set JWT_SECRET",
			Severity: Fatal,
		}, true
	},
	// ── Datastore transport ───────────────────────────────────────────────────
	func(env Env, fx func(string) bool) (Finding, bool) {
		if !plaintextURL(env("OPENSEARCH_URL")) {
			return Finding{}, false
		}
		return Finding{
			Rule: "STORE-001", Control: "search store reached over TLS", Component: "opensearch",
			Source: "OPENSEARCH_URL", Observed: "http:// (plaintext)", Required: "https://",
			Remedy:   "enable the OpenSearch security plugin + TLS; docs/runbooks/security/opensearch-security-bootstrap.md",
			Severity: Fatal,
		}, true
	},
	func(env Env, fx func(string) bool) (Finding, bool) {
		if !plaintextURL(env("CLICKHOUSE_URL")) {
			return Finding{}, false
		}
		return Finding{
			Rule: "STORE-002", Control: "OLAP store reached over TLS", Component: "clickhouse",
			Source: "CLICKHOUSE_URL", Observed: "http:// (Basic credentials in cleartext)", Required: "https://",
			Remedy:   "docs/runbooks/security/clickhouse-tls-migration.md",
			Severity: Fatal,
		}, true
	},
	func(env Env, fx func(string) bool) (Finding, bool) {
		u := env("VICTORIA_URL")
		if u == "" {
			u = env("METRICS_URL")
		}
		if !plaintextURL(u) {
			return Finding{}, false
		}
		return Finding{
			Rule: "STORE-003", Control: "metrics store reached over TLS + authorized", Component: "victoriametrics",
			Source: "VICTORIA_URL / METRICS_URL", Observed: "http:// (unauthenticated read AND write)", Required: "https:// via vmauth",
			Remedy:   "front VictoriaMetrics with vmauth; anonymous write lets an attacker forge or suppress alerts",
			Severity: Fatal,
		}, true
	},
	func(env Env, fx func(string) bool) (Finding, bool) {
		dsn := strings.ToLower(env("DATABASE_URL"))
		if dsn == "" || !strings.Contains(dsn, "sslmode=disable") {
			return Finding{}, false
		}
		return Finding{
			Rule: "STORE-004", Control: "relational store uses verified TLS", Component: "postgres",
			Source: "DATABASE_URL", Observed: "sslmode=disable", Required: "sslmode=verify-full",
			Remedy:   "docs/runbooks/security/postgres-tls-migration.md (verify-full, not require — require does not verify)",
			Severity: Fatal,
		}, true
	},
	func(env Env, fx func(string) bool) (Finding, bool) {
		if env("REDIS_HOST") == "" || env("REDIS_PASSWORD") != "" {
			return Finding{}, false
		}
		return Finding{
			Rule: "STORE-005", Control: "cache/evidence store authenticates", Component: "valkey",
			Source: "REDIS_PASSWORD", Observed: "unset (anonymous access)", Required: "an ACL user or password",
			Remedy:   "docs/runbooks/security/valkey-acl-migration.md — NOTE the sequencing: fix the write-path fallback FIRST or RCA path evidence is silently dropped",
			Severity: Fatal,
		}, true
	},
	func(env Env, fx func(string) bool) (Finding, bool) {
		if !plaintextURL(env("CORRELATION_URL")) {
			return Finding{}, false
		}
		return Finding{
			Rule: "APP-001", Control: "correlation service reached over TLS + authenticated", Component: "correlation",
			Source: "CORRELATION_URL", Observed: "http:// (and the service authenticates no caller)",
			Required: "https:// with workload authentication",
			Remedy:   "SEC-013 structural remediation — the service is also cross-tenant capable, so encryption alone is insufficient",
			Severity: Fatal,
		}, true
	},
	func(env Env, fx func(string) bool) (Finding, bool) {
		// APP-002: the PDF sidecar receives FULL tenant RCA/report document
		// bodies (multipart HTML) — plaintext here puts tenant document
		// content on the wire. Gated on the mesh signal (TLS_INTERNAL_CA,
		// the same signal SEC-002 keys on): a deployment that runs the mesh
		// has the gotenberg SVID minted and the TLS variant available, so a
		// remaining http:// sidecar URL is an unconverted hop, never a
		// baseline. Unset = PDF disabled = nothing to protect.
		if env("TLS_INTERNAL_CA") != "true" || !plaintextURL(env("REPORT_PDF_SIDECAR_URL")) {
			return Finding{}, false
		}
		return Finding{
			Rule: "APP-002", Control: "PDF sidecar reached over TLS", Component: "gotenberg",
			Source: "REPORT_PDF_SIDECAR_URL", Observed: "http:// (tenant report/RCA document bodies in cleartext)",
			Required: "https:// (mesh-CA-verified; compose.tls.yml stages the gotenberg SVID)",
			Remedy:   "set REPORT_PDF_SIDECAR_URL=https://gotenberg:3000/forms/chromium/convert/html and run the TLS variant's gotenberg-tls-init + --api-tls flags",
			Severity: Fatal,
		}, true
	},
	// ── Device plane: never claim more than the protocol gives ────────────────
	func(env Env, fx func(string) bool) (Finding, bool) {
		if env("GNMI_ALLOW_INSECURE") != "true" {
			return Finding{}, false
		}
		return Finding{
			Rule: "DEV-001", Control: "gNMI verifies device certificates", Component: "gnmic",
			Source: "GNMI_ALLOW_INSECURE", Observed: "true (skip-verify / insecure targets permitted)",
			Required: "unset", Remedy: "supply a CA bundle per target; gNMI prohibits plaintext fallback by specification",
			Severity: Fatal,
		}, true
	},
	// ── Declared, visible exceptions (never silent) ────────────────────────────
	func(env Env, fx func(string) bool) (Finding, bool) {
		if env("SYSLOG_LEGACY_LANE") != "true" {
			return Finding{}, false
		}
		return Finding{
			Rule: "DEV-002", Control: "legacy syslog lane is declared", Component: "syslog-ng",
			Source: "SYSLOG_LEGACY_LANE", Observed: "true (UDP/TCP 514, unauthenticated)",
			Required: "declared + segmented + expiring",
			Remedy:   "bind to a management interface, allowlist sources, and label events transport_authenticated=false",
			Severity: Info,
		}, true
	},
	func(env Env, fx func(string) bool) (Finding, bool) {
		// Backups are OUT of Security v1 by owner decision; the validator's job
		// is to make that visible rather than let it be assumed covered.
		if env("BACKUP_ENCRYPTED_DESTINATION") == "true" {
			return Finding{}, false
		}
		return Finding{
			Rule: "BKP-001", Control: "backup destination encryption is verified", Component: "backup",
			Source: "BACKUP_ENCRYPTED_DESTINATION", Observed: "not asserted",
			Required: "an operator-provided encrypted volume or destination",
			Remedy:   "set BACKUP_ENCRYPTED_DESTINATION=true once the destination is confirmed encrypted; product-level backup encryption is deferred (v1 scope §7)",
			Severity: Warn,
		}, true
	},
}
