package backend

// env_gate_guard_test.go — the CLASS guard behind review finding H8.
//
// The gap: a test that skips itself unless an env var is set is a PROMISE that
// some CI leg sets the var. Nothing checked that promise, and it broke exactly
// the way promises do: ~50 RLS/isolation/conformance tests across ~25 files
// gated on DATABASE_URL_TEST, the pg-integration job never exported it (and its
// `-run TestPG` filter never matched their names), so the entire
// database-enforced tenant-isolation corpus was green-by-omission for its whole
// life. A skip-gated test that no CI leg can ever un-skip is not a test — it is
// documentation wearing a test's filename.
//
// This guard closes the mechanically-checkable half of that class (mirroring
// env_docs_guard_test.go's mechanic): every env var a *_test.go file uses as a
// skip gate must either be exported by some workflow under .github/workflows/
// or carry an exemption WITH a reason (live hardware, external services, and
// opt-in artifact emitters legitimately have no CI leg). What it deliberately
// does NOT prove is that the exporting job actually REACHES those tests (run
// filters, build tags) — that part is held by the pg-integration job running
// unfiltered.
//
// Per the guard convention: exemptions carry a reason; never delete the guard.

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// envGateExempt lists skip-gate vars that legitimately have no CI export, with
// the reason. An entry here means "this corpus runs only by hand" — adding one
// for a var CI could feasibly provide (a database, a compose service) is how
// the DATABASE_URL_TEST hole happened; prefer wiring the service.
var envGateExempt = map[string]string{
	"AI_EVAL_LIVE":                "live LLM evals need a paid provider key; opt-in by hand",
	"CH_TEST_URL":                 "live ClickHouse integration; run via the docker line in chhttp_integration_test.go",
	"CLICKHOUSE_URL":              "live ClickHouse settings-precedence contract; needs a real server, run by hand",
	"LIVE_TRACE_DST":              "live traceroute needs CAP_NET_RAW and a real network destination",
	"NETOPS_LDAP_LIVE":            "live LDAP IdP round-trip; needs lab directory infrastructure",
	"NETOPS_OIDC_LIVE":            "live OIDC IdP round-trip; needs lab identity provider",
	"PG_HOSTSSL_TEST_DSN":         "needs a TLS-wrapped (hostssl) postgres, which the plain CI service container is not",
	"RCA_EMIT_HTML":               "opt-in artifact emitter (writes an HTML file for eyeballing), not an assertion gate",
	"RCA_EMIT_HTML_RICH":          "opt-in artifact emitter (writes an HTML file for eyeballing), not an assertion gate",
	"RCA_EMIT_P027379":            "opt-in artifact emitter for one historical incident's report, not an assertion gate",
	"REPORT_PDF_SIDECAR_TEST_URL": "live PDF-render sidecar (gotenberg) integration; run by hand against a running sidecar",
	"SEAL_SWTPM_TEST":             "needs the swtpm secrets-seal sidecar running; hardware-adjacent, run by hand",
	"SKIP_SEALED_VAULT_TEST":      "inverse gate — set to SKIP a test, so CI runs it precisely by NOT exporting this",
	"SNMP_LIVE":                   "live SNMP device poll; needs lab hardware",
	// Not an enable-gate: the timeintel live pick-shape check turns ITSELF on by
	// probing (docker on PATH → a running *clickhouse* container → SELECT 1 →
	// the netops corr tables), so CI exports nothing and it skips cleanly. This
	// var only NAMES a non-default container or turns the check off (=off) — the
	// SKIP_SEALED_VAULT_TEST shape, where exporting it in CI would REMOVE
	// coverage rather than add it.
	"TIMEINTEL_LIVE_CH_CONTAINER": "inverse/override gate — the live pick-shape check self-enables by probing docker; setting this only renames the container or disables it",
}

var envGateGetenvRe = regexp.MustCompile(`os\.Getenv\("([A-Z][A-Z0-9_]*)"\)`)

// collectTestEnvGates scans every *_test.go under the module for env vars used
// as skip gates: an os.Getenv whose surrounding lines (the read, then the
// guard clause) reach a t.Skip within a short window.
func collectTestEnvGates(t *testing.T) map[string][]string {
	t.Helper()
	gates := map[string][]string{}
	skipDir := map[string]bool{"vendor": true, "testdata": true, "node_modules": true}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir[d.Name()] || (strings.HasPrefix(d.Name(), ".") && d.Name() != ".") {
				return filepath.SkipDir
			}
			return nil
		}
		// The guard names its own subject in prose; don't let it gate itself.
		if !strings.HasSuffix(d.Name(), "_test.go") || d.Name() == "env_gate_guard_test.go" {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		lines := strings.Split(string(b), "\n")
		for i, line := range lines {
			m := envGateGetenvRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			// Skip window: the read, the emptiness check, and the Skip call sit
			// within a handful of lines in every gate shape this repo uses.
			end := i + 6
			if end > len(lines) {
				end = len(lines)
			}
			for _, w := range lines[i:end] {
				if strings.Contains(w, ".Skip(") || strings.Contains(w, ".Skipf(") {
					gates[m[1]] = append(gates[m[1]], filepath.ToSlash(path))
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk backend module: %v", err)
	}
	return gates
}

// readWorkflows concatenates every workflow file so a gate var can be matched
// anywhere it is exported (env:, run: export, service config).
func readWorkflows(t *testing.T) string {
	t.Helper()
	dir := "../../../.github/workflows"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v (the guard needs the workflows to check against)", dir, err)
	}
	var sb strings.Builder
	n := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read workflow %s: %v", name, err)
		}
		sb.Write(b)
		sb.WriteByte('\n')
		n++
	}
	if n < 5 {
		t.Fatalf("only %d workflow files found in %s — the guard is not seeing the real CI", n, dir)
	}
	return sb.String()
}

func TestSkipGateEnvVarsAreExportedBySomeWorkflow(t *testing.T) {
	gates := collectTestEnvGates(t)
	if len(gates) == 0 {
		t.Fatal("no skip-gated env vars found at all — the scanner is broken (DATABASE_URL_TEST alone gates ~25 files)")
	}
	if _, ok := gates["DATABASE_URL_TEST"]; !ok {
		t.Fatal("scanner failed to find the DATABASE_URL_TEST gate — the pattern this guard exists for")
	}
	workflows := readWorkflows(t)
	for v, files := range gates {
		if _, exempt := envGateExempt[v]; exempt {
			continue
		}
		if !strings.Contains(workflows, v) {
			t.Errorf("env var %q gates tests (e.g. %s and %d other file(s)) but NO workflow under "+
				".github/workflows/ ever sets it — those tests can never run in CI. Export it in the "+
				"job that provides its dependency, or add an envGateExempt entry with the reason it is "+
				"hand-run only.", v, files[0], len(files)-1)
		}
	}
	// Exemptions must stay live: a stale entry hides a var that GAINED a CI
	// export (fine) or lost its tests (rot) — prune it either way.
	for v := range envGateExempt {
		if _, ok := gates[v]; !ok {
			t.Errorf("envGateExempt entry %q matches no skip-gated test anymore — prune it", v)
		}
	}
}
