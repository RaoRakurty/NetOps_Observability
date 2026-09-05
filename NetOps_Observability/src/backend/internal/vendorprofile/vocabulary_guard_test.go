package vendorprofile

// vocabulary_guard_test.go — the ONE VENDOR VOCABULARY guard (CLAUDE.md §13,
// T9 residual, tracker 216).
//
// The registry only pays for itself if it is the ONLY place vendor knowledge
// lives. Every regression this project has had here looked the same: someone
// needed "the Cisco command for X" or "which dialect is this platform", wrote a
// small `map[string]string{"cisco": …, "juniper": …}` next to the code that
// needed it, and from then on onboarding a vendor meant editing two places —
// and the two places drifted.
//
// This test makes that shape a BUILD FAILURE. It parses every non-test Go file
// in the backend module and fails on two constructs:
//
//	1. a map COMPOSITE LITERAL whose keys include two or more of the registry's
//	   own vendor ids or CLI dialect ids — a second vendor→(command|dialect|…)
//	   table;
//	2. a SWITCH whose case clauses carry two or more of those ids as raw STRING
//	   LITERALS — the same table written as control flow (the shape
//	   protocoldiag.VendorFromPlatform had before it moved into the registry).
//
// What it deliberately does NOT flag, and why:
//
//   - _test.go files. A test that pins the exact rows the registry serves is
//     precisely the no-regression gate this design wants (see
//     TestVerifyCommandsResolveThroughTheRegistry); forbidding vendor ids in
//     test expectations would forbid proving the data is right.
//   - switches over CONSTANTS (`case showparse.DialectJunos:`,
//     `case VendorJuniper:`). Those identifiers ARE the registry's vocabulary,
//     reached through it — protocoldiag's vrfScopeToken and statebattery's
//     batteryVRFScope render a dialect's CLI qualifier keyword that way, beside
//     the per-dialect command templates they scope. They are dialect
//     RENDERERS, not vendor identity maps: the identity question ("which
//     dialect is this platform?") is answered by the registry, and only the
//     keyword that belongs with the authored template is written here.
//   - internal/vendorprofile itself, which is where the vocabulary belongs, and
//     vendor/ (third-party source).
//
// ALLOWLIST. Every call site tracker row 216 named — internal/verify's two
// command tables, internal/protocoldiag's platform switch, internal/showparse's
// fallback token map — is gone, and this guard is what keeps them gone. So are
// the five residuals this guard found ELSEWHERE the first time it ran and row
// 221 carried: internal/configstore's platform/command/volatile tables,
// internal/snmpcred's onboarding CLI blocks, internal/pcap's capture-family
// resolver, the root device-type inference and topology's firewall vendor hint.
// Each moved into a profile document under its own strict-validated key
// (config_capture, snmp_configgen, device_type, capture.pcap_family +
// pcap_platform_rules) with a byte-parity golden in its own package proving the
// move changed nothing, and a row pin in consumer_bindings_test.go proving the
// data is the data that moved.
//
// ONE entry remains, and it is not a residual: it is a legitimate implementation
// switch that selects Go code, not a vendor fact. It carries its reason inline,
// so the exception is reviewable rather than invisible — and adding a second
// should be an argument, not a reflex.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// vocabularyGuardAllowlist maps a module-relative file path to the REASON that
// file is permitted to carry a vendor-keyed literal.
//
// A reason is either "not a vocabulary" (the literal selects an implementation
// or a heuristic, not a vendor fact the registry owns) or "residual, tracked" —
// a table that SHOULD move into the registry and is carried on a tracker row.
// Nothing lands here just to make the test green.
var vocabularyGuardAllowlist = map[string]string{
	// NOT A VOCABULARY — the switch picks a Go IMPLEMENTATION (a MIB-specific
	// SNMP walker), not a vendor fact. The knowledge in each adapter is an OID
	// table for one vendor's private MIB; it is code, and moving the selector
	// into the registry would only add indirection to reach the same two types.
	"collectors/dom_adapters.go": "vendor → domAdapter implementation selection (code, not data)",
	// NOT DEVICE VOCABULARY — these tables are keyed by the vendor as a SUPPORT
	// ORGANISATION (its TAC mailbox, its case portal URL and the fields that
	// portal asks for), which is knowledge about the vendor's support system, not
	// about its devices. The registry describes platforms and dialects; a
	// support-portal descriptor has no home there and would only add a second
	// meaning to the profile data.
	"internal/ticketing/attach_email.go":    "vendor → TAC attachment mailbox / subject convention (support organisation, not device profile)",
	"internal/ticketing/caseconn_portal.go": "vendor → case-portal descriptor (URL + form fields the portal asks for), not device profile",
	// The CLI keyword that scopes a lookup to a VRF ("vrf X" / "instance X" /
	// "vpn-instance X" / bare name on SR Linux) is dispatched on the DIALECT id
	// the registry itself resolved (CLIDialectForPlatform); the switch is a
	// rendering of that dialect, not a second vocabulary. The right long-term
	// home is a Dialect.VRFScopeKeyword field — tracked, not done here.
	"internal/tac/plan.go": "VRF scope keyword rendered per registry-resolved dialect id (Dialect.VRFScopeKeyword is the intended home)",
}

// vocabularyGuardMinHits is how many distinct registry ids one literal must
// carry before it counts as a second vocabulary. Two is the threshold because a
// single vendor id is usually a legitimate one-off (a fixture device, a log
// message); two or more in one table is a table.
const vocabularyGuardMinHits = 2

func TestNoVendorVocabularyOutsideTheRegistry(t *testing.T) {
	root := moduleRoot(t)
	reg := Default()

	// The guarded vocabulary: vendor ids and CLI dialect ids. Both are the
	// registry's OWN keys — the exact strings a second table would have to
	// repeat to be a second table.
	guarded := map[string]string{}
	for _, v := range reg.VendorIDs() {
		guarded[v] = "vendor id"
	}
	for _, p := range reg.Profiles() {
		if p.CLI.Dialect != "" {
			guarded[p.CLI.Dialect] = "cli dialect id"
		}
		if p.Hardening.Binding != "" {
			guarded[p.Hardening.Binding] = "hardening binding id"
		}
	}

	scanned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "node_modules", ".git", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		if strings.HasPrefix(rel, filepath.Join("internal", "vendorprofile")+string(filepath.Separator)) {
			return nil
		}
		if reason, ok := vocabularyGuardAllowlist[filepath.ToSlash(rel)]; ok {
			t.Logf("allowlisted: %s (%s)", rel, reason)
			return nil
		}
		scanned++
		for _, finding := range scanVendorVocabulary(t, path, guarded) {
			t.Errorf("%s: %s\n\tThe vendor vocabulary lives in internal/vendorprofile. Author the knowledge as "+
				"profile data and resolve it through the registry (VerifyCommand / CLIDialectForPlatform / "+
				"ProfileForPlatformText / CaptureFor), or add this file to vocabularyGuardAllowlist with a reason.",
				filepath.ToSlash(rel), finding)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if scanned < 50 {
		t.Fatalf("only %d files scanned — the guard is not looking at the backend", scanned)
	}
	t.Logf("scanned %d non-test Go files for a second vendor vocabulary", scanned)
}

// scanVendorVocabulary parses one file and reports every offending construct.
func scanVendorVocabulary(t *testing.T, path string, guarded map[string]string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CompositeLit:
			if _, isMap := node.Type.(*ast.MapType); !isMap {
				return true
			}
			var keys []string
			for _, elt := range node.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if s, ok := stringLit(kv.Key); ok {
					keys = append(keys, s)
				}
			}
			if hits := guardedHits(keys, guarded); len(hits) >= vocabularyGuardMinHits {
				out = append(out, "line "+strconv.Itoa(fset.Position(node.Pos()).Line)+
					": map literal keyed by the registry's own vocabulary ("+strings.Join(hits, ", ")+")")
			}
		case *ast.SwitchStmt:
			var lits []string
			for _, stmt := range node.Body.List {
				cc, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, expr := range cc.List {
					ast.Inspect(expr, func(inner ast.Node) bool {
						if s, ok := stringLit(inner); ok {
							lits = append(lits, s)
						}
						return true
					})
				}
			}
			if hits := guardedHits(lits, guarded); len(hits) >= vocabularyGuardMinHits {
				out = append(out, "line "+strconv.Itoa(fset.Position(node.Pos()).Line)+
					": switch dispatching on the registry's own vocabulary as string literals ("+strings.Join(hits, ", ")+")")
			}
		}
		return true
	})
	return out
}

// guardedHits returns the DISTINCT guarded ids present in vals, in a stable
// order (first appearance), each annotated with what kind of id it is.
func guardedHits(vals []string, guarded map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range vals {
		kind, ok := guarded[strings.ToLower(strings.TrimSpace(v))]
		if !ok || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, strconv.Quote(v)+" ("+kind+")")
	}
	return out
}

func stringLit(n ast.Node) (string, bool) {
	bl, ok := n.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

// moduleRoot walks up from the package directory to the directory holding
// go.mod — the backend module the guard covers.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found above the package directory")
		}
		dir = parent
	}
}
