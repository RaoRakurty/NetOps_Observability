package tac

import (
	"strings"
	"testing"

	"netops/backend/internal/protocoldiag"
)

// TestDefaultCatalogLoads is the DATA GATE: the shipped taxonomy and every
// shipped plan must parse, validate and cross-reference cleanly. A data change
// that breaks any rule in ai/tac/README.md fails here, in CI, before it can
// reach a device.
func TestDefaultCatalogLoads(t *testing.T) {
	c, err := Default()
	if err != nil {
		t.Fatalf("the embedded TAC catalog does not load: %v", err)
	}
	if c.Version == "" {
		t.Fatal("catalog carries no version — every bundle stamps it")
	}
	if len(c.Classes()) < 20 {
		t.Fatalf("taxonomy has %d classes, expected the full closed list", len(c.Classes()))
	}
	if _, ok := c.Class(GenericClassID); !ok {
		t.Fatal("the mandatory generic fallback class is missing")
	}
	if len(c.Dialects()) < 4 {
		t.Fatalf("only %d dialect plans loaded: %v", len(c.Dialects()), c.Dialects())
	}
	for _, want := range []string{"cisco-iosxe", "arista-eos", "cisco-nxos", "juniper-junos"} {
		if _, ok := c.PlanFor(want); !ok {
			t.Errorf("no plan for dialect %q", want)
		}
	}
}

// TestEveryPlannedCommandIsReadOnly is the SAFETY GATE. It re-runs the read-only
// grammar over every shipped binding rather than trusting that the loader ran
// it: this is the assertion that would fail if someone widened the loader.
func TestEveryPlannedCommandIsReadOnly(t *testing.T) {
	c, err := Default()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	exceptions, probes, scoped := 0, 0, 0
	for _, d := range c.Dialects() {
		p, _ := c.PlanFor(d)
		for intent, b := range p.Bindings {
			// A BOUNDED REACHABILITY PROBE is not a read and is still allowed
			// (owner, 2026-09-05). It passes its own grammar, every parameter
			// inside the bound, and it may never carry a teardown.
			if protocoldiag.IsProbeCommand(b.Command) {
				probes++
				if err := protocoldiag.ValidateBoundedProbe(b.Command); err != nil {
					t.Errorf("%s/%s: %q is outside the bounded-probe grammar: %v", d, intent, b.Command, err)
				}
				if err := ValidateCommand(b.Command); err != nil {
					t.Errorf("%s/%s: %v", d, intent, err)
				}
				if b.Teardown != "" {
					t.Errorf("%s/%s: a probe carries a teardown", d, intent)
				}
				continue
			}
			// A DOCUMENTED SESSION-SCOPED SETTER is admitted by the policy and
			// by nothing else, and only WITH the teardown the policy documents.
			if scope, ok := c.Policy().SessionScope(d, b.Command); ok {
				scoped++
				if err := ValidateScopedSetter(b.Command); err != nil {
					t.Errorf("%s/%s: %v", d, intent, err)
				}
				if b.Teardown != scope.Teardown {
					t.Errorf("%s/%s: teardown is %q, the policy documents %q", d, intent, b.Teardown, scope.Teardown)
				}
				continue
			}
			if b.Teardown != "" {
				t.Errorf("%s/%s: carries a teardown but is not a session-scoped setter", d, intent)
			}
			if b.ReadOnlyException != "" {
				// The narrow, CITED documented-status-read path. It must still
				// pass every structural rule, and it must say where the
				// exception comes from — an uncited exception is a hole.
				exceptions++
				if err := ValidateCommandWithException(b.Command, b.ReadOnlyException); err != nil {
					t.Errorf("%s/%s: %v", d, intent, err)
				}
				if len(b.Sources) == 0 {
					t.Errorf("%s/%s: read-only exception with no citation", d, intent)
				}
				continue
			}
			if err := protocoldiag.ValidateReadOnly(b.Command); err != nil {
				t.Errorf("%s/%s: %q is not read-only: %v", d, intent, b.Command, err)
			}
			for _, forbidden := range []string{"debug", "clear", "configure", "request", "test", "monitor", "reload", "delete", "start"} {
				if strings.EqualFold(strings.Fields(b.Command)[0], forbidden) {
					t.Errorf("%s/%s: command leads with %q", d, intent, forbidden)
				}
			}
			if err := ValidateCommand(b.Command); err != nil {
				t.Errorf("%s/%s: %v", d, intent, err)
			}
		}
	}
	// The exception list is meant to be TINY. If it grows, someone has started
	// using it as a way around the grammar rather than as a footnote to it.
	if exceptions > 20 {
		t.Errorf("%d read-only exceptions are shipped; the allowlist is a footnote to the "+
			"grammar, not a second grammar — review them", exceptions)
	}
	// The two non-read admissions are meant to stay small and enumerable: a
	// probe per concept a vendor documents, and the two FortiOS scope setters.
	if scoped > 8 {
		t.Errorf("%d session-scoped setters are shipped; the exemption is two documented FortiOS "+
			"setters, not a category", scoped)
	}
	t.Logf("shipped bindings carry %d cited read-only exceptions, %d bounded probes and %d session-scoped setters",
		exceptions, probes, scoped)
}

// TestEveryReferencedIntentIsDeclared proves the vocabulary is closed in both
// directions: no class asks for an intent that does not exist, and no plan binds
// one that does not exist.
func TestEveryReferencedIntentIsDeclared(t *testing.T) {
	c, err := Default()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, cl := range c.Classes() {
		for _, in := range cl.Intents {
			if _, ok := c.Intent(in); !ok {
				t.Errorf("class %s references undeclared intent %q", cl.ID, in)
			}
		}
	}
	for _, d := range c.Dialects() {
		p, _ := c.PlanFor(d)
		for in := range p.Bindings {
			if _, ok := c.Intent(in); !ok {
				t.Errorf("plan %s binds undeclared intent %q", d, in)
			}
		}
	}
}

// TestLoaderRefusesUnsafeData pins the loader's fail-closed behaviour on the
// shapes that matter: a write command, a placeholder outside the grammar, an
// unknown field, a dangling intent, and a doc_claimed binding with no citation.
func TestLoaderRefusesUnsafeData(t *testing.T) {
	const classes = `
schema_version: 1
version: t
intents:
  - id: system.version
    area: system
    title: Version
classes:
  - id: generic
    title: Generic
    protocol: generic
    intents: []
`
	base := func(binding string) string {
		return `
schema_version: 1
dialect: cisco-iosxe
profile: cisco/ios_xe
display: Cisco IOS-XE
version: t
sources:
  - title: Ref
    url: https://example.invalid/doc
    retrieved: 2026-09-05
baseline:
  - system.version
bindings:
` + binding
	}
	cases := []struct {
		name, binding, want string
	}{
		{"write command", "  system.version:\n    command: configure terminal\n    verified: capture\n", "not a read-only show"},
		{"debug command", "  system.version:\n    command: debug ip ospf\n    verified: capture\n", "not a read-only show"},
		{"chained command", "  system.version:\n    command: show version; reload\n    verified: capture\n", "not a read-only show"},
		{"unknown placeholder", "  system.version:\n    command: show version {secret}\n    verified: capture\n", "closed substitution grammar"},
		{"unknown field", "  system.version:\n    command: show version\n    verified: capture\n    oops: 1\n", "unknown field"},
		{"bad verified", "  system.version:\n    command: show version\n    verified: probably\n", "`verified` must be"},
		{"dangling intent", "  system.nope:\n    command: show version\n    verified: capture\n", "not in the classes.yaml vocabulary"},
	}
	c, err := loadClasses(classes)
	if err != nil {
		t.Fatalf("fixture classes: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadPlan(c, "cisco-iosxe", base(tc.binding))
			if err == nil {
				t.Fatalf("expected a refusal, got none")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
}

// TestDocClaimedNeedsACitation proves the honesty rule is enforced, not merely
// documented: an unverified command must say where it came from.
func TestDocClaimedNeedsACitation(t *testing.T) {
	const classes = `
schema_version: 1
version: t
intents:
  - id: system.version
    area: system
    title: Version
classes:
  - id: generic
    title: Generic
    protocol: generic
    intents: []
`
	c, err := loadClasses(classes)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	plan := `
schema_version: 1
dialect: cisco-iosxe
profile: cisco/ios_xe
display: Cisco IOS-XE
version: t
baseline:
  - system.version
bindings:
  system.version:
    command: show version
    verified: doc_claimed
`
	if _, err := loadPlan(c, "cisco-iosxe", plan); err == nil ||
		!strings.Contains(err.Error(), "carries `sources`") {
		t.Fatalf("expected a citation refusal, got %v", err)
	}
}

// TestDialectSlug pins the one place the vendorprofile id space and this
// package's slug space are joined.
func TestDialectSlug(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"cisco/ios_xe", "cisco-iosxe"},
		{"cisco/nx-os", "cisco-nxos"},
		{"arista/eos", "arista-eos"},
		{"juniper/junos", "juniper-junos"},
		{"nokia/srlinux", "nokia-srlinux"},
		{"paloalto/pan-os", "paloalto-panos"},
		{"nonsense", ""},
	} {
		if got := DialectSlug(tc.in); got != tc.want {
			t.Errorf("DialectSlug(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// mustCatalog is the fixtures' catalog. It FAILS the test on a load error
// rather than handing back a nil catalog for something else to dereference —
// a data bug should read as "the data does not load", not as a segfault three
// files away.
func mustCatalog(t *testing.T) *Catalog {
	t.Helper()
	c, err := Default()
	if err != nil {
		t.Fatalf("the embedded TAC catalog does not load: %v", err)
	}
	return c
}
