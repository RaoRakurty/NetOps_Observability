// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package catalog

// drift_test.go — the catalog must describe the product that actually runs.
// Every metric's emitter must literally exist, every enum must equal its source
// of truth, and the N-B5 tripwire forces the gated flag to be flipped in the
// same change that makes circuit/probe series visible to scoped tenants.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// projectRoot walks up to the NetOps_Observability directory (it holds both
// src/ and deployment/).
func projectRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if st, err := os.Stat(filepath.Join(dir, "deployment")); err == nil && st.IsDir() {
			if st, err := os.Stat(filepath.Join(dir, "src", "backend")); err == nil && st.IsDir() {
				return dir
			}
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("project root (NetOps_Observability) not found")
	return ""
}

func readFile(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel)) // #nosec G304 -- test reads repo files named by the catalog
	if err != nil {
		t.Fatalf("emitter file %s: %v", rel, err)
	}
	return string(b)
}

func TestEveryEmitterExists(t *testing.T) {
	root, c := projectRoot(t), MustLoad()
	for _, m := range c.Metrics {
		covered := map[string]bool{}
		for _, e := range m.Emitters {
			if !strings.Contains(readFile(t, root, e.File), e.Contains) {
				t.Errorf("metric %s: %s no longer contains %q — the catalog describes a metric the product does not emit", m.Name, e.File, e.Contains)
			}
			for _, pm := range m.PhysicalMetrics {
				if strings.Contains(e.Contains, pm) {
					covered[pm] = true
				}
			}
		}
		for _, pm := range m.PhysicalMetrics {
			if !covered[pm] {
				t.Errorf("metric %s: physical metric %s has no emitter", m.Name, pm)
			}
		}
	}
}

func TestChangeTypeEnumMatchesStoreAndMigration(t *testing.T) {
	root, c := projectRoot(t), MustLoad()
	d, ok := c.Dimension("change", "type")
	if !ok {
		t.Fatal("change.type missing")
	}
	var cat []string
	for _, v := range d.Enum {
		cat = append(cat, v.Value)
	}
	sort.Strings(cat)

	src := readFile(t, root, "src/backend/internal/dem/experience/change.go")
	constRe := regexp.MustCompile(`Change[A-Za-z]+\s*=\s*"([A-Z_]+)"`)
	var consts []string
	for _, m := range constRe.FindAllStringSubmatch(src, -1) {
		consts = append(consts, m[1])
	}
	sort.Strings(consts)

	mig := readFile(t, root, "src/backend/internal/platformdb/migrations/0044_dem_experience.sql")
	i := strings.Index(mig, "change_type TEXT NOT NULL CHECK")
	j := strings.Index(mig[i:], "))")
	var check []string
	for _, m := range regexp.MustCompile(`'([A-Z_]+)'`).FindAllStringSubmatch(mig[i:i+j], -1) {
		check = append(check, m[1])
	}
	sort.Strings(check)

	if strings.Join(cat, ",") != strings.Join(consts, ",") || strings.Join(cat, ",") != strings.Join(check, ",") {
		t.Fatalf("change types drifted:\n catalog   %v\n constants %v\n migration %v", cat, consts, check)
	}
	// Every class maps only to real stored types.
	cls, _ := c.Dimension("change", "class")
	known := map[string]bool{}
	for _, v := range cat {
		known[v] = true
	}
	for _, ev := range cls.Enum {
		for _, p := range ev.Physical {
			if !known[p] {
				t.Errorf("change class %s maps to unknown type %s", ev.Value, p)
			}
		}
	}
}

func TestSeamEnumMatchesTheEngine(t *testing.T) {
	root, c := projectRoot(t), MustLoad()
	eng := readFile(t, root, "src/correlation/engine.py")
	i := strings.Index(eng, "SEAM_TYPE_AFFINITY")
	block := eng[i : i+strings.Index(eng[i:], "\n}")]
	var engine []string
	for _, m := range regexp.MustCompile(`"([A-Z_]+)":\s*frozenset`).FindAllStringSubmatch(block, -1) {
		engine = append(engine, m[1])
	}
	sort.Strings(engine)
	seam, _ := c.Dimension("change", "seam")
	var cat []string
	for _, v := range seam.Enum {
		cat = append(cat, v.Value)
	}
	sort.Strings(cat)
	if strings.Join(cat, ",") != strings.Join(engine, ",") {
		t.Fatalf("seam enum drifted: catalog %v, engine %v", cat, engine)
	}
	sc, _ := c.Dimension("incident", "seam_class")
	valid := map[string]bool{}
	for _, v := range engine {
		valid[v] = true
	}
	for _, ev := range sc.Enum {
		for _, p := range ev.Physical {
			if !valid[p] {
				t.Errorf("incident seam_class %s maps to unknown seam %s", ev.Value, p)
			}
		}
	}
}

// The N-B5 tripwire. A gated metric is one whose series carry no label the
// tenant scope filter matches (device | hostname | source). The day an emitter
// adds one, this fails — and whoever lands N-B5 must flip the catalog's scope
// to device_scoped in the same change, so the validator stops refusing a
// query the product can now answer.
func TestGatedMetricsAreStillUnscopedAtTheEmitter(t *testing.T) {
	root, c := projectRoot(t), MustLoad()
	scopeLabel := regexp.MustCompile(`[{,](device|hostname|source)=`)
	for _, m := range c.Metrics {
		if m.Scope != "gated:N-B5" {
			continue
		}
		for _, e := range m.Emitters {
			src := readFile(t, root, e.File)
			i := strings.Index(src, e.Contains)
			line := src[i:]
			if k := strings.IndexByte(line, '\n'); k > 0 {
				line = line[:k]
			}
			label := line
			if strings.Contains(line, "{%s}") {
				// The label set is built into a separate format string (echo.go):
				// take the first back-quoted literal after `lbl := fmt.Sprintf(`.
				label = labelFormat(t, src, e.File)
			}
			if scopeLabel.MatchString("{" + strings.Trim(label, "`")) {
				t.Errorf("metric %s: its emitter now carries a scope label — flip catalog scope to device_scoped (N-B5 landed)", m.Name)
			}
		}
	}
}

// labelFormat returns the back-quoted label format string passed to the
// `lbl := fmt.Sprintf(` call in an emitter file. Failing to find it is a test
// failure — a tripwire that silently inspects nothing is worse than none.
func labelFormat(t *testing.T, src, file string) string {
	t.Helper()
	i := strings.Index(src, "lbl := fmt.Sprintf(")
	if i < 0 {
		t.Fatalf("%s: no `lbl := fmt.Sprintf(` — update the tripwire to the emitter's new shape", file)
	}
	rest := src[i:]
	a := strings.IndexByte(rest, '`')
	b := strings.IndexByte(rest[a+1:], '`')
	if a < 0 || b < 0 {
		t.Fatalf("%s: label format literal not found", file)
	}
	return rest[a+1 : a+1+b]
}

func TestTripwireSeesTheCircuitLabelSet(t *testing.T) {
	root := projectRoot(t)
	got := labelFormat(t, readFile(t, root, "src/backend/collectors/echo.go"), "echo.go")
	if !strings.Contains(got, "local_device=%q") || !strings.Contains(got, "circuit=%q") {
		t.Fatalf("the tripwire is not reading the circuit label set: %q", got)
	}
}

// Change classes must PARTITION the stored change types: every type in exactly
// one class. A type outside every class would silently vanish from a negated
// class filter ("everything except WAN changes").
func TestChangeClassesPartitionTheTypes(t *testing.T) {
	c := MustLoad()
	typ, _ := c.Dimension("change", "type")
	cls, _ := c.Dimension("change", "class")
	count := map[string]int{}
	for _, ev := range cls.Enum {
		for _, p := range ev.Physical {
			count[p]++
		}
	}
	for _, ev := range typ.Enum {
		if count[ev.Value] != 1 {
			t.Errorf("change type %s is in %d classes — it must be in exactly one", ev.Value, count[ev.Value])
		}
	}
}
