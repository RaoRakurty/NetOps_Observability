// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// pipeline_processors_regen_test.go — F-11 review fix (2026-08-14): a config
// regeneration that cannot render the quarantine stage while sealing is
// configured must FAIL LOUDLY and leave the last-good config live.
//
// THE DEFECT PINNED HERE: quarantineStageVRL's error was swallowed
// (quarantine.go) and GenerateRouterConfig silently omitted the stage
// (generate.go) — no error, no log, no metric, and no SECRET[] references
// left in the file, so Vector's exit-78 fail-closed boot check never fired
// either. One transient custody failure during a regen (e.g. a lazy
// first-mint store failure in vault/tenantkeys.go) and every registry-MISS
// event flowed PLAINTEXT into the shared -untagged- indices until the next
// regen — the exact confidentiality downgrade INV-F11-01/06 forbids, with no
// signal anywhere.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/internal/applog"
	"netops/backend/processors"
)

// regenStubEngine implements processors.SealEngine; failQuarantine simulates
// a custody hiccup scoped to the quarantine key (tenant scopes keep working,
// which is what made the omission so quiet).
type regenStubEngine struct{ failQuarantine bool }

func (e regenStubEngine) EdgeSnippet(tenant, processorID, field, dataType, path string) (string, error) {
	if e.failQuarantine && tenant == processors.QuarantineScope {
		return "", fmt.Errorf("no key custody for %q", tenant)
	}
	return path + " = \"<enc:v1:regen-stub>\"\n", nil
}

func (e regenStubEngine) SealValue(tenant, processorID, field, dataType, plaintext string) (string, error) {
	return "<enc:v1:regen-stub>", nil
}

func (e regenStubEngine) DisplayForm(plaintext string, keepLast int) string { return "****" }

func TestProcessorsRegenKeepsLastGoodConfigOnQuarantineSealFailure(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PROCESSORS_DIR", dir)
	s := &server{processors: processors.NewFileStore(filepath.Join(t.TempDir(), "rules.json"))}

	// Healthy custody: the regen writes a config carrying the quarantine stage.
	processors.SetSealEngine(regenStubEngine{})
	t.Cleanup(func() { processors.SetSealEngine(nil) })
	if err := s.writeProcessorsConfig(context.Background()); err != nil {
		t.Fatalf("healthy regen: %v", err)
	}
	target := filepath.Join(dir, "router", "processors.yaml")
	good, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	for _, lane := range []string{"syslog", "snmptrap", "flows"} {
		if !strings.Contains(string(good), lane+"_quarantine:") {
			t.Fatalf("healthy config must carry the %s quarantine stage:\n%s", lane, good)
		}
	}

	// Custody hiccup for the quarantine scope only. The regen must FAIL (the
	// router keeps the watched last-good file, stage intact) — never write a
	// config that quietly lets registry-MISS events flow plaintext.
	processors.SetSealEngine(regenStubEngine{failQuarantine: true})
	var logged bytes.Buffer
	restore := applog.SwapWriterForTest(&logged)
	err = s.writeProcessorsConfig(context.Background())
	restore()
	if err == nil {
		t.Fatal("a regen that cannot render the quarantine stage must return an error, " +
			"not silently render a config without it (F-11 INV-F11-06)")
	}
	after, rerr := os.ReadFile(target)
	if rerr != nil {
		t.Fatalf("re-read config: %v", rerr)
	}
	if !bytes.Equal(after, good) {
		t.Fatalf("last-good config must remain live on generation failure; it was rewritten:\n%s", after)
	}
	// Loud and structured (§10 no silent failures): the failure must reach the
	// applogs pipeline, not only the process stdout printf.
	if !strings.Contains(logged.String(), `"level":"error"`) ||
		!strings.Contains(logged.String(), "quarantine") {
		t.Fatalf("generation failure must be logged as a structured error naming the "+
			"quarantine stage, got: %s", logged.String())
	}
}
