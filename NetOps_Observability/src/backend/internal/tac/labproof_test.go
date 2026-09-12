// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// labproof_test.go — the LIVE LAB PROOF, skipped everywhere except a lab run.
//
// It is a test rather than a throwaway script for one reason: the proof this
// feature owes is not "it compiled", it is "it ran read-only commands on real
// hardware, refused to guess at the platform it does not know, and produced a
// bundle a TAC engineer could open". That claim has to be re-runnable.
//
// It NEVER runs in CI: it is skipped unless TAC_LAB_PROOF=1 and the read-only
// credentials are in the environment. It runs SHOW COMMANDS ONLY — the closed
// plan table is the same one production uses, so it cannot emit anything else —
// and it writes nothing to any device.
//
//	TAC_LAB_PROOF=1 \
//	TAC_LAB_EOS=172.40.40.21 TAC_LAB_SRLINUX=172.40.40.11 \
//	PROTOCOL_DIAG_SSH_USER=… PROTOCOL_DIAG_SSH_PASSWORD=… \
//	go test ./internal/tac/ -run TestLabProof -v

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/protocoldiag"
)

// labTOFU is a trust-on-first-use host-key store for the proof run. It has the
// SAME policy as the platform's pinned store — first sighting is recorded, a
// changed key is refused — it simply does not persist. There is no
// InsecureIgnoreHostKey anywhere in this file.
type labTOFU struct {
	mu   sync.Mutex
	seen map[string]string
}

func (l *labTOFU) check(addr, fingerprint string) (bool, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil {
		l.seen = map[string]string{}
	}
	prev, ok := l.seen[addr]
	if !ok {
		l.seen[addr] = fingerprint
		return true, true
	}
	return false, prev == fingerprint
}

// labCredential is the proof run's identity. The private key is read from a
// FILE PATH, never from an environment variable and never echoed: a key that
// reaches a process argument or a log is a key that has to be rotated.
type labCredential struct {
	user       string
	password   string
	privateKey string
}

func labSkip(t *testing.T) labCredential {
	t.Helper()
	if os.Getenv("TAC_LAB_PROOF") != "1" {
		t.Skip("lab proof: set TAC_LAB_PROOF=1 to run against real devices")
	}
	cred := labCredential{
		user:     os.Getenv("PROTOCOL_DIAG_SSH_USER"),
		password: os.Getenv("PROTOCOL_DIAG_SSH_PASSWORD"),
	}
	if path := os.Getenv("PROTOCOL_DIAG_SSH_KEY_FILE"); path != "" {
		b, err := os.ReadFile(path) // #nosec G304 -- an operator-supplied lab key path, test-only
		if err != nil {
			t.Skipf("lab proof: key file %s is not readable", path)
		}
		cred.privateKey = string(b)
	}
	if cred.user == "" || (cred.password == "" && cred.privateKey == "") {
		t.Skip("lab proof: no read-only SSH credentials in the environment")
	}
	return cred
}

func labGateway(cred labCredential) *protocoldiag.SSHGateway {
	tofu := &labTOFU{}
	return &protocoldiag.SSHGateway{
		Credentials: func(context.Context, protocoldiag.Device) (protocoldiag.Credential, error) {
			return protocoldiag.Credential{
				Username: cred.user, Password: cred.password, PrivateKey: cred.privateKey,
			}, nil
		},
		HostKeyCheck: tofu.check,
		DialTimeout:  10 * time.Second,
		Port:         22,
	}
}

// TestLabProofSRLinuxCollects is the SR Linux half, run against a lab spine.
//
// It was originally the honest "no authored plan for this platform" proof. The
// vendor research then supplied 40 cited SR Linux issues, SR Linux gained a real
// plan, and keeping the old assertion would have meant refusing knowledge to
// protect a demonstration. So this now proves the harder thing: a real read-only
// collection on the platform Correlix knew least about. The honest no-plan path
// is still proven — by TestLabProofUnknownPlatformRunsNothing below, and by
// TestPlanNoAuthoredPlanIsHonest offline.
func TestLabProofSRLinuxCollects(t *testing.T) {
	cred := labSkip(t)
	addr := os.Getenv("TAC_LAB_SRLINUX")
	if addr == "" {
		t.Skip("lab proof: set TAC_LAB_SRLINUX to a reachable SR Linux spine")
	}
	cat, err := Default()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	dev := Device{ID: "spine1", Hostname: "spine1", Platform: "Nokia SR Linux 24.3.2",
		TenantID: "lab", Address: addr, Port: 22}
	cls := cat.Classify(Evidence{
		Alerts:     []string{"ISISAdjacencyDown"},
		Hypotheses: []string{"sig.ent.fabric.isis-adjacency-flap"},
	})
	t.Logf("classified: %s (%s) — %s", cls.ClassID, cls.Title, cls.Note)

	plan, err := cat.Plan(cls.ClassID, dev, PlanOptions{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	plan.IncidentID = "lab-proof-srlinux"
	if !plan.HasPlan {
		t.Fatalf("SR Linux gained an authored plan when the research merged; HasPlan must be true")
	}
	t.Logf("plan %s: %d commands, %d unbound", plan.ID, len(plan.Steps), len(plan.Unbound))
	for i, u := range plan.Unbound {
		if i >= 5 {
			t.Logf("  … and %d more unbound intents", len(plan.Unbound)-5)
			break
		}
		t.Logf("  unbound %s — %s", u.Intent, u.Note)
	}

	runner, err := protocoldiag.NewSSHGatedRunner(NewGate(cat), labGateway(cred))
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	col, err := NewCollector(runner, WithPacing(400*time.Millisecond))
	if err != nil {
		t.Fatalf("collector: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	capt, err := col.Collect(ctx, plan, nil, func(pr Progress) {
		if pr.Phase != "start" {
			detail := fmt.Sprintf(" (%d bytes)", pr.Bytes)
			if pr.Err != "" {
				detail = " — " + pr.Err
			}
			t.Logf("  [%d/%d] %-34s %s%s", pr.Index+1, pr.Total, pr.Intent, pr.Phase, detail)
		}
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	ok := 0
	for _, cc := range capt.Commands {
		if cc.OK() {
			ok++
		}
	}
	t.Logf("collected %d commands, %d returned output, %d bytes total", len(capt.Commands), ok, capt.TotalBytes)
}

// TestLabProofUnknownPlatformRunsNothing is the honest path, kept as a LIVE
// assertion: a platform Correlix does not recognise gets no plan, no commands
// and no borrowed dialect — and the run-time gate refuses independently of the
// plan, so even a caller that skipped planning could not reach the device.
func TestLabProofUnknownPlatformRunsNothing(t *testing.T) {
	_ = labSkip(t)
	cat, err := Default()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	dev := Device{ID: "unknown1", Hostname: "unknown1", Platform: "Acme RouterThing 1.0", TenantID: "lab"}
	plan, err := cat.Plan("ospf-adjacency", dev, PlanOptions{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.HasPlan || len(plan.Steps) != 0 {
		t.Fatalf("an unrecognised platform produced %d commands", len(plan.Steps))
	}
	t.Logf("plan note: %s", plan.Note)
	if NewGate(cat).Allows(protocoldiag.Device{Platform: dev.Platform}, "show version") {
		t.Fatal("the gate allowed a command against a platform it does not recognise")
	}
}

// TestLabProofEOSCollectsAndBundles is the cEOS half: a real read-only
// collection through the same gateway production uses, and a real bundle.
func TestLabProofEOSCollectsAndBundles(t *testing.T) {
	cred := labSkip(t)
	addr := os.Getenv("TAC_LAB_EOS")
	if addr == "" {
		t.Skip("lab proof: set TAC_LAB_EOS to a reachable cEOS leaf")
	}
	cat, err := Default()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	runner, err := protocoldiag.NewSSHGatedRunner(NewGate(cat), labGateway(cred))
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	col, err := NewCollector(runner, WithPacing(500*time.Millisecond))
	if err != nil {
		t.Fatalf("collector: %v", err)
	}

	className := os.Getenv("TAC_LAB_CLASS")
	if className == "" {
		className = "bgp-session"
	}
	dev := Device{ID: "leaf1", Hostname: "leaf1", Platform: "Arista EOS 4.36.0F",
		TenantID: "lab", Address: addr, Port: 22}
	cls := cat.Classify(Evidence{Alerts: []string{"BGPSessionDown"}, Skills: []string{"bgp-session-down"}})
	t.Logf("classified: %s — %s", cls.ClassID, cls.Note)

	plan, err := cat.Plan(className, dev, PlanOptions{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	plan.IncidentID = "lab-proof"
	if !plan.HasPlan {
		t.Fatalf("Arista EOS must have an authored plan")
	}
	t.Logf("plan %s: %d commands, %d unbound, ≤%d bytes, ≤%ds",
		plan.ID, len(plan.Steps), len(plan.Unbound), plan.EstimatedBytes, plan.EstimatedSeconds)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	capt, err := col.Collect(ctx, plan, nil, func(pr Progress) {
		if pr.Phase != "start" {
			t.Logf("  [%d/%d] %-28s %s%s", pr.Index+1, pr.Total, pr.Intent, pr.Phase,
				func() string {
					if pr.Err != "" {
						return " — " + pr.Err
					}
					return fmt.Sprintf(" (%d bytes)", pr.Bytes)
				}())
		}
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	ok := 0
	for _, cc := range capt.Commands {
		if cc.OK() {
			ok++
		}
	}
	t.Logf("collected %d commands, %d returned output, %d bytes total", len(capt.Commands), ok, capt.TotalBytes)
	if ok == 0 {
		t.Fatalf("no command returned output — the lab run proved nothing")
	}

	b, err := BuildBundle(ctx, BundleInput{
		TenantID: "lab", IncidentID: "lab-proof", IncidentRef: "LAB-PROOF",
		Title:       "Lab proof: " + className + " on " + dev.Hostname,
		WindowStart: capt.StartedAt.Add(-time.Hour), WindowEnd: capt.StartedAt,
		Actor: "lab-proof", Class: cls, Plan: plan, Capture: capt,
		Alerts: []AlertFact{{Name: "BGPSessionDown", Severity: "critical", Device: dev.Hostname}},
	}, nil, time.Now)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	t.Logf("bundle %s: %d bytes, %d files", b.Name, len(b.Zip), len(b.Manifest.Files))

	manifest, _ := json.MarshalIndent(b.Manifest, "", "  ")
	t.Logf("MANIFEST.json (excerpt):\n%s", clip(string(manifest), 4000))
	t.Logf("PROBLEM_STATEMENT.md:\n%s", b.Statement.Text)

	if out := os.Getenv("TAC_LAB_OUT"); out != "" {
		if err := os.WriteFile(out, b.Zip, 0o600); err != nil {
			t.Fatalf("write bundle: %v", err)
		}
		t.Logf("bundle written to %s", out)
	}
	// The bundle must never carry an unredacted secret, even from a real device.
	for _, needle := range []string{cred.password, cred.privateKey} {
		if needle != "" && strings.Contains(string(b.Zip), needle) {
			t.Fatal("the SSH password appeared in the bundle")
		}
	}
}
