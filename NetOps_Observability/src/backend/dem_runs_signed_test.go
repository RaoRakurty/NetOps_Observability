// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// dem_runs_signed_test.go — tracker 475 end to end on the api side for the
// Digital Experience runs. A run batch written into the prober's channel by
// anyone but the prober (here: an unsigned batch naming tenant A) must reach
// NO tenant's experience grade; the prober's signed batch reaches its tenant,
// attributed to the signing vantage (§3a: the run store is tenant-keyed).

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/internal/dem"
	"netops/backend/internal/featureflags"
	"netops/backend/internal/probercontrol"
)

// scriptedRedis answers ONE connection with replies, in order.
func scriptedRedis(t *testing.T, replies ...string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("REDIS_HOST", host)
	t.Setenv("REDIS_PORT", port)
	t.Setenv("REDIS_PASSWORD", "")
	t.Setenv("REDIS_TLS", "")
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(c)
		for _, reply := range replies {
			hdr, rerr := r.ReadString('\n')
			if rerr != nil || len(hdr) == 0 || hdr[0] != '*' {
				return
			}
			n, cerr := strconv.Atoi(strings.TrimSpace(hdr[1:]))
			if cerr != nil {
				return
			}
			for i := 0; i < n*2; i++ {
				if _, rerr = r.ReadString('\n'); rerr != nil {
					return
				}
			}
			if _, werr := c.Write([]byte(reply)); werr != nil {
				return
			}
		}
	}()
}

func respBulkStr(s string) string { return "$" + strconv.Itoa(len(s)) + "\r\n" + s + "\r\n" }

func respArrayStr(items ...string) string {
	var b strings.Builder
	b.WriteString("*" + strconv.Itoa(len(items)) + "\r\n")
	for _, s := range items {
		b.WriteString(respBulkStr(s))
	}
	return b.String()
}

func TestDEMRunIntakeRefusesAForgedRunAndGradesTheSignedOne(t *testing.T) {
	const tenant = "t_dem_sig"
	now := time.Now().UTC()
	run := func(id, vantage string) dem.WireRun {
		return dem.WireRun{ID: id, Tenant: tenant, TargetID: "dem-1", Kind: dem.KindHTTP, Vantage: vantage,
			StartedAt: now.Add(-time.Second), EndedAt: now, Outcome: dem.RunFailure, FailReason: "timeout"}
	}
	forged, err := json.Marshal([]dem.WireRun{run("forged", "van-a")})
	if err != nil {
		t.Fatal(err)
	}
	good, err := json.Marshal([]dem.WireRun{run("signed", "claimed-elsewhere")})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := collectors.NewDEMRunSealer(proberTestRing())("van-b", good)
	if err != nil {
		t.Fatal(err)
	}
	scriptedRedis(t,
		respArrayStr("van-a", "van-b"), // SMEMBERS
		respBulkStr(string(forged)),    // GET van-a: forged, unsigned
		respBulkStr(sealed),            // GET van-b: the prober's signed batch
	)

	v := probercontrol.NewResultVerifier(proberTestRing(), probercontrol.KindDEMRuns, collectors.DEMRunsMaxAge,
		time.Now, func() bool { return false }, nil)
	store := dem.NewRunStore()
	intake, err := dem.NewRunIntake(demRunFetcher{op: v}, store, dem.DefaultRunIntakeInterval, nil,
		func(string, map[string]any) {})
	if err != nil {
		t.Fatal(err)
	}
	if err := intake.RunOnce(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}
	graded, err := demRunSource{store: store}.Runs(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, list := range graded {
		for _, r := range list {
			ids = append(ids, r.ID)
			if r.VantageID != "van-b" {
				t.Errorf("run %s is attributed to %q, want the signing vantage van-b", r.ID, r.VantageID)
			}
		}
	}
	if len(ids) != 1 || ids[0] != "signed" {
		t.Fatalf("the tenant's grade reads runs %v, want only the signed one", ids)
	}
	if v.Count(probercontrol.ReasonUnsigned) != 1 {
		t.Fatal("the forged batch was not counted as unsigned")
	}
}

// No verifier wired reads no run at all.
func TestDEMRunFetcherWithoutAVerifierBelievesNothing(t *testing.T) {
	runs, err := demRunFetcher{}.FetchRuns(context.Background())
	if err == nil || len(runs) != 0 {
		t.Fatalf("a fetcher with no verifier read %v (err %v)", runs, err)
	}
}

// The switch is console-only: an environment variable never turns it on, and
// it is not the path-set switch either.
func TestAcceptUnsignedDEMRunsIsConsoleOnlyAndSeparate(t *testing.T) {
	// The api holds its key (the switch accepts the unsigned form, never a
	// record it cannot check at all).
	keyFile := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(keyFile, []byte(proberTestKey), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(probercontrol.EnvKeyFile, keyFile)
	t.Setenv(probercontrol.EnvAcceptUnsignedDEMRuns, "true")
	if _, why, ok := newDEMRunVerifier(nil).Open("prober", `[{"id":"r1"}]`); ok {
		t.Fatalf("an environment variable turned on unsigned acceptance: %s", why)
	}
	reg := featureflags.New(featureflags.PlatformSpecs(),
		&memEnv{m: map[string]string{probercontrol.EnvAcceptUnsignedDEMRuns: "true"}}, &memStore{})
	if _, why, ok := newDEMRunVerifier(reg).Open("prober", `[{"id":"r1"}]`); ok {
		t.Fatalf("an install-file value turned on a console-only switch: %s", why)
	}
	if _, _, err := reg.Set(probercontrol.EnvAcceptUnsignedPaths, true, probercontrol.EnvAcceptUnsignedPaths, "admin", time.Now()); err != nil {
		t.Fatalf("set the path switch: %v", err)
	}
	if _, why, ok := newDEMRunVerifier(reg).Open("prober", `[{"id":"r1"}]`); ok {
		t.Fatalf("the PATH switch accepted an unsigned RUN batch: %s", why)
	}
	if _, _, err := reg.Set(probercontrol.EnvAcceptUnsignedDEMRuns, true, probercontrol.EnvAcceptUnsignedDEMRuns, "admin", time.Now()); err != nil {
		t.Fatalf("set the DEM switch: %v", err)
	}
	if _, why, ok := newDEMRunVerifier(reg).Open("prober", `[{"id":"r1"}]`); !ok || why != probercontrol.ReasonUnsignedAccepted {
		t.Fatalf("the saved console switch did not accept the unsigned form: %s %v", why, ok)
	}
}
