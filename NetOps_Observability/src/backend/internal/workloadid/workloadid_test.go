package workloadid

// SEC-003.3 guards. The registry is only trustworthy if it is COMPLETE (every
// compose service made an explicit identity decision), UNIQUE (no shared
// identities — the attribution requirement), and shaped (no wildcards,
// servers declare the names their clients dial).

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// composeServiceNames parses the services: block of docker-compose.yml.
// Line-oriented on purpose: no YAML dependency in Go, and the 2-space service
// indent is load-bearing compose syntax the file cannot drift from.
func composeServiceNames(t *testing.T) []string {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "..", "..", "deployment", "docker", "docker-compose.yml"))
	if err != nil {
		t.Fatalf("open compose: %v", err)
	}
	defer f.Close()
	var names []string
	inServices := false
	top := regexp.MustCompile(`^[a-zA-Z]`)
	svc := regexp.MustCompile(`^  ([a-z0-9-]+):\s*(#.*)?$`)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "services:" {
			inServices = true
			continue
		}
		if inServices && top.MatchString(line) {
			inServices = false
		}
		if inServices {
			if m := svc.FindStringSubmatch(line); m != nil {
				names = append(names, m[1])
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan compose: %v", err)
	}
	if len(names) < 20 {
		t.Fatalf("parsed only %d compose services — parser drift?", len(names))
	}
	return names
}

// TestEveryComposeServiceHasAnIdentityDecision is the ratchet: a new compose
// service fails CI until it is added to Registry OR Exempt (with a reason). A
// service in BOTH is equally a bug.
func TestEveryComposeServiceHasAnIdentityDecision(t *testing.T) {
	inRegistry := map[string]bool{}
	for _, e := range Registry {
		inRegistry[e.Service] = true
	}
	compose := map[string]bool{}
	for _, name := range composeServiceNames(t) {
		compose[name] = true
		_, exempt := Exempt[name]
		switch {
		case inRegistry[name] && exempt:
			t.Errorf("service %q is BOTH registered and exempt — pick one", name)
		case !inRegistry[name] && !exempt:
			t.Errorf("service %q has NO identity decision — add it to workloadid.Registry or workloadid.Exempt (with the reason)", name)
		}
	}
	// Reverse direction: a row for a service that no longer exists is a ghost
	// that hides renames.
	for _, e := range Registry {
		if !compose[e.Service] {
			t.Errorf("registry row %q names a non-existent compose service", e.Service)
		}
	}
	for name := range Exempt {
		if !compose[name] {
			t.Errorf("exemption %q names a non-existent compose service", name)
		}
	}
}

func TestRegistryIdentitiesAreUniqueAndWildcardFree(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range Registry {
		if seen[e.Service] {
			t.Errorf("service %q appears twice — no shared identities", e.Service)
		}
		seen[e.Service] = true
		if !e.Client && !e.Server {
			t.Errorf("service %q has neither Client nor Server role — dead row", e.Service)
		}
		for _, d := range e.DNS {
			if strings.Contains(d, "*") {
				t.Errorf("service %q declares wildcard DNS %q — forbidden (SEC-003.3)", e.Service, d)
			}
		}
		if e.Server && len(e.DNS) == 0 {
			t.Errorf("server %q declares no DNS names — clients could never verify it", e.Service)
		}
		if len(e.DNS) > 0 && !e.Server {
			t.Errorf("client-only %q declares DNS names %v — either it serves (set Server) or the names are dead weight", e.Service, e.DNS)
		}
	}
}

// TestKafkaIdentityKeepsClientEKU pins the 2026-08-06 decision: the broker's
// SVID is also the Kafka ADMIN-PLANE client credential (its DN is the
// KAFKA_SUPER_USERS principal; rotate-tls keystore re-sets, consumer-group
// diagnostics and kafka-init all authenticate with it on MTLS:9094). Dropping
// Client here would strand every admin operation after the SEC-007.2
// default-deny flip — the broker refuses a serverAuth-only client cert.
func TestKafkaIdentityKeepsClientEKU(t *testing.T) {
	for _, e := range Registry {
		if e.Service == "kafka" {
			if !e.Client || !e.Server {
				t.Fatalf("kafka identity must carry BOTH EKUs (got client=%v server=%v) — see comment for why", e.Client, e.Server)
			}
			return
		}
	}
	t.Fatal("kafka missing from the registry")
}
