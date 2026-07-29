package main

// tacacs_env_test.go — env-constructor tests for the TACACS+ wiring that
// stays in main (Phase-2 W1.9); the protocol suite moved to internal/tacacs.

import (
	"testing"
)

func TestTACACSDisabledByDefault(t *testing.T) {
	for _, k := range []string{"TACACS_ENABLED", "TACACS_HOST", "TACACS_SECRET"} {
		t.Setenv(k, "")
	}
	if newTACACS().Enabled() {
		t.Error("TACACS+ must be disabled with no config")
	}
}

func TestTACACSConfigFromEnv(t *testing.T) {
	t.Setenv("TACACS_ENABLED", "true")
	t.Setenv("TACACS_HOST", "aaa.example.com")
	t.Setenv("TACACS_PORT", "49")
	t.Setenv("TACACS_SECRET", "s3cr3t")
	c := newTACACS()
	if !c.Enabled() {
		t.Fatal("should be enabled")
	}
	if c.Addr() != "aaa.example.com:49" {
		t.Errorf("addr = %q", c.Addr())
	}
	if c.DefaultRole() != RoleReadOnly {
		t.Errorf("default role should be read-only, got %q", c.DefaultRole())
	}
}

// Authenticate is a no-op (false,nil) when disabled — never blocks login.
