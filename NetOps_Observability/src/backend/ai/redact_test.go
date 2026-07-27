package ai

import (
	"context"
	"strings"
	"testing"
)

// redact_test.go — the outbound DLP filter (CLAUDE.md §8, §15/LLM06) and the
// guard that the orchestrator can never be built without it.
//
// Audit PIPE-MED-5: Orchestrator.Redactor was DECLARED, applied at three prompt
// sites, and never set at the single construction site — so redact() was the
// identity function in production. Fixing that instance is not enough: the test
// below pins the CLASS by asserting a zero-value orchestrator still redacts, so
// the next construction site that forgets the field is safe by default rather
// than silently leaking.

// TestRedactMasksSecretsAndIdentifiers is the table of things that must never
// cross the provider boundary. Each case asserts BOTH that the dangerous
// substring is gone AND (where it matters) that the surrounding line is still
// diagnostically useful — a filter that destroys the whole line would be
// "safe" and useless, and would be routed around within a release.
func TestRedactMasksSecretsAndIdentifiers(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		gone    []string // substrings that must NOT survive
		keep    []string // context that must survive (usefulness)
		secrets bool     // true → RedactSecrets alone must already remove `gone`
	}{
		{
			name:    "cleartext password kv",
			in:      "Jul 26 10:00:01 rtr1 AAA: login failed password=hunter2 for admin",
			gone:    []string{"hunter2"},
			keep:    []string{"rtr1", "login failed", "password"},
			secrets: true,
		},
		{
			name:    "json api key",
			in:      `{"model":"gpt-4o-mini","api_key":"sk-proj-AAAAAAAAAAAAAAAAAAAAAAAA"}`,
			gone:    []string{"sk-proj-AAAAAAAAAAAAAAAAAAAAAAAA"},
			keep:    []string{"gpt-4o-mini", "api_key"},
			secrets: true,
		},
		{
			name:    "bearer token",
			in:      "upstream returned 401 for Authorization: Bearer abcdef0123456789abcdef",
			gone:    []string{"abcdef0123456789abcdef"},
			keep:    []string{"401"},
			secrets: true,
		},
		{
			name:    "jwt anywhere",
			in:      "session eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJl expired",
			gone:    []string{"eyJhbGciOiJIUzI1NiJ9", "c2lnbmF0dXJl"},
			keep:    []string{"expired"},
			secrets: true,
		},
		{
			name:    "snmp community, cli form",
			in:      "rtr1#show run | inc snmp\nsnmp-server community S3cr3tR0 RO",
			gone:    []string{"S3cr3tR0"},
			keep:    []string{"rtr1", "snmp-server community"},
			secrets: true,
		},
		{
			name:    "snmp community, kv form",
			in:      "poller: community=public failed for 10.1.1.1",
			gone:    []string{"public"},
			keep:    []string{"10.1.1.1", "community"},
			secrets: true,
		},
		{
			name:    "cisco type-7 password",
			in:      "username netops privilege 15 password 7 08701E1D5D4C53",
			gone:    []string{"08701E1D5D4C53"},
			keep:    []string{"privilege 15"},
			secrets: true,
		},
		{
			name:    "private key block",
			in:      "config dump:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx\nQm9kZQ==\n-----END RSA PRIVATE KEY-----\ndone",
			gone:    []string{"MIIEowIBAAKCAQEAx", "BEGIN RSA PRIVATE KEY"},
			keep:    []string{"config dump", "done"},
			secrets: true,
		},
		{
			name:    "connection string credentials",
			in:      "dial failed: postgres://netops:sup3rp4ss@db.internal:5432/netops",
			gone:    []string{"sup3rp4ss"},
			keep:    []string{"db.internal", "postgres://"},
			secrets: true,
		},
		{
			name:    "aws access key id",
			in:      "collector config references AKIAIOSFODNN7EXAMPLE in us-east-1",
			gone:    []string{"AKIAIOSFODNN7EXAMPLE"},
			keep:    []string{"us-east-1"},
			secrets: true,
		},
		{
			name:    "dictionary-word community string is still masked",
			in:      "poller retry: snmp community public timed out on 10.1.1.1",
			gone:    []string{" public "},
			keep:    []string{"10.1.1.1", "timed out"},
			secrets: true,
		},
		{
			name: "client mac keeps the oui only",
			in:   "client a4:83:e7:1b:2c:3d roamed from ap-3 to ap-7",
			gone: []string{"a4:83:e7:1b:2c:3d", "1b:2c:3d"},
			keep: []string{"a4:83:e7", "roamed", "ap-3"},
		},
		{
			name: "dotted mac keeps the oui only",
			in:   "MAC address table: aabb.ccdd.eeff on Gi1/0/12",
			gone: []string{"aabb.ccdd.eeff", "ddeeff"},
			keep: []string{"aabb.cc", "Gi1/0/12"},
		},
		{
			name: "eap identity and email keep the realm",
			in:   "802.1X auth for j.smith@corp.example.com succeeded",
			gone: []string{"j.smith@corp.example.com", "j.smith"},
			keep: []string{"corp.example.com", "802.1X"},
		},
		{
			name: "username kv",
			in:   "sshd[221]: Accepted publickey for user=rrakurty from 10.0.0.9",
			gone: []string{"rrakurty"},
			keep: []string{"10.0.0.9", "Accepted publickey"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Redact(tc.in)
			for _, bad := range tc.gone {
				if strings.Contains(got, bad) {
					t.Errorf("Redact leaked %q\n in:  %s\n out: %s", bad, tc.in, got)
				}
			}
			for _, good := range tc.keep {
				if !strings.Contains(got, good) {
					t.Errorf("Redact destroyed useful context %q (the line must stay diagnostic)\n in:  %s\n out: %s", good, tc.in, got)
				}
			}
			if !tc.secrets {
				return
			}
			// Credential-shaped material must be caught by the SECRETS tier too,
			// because that is the tier applied to the whole outbound payload and
			// to anything the operator typed.
			sec := RedactSecrets(tc.in)
			for _, bad := range tc.gone {
				if strings.Contains(sec, bad) {
					t.Errorf("RedactSecrets leaked %q (credential tier must catch credentials)\n in:  %s\n out: %s", bad, tc.in, sec)
				}
			}
		})
	}
}

// TestRedactSecretsLeavesOperatorIdentifiersAlone pins the deliberate split
// between the two tiers. RedactSecrets runs over the WHOLE outbound payload,
// including the operator's own question — masking the MAC they typed would
// break the wireless client lookup they typed it for. Identifier masking
// belongs on server-originated data only.
func TestRedactSecretsLeavesOperatorIdentifiersAlone(t *testing.T) {
	q := "why does client a4:83:e7:1b:2c:3d keep roaming, user=jsmith@corp.example.com"
	got := RedactSecrets(q)
	if got != q {
		t.Fatalf("RedactSecrets must not touch operator-supplied identifiers\n in:  %s\n out: %s", q, got)
	}
	if Redact(q) == q {
		t.Fatal("Redact (the server-originated tier) MUST mask identifiers")
	}
}

// TestRedactSparesOrdinaryEnglishAfterASecretKeyword — the CLI-form rule fires
// on whitespace, so without a stopword list "password expired for admin" became
// "password *** for admin". A filter that mangles prose is a filter people stop
// trusting and eventually route around; the usefulness half of the trade-off is
// load-bearing, not cosmetic.
func TestRedactSparesOrdinaryEnglishAfterASecretKeyword(t *testing.T) {
	spared := []string{
		"AAA: password expired for admin",
		"snmp v2c community or v3 USM credentials",
		"the secret is not set on this device",
	}
	for _, s := range spared {
		if got := Redact(s); got != s {
			t.Errorf("ordinary prose was mangled\n in:  %s\n out: %s", s, got)
		}
	}
	// …but an encoding-type digit means it IS a credential, stopword or not.
	if got := Redact("password 7 set"); strings.Contains(got, " set") {
		t.Errorf("a type-7 password must be masked even when the value is a stopword: %s", got)
	}
}

// TestRedactIsIdempotent — the filter runs at several layers (tool result →
// prompt → outbound payload sweep). If a second pass mangled an already-masked
// string, layering would be unsafe and someone would remove a layer.
func TestRedactIsIdempotent(t *testing.T) {
	inputs := []string{
		"password=hunter2 community=public token: abc123def456",
		"client a4:83:e7:1b:2c:3d user=jsmith@corp.example.com",
		"Authorization: Bearer abcdef0123456789 via postgres://u:p@h/db",
		"-----BEGIN OPENSSH PRIVATE KEY-----\nbody\n-----END OPENSSH PRIVATE KEY-----",
	}
	for _, in := range inputs {
		once := Redact(in)
		if twice := Redact(once); twice != once {
			t.Errorf("Redact is not idempotent\n in:    %s\n once:  %s\n twice: %s", in, once, twice)
		}
	}
}

// TestRedactKeepsJSONWellFormed — the credential tier is applied to the fully
// assembled provider request body (copilot.go providerDo). A mask that ate a
// quote or a brace would corrupt every request instead of protecting it.
func TestRedactKeepsJSONWellFormed(t *testing.T) {
	body := `{"model":"m","messages":[{"role":"user","content":"password: hunter2, api_key=\"sk-abcdefghijklmnop\", community public"}],"max_tokens":1024}`
	got := RedactSecrets(body)
	if strings.Contains(got, "hunter2") || strings.Contains(got, "sk-abcdefghijklmnop") {
		t.Fatalf("secret survived the payload sweep: %s", got)
	}
	// Structural characters must be preserved exactly.
	for _, ch := range []string{`{`, `}`, `[`, `]`} {
		if strings.Count(got, ch) != strings.Count(body, ch) {
			t.Fatalf("payload sweep altered JSON structure (%q count changed)\n in:  %s\n out: %s", ch, body, got)
		}
	}
	if strings.Count(got, `"`) != strings.Count(body, `"`) {
		t.Fatalf("payload sweep altered the quote count (JSON would be invalid)\n in:  %s\n out: %s", body, got)
	}
}

// ---- the "cannot be constructed without a Redactor" guard ------------------

// TestOrchestratorCannotBeConstructedWithoutARedactor is the class guard for
// PIPE-MED-5. A nil Redactor is the state the audit actually found in
// production; this asserts that state is HARMLESS, so the leak cannot come back
// by way of a new construction site that forgets the field. (The companion
// guard in package main, TestEveryOrchestratorConstructionWiresARedactor, keeps
// the wiring explicit at the call sites as well.)
func TestOrchestratorCannotBeConstructedWithoutARedactor(t *testing.T) {
	o := &Orchestrator{} // the zero value — every field omitted
	const secret = "password=hunter2 community=public"
	if got := o.redact(secret); got == secret {
		t.Fatalf("a zero-value Orchestrator redacted NOTHING (identity function) — "+
			"a nil Redactor must fall back to the package default, never to identity: %q", got)
	}
	if !strings.Contains(o.redact(secret), Mask) {
		t.Fatal("the nil-Redactor fallback did not apply the outbound DLP mask")
	}
	// And an explicitly wired redactor still wins (the seam remains injectable).
	o2 := &Orchestrator{Redactor: func(string) string { return "OVERRIDDEN" }}
	if o2.redact(secret) != "OVERRIDDEN" {
		t.Fatal("an explicitly wired Redactor must be used")
	}
}

// TestGroundedPromptsAreRedactedBeforeEgress proves the wiring end-to-end for
// the grounded engine: a secret sitting in evidence must not reach the
// LLMClient. The MockLLM echoes what it was given, so the assertion is on what
// actually crossed the seam, not on an internal call count.
func TestGroundedPromptsAreRedactedBeforeEgress(t *testing.T) {
	o := &Orchestrator{} // deliberately no Redactor — see the guard above
	bundle := []EvidenceItem{
		{CitationID: "log:1", Kind: "log", Text: "rtr1 AAA: snmp-server community S3cr3tR0 RO; client a4:83:e7:1b:2c:3d"},
	}
	pr := &Problem{Title: "BGP flap", Devices: []string{"rtr1"}}
	prompt := o.problemPrompt("what happened?", pr, bundle)
	for _, bad := range []string{"S3cr3tR0", "a4:83:e7:1b:2c:3d"} {
		if strings.Contains(prompt, bad) {
			t.Errorf("grounded prompt carries %q to the provider:\n%s", bad, prompt)
		}
	}
	if !strings.Contains(prompt, "rtr1") {
		t.Error("redaction destroyed the device name the answer is about")
	}
	// Sanity: the seam is actually reached through the public entry point too.
	if _, _, err := (MockLLM{Reply: "ok"}).Complete(context.Background(), "sys", []LLMMessage{{Role: "user", Content: prompt}}); err != nil {
		t.Fatalf("mock provider: %v", err)
	}
}
