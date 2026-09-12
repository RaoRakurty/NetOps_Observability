// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package vendorprofile

// device_command_bytes_test.go — the BYTES half of the contract on every string
// this product sends to a device prompt (review 3.5-19).
//
// THE GAP. validateIdentityProbe's own doc says an identity command "carries no
// chaining metacharacter and no control character — the same list a
// config-capture command is held to". It applied the metacharacter list and
// nothing else: a profile could author a command with an embedded ESC or BEL.
// `capture.show_version_cmd` had no command validation AT ALL, though it is run
// verbatim at a live device by the OS-version rung and the inventory identity
// probe — it rested entirely on osprobe's runtime second gate.
//
// WHAT IS DELIBERATELY NOT ADDED HERE is the config-capture READ-ONLY VERB
// allowlist ({show, display, admin display, info}). Two commands already
// shipping would fail it — FortiOS `get system status` and RouterOS
// `/system resource print` — so it is a capture-command rule, not a
// device-command rule, and imposing it would either break real profiles or
// force a guess at four vendors' CLI grammars. The read-verb rule for identity
// commands is enforced on the DATA instead, by
// TestEveryIdentityCommandIsAReadOnlyShow, which knows the three verbs the
// shipped profiles actually use.

import (
	"strings"
	"testing"
	"testing/fstest"
)

func loadCaptureDoc(t *testing.T, showVersionCmd string) error {
	t.Helper()
	doc := strings.Replace(identityDoc(`{}`),
		`"capture": {"show_version_cmd": "show version"}`,
		`"capture": {"show_version_cmd": `+showVersionCmd+`}`, 1)
	files := fstest.MapFS{"profiles/acme.json": &fstest.MapFile{Data: []byte(doc)}}
	_, err := Load(files, "profiles")
	return err
}

func TestLoaderRefusesAnUnsafeShowVersionCommand(t *testing.T) {
	cases := map[string]struct{ cmd, wantIn string }{
		"a chained command":       {`"show version; reload"`, "contains"},
		"a redirection":           {`"show version > flash:x"`, "contains"},
		"a command substitution":  {"\"show version `id`\"", "contains"},
		"an embedded newline":     {`"show version\nreload"`, "contains"},
		"an escape sequence":      {`"show version\u001b[2J"`, "control character"},
		"a bell":                  {`"show version\u0007"`, "control character"},
		"a delete byte":           {`"show version\u007f"`, "control character"},
		"untrimmed leading space": {`" show version"`, "trimmed"},
	}
	for name, tc := range cases {
		err := loadCaptureDoc(t, tc.cmd)
		if err == nil {
			t.Errorf("%s: accepted %s — it is run verbatim at a live device", name, tc.cmd)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantIn) {
			t.Errorf("%s: error %q does not mention %q", name, err, tc.wantIn)
		}
	}
}

func TestLoaderAcceptsTheShowVersionCommandsThatShip(t *testing.T) {
	// Every distinct shipped value, including the two that are NOT show/display
	// verbs and are exactly why the capture verb allowlist is not applied here.
	for _, cmd := range []string{
		`"show version"`, `"display version"`, `"show system info"`,
		`"get system status"`, `"/system resource print"`,
	} {
		if err := loadCaptureDoc(t, cmd); err != nil {
			t.Errorf("a shipped show-version command was refused: %s -> %v", cmd, err)
		}
	}
}

func TestLoaderRefusesAControlCharacterInAnIdentityCommand(t *testing.T) {
	pat := `"serial_patterns": ["(?m)^SN:[ \\t]*(\\S+)[ \\t\\r]*$"]`
	for name, cmd := range map[string]string{
		"an escape sequence": `show version\u001b[2J`,
		"a bell":             `show version\u0007`,
		"a delete byte":      `show version\u007f`,
	} {
		err := loadIdentityDoc(t, `{"commands": [{"command": "`+cmd+`", `+pat+`}]}`)
		if err == nil {
			t.Errorf("%s: accepted — the doc on validateIdentityProbe promises it is refused", name)
			continue
		}
		if !strings.Contains(err.Error(), "control character") {
			t.Errorf("%s: error %q does not name the control character", name, err)
		}
	}
}
