// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/internal/workloadid"
)

// TestServiceKeyModeRefusesOtherBits: a mode with an "other" bit makes a private
// key readable by every local user. Refused unless the dev escape hatch is on.
func TestServiceKeyModeRefusesOtherBits(t *testing.T) {
	for _, tc := range []struct {
		value   string
		dev     string
		want    os.FileMode
		wantErr bool
	}{
		{value: "", want: 0o600},
		{value: "0600", want: 0o600},
		{value: "0640", want: 0o640},
		{value: "0o640", want: 0o640},
		{value: "0400", want: 0o400},
		{value: "0440", want: 0o440},
		{value: "0644", wantErr: true}, // what every TLS install carried before 2026-11-09
		{value: "0604", wantErr: true},
		{value: "0601", wantErr: true},
		{value: "0666", wantErr: true},
		{value: "0777", wantErr: true},
		{value: "0660", wantErr: true}, // group write
		{value: "0700", wantErr: true}, // owner execute
		{value: "0040", wantErr: true}, // owner cannot read
		{value: "04600", wantErr: true},
		{value: "rw-r-----", wantErr: true},
		{value: "0644", dev: "true", want: 0o644},
		{value: "0640", dev: "true", want: 0o640},
		{value: "04600", dev: "true", wantErr: true}, // the hatch covers permission bits only
		{value: "0040", dev: "true", wantErr: true},
		{value: "0644", dev: "false", wantErr: true},
	} {
		t.Run(tc.value+"/dev="+tc.dev, func(t *testing.T) {
			t.Setenv("TLS_SERVICE_KEY_MODE", tc.value)
			t.Setenv("ALLOW_DEV_SECRETS", tc.dev)
			got, err := serviceKeyMode()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("mode %q accepted as %04o", tc.value, got)
				}
				if !strings.Contains(err.Error(), "TLS_SERVICE_KEY_MODE") {
					t.Fatalf("error does not name the variable: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("mode %q refused: %v", tc.value, err)
			}
			if got != tc.want {
				t.Fatalf("mode %q = %04o, want %04o", tc.value, got, tc.want)
			}
		})
	}
}

// TestNginxKeyModeHasTheSameCeiling: nginx's key has its own variable. It must
// not be the way around the ceiling.
func TestNginxKeyModeHasTheSameCeiling(t *testing.T) {
	m := newTestCA(t)
	dir := filepath.Join(t.TempDir(), "nginx")
	t.Setenv("TLS_NGINX_CERT_DIR", dir)
	t.Setenv("TLS_NGINX_KEY_MODE", "0644")
	t.Setenv("ALLOW_DEV_SECRETS", "")
	err := m.provisionFromEnv()
	if err == nil || !strings.Contains(err.Error(), "TLS_NGINX_KEY_MODE") {
		t.Fatalf("0644 on the nginx key: err = %v, want a refusal naming the variable", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, "nginx.key")); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("a refused mode must mint nothing: stat = %v", serr)
	}
}

type readerTable struct {
	Dirs map[string]string `json:"dirs"`
	Keys []struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
		How  string `json:"how"`
	} `json:"keys"`
}

func loadReaderTable(t *testing.T) readerTable {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "deployment", "docker", "tls-key-readers.json"))
	if err != nil {
		t.Fatalf("read the reader table: %v", err)
	}
	var table readerTable
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatalf("parse the reader table: %v", err)
	}
	return table
}

// TestMintedTreeMatchesTheReaderTable mints with the settings a TLS install uses
// and compares every key and directory against the reader table the installer's
// --verify-custody and the compose shape test also read. A registry row and a
// table row cannot drift apart without one side failing here.
func TestMintedTreeMatchesTheReaderTable(t *testing.T) {
	table := loadReaderTable(t)
	m := newTestCA(t)
	root := filepath.Join(t.TempDir(), "tls")
	for _, sub := range []string{"", "services", "services/opensearch", "nginx", "victoria", "admin"} {
		// Created wide, the shape of a directory on an install before the fix.
		d := filepath.Join(root, sub)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o775); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("ALLOW_DEV_SECRETS", "")
	for k, v := range map[string]string{
		"TLS_MINT_ROOT":         root,
		"TLS_CLIENT_CA_FILE":    filepath.Join(root, "ca.pem"),
		"TLS_CERT_FILE":         filepath.Join(root, "api.crt"),
		"TLS_KEY_FILE":          filepath.Join(root, "api.key"),
		"TLS_NGINX_CERT_DIR":    filepath.Join(root, "nginx"),
		"TLS_NGINX_KEY_MODE":    "0640",
		"TLS_VICTORIA_CERT_DIR": filepath.Join(root, "victoria"),
		"TLS_SERVICE_CERT_ROOT": filepath.Join(root, "services"),
		"TLS_OS_ADMIN_CERT_DIR": filepath.Join(root, "admin"),
		"TLS_SERVICE_KEY_MODE":  "0640",
	} {
		t.Setenv(k, v)
	}
	if err := m.provisionFromEnv(); err != nil {
		t.Fatalf("provision: %v", err)
	}

	want := map[string]string{}
	for _, k := range table.Keys {
		want[k.Path] = k.Mode
	}
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		fi, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		mode := fi.Mode().Perm()
		if d.IsDir() {
			if mode&0o007 != 0 {
				t.Errorf("directory %s is %04o: other users have access", rel, mode)
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".key") {
			return nil
		}
		seen[rel] = true
		wantMode, ok := want[rel]
		if !ok {
			t.Errorf("minted key %s is not in the reader table", rel)
			return nil
		}
		if got := fmt.Sprintf("%04o", mode); got != wantMode {
			t.Errorf("%s is %s, the table says %s", rel, got, wantMode)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	for _, k := range table.Keys {
		if !seen[k.Path] {
			t.Errorf("the reader table lists %s but the mint did not write it", k.Path)
		}
	}
	for rel, wantMode := range table.Dirs {
		if got := fmt.Sprintf("%04o", fileMode(t, filepath.Join(root, rel))); got != wantMode {
			t.Errorf("directory %q is %s, the table says %s", rel, got, wantMode)
		}
	}
	// Every service directory follows its key: group-readable only for a group reader.
	for _, e := range workloadid.Registry {
		dirWant := os.FileMode(0o700)
		if e.KeyGroupRead {
			dirWant = 0o750
		}
		if got := fileMode(t, filepath.Join(root, "services", e.Service)); got != dirWant {
			t.Errorf("services/%s is %04o, want %04o", e.Service, got, dirWant)
		}
	}
}

// TestRegistryFlagAgreesWithTheReaderTable: KeyGroupRead is what the mint acts
// on; the table's "group" rows are what compose must then carry group_add for.
func TestRegistryFlagAgreesWithTheReaderTable(t *testing.T) {
	how := map[string]string{}
	for _, k := range loadReaderTable(t).Keys {
		how[k.Path] = k.How
	}
	for _, e := range workloadid.Registry {
		rel := "services/" + e.Service + "/" + e.Service + ".key"
		if (how[rel] == "group") != e.KeyGroupRead {
			t.Errorf("%s: registry KeyGroupRead=%v, reader table how=%q", e.Service, e.KeyGroupRead, how[rel])
		}
	}
}
