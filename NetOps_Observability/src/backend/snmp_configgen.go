package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/snmpcred"
	"strings"
)

// snmp_configgen.go — the SNMP config generator (onboarding automation). Turns
// "read the docs, translate to your vendor, invent keys, configure BOTH sides"
// into one call: pick a vendor + version, and Correlix generates real
// credentials, provisions the matching credential profile server-side
// (secrets write-only, encrypted at rest), and returns the ready-to-paste
// device CLI block. Zero write-access to the device — the operator pastes one
// block, and the credential sentinel verifies it live within ~2 minutes.
//
// The device-config templates mirror docs/onboard-devices/vendor-snmp-configs;
// this file is the executable version of that page.

// The generator's pure core (vendor templates, credential minting) lives in
// internal/snmpcred/configgen.go (P2 RA.14); this file keeps the handler,
// profile persistence and the once-only secret return.

var snmpGenVendors = snmpcred.GenVendors

func genSecret(n int) (string, error) { return snmpcred.GenSecret(n) }

// snmpGenResult is what the generator returns: the device CLI block + the
// created profile id + the (once-shown) secrets so the operator can paste them.
type snmpGenResult struct {
	Vendor       string `json:"vendor"`
	Version      string `json:"version"`
	Templated    bool   `json:"templated"`
	ProfileID    string `json:"profile_id"`
	DeviceConfig string `json:"device_config"`
	// Secrets are returned ONCE for the operator to paste onto the device; they
	// are stored write-only in the profile and never returned again.
	Community    string `json:"community,omitempty"`
	SecurityName string `json:"security_name,omitempty"`
	AuthKey      string `json:"auth_key,omitempty"`
	PrivKey      string `json:"priv_key,omitempty"`
}

func buildSNMPCredential(vendor, version, community, secName, authKey, privKey string) snmpcred.Credential {
	return snmpcred.BuildGeneratedCredential(vendor, version, community, secName, authKey, privKey)
}

func deviceSNMPConfig(vendor, version, community, secName, authKey, privKey, mgmtSubnet, mask string) string {
	return snmpcred.DeviceConfig(vendor, version, community, secName, authKey, privKey, mgmtSubnet, mask)
}

// handleGenerateSNMPConfig: POST /api/onboard/snmp-config — the onboarding
// automation. Platform-admin gated (it creates a credential). Generates real
// credentials, provisions the matching profile (write-only), returns the
// device CLI block + the once-shown secrets.
func (s *server) handleGenerateSNMPConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<12)
	var req struct {
		Vendor      string `json:"vendor"`
		Version     string `json:"version"` // v2c | v3
		MgmtSubnet  string `json:"mgmt_subnet"`
		Mask        string `json:"mask"`
		SkipProfile bool   `json:"skip_profile"` // default false → provision the profile
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	vendor := strings.ToLower(strings.TrimSpace(req.Vendor))
	if vendor == "" {
		writeError(w, http.StatusBadRequest, errors.New("vendor required"))
		return
	}
	version := req.Version
	if version != "v2c" && version != "v3" {
		version = "v3" // default to the secure option
	}

	res := snmpGenResult{Vendor: vendor, Version: version, Templated: snmpGenVendors[vendor]}
	var cred snmpcred.Credential
	if version == "v2c" {
		comm, err := genSecret(20)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		res.Community = comm
		cred = buildSNMPCredential(vendor, version, comm, "", "", "")
	} else {
		authKey, e1 := genSecret(20)
		privKey, e2 := genSecret(20)
		if e1 != nil || e2 != nil {
			writeError(w, http.StatusInternalServerError, errors.New("key generation failed"))
			return
		}
		res.SecurityName, res.AuthKey, res.PrivKey = "correlix", authKey, privKey
		cred = buildSNMPCredential(vendor, version, "", "correlix", authKey, privKey)
	}
	res.DeviceConfig = deviceSNMPConfig(vendor, version, res.Community, res.SecurityName, res.AuthKey, res.PrivKey, req.MgmtSubnet, req.Mask)

	// Provision the matching profile by default — the whole point is to configure
	// the Correlix side automatically; skip_profile=true returns config only.
	if !req.SkipProfile && s.snmpCreds != nil {
		if _, err := s.snmpCreds.Upsert(cred); err != nil {
			writeError(w, http.StatusBadGateway, fmt.Errorf("profile provisioning failed: %w", err))
			return
		}
		res.ProfileID = cred.ID
	}
	// Audit WITHOUT the secrets (LLM06/secret discipline).
	logInfo("onboard", "snmp config generated", map[string]any{
		"vendor": vendor, "version": version, "profile_id": res.ProfileID})
	writeJSON(w, http.StatusOK, res)
}
