package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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

// snmpGenVendors are the vendors with a first-class device template. Anything
// else falls back to the generic guidance (still generates the credential).
var snmpGenVendors = map[string]bool{
	"cisco": true, "juniper": true, "arista": true, "fortinet": true,
	"paloalto": true, "f5": true, "checkpoint": true, "mikrotik": true,
	"huawei": true, "extreme": true, "ubiquiti": true,
}

// genSecret returns a URL/CLI-safe random secret of ~n characters (base32, no
// padding, lowercased) — safe to paste into any vendor CLI (no quotes/specials).
func genSecret(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	s := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(raw), "="))
	if len(s) > n {
		s = s[:n]
	}
	return s, nil
}

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

// titleVendor uppercases the first letter of an ASCII vendor slug ("cisco" →
// "Cisco") — replaces the deprecated strings.Title for this single use.
func titleVendor(v string) string {
	if v == "" {
		return v
	}
	return strings.ToUpper(v[:1]) + v[1:]
}

// buildSNMPCredential builds the credential profile that matches a generated
// config (pure; the caller persists it). v3 uses SHA + AES128 (the widest
// interoperable pairing Correlix supports).
func buildSNMPCredential(vendor, version, community, secName, authKey, privKey string) SNMPCredential {
	c := SNMPCredential{
		ID:      fmt.Sprintf("%s-%s-gen", vendor, version),
		Name:    fmt.Sprintf("%s %s (generated)", titleVendor(vendor), version),
		Version: version,
		Port:    161,
	}
	if version == "v2c" {
		c.Community = community
	} else {
		c.SecurityName = secName
		c.SecurityLevel = "authPriv"
		c.AuthProtocol = "SHA"
		c.AuthKey = authKey
		c.PrivProtocol = "AES128"
		c.PrivKey = privKey
	}
	return c
}

// deviceSNMPConfig renders the vendor CLI block for the generated credential.
// Pure + unit-tested. mgmtSubnet/mask default to the whole space when empty.
func deviceSNMPConfig(vendor, version, community, secName, authKey, privKey, mgmtSubnet, mask string) string {
	v3 := version == "v3"
	switch vendor {
	case "cisco":
		if v3 {
			return "snmp-server group CORRELIX v3 priv\n" +
				fmt.Sprintf("snmp-server user %s CORRELIX v3 auth sha %s priv aes 128 %s", secName, authKey, privKey)
		}
		return fmt.Sprintf("snmp-server community %s RO", community)
	case "arista":
		if v3 {
			return "snmp-server group CORRELIX v3 priv\n" +
				fmt.Sprintf("snmp-server user %s CORRELIX v3 auth sha %s priv aes %s", secName, authKey, privKey)
		}
		return fmt.Sprintf("snmp-server community %s ro", community)
	case "juniper":
		if v3 {
			return fmt.Sprintf(`set snmp v3 usm local-engine user %s authentication-sha authentication-key "%s"
set snmp v3 usm local-engine user %s privacy-aes128 privacy-key "%s"
set snmp v3 vacm security-to-group security-model usm security-name %s group correlix-grp
set snmp v3 vacm access group correlix-grp default-context-prefix security-model usm security-level privacy read-view all
set snmp view all oid .1 include`, secName, authKey, secName, privKey, secName)
		}
		return fmt.Sprintf("set snmp community %s authorization read-only", community)
	case "fortinet":
		if v3 {
			return fmt.Sprintf(`config system snmp user
    edit "%s"
        set status enable
        set queries enable
        set query-port 161
        set security-level auth-priv
        set auth-proto sha
        set auth-pwd %s
        set priv-proto aes
        set priv-pwd %s
    next
end`, secName, authKey, privKey)
		}
		return fmt.Sprintf(`config system snmp sysinfo
    set status enable
end
config system snmp community
    edit 1
        set name "%s"
        set status enable
        set query-v2c-status enable
        config hosts
            edit 1
                set ip %s %s
            next
        end
    next
end`, community, orDefault(mgmtSubnet, "0.0.0.0"), orDefault(mask, "0.0.0.0"))
	case "paloalto":
		if v3 {
			return fmt.Sprintf("set deviceconfig system snmp-setting access-setting version v3 users %s "+
				"authpwd %s privpwd %s authprotocol sha privprotocol aes-128\ncommit", secName, authKey, privKey)
		}
		return fmt.Sprintf("set deviceconfig system snmp-setting access-setting version v2c snmp-community-string %s", community)
	case "f5":
		if v3 {
			return fmt.Sprintf("modify sys snmp users add { %s { username %s auth-protocol sha "+
				"auth-password %s privacy-protocol aes privacy-password %s security-level auth-privacy access ro } }\nsave sys config",
				secName, secName, authKey, privKey)
		}
		return fmt.Sprintf("modify sys snmp communities add { correlix-ro { community-name %s access ro } }\nsave sys config", community)
	case "checkpoint":
		if v3 {
			return fmt.Sprintf("set snmp agent-version v3-Only\nadd snmp usm user %s security-level authPriv "+
				"auth-pass-phrase %s privacy-pass-phrase %s authentication-protocol SHA1 privacy-protocol AES\nset snmp enable\nsave config",
				secName, authKey, privKey)
		}
		return fmt.Sprintf("set snmp community %s read-only\nset snmp agent-version v2\nset snmp enable\nsave config", community)
	case "mikrotik":
		if v3 {
			return fmt.Sprintf("/snmp community add name=%s authentication-protocol=SHA1 authentication-password=%s "+
				"encryption-protocol=AES encryption-password=%s security=private read-access=yes\n/snmp set enabled=yes", secName, authKey, privKey)
		}
		return fmt.Sprintf("/snmp community add name=%s read-access=yes\n/snmp set enabled=yes", community)
	case "huawei":
		if v3 {
			return fmt.Sprintf(`snmp-agent sys-info version v3
snmp-agent group v3 correlix-grp privacy read-view iso-view
snmp-agent mib-view included iso-view iso
snmp-agent usm-user v3 %s group correlix-grp
snmp-agent usm-user v3 %s authentication-mode sha2-256 cipher %s
snmp-agent usm-user v3 %s privacy-mode aes128 cipher %s`, secName, secName, authKey, secName, privKey)
		}
		return fmt.Sprintf("snmp-agent\nsnmp-agent community read cipher %s\nsnmp-agent sys-info version v2c", community)
	case "extreme":
		if v3 {
			return fmt.Sprintf(`configure snmpv3 add user %s authentication sha auth-password %s privacy aes priv-password %s
configure snmpv3 add group correlix-grp user %s sec-model usm
configure snmpv3 add access correlix-grp sec-model usm sec-level priv read-view defaultAdminView
enable snmp access snmp-v3`, secName, authKey, privKey, secName)
		}
		return fmt.Sprintf("configure snmp add community readonly %s\nenable snmp access", community)
	case "ubiquiti":
		if v3 {
			return fmt.Sprintf(`set service snmp v3 user %s auth type sha
set service snmp v3 user %s auth plaintext-key %s
set service snmp v3 user %s privacy type aes
set service snmp v3 user %s privacy plaintext-key %s
set service snmp v3 user %s mode ro
commit ; save`, secName, secName, authKey, secName, privKey, secName, secName)
		}
		return fmt.Sprintf("set service snmp community %s authorization ro\ncommit ; save", community)
	}
	// Generic fallback — the credential is real; the operator applies it with
	// their vendor's syntax (enable SNMP + a read-only credential).
	if v3 {
		return fmt.Sprintf("# Configure an SNMPv3 read-only user on this device:\n#   user=%s  auth=SHA key=%s  priv=AES-128 key=%s", secName, authKey, privKey)
	}
	return fmt.Sprintf("# Configure an SNMPv2c read-only community on this device:\n#   community=%s", community)
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
	var cred SNMPCredential
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
