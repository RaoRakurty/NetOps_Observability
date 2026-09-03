package snmpcred

// configgen_parity_test.go — the PARITY GOLDEN for the move of the SNMP
// onboarding CLI blocks into the Vendor Profile registry (tracker 221).
//
// Until this change internal/snmpcred SHIPPED the eleven vendors' blocks as a
// switch of positional fmt.Sprintf templates. They now live in
// internal/vendorprofile's profile documents (snmp_configgen.v2c_template /
// v3_template) and DeviceConfig renders them. A move like that is only safe if
// it is a move: the exact bytes an operator used to paste into a production
// device must still be the bytes they paste.
//
// So the deleted hand-written table is preserved HERE, verbatim, as the golden.
// TestDeviceConfigIsByteIdenticalToTheHandWrittenTable renders both over the
// same vendor × version × value matrix and compares byte for byte. If a profile
// edit ever changes what an operator is told to configure, this test says so in
// terms of the CLI block, not in terms of JSON.
//
// It is a golden, not a second implementation: nothing in the package builds on
// it, and when a profile deliberately changes a block the golden is updated in
// the same commit as the profile — deliberately, and visibly in the diff.
//
// KNOWN, PRESERVED DEFECT (ubiquiti v3). The fourth line of the hand-written
// Ubiquiti block renders the PRIVACY KEY where the user name belongs and the
// user name where the privacy key belongs — a positional-argument slip in the
// Sprintf table (…, secName, privKey, secName, secName), not a Ubiquiti syntax
// quirk. The move reproduces it BYTE FOR BYTE on purpose: this change is a
// vocabulary move, and silently correcting a device-facing block inside it would
// make the parity assertion meaningless and hide the fix from review. The named
// placeholders now make the defect legible in ubiquiti.json (which records it in
// its notes) instead of invisible in an argument list; correcting it is a
// one-line profile edit and belongs on its own row, with its own golden update.

import (
	"fmt"
	"strings"
	"testing"
)

func handWrittenDeviceConfig(vendor, version, community, secName, authKey, privKey, mgmtSubnet, mask string) string {
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
end`, community, orDefaultGen(mgmtSubnet, "0.0.0.0"), orDefaultGen(mask, "0.0.0.0"))
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

// parityValues is the value matrix. It includes the empty management subnet and
// mask (the defaulting path) and a set of markers no template could produce by
// accident, so a placeholder rendered into the WRONG hole is visible as a marker
// in the wrong place rather than as two identical-looking secrets.
func parityValues() []struct {
	community, secName, authKey, privKey, mgmtSubnet, mask string
} {
	return []struct {
		community, secName, authKey, privKey, mgmtSubnet, mask string
	}{
		{"COMMUNITY", "SECNAME", "AUTHKEY", "PRIVKEY", "SUBNET", "MASK"},
		{"c0mmun1ty", "correlix", "a5b6c7d8", "e9f0a1b2", "", ""},
		{"", "", "", "", "10.0.0.0", "255.0.0.0"},
		{"q<<mask>>q", "s<<auth_key>>s", "k1", "k2", "<<priv_key>>", "<<community>>"},
	}
}

// TestDeviceConfigIsByteIdenticalToTheHandWrittenTable is the whole
// justification for moving the blocks into the registry: the operator pastes
// exactly what they pasted before.
func TestDeviceConfigIsByteIdenticalToTheHandWrittenTable(t *testing.T) {
	vendors := []string{
		"cisco", "juniper", "arista", "fortinet", "paloalto", "f5",
		"checkpoint", "mikrotik", "huawei", "extreme", "ubiquiti",
		// not templated: the generic-guidance path must match too
		"acme", "nokia", "",
	}
	rendered := 0
	for _, vendor := range vendors {
		for _, version := range []string{"v2c", "v3", "v1"} {
			for _, v := range parityValues() {
				got := DeviceConfig(vendor, version, v.community, v.secName, v.authKey, v.privKey, v.mgmtSubnet, v.mask)
				want := handWrittenDeviceConfig(vendor, version, v.community, v.secName, v.authKey, v.privKey, v.mgmtSubnet, v.mask)
				if got != want {
					t.Fatalf("BLOCK DRIFT for %s %s:\n registry:\n%s\n golden:\n%s", vendor, version, got, want)
				}
				rendered++
			}
		}
	}
	if rendered == 0 {
		t.Fatal("no case rendered — the parity assertion is vacuous")
	}
	t.Logf("compared %d rendered onboarding blocks", rendered)
}

// TestVendorLookupIsCaseAndSpaceInsensitive names the ONE deliberate difference
// between the hand-written table and the registry: the old switch matched the
// vendor string EXACTLY, so "CISCO" fell through to the generic guidance, while
// every registry accessor (VerifyCommand, ConfigCaptureCommand, …) resolves a
// vendor token lower-cased and trimmed, so "CISCO" now renders the Cisco block.
//
// It is unreachable from the API: handleGenerateSNMPConfig lower-cases and trims
// the requested vendor before it reaches here, and GenVendors — what the
// response reports as `templated` — is keyed by the same canonical ids. The
// difference is therefore strictly a robustness gain for a direct caller, and it
// is asserted rather than left as an accident.
func TestVendorLookupIsCaseAndSpaceInsensitive(t *testing.T) {
	canonical := DeviceConfig("cisco", "v3", "", "correlix", "A", "B", "", "")
	for _, spelling := range []string{"CISCO", " cisco", "Cisco "} {
		if got := DeviceConfig(spelling, "v3", "", "correlix", "A", "B", "", ""); got != canonical {
			t.Errorf("DeviceConfig(%q) = %q, want the canonical Cisco block", spelling, got)
		}
	}
}

// TestGenVendorsMatchesTheProfilesThatDeclareATemplate — GenVendors is what the
// API reports as `templated`. It must be exactly the set of vendors whose
// profile declares a block, or the API claims a first-class template for a
// vendor that gets generic guidance (or hides one that exists).
func TestGenVendorsMatchesTheProfilesThatDeclareATemplate(t *testing.T) {
	want := []string{"arista", "checkpoint", "cisco", "extreme", "f5", "fortinet",
		"huawei", "juniper", "mikrotik", "paloalto", "ubiquiti"}
	if len(GenVendors) != len(want) {
		t.Fatalf("GenVendors = %v, want exactly %v", GenVendors, want)
	}
	for _, v := range want {
		if !GenVendors[v] {
			t.Errorf("GenVendors is missing %q", v)
		}
		if DeviceConfig(v, "v3", "", "correlix", "A", "B", "", "") == "" {
			t.Errorf("%s renders an empty v3 block", v)
		}
		if strings.HasPrefix(DeviceConfig(v, "v3", "", "correlix", "A", "B", "", ""), "# Configure") {
			t.Errorf("%s claims a first-class template but renders the generic fallback", v)
		}
	}
}

// TestRenderedBlockNeverLeaksAKeyThroughAnOperatorSuppliedValue is the
// single-pass rendering contract. The management subnet is OPERATOR INPUT; with
// a sequential ReplaceAll renderer, submitting the literal text "<<priv_key>>"
// as a subnet would have the next pass substitute the MINTED PRIVACY KEY into
// it. A single left-to-right pass never re-examines what it already emitted.
func TestRenderedBlockNeverLeaksAKeyThroughAnOperatorSuppliedValue(t *testing.T) {
	const privCanary = "PRIVKEYCANARY"
	for _, vendor := range []string{"fortinet", "cisco", "juniper", "f5"} {
		for _, version := range []string{"v2c", "v3"} {
			block := DeviceConfig(vendor, version, "<<priv_key>>", "<<priv_key>>", "<<priv_key>>", privCanary, "<<priv_key>>", "<<priv_key>>")
			if version == "v2c" && strings.Contains(block, privCanary) {
				t.Errorf("SECRET LEAK: the v3 privacy key reached the %s v2c block through an operator-supplied value:\n%s", vendor, block)
			}
		}
	}
}
