package compliance

import (
	"strings"
	"testing"

	"netops/backend/internal/vuln"
	"netops/backend/models"
)

// findingsByCheck buckets findings for assertion convenience.
func findingsByCheck(fs []Finding) map[string][]Finding {
	out := map[string][]Finding{}
	for _, f := range fs {
		out[f.Check] = append(out[f.Check], f)
	}
	return out
}

func nbDev(id, name, ip, serial, platform, vendor string) models.Device {
	d := models.Device{ID: id, Name: name, Address: ip, Vendor: vendor, OS: platform, Source: "netbox", Labels: map[string]string{}}
	if serial != "" {
		d.Labels["serial"] = serial
	}
	return d
}

func obsDev(id, name, ip, serial, sysDescr, vendor string) models.Device {
	d := models.Device{ID: id, Name: name, Address: ip, Vendor: vendor, OS: sysDescr, Source: "static", Labels: map[string]string{}}
	if serial != "" {
		d.Labels["serial"] = serial
	}
	return d
}

func TestEvalDriftUnregistered(t *testing.T) {
	sot := []models.Device{nbDev("netbox-1", "core-1", "10.0.0.1", "SN1", "", "")}
	obs := []models.Device{
		obsDev("static-core-1", "core-1", "10.0.0.1", "", "", ""), // matched by IP
		obsDev("static-rogue", "rogue-sw", "10.0.0.99", "", "", ""),
	}
	got := findingsByCheck(evalDrift(sot, obs))
	if n := len(got[ckSotRegistered]); n != 1 {
		t.Fatalf("unregistered findings = %d, want 1", n)
	}
	if got[ckSotRegistered][0].DeviceName != "rogue-sw" {
		t.Fatalf("unregistered device = %q, want rogue-sw", got[ckSotRegistered][0].DeviceName)
	}
}

func TestEvalDriftMatchPrecedenceAndFieldGating(t *testing.T) {
	// Pair matches on serial → IP and name diffs are reportable, serial is not.
	sot := []models.Device{nbDev("netbox-1", "edge-1", "10.0.0.1", "SN42", "", "")}
	obs := []models.Device{obsDev("static-1", "edge-1-old", "10.0.0.2", "SN42", "", "")}
	got := findingsByCheck(evalDrift(sot, obs))
	if len(got[ckSotMgmtIP]) != 1 {
		t.Fatalf("mgmt-ip drift findings = %d, want 1", len(got[ckSotMgmtIP]))
	}
	f := got[ckSotMgmtIP][0]
	if f.Observed != "10.0.0.2" || f.Intended != "10.0.0.1" {
		t.Fatalf("mgmt-ip observed/intended = %q/%q", f.Observed, f.Intended)
	}
	if len(got[ckSotName]) != 1 {
		t.Fatalf("name drift findings = %d, want 1", len(got[ckSotName]))
	}
	if len(got[ckSotSerial]) != 0 {
		t.Fatalf("serial drift on a serial-matched pair must not fire")
	}
}

func TestEvalDriftSerialMismatchOnIPMatch(t *testing.T) {
	sot := []models.Device{nbDev("netbox-1", "core-1", "10.0.0.1", "SN-OLD", "", "")}
	obs := []models.Device{obsDev("static-1", "core-1", "10.0.0.1", "SN-NEW", "", "")}
	got := findingsByCheck(evalDrift(sot, obs))
	if len(got[ckSotSerial]) != 1 {
		t.Fatalf("serial drift findings = %d, want 1", len(got[ckSotSerial]))
	}
	if got[ckSotSerial][0].Severity != "high" {
		t.Fatalf("serial drift severity = %q, want high", got[ckSotSerial][0].Severity)
	}
}

func TestPlatformDrift(t *testing.T) {
	iosxe := "Cisco IOS XE Software, Version 17.09.04a"
	cases := []struct {
		platform string
		sysDescr string
		vendor   string
		drift    bool
	}{
		{"Cisco IOS-XE", iosxe, "cisco", false}, // punctuation variant — same platform
		{"IOS XE 17", iosxe, "cisco", false},    // version digits in platform name
		{"Cisco IOS", iosxe, "cisco", true},     // IOS vs IOS-XE is real drift
		{"Juniper Junos", iosxe, "cisco", true}, // wrong family entirely
		{"Arista EOS", "Arista Networks EOS version 4.33.1F", "arista", false},
		{"", iosxe, "cisco", false}, // no declared platform → nothing to diff
	}
	for _, c := range cases {
		nb := nbDev("netbox-1", "d", "10.0.0.1", "", c.platform, c.vendor)
		o := obsDev("static-1", "d", "10.0.0.1", "", c.sysDescr, c.vendor)
		_, drifted := platformDrift(o, nb)
		if drifted != c.drift {
			t.Errorf("platformDrift(platform=%q, descr=%q) = %v, want %v", c.platform, c.sysDescr, drifted, c.drift)
		}
	}
}

func TestEvalSNMPPolicy(t *testing.T) {
	d := models.Device{ID: "x", Name: "sw1", Address: "10.0.0.1", CredentialRef: "lab"}

	if fs := evalSNMPPolicy(d, SNMPProfile{Name: "lab", Version: "v2c"}); len(fs) != 1 || fs[0].Check != ckSnmpVersion {
		t.Fatalf("v2c: findings = %+v, want one %s", fs, ckSnmpVersion)
	}
	weak := SNMPProfile{Name: "lab", Version: "v3", SecurityLevel: "authNoPriv", AuthProtocol: "MD5", PrivProtocol: "DES"}
	fs := evalSNMPPolicy(d, weak)
	if len(fs) != 1 || fs[0].Check != ckSnmpV3Weak {
		t.Fatalf("weak v3: findings = %+v, want one %s", fs, ckSnmpV3Weak)
	}
	for _, want := range []string{"authNoPriv", "MD5", "DES"} {
		if !strings.Contains(fs[0].Observed, want) {
			t.Errorf("weak v3 observed %q missing %q", fs[0].Observed, want)
		}
	}
	strong := SNMPProfile{Name: "lab", Version: "v3", SecurityLevel: "authPriv", AuthProtocol: "SHA256", PrivProtocol: "AES256"}
	if fs := evalSNMPPolicy(d, strong); len(fs) != 0 {
		t.Fatalf("strong v3 must produce no findings, got %+v", fs)
	}
}

func TestEvalConsensus(t *testing.T) {
	mk := func(id, ver string) osVersionSeen {
		return osVersionSeen{dev: models.Device{ID: id, Name: id, Vendor: "arista"}, version: ver}
	}
	// Majority 2/3 on 4.33.1F → the 4.30.0F device is the outlier.
	out, ran := evalConsensus([]osVersionSeen{mk("a", "4.33.1F"), mk("b", "4.33.1F"), mk("c", "4.30.0F")})
	if !ran || len(out) != 1 || out[0].DeviceName != "c" || out[0].Intended != "4.33.1F" {
		t.Fatalf("consensus: ran=%v out=%+v", ran, out)
	}
	// Too small a group → no baseline.
	if _, ran := evalConsensus([]osVersionSeen{mk("a", "1"), mk("b", "2")}); ran {
		t.Fatal("group of 2 must not establish a baseline")
	}
	// No strict majority → no defensible baseline, no findings.
	out, ran = evalConsensus([]osVersionSeen{mk("a", "1.0"), mk("b", "2.0"), mk("c", "3.0"), mk("d", "3.0")})
	if !ran || len(out) != 0 {
		t.Fatalf("no-majority group: ran=%v out=%+v, want ran with no findings", ran, out)
	}
}

func TestEvaluateComplianceChecksAndGaps(t *testing.T) {
	merged := []models.Device{
		{ID: "d1", Name: "leaf1", Address: "10.0.0.1", Vendor: "arista", OS: "Arista Networks EOS version 4.33.1F", CredentialRef: "lab"},
		{ID: "d2", Name: "mystery", Address: "10.0.0.2"}, // no vendor, no creds → gaps only
	}
	resolve := func(ref string) (SNMPProfile, bool) {
		if ref == "lab" {
			return SNMPProfile{Name: "lab", Version: "v2c"}, true
		}
		return SNMPProfile{}, false
	}

	// No declared SoT records (sotSource "") + no vuln feed → drift and KEV
	// checks inactive, with reasons.
	res := Evaluate(merged, merged, "", resolve, nil)
	status := map[string]Check{}
	for _, c := range res.Checks {
		status[c.ID] = c
	}
	if status[ckSotRegistered].Active || status[ckSotRegistered].Reason == "" {
		t.Fatalf("SoT check must be inactive with a reason when no declared records exist: %+v", status[ckSotRegistered])
	}
	if status[ckKEV].Active {
		t.Fatalf("KEV check must be inactive without a feed")
	}
	if !status[ckSnmpVersion].Active || status[ckSnmpVersion].Findings != 1 {
		t.Fatalf("snmp-version check: %+v, want active with 1 finding", status[ckSnmpVersion])
	}
	if len(res.Gaps) != 1 || res.Gaps[0].DeviceName != "mystery" {
		t.Fatalf("gaps = %+v, want one row for mystery", res.Gaps)
	}

	// With a KEV-bearing feed match, the policy finding appears, severity high.
	match := func(vendor, product, version string) []vuln.Entry {
		if vendor == "arista" && product == "eos" {
			return []vuln.Entry{{CVE: "CVE-2024-0001", KEV: true, Severity: "critical"}, {CVE: "CVE-2024-0002"}}
		}
		return nil
	}
	res = Evaluate(merged, merged, "", resolve, match)
	got := findingsByCheck(res.Findings)
	if len(got[ckKEV]) != 1 || got[ckKEV][0].Severity != "high" {
		t.Fatalf("kev findings = %+v, want one high", got[ckKEV])
	}
	if !strings.Contains(got[ckKEV][0].Detail, "CVE-2024-0001") {
		t.Fatalf("kev detail %q missing the CVE id", got[ckKEV][0].Detail)
	}
}

func TestEvaluateCompliancePhysicalAggregation(t *testing.T) {
	// One physical device, two merged records (an IP-less NetBox record never
	// merges with its IP-bearing twin): the NetBox twin must not produce a
	// "no credential" gap when the static twin is monitored, and the device
	// counts once.
	merged := []models.Device{
		{ID: "leaf1", Name: "leaf1", Address: "10.0.0.1", Vendor: "arista", OS: "Arista Networks EOS version 4.33.1F", CredentialRef: "lab", Source: "static"},
		{ID: "netbox-9", Name: "leaf1", Vendor: "Arista", OS: "Arista EOS", Source: "netbox"},
	}
	resolve := func(ref string) (SNMPProfile, bool) {
		return SNMPProfile{Name: "lab", Version: "v3", SecurityLevel: "authPriv", AuthProtocol: "SHA256", PrivProtocol: "AES256"}, ref == "lab"
	}
	res := Evaluate(merged, merged, "", resolve, nil)
	if res.Physical != 1 {
		t.Fatalf("physical = %d, want 1", res.Physical)
	}
	if len(res.Gaps) != 0 {
		t.Fatalf("gaps = %+v, want none (twin records must aggregate)", res.Gaps)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("findings = %+v, want none", res.Findings)
	}
}

func TestEvaluateComplianceDriftEndToEnd(t *testing.T) {
	raw := []models.Device{
		nbDev("netbox-1", "core-1", "10.0.0.1", "SN1", "Cisco IOS", "Cisco"),
		obsDev("static-1", "core-1", "10.0.0.1", "SN1", "Cisco IOS XE Software, Version 17.09.04a", "cisco"),
		obsDev("manual-1", "rogue", "10.0.0.50", "", "", ""),
	}
	merged := []models.Device{ // what Devices() would fold raw into
		{ID: "netbox-1", Name: "core-1", Address: "10.0.0.1", Vendor: "cisco", OS: "Cisco IOS XE Software, Version 17.09.04a"},
		{ID: "manual-1", Name: "rogue", Address: "10.0.0.50"},
	}
	res := Evaluate(merged, raw, "netbox", nil, nil)
	got := findingsByCheck(res.Findings)
	if len(got[ckSotRegistered]) != 1 || got[ckSotRegistered][0].DeviceName != "rogue" {
		t.Fatalf("registered findings = %+v", got[ckSotRegistered])
	}
	if len(got[ckSotPlatform]) != 1 {
		t.Fatalf("platform drift findings = %+v, want 1 (declared IOS, running IOS-XE)", got[ckSotPlatform])
	}
	// Findings sort worst-first; both are medium drift, so the tie breaks on
	// check id: sot-platform sorts before sot-registered.
	if res.Findings[0].Check != ckSotPlatform {
		t.Fatalf("sort: first finding = %s", res.Findings[0].Check)
	}
}

// Drift is provider-agnostic: the declared records are whichever Device.Source
// the active provider reports, NOT a hardcoded "netbox". A future ServiceNow
// provider whose records carry Source "servicenow" must drift identically, and
// the same records become observed (not declared) when sotSource doesn't match.
func TestEvaluateComplianceProviderAgnostic(t *testing.T) {
	declared := models.Device{ID: "snow-1", Name: "core-1", Address: "10.0.0.1", Source: "servicenow", Labels: map[string]string{}}
	rogue := obsDev("static-1", "rogue", "10.0.0.50", "", "", "")
	raw := []models.Device{declared, rogue}
	merged := []models.Device{
		{ID: "snow-1", Name: "core-1", Address: "10.0.0.1"},
		{ID: "static-1", Name: "rogue", Address: "10.0.0.50"},
	}

	// sotSource = the provider's own label → declared/observed partition works.
	got := findingsByCheck(Evaluate(merged, raw, "servicenow", nil, nil).Findings)
	if len(got[ckSotRegistered]) != 1 || got[ckSotRegistered][0].DeviceName != "rogue" {
		t.Fatalf("servicenow-sourced SoT: registered findings = %+v, want one for rogue", got[ckSotRegistered])
	}

	// Empty sotSource (internal authority) → no record is "declared", so even the
	// servicenow-sourced record is treated as observed and NO drift fires.
	res := Evaluate(merged, raw, "", nil, nil)
	if n := len(findingsByCheck(res.Findings)[ckSotRegistered]); n != 0 {
		t.Fatalf("internal SoT: drift must be inactive, got %d registered findings", n)
	}
	for _, c := range res.Checks {
		if c.Class == "drift" && (c.Active || c.Reason == "") {
			t.Fatalf("internal SoT: drift check %s must be inactive with a reason: %+v", c.ID, c)
		}
	}
}
