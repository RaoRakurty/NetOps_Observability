package portintel

// reference.go — static reference the API serves to the UI: the normalized
// taxonomies (module family / media / PMD / connector) and a compact catalog of
// the physical-layer signatures. The signature MATCH wording (operator/manager
// phrase, evidence, confidence) rides the live RCA object from the correlation
// engine; this catalog is only the "what can match" list the playbook drawer +
// filter chips need Go-side, so the id↔name↔seam mapping lives here without
// duplicating the engine's full evidence contracts.

// TaxonomyReference returns the closed enums for the UI filters/legends so the
// frontend and backend never drift out of sync.
func TaxonomyReference() map[string]any {
	fams := make([]string, 0, len(knownFamilies))
	for f := range knownFamilies {
		fams = append(fams, string(f))
	}
	media := make([]string, 0, len(knownMedia))
	for m := range knownMedia {
		media = append(media, string(m))
	}
	return map[string]any{
		"module_families": fams,
		"media_types":     media,
		"supported_status": []string{
			string(SupSupported), string(SupThirdParty), string(SupUnsupported), string(SupUnknown),
		},
		"detection_methods": []string{"form_factor_field", "pmd_app_code", "part_number", "heuristic", "unknown"},
	}
}

// SignatureRef is one physical-layer signature's listing entry.
type SignatureRef struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Seams string `json:"seams"`
}

// SignatureCatalog lists the sig.ent.spdc.* families the engine can attach to a
// physical-layer incident. Ordered, stable. (Mirrors the enabled SP/DC set in
// the correlation catalog; the live match carries the phrases.)
func SignatureCatalog() []SignatureRef {
	return []SignatureRef{
		{"sig.ent.spdc.mpo-polarity-mismatch", "MPO polarity (Type A/B/C) mismatch", "DC_FABRIC,CARRIER_INTERCONNECT"},
		{"sig.ent.spdc.mpo-pinout-gender-mismatch", "MPO pinout / connector gender mismatch", "DC_FABRIC"},
		{"sig.ent.spdc.mpo-row-flip", "MPO row flip (2-row MPO16/32 mis-seat)", "DC_FABRIC"},
		{"sig.ent.spdc.mpo-missing-fibers", "MPO missing / unpopulated fibers", "DC_FABRIC,CARRIER_INTERCONNECT"},
		{"sig.ent.spdc.mpo-dirty-multifiber", "Dirty multifiber endface", "DC_FABRIC,CARRIER_INTERCONNECT"},
		{"sig.ent.spdc.mpo-broken-strand", "Broken / high-loss individual strand", "DC_FABRIC,CARRIER_INTERCONNECT"},
		{"sig.ent.spdc.mpo-cassette-type-mismatch", "MPO cassette type mismatch", "DC_FABRIC"},
		{"sig.ent.spdc.patchpanel-crossconnect-error", "Patch-panel cross-connect error", "DC_FABRIC,CARRIER_INTERCONNECT"},
		{"sig.ent.spdc.patchpanel-label-drift", "Patch-panel label / documentation drift", "DC_FABRIC,CARRIER_INTERCONNECT"},
		{"sig.ent.spdc.parallel-optic-lane-swap", "Parallel-optic lane swap", "DC_FABRIC"},
		{"sig.ent.spdc.pam4-lane-skew-excessive", "PAM4 excessive lane skew", "DC_FABRIC,CARRIER_INTERCONNECT"},
		{"sig.ent.spdc.pam4-lane-ber-divergence", "PAM4 per-lane BER divergence", "DC_FABRIC,CARRIER_INTERCONNECT"},
		{"sig.ent.spdc.qsfpdd-single-lane-failure", "QSFP-DD single-lane failure", "DC_FABRIC"},
		{"sig.ent.spdc.osfp-incompatible-part", "OSFP incompatible / unsupported part", "DC_FABRIC"},
		{"sig.ent.spdc.high-power-module-thermal-throttle", "High-power module thermal throttle", "DC_FABRIC"},
		{"sig.ent.spdc.fec-masking-highspeed", "FEC masking a degrading high-speed link", "DC_FABRIC,CARRIER_INTERCONNECT"},
		{"sig.ent.spdc.pcs-lane-deskew-failure", "PCS lane deskew failure", "DC_FABRIC,CARRIER_INTERCONNECT"},
		{"sig.ent.spdc.dwdm-mux-demux-attenuation", "DWDM mux/demux attenuation", "CARRIER_INTERCONNECT"},
		{"sig.ent.spdc.channel-frequency-misalignment", "Channel frequency / grid misalignment", "CARRIER_INTERCONNECT"},
		{"sig.ent.spdc.roadm-filter-edge-impairment", "ROADM filter-edge impairment", "CARRIER_INTERCONNECT"},
		{"sig.ent.spdc.edfa-saturation-or-gain-tilt", "EDFA saturation or gain tilt", "CARRIER_INTERCONNECT"},
		{"sig.ent.spdc.coherent-osnr-degradation", "Coherent OSNR degradation", "CARRIER_INTERCONNECT"},
		{"sig.ent.spdc.cfp-osfp-vendor-interoperability-risk", "CFP/OSFP vendor interoperability risk", "DC_FABRIC,CARRIER_INTERCONNECT"},
	}
}
