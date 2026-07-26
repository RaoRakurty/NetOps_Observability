// Package wireless is Correlix's vendor-neutral wireless canonical model
// (tracker #128, design docs/Wireslessdesign.md §7, owner-approved 2026-07-26).
//
// It models multi-vendor wireless — controller-based (CAPWAP central/local/
// mixed forwarding), gateway-tunneled, cloud-managed, and controllerless — as
// entities the existing platform already understands: inventory rows in
// Postgres (migration 0030), per-client events in ClickHouse
// (wireless_schema.go), and correlation signals on the existing spine.
//
// Like nms (its sibling), the package core is vendor-neutral and stdlib-only.
// Vendor specifics live in per-vendor connector transformers; the canonical
// model here stays stable so adding a vendor never touches the core or the
// correlation engine.
//
// The three identities the model refuses to conflate (report §9):
//
//	SSID  — the broadcast NAME. Not unique, not owned, estate-wide.
//	WLAN  — the CONFIGURATION PROFILE on a controller (SSID + security +
//	        auth + VLAN + forwarding). Controller-scoped.
//	BSSID — the MAC one RADIO broadcasts for one WLAN. The only precise
//	        "where was this client".
//
// And the logical/physical split (report §11): a Controller is the LOGICAL
// control domain APs join; Members are the physical boxes. A member failover
// changes member state, never an AP's controller binding.
package wireless

import "time"

// ClusterRole classifies the logical control domain.
type ClusterRole string

const (
	ClusterStandalone     ClusterRole = "standalone"
	ClusterHAPair         ClusterRole = "ha_pair"
	ClusterNPlus1         ClusterRole = "n_plus_1"
	ClusterCloudManaged   ClusterRole = "cloud_managed"
	ClusterControllerless ClusterRole = "controllerless"
)

// ForwardingMode is where client DATA goes — a WLAN property first (mixed
// forwarding is a per-WLAN split on one controller), with a controller-level
// default. Central = tunneled to the controller; local = switched at the AP.
// The distinction is load-bearing: in local switching the AP_TUNNELS_TO_
// CONTROLLER edge does not exist and its absence is not missing evidence.
type ForwardingMode string

const (
	ForwardCentral ForwardingMode = "central"
	ForwardLocal   ForwardingMode = "local"
	ForwardMixed   ForwardingMode = "mixed"
	ForwardUnknown ForwardingMode = "unknown"
)

// Controller is the LOGICAL control domain (report §11) — what APs join and
// configuration binds to. For cloud-managed estates the members are the
// vendor's cloud (opaque; Visibility stays "partial" — full is earned, never
// assumed, mirroring the seam model). For controllerless estates there are
// zero members and APs bind directly.
type Controller struct {
	TenantID          string         `json:"-"`
	ControllerID      string         `json:"controller_id"`
	Name              string         `json:"name"`
	Vendor            string         `json:"vendor"`
	Model             string         `json:"model,omitempty"`
	OSVersion         string         `json:"os_version,omitempty"`
	Kind              string         `json:"kind,omitempty"` // controller | gateway
	ClusterRole       ClusterRole    `json:"cluster_role"`
	ManagementAddress string         `json:"management_address,omitempty"`
	ForwardingDefault ForwardingMode `json:"forwarding_default,omitempty"`
	Visibility        string         `json:"visibility,omitempty"` // full | partial | blind
	Members           []Member       `json:"members,omitempty"`
	FirstSeen         time.Time      `json:"first_seen,omitempty"`
	LastSeen          time.Time      `json:"last_seen,omitempty"`
	Stale             bool           `json:"stale,omitempty"`
	Attrs             map[string]any `json:"attrs,omitempty"` // lossless vendor record
}

// Member is one PHYSICAL box/VM/instance of a logical controller. Controller
// HEALTH signals attach to the member; controller CAPABILITY signals (AP
// capacity, licence limits) attach to the logical controller.
type Member struct {
	TenantID       string    `json:"-"`
	MemberID       string    `json:"member_id"`
	ControllerID   string    `json:"controller_id"`
	Name           string    `json:"name"`
	Serial         string    `json:"serial,omitempty"`
	MemberState    string    `json:"member_state"`    // active|standby|member|failed|maintenance
	RedundancyRole string    `json:"redundancy_role"` // primary|secondary|tertiary
	APCapacity     int       `json:"ap_capacity,omitempty"`
	FirstSeen      time.Time `json:"first_seen,omitempty"`
	LastSeen       time.Time `json:"last_seen,omitempty"`
	Stale          bool      `json:"stale,omitempty"`
}

// AccessPoint is a physical AP. Identity is APID() — serial-based, NEVER the
// name: APs are renamed routinely and a rename must not fork identity.
//
// The uplink fields are the rank-1 structural join to the LAN (report §6): the
// same switch:port names an ordinary interface entity, so wireless↔LAN edges
// ground on resource identity with no new engine code. Model the uplink even
// when the controller does not report it — it is also the second independent
// witness a confirmed wireless verdict needs (report B2).
type AccessPoint struct {
	TenantID        string         `json:"-"`
	APID            string         `json:"ap_id"`
	Name            string         `json:"name"`
	MACBase         string         `json:"mac_base,omitempty"`
	Serial          string         `json:"serial,omitempty"`
	Model           string         `json:"model,omitempty"`
	Vendor          string         `json:"vendor,omitempty"`
	ControllerRef   string         `json:"controller_ref,omitempty"` // LOGICAL controller, never a member
	SiteID          string         `json:"site_id,omitempty"`
	FloorRef        string         `json:"floor_ref,omitempty"`
	X               float64        `json:"x,omitempty"`
	Y               float64        `json:"y,omitempty"`
	UplinkSwitchRef string         `json:"uplink_switch_ref,omitempty"`
	UplinkPortRef   string         `json:"uplink_port_ref,omitempty"`
	PoEClass        string         `json:"poe_class,omitempty"`
	PoEDrawW        float64        `json:"poe_draw_w,omitempty"`
	MgmtAddress     string         `json:"mgmt_address,omitempty"`
	MgmtVLAN        int            `json:"mgmt_vlan,omitempty"`
	ForwardingMode  ForwardingMode `json:"forwarding_mode,omitempty"`
	Radios          []Radio        `json:"radios,omitempty"`
	FirstSeen       time.Time      `json:"first_seen,omitempty"`
	LastSeen        time.Time      `json:"last_seen,omitempty"`
	Stale           bool           `json:"stale,omitempty"`
	Attrs           map[string]any `json:"attrs,omitempty"`
}

// Radio is one AP radio. Identity is (AP, slot) — slot, not band: dual-5GHz
// and tri-band APs make band ambiguous as an identity axis.
type Radio struct {
	TenantID        string    `json:"-"`
	RadioID         string    `json:"radio_id"`
	APID            string    `json:"ap_id"`
	Slot            int       `json:"slot"`
	Band            string    `json:"band,omitempty"` // 2.4GHz|5GHz|6GHz — display/query, not identity
	Channel         int       `json:"channel,omitempty"`
	ChannelWidthMHz int       `json:"channel_width_mhz,omitempty"`
	TxPowerDBm      float64   `json:"tx_power_dbm,omitempty"`
	TxPowerMaxDBm   float64   `json:"tx_power_max_dbm,omitempty"`
	AdminState      string    `json:"admin_state,omitempty"` // enabled|disabled|unknown
	OperState       string    `json:"oper_state,omitempty"`  // up|down|unknown
	Generation      string    `json:"generation,omitempty"`  // wifi5|wifi6|wifi6e|wifi7
	MLOCapable      bool      `json:"mlo_capable,omitempty"`
	FirstSeen       time.Time `json:"first_seen,omitempty"`
	LastSeen        time.Time `json:"last_seen,omitempty"`
	Stale           bool      `json:"stale,omitempty"`
}

// WLAN is a controller-scoped configuration profile. Forwarding is a WLAN
// property (mixed = per-WLAN split); MobilityDomainRef is populated ONLY when
// the controller exposes one — never inferred from SSID equality (report
// §9.2): a nil mobility domain means roam analysis abstains, which is honest.
type WLAN struct {
	TenantID          string         `json:"-"`
	WLANID            string         `json:"wlan_id"`
	ProfileName       string         `json:"profile_name"`
	SSIDName          string         `json:"ssid_name"`
	SSIDRef           string         `json:"ssid_ref,omitempty"`
	ControllerRef     string         `json:"controller_ref,omitempty"`
	SecurityMode      string         `json:"security_mode,omitempty"` // wpa2_psk|wpa2_enterprise|wpa3_sae|owe|open|...
	AuthMethod        string         `json:"auth_method,omitempty"`   // dot1x|psk|sae|owe|open|mac_auth|portal
	AAARef            string         `json:"aaa_ref,omitempty"`
	VLANOrPool        string         `json:"vlan_or_pool,omitempty"`
	ForwardingMode    ForwardingMode `json:"forwarding_mode,omitempty"`
	BandPolicy        string         `json:"band_policy,omitempty"`
	MobilityDomainRef string         `json:"mobility_domain_ref,omitempty"`
	Enabled           bool           `json:"enabled"`
	FirstSeen         time.Time      `json:"first_seen,omitempty"`
	LastSeen          time.Time      `json:"last_seen,omitempty"`
	Stale             bool           `json:"stale,omitempty"`
	Attrs             map[string]any `json:"attrs,omitempty"`
}

// BSSID is one broadcast MAC (radio × WLAN). The MAC itself is the identity.
type BSSID struct {
	TenantID  string    `json:"-"`
	BSSID     string    `json:"bssid"`
	RadioRef  string    `json:"radio_ref,omitempty"`
	WLANRef   string    `json:"wlan_ref,omitempty"`
	APRef     string    `json:"ap_ref,omitempty"`
	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	Stale     bool      `json:"stale,omitempty"`
}

// IdentityConfidence is the client cross-session identity ladder (report
// §9.3). A randomized-MAC client is UNKNOWN: cross-session history honestly
// does not exist and is never guessed.
type IdentityConfidence string

const (
	IdentityAuthoritative IdentityConfidence = "authoritative" // EAP-TLS certificate CN
	IdentityStrong        IdentityConfidence = "strong"        // 802.1X username / stable (non-randomized) MAC
	IdentityCandidate     IdentityConfidence = "candidate"     // DHCP client-id
	IdentityUnknown       IdentityConfidence = "unknown"       // randomized MAC — session-scoped only
)
