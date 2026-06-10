"""Application catalog — enterprise / SaaS / AI app signatures.

Each entry models a real application the way the platform's flow analytics see
it: by destination prefix(es), L4 protocol, destination port(s), and a
byte/packet/duration profile. Prefixes are REAL public ranges (so the geo +
by-app boards classify correctly); categories follow nDPI's taxonomy
(github.com/ntop/nDPI). L7 hint drives the optional real-session generator.

This is data, not code — extend freely. Weights set the relative mix.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Proto = Literal["tcp", "udp"]
L7 = Literal["https", "http", "quic", "dns", "ntp", "rtp", "tls", "raw"]


@dataclass(frozen=True)
class App:
    name: str
    category: str
    proto: Proto
    dst_prefixes: tuple[str, ...]          # real public CIDRs
    dst_ports: tuple[int, ...]
    l7: L7 = "https"
    # Per-flow byte/packet envelope (forward = client→server, rev = server→client).
    fwd_bytes: tuple[int, int] = (2_000, 60_000)
    rev_bytes: tuple[int, int] = (8_000, 1_200_000)
    fwd_pkts: tuple[int, int] = (8, 120)
    rev_pkts: tuple[int, int] = (10, 1_500)
    dur_ms: tuple[int, int] = (200, 30_000)   # flow duration envelope
    weight: int = 10                          # relative frequency in the mix
    bidir_media: bool = False                 # symmetric RTP-style media


# Enterprise client source pools (the "inside" of the network).
CLIENT_PREFIXES: tuple[str, ...] = (
    "10.10.0.0/16", "10.20.0.0/16", "10.30.0.0/16",
    "172.16.0.0/16", "172.40.40.0/24", "192.168.10.0/24",
)

CATALOG: list[App] = [
    # ── AI assistants ──────────────────────────────────────────────────────
    App("ChatGPT", "AI", "tcp", ("104.18.0.0/16", "162.159.128.0/19"), (443,), "https",
        fwd_bytes=(3_000, 90_000), rev_bytes=(5_000, 400_000), dur_ms=(1_000, 60_000), weight=14),
    App("Claude", "AI", "tcp", ("160.79.104.0/23",), (443,), "https",
        fwd_bytes=(3_000, 80_000), rev_bytes=(5_000, 350_000), dur_ms=(1_000, 60_000), weight=10),
    App("GitHubCopilot", "AI", "tcp", ("140.82.112.0/20", "20.190.128.0/18"), (443,), "https",
        fwd_bytes=(2_000, 40_000), rev_bytes=(4_000, 120_000), weight=8),
    App("GeminiAI", "AI", "tcp", ("142.250.0.0/15",), (443,), "https", weight=6),

    # ── Microsoft 365 ──────────────────────────────────────────────────────
    App("M365-Outlook", "Productivity", "tcp", ("40.96.0.0/13", "52.96.0.0/14"), (443,), "https",
        rev_bytes=(20_000, 2_000_000), weight=16),
    App("M365-SharePoint", "Productivity", "tcp", ("13.107.136.0/22", "52.108.0.0/14"), (443,), "https",
        rev_bytes=(50_000, 5_000_000), weight=12),
    App("M365-OneDrive", "Storage", "tcp", ("13.107.42.0/24", "52.120.0.0/14"), (443,), "https",
        rev_bytes=(50_000, 8_000_000), weight=10),
    App("Teams-Signaling", "Collaboration", "tcp", ("52.112.0.0/14", "52.122.0.0/15"), (443,), "https", weight=8),
    App("Teams-Media", "Collaboration", "udp", ("52.112.0.0/14", "52.122.0.0/15"),
        tuple(range(3478, 3482)), "rtp",
        fwd_bytes=(200_000, 4_000_000), rev_bytes=(200_000, 4_000_000),
        fwd_pkts=(500, 8_000), rev_pkts=(500, 8_000), dur_ms=(30_000, 1_800_000),
        weight=12, bidir_media=True),

    # ── Video / collaboration ──────────────────────────────────────────────
    App("Zoom-Media", "Collaboration", "udp", ("170.114.0.0/16", "162.255.36.0/22", "213.19.144.0/24"),
        tuple(range(8801, 8811)), "rtp",
        fwd_bytes=(300_000, 6_000_000), rev_bytes=(300_000, 6_000_000),
        fwd_pkts=(800, 12_000), rev_pkts=(800, 12_000), dur_ms=(60_000, 3_600_000),
        weight=12, bidir_media=True),
    App("Zoom-Signaling", "Collaboration", "tcp", ("170.114.0.0/16",), (443,), "https", weight=5),
    App("Webex-Media", "Collaboration", "udp", ("62.109.192.0/18", "207.182.160.0/19", "144.196.0.0/16"),
        (9000, 5004), "rtp", fwd_bytes=(200_000, 4_000_000), rev_bytes=(200_000, 4_000_000),
        fwd_pkts=(500, 9_000), rev_pkts=(500, 9_000), weight=6, bidir_media=True),
    App("Slack", "Collaboration", "tcp", ("52.84.0.0/15", "3.101.0.0/16"), (443,), "https", weight=9),
    App("GoogleMeet", "Collaboration", "udp", ("142.250.0.0/15",), tuple(range(19302, 19310)), "rtp",
        fwd_bytes=(200_000, 3_000_000), rev_bytes=(200_000, 3_000_000), weight=5, bidir_media=True),

    # ── Enterprise SaaS — CRM / HR / Travel / ITSM / Finance ───────────────
    App("Salesforce", "CRM", "tcp", ("13.108.0.0/14", "96.43.144.0/20"), (443,), "https", weight=10),
    App("HubSpot", "CRM", "tcp", ("104.16.0.0/13",), (443,), "https", weight=4),
    App("Workday", "HR", "tcp", ("173.241.192.0/19",), (443,), "https", weight=8),
    App("SuccessFactors", "HR", "tcp", ("155.56.0.0/16",), (443,), "https", weight=4),
    App("SAP-Concur", "Travel", "tcp", ("12.130.0.0/16",), (443,), "https", weight=5),
    App("ServiceNow", "ITSM", "tcp", ("149.96.0.0/16",), (443,), "https", weight=8),
    App("Jira-Atlassian", "ITSM", "tcp", ("104.192.136.0/21",), (443,), "https", weight=6),
    App("Coupa-Procure", "Finance", "tcp", ("63.128.0.0/14",), (443,), "https", weight=3),

    # ── Cloud storage / sync ───────────────────────────────────────────────
    App("Box", "Storage", "tcp", ("74.112.184.0/21",), (443,), "https", rev_bytes=(50_000, 6_000_000), weight=5),
    App("Dropbox", "Storage", "tcp", ("162.125.0.0/16",), (443,), "https", rev_bytes=(50_000, 6_000_000), weight=5),
    App("GoogleDrive", "Storage", "tcp", ("142.250.0.0/15", "172.217.0.0/16"), (443,), "https",
        rev_bytes=(50_000, 8_000_000), weight=7),

    # ── Dev / SCM ──────────────────────────────────────────────────────────
    App("GitHub", "Dev", "tcp", ("140.82.112.0/20",), (443, 22), "https", weight=6),
    App("GitLab", "Dev", "tcp", ("172.65.0.0/16",), (443, 22), "https", weight=3),

    # ── Web / infra background ─────────────────────────────────────────────
    App("Web-HTTPS", "Web", "tcp", ("23.0.0.0/12", "104.16.0.0/12", "151.101.0.0/16"), (443,), "https",
        weight=18),
    App("Web-QUIC", "Web", "udp", ("142.250.0.0/15", "104.16.0.0/12"), (443,), "quic",
        fwd_bytes=(2_000, 50_000), rev_bytes=(10_000, 1_500_000), weight=10),
    App("DNS", "Infra", "udp", ("8.8.8.8/32", "8.8.4.4/32", "1.1.1.1/32"), (53,), "dns",
        fwd_bytes=(60, 200), rev_bytes=(120, 800), fwd_pkts=(1, 2), rev_pkts=(1, 2), dur_ms=(1, 50), weight=14),
    App("NTP", "Infra", "udp", ("162.159.200.0/24",), (123,), "ntp",
        fwd_bytes=(76, 90), rev_bytes=(76, 90), fwd_pkts=(1, 1), rev_pkts=(1, 1), dur_ms=(1, 10), weight=5),
    App("ICMP-Ping", "Infra", "udp", ("8.8.8.8/32", "1.1.1.1/32"), (0,), "raw",
        fwd_bytes=(64, 1_500), rev_bytes=(64, 1_500), fwd_pkts=(1, 5), rev_pkts=(1, 5), dur_ms=(1, 100), weight=6),
]


def by_names(names: list[str]) -> list[App]:
    """Filter the catalog by app or category names (case-insensitive)."""
    want = {n.strip().lower() for n in names if n.strip()}
    if not want:
        return CATALOG
    return [a for a in CATALOG if a.name.lower() in want or a.category.lower() in want]


def categories() -> set[str]:
    return {a.category for a in CATALOG}
