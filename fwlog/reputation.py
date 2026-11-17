"""Source reputation model - explicit assumptions, no hidden threat feed.

This tool ships NO reputation data. It cannot: a bundled blocklist would be
stale on arrival and would silently decide attribution for the analyst. What it
does instead is classify each source by address space and state, in the report,
exactly which assumption that classification rests on.
"""

from __future__ import annotations

import ipaddress

INTERNAL_NETS = tuple(
    ipaddress.ip_network(net)
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")
)
DOCUMENTATION_NETS = tuple(
    ipaddress.ip_network(net)
    for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
RESERVED_NETS = tuple(
    ipaddress.ip_network(net)
    for net in ("0.0.0.0/8", "100.64.0.0/10", "224.0.0.0/4", "240.0.0.0/4")
)

# How much a finding matters, given where the source sits.
_RISK = {
    "internal": ("possible_compromised_host",
                 "An internal source is more likely a misconfigured job, a "
                 "vulnerability scanner or a compromised host than an outside "
                 "attacker. Assume nothing until you know what runs on it."),
    "documentation": ("untrusted_external_placeholder",
                      "RFC 5737 documentation range: not a routable address, so in "
                      "this synthetic set it stands in for an internet source. On a "
                      "real log an address here means spoofing, a lab leak or a "
                      "mis-typed export."),
    "reserved": ("untrusted_reserved",
                 "Reserved/special-use space. Its presence in a perimeter deny log "
                 "is itself suspicious: spoofing, a bogon leak, or a broken exporter."),
    "external": ("untrusted_external",
                 "Routable address outside every internal range. Treated as untrusted "
                 "by default on address space alone - not on any reputation lookup."),
    "invalid": ("unknown",
                "Not a parseable IP address. Attribution is impossible; treat the "
                "finding as telemetry corruption until proven otherwise."),
}


def classify(address: str) -> str:
    """Return the address-space class of a source: internal/external/..."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "invalid"
    if ip.is_loopback or any(ip in net for net in INTERNAL_NETS):
        return "internal"
    if any(ip in net for net in DOCUMENTATION_NETS):
        return "documentation"
    if any(ip in net for net in RESERVED_NETS):
        return "reserved"
    return "external"


def assess(address: str, score: float) -> dict:
    """Reputation view for one source, including what would falsify it."""
    klass = classify(address)
    label, note = _RISK[klass]
    if klass == "internal":
        confidence = "medium"
        basis = "address space (RFC 1918) + observed deny behaviour"
    elif klass in ("documentation", "reserved"):
        confidence = "low"
        basis = "address space only; address is not routable in the real internet"
    elif klass == "external":
        confidence = "medium"
        basis = "address space (outside RFC 1918) + observed deny behaviour"
    else:
        confidence = "low"
        basis = "unparseable address"

    if score >= 0.8:
        posture = "hostile_by_behaviour"
    elif score >= 0.6:
        posture = "suspicious_by_behaviour"
    else:
        posture = "insufficient_evidence"

    return {
        "address_class": klass,
        "posture": posture,
        "confidence": confidence,
        "basis": basis,
        "label": label,
        "note": note,
        "feed_consulted": False,
        "if_wrong": (
            "If this address is a NAT/CGNAT egress, a proxy, a CDN edge or a "
            "cloud egress range, the finding belongs to whoever sits behind "
            "that address and not to the address itself."
        ),
    }


def assumptions() -> list[dict]:
    """The assumptions the whole analysis rests on, stated for the report."""
    return [
        {
            "id": "R1",
            "assumption": "The SRC field is the true originator of the traffic.",
            "because": "It is the only identity a deny log carries.",
            "breaks_when": "NAT, CGNAT, a forward proxy, cloud egress or a VPN "
                           "concentrator rewrites the source.",
            "effect": "Every finding becomes an attribution to a middlebox, not a host.",
            "validate": "Correlate SRC against NAT translation logs before any block "
                        "or takedown action.",
        },
        {
            "id": "R2",
            "assumption": "No reputation feed is consulted; reputation is derived "
                          "from address space and observed behaviour only.",
            "because": "A bundled blocklist goes stale and silently decides attribution.",
            "breaks_when": "You need prior badness for a first-seen address, or you need "
                           "to clear an address that a feed already flagged.",
            "effect": "A known-bad scanner on its first visit here scores the same as any "
                      "noisy host; a compromised friendly host is never pre-cleared.",
            "validate": "Join SRC against your own threat-intel and asset inventory, then "
                        "re-run with --known-bad / --internal.",
        },
        {
            "id": "R3",
            "assumption": "Internal RFC 1918 sources are lower risk than external ones.",
            "because": "Most internal deny bursts are broken jobs, not intrusions.",
            "breaks_when": "The internal host is already compromised and is scanning "
                           "east-west, which is the exact behaviour this assumption "
                           "de-prioritises.",
            "effect": "Lateral movement from an internal host can be ranked below a "
                      "noisy internet scanner.",
            "validate": "Treat internal high-score findings as containment candidates, "
                        "not as noise; check EDR/AV history for the host.",
        },
        {
            "id": "R4",
            "assumption": "One firewall's view equals the whole network's view.",
            "because": "Only one deny log was supplied.",
            "breaks_when": "Traffic is denied (or permitted) on a path this sensor does "
                           "not see: east-west segments, cloud VPC, host firewalls.",
            "effect": "Scan volume is under-counted and a scan that succeeds elsewhere "
                      "looks like a scan that stopped.",
            "validate": "Aggregate every deny source you have; compare per-sensor counts.",
        },
    ]
