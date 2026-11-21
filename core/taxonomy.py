"""
core/taxonomy.py
Single source of truth for the v4 domain taxonomy.

7 domains replace the legacy 12 categories. Every layer derives from this
module: YAML directory layout, YAML `category:` values, MITRE map keys,
UI picker, DB domain names, and generator validation.

Curation rules:
- DELETE_CATEGORIES  — legacy dirs removed entirely
- DELETED_FILES      — individual YAMLs removed (niche / duplicates / cut topics)
- FILE_REDIRECTS     — kept YAMLs that move to a different domain than their dir's default
- OLD_DIR_TO_DOMAIN  — default routing for each legacy dir
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Domain:
    slug: str                 # directory name under scenarios/data/
    name: str                 # display name -> YAML `category:` + MITRE map key + UI
    description: str


DOMAINS: list[Domain] = [
    Domain(
        "endpoint",
        "Endpoint",
        "Host compromise, malware, persistence, privilege escalation, ransomware, and endpoint defense.",
    ),
    Domain(
        "web_app",
        "Web App",
        "OWASP-class web application attacks: injection, auth flaws, SSRF, XXE, and API abuse.",
    ),
    Domain(
        "cloud",
        "Cloud",
        "Cloud-native incidents: S3, IAM, serverless, containers, Kubernetes, and multi-cloud.",
    ),
    Domain(
        "identity",
        "Identity & Access",
        "Phishing, credential attacks, Kerberos/AD abuse, MFA bypass, and account takeovers.",
    ),
    Domain(
        "network",
        "Network",
        "Network-layer detection and response: DDoS, MITM, DNS abuse, rogue devices, and wireless.",
    ),
    Domain(
        "ai_ml",
        "AI & ML",
        "Attacks on AI systems: prompt injection, poisoning, extraction, and adversarial examples.",
    ),
    Domain(
        "advanced",
        "Advanced Threats",
        "Nation-state APTs, stealth, supply chain, and sophisticated multi-stage campaigns.",
    ),
]

DOMAIN_BY_SLUG: dict[str, Domain] = {d.slug: d for d in DOMAINS}
DOMAIN_BY_NAME: dict[str, Domain] = {d.name: d for d in DOMAINS}

# --------------------------------------------------------------------------- #
# Legacy routing
# --------------------------------------------------------------------------- #

# Legacy category dir -> new domain slug (default; per-file overrides below).
OLD_DIR_TO_DOMAIN: dict[str, str | None] = {
    "advanced_persistent_threat": "advanced",
    "ai_ml_security": "ai_ml",
    "cloud_security": "cloud",
    "crypto_attacks": "endpoint",
    "mobile_security": "endpoint",
    "network": "network",
    "social_engineering": "identity",
    "supply_chain": "advanced",
    "system_exploit": "endpoint",
    "webapp": "web_app",
    # None => every file must be listed in FILE_REDIRECTS or DELETED_FILES
    "physical_security": None,
    "iot_ot_security": None,
}

# Legacy dirs removed entirely.
DELETE_CATEGORIES: frozenset[str] = frozenset({"physical_security", "iot_ot_security"})

# Kept YAMLs routed to a domain other than their dir's default.
# Key = YAML stem (filename without .yaml).
FILE_REDIRECTS: dict[str, str] = {
    # crypto_attacks
    "heartbleed-style_memory_leak___openssl_vulnerability": "endpoint",
    "kerberos_as-rep_roasting___offline_credential_attack": "identity",
    # mobile_security
    "sim_swapping___mfa_bypass_via_carrier_fraud": "identity",
    "mobile_phishing___smishing_with_malware_link": "identity",
    # network
    "vpn_credential_stuffing": "identity",
    # system_exploit
    "kerberoasting___service_account_cracking": "identity",
    "gpo_abuse___domain-wide_policy_manipulation": "identity",
    "golden_ticket___forged_kerberos_tgts": "identity",
    "container_escape___kubernetes_pod_breakout": "cloud",
    "supply_chain___compromised_npm_package": "advanced",
    # social_engineering
    "usb_baiting___malware_delivery_via_curiosity": "endpoint",
}

# Individual YAMLs removed (niche, duplicates, or topics cut from the curriculum).
# Key = YAML stem. Files in DELETE_CATEGORIES dirs are implied and need not be listed.
DELETED_FILES: frozenset[str] = frozenset({
    # crypto_attacks — crypto-focused niche attacks (Heartbleed + Kerberos kept)
    "timing_attack_on_authentication___side-channel_credential_extraction",
    "hash_collision_attack___md5_sha1_weakness_exploitation",
    "padding_oracle_attack___cryptographic_block_cipher_exploitation",
    "quantum_computing_threat___post-quantum_cryptography_migration",
    # mobile_security — niche / overlaps
    "jailbreak_root_detection_bypass___mobile_security_control_evasion",
    "bluetooth_pairing_attack__blueborne____proximity_mobile_exploit",
    # network — niche protocols
    "bgp_prefix_hijack",
    "802_1x_bypass___unauthorized_switch_port_access",
    "ipv6_neighbor_discovery_spoofing_attack",
    "iot_botnet_c2_communication",
    "bluetooth_ble_replay_attack___wireless_access_control_bypass",
    "voip_eavesdropping_via_sip_spoofing",
    # social_engineering — duplicates / niche / physical overlap
    "honey_trap___sextortion___blackmail_attack",
    "physical_tailgating___data_center_access",
    "linkedin_reconnaissance___targeted_credential_theft",
    "recruiter_scam___fake_job_offer_with_malware",
    "social_media_osint_reconnaissance",
    "vishing_campaign___it_helpdesk_impersonation",
    # supply_chain — niche hardware
    "hardware_implant",
    # system_exploit — OT
    "ics_scada___manufacturing_plant_attack",
    # webapp — niche / lower-value
    "web_cache_poisoning___persistent_xss_delivery",
    "websocket_hijacking___real-time_data_exfiltration",
    "waf_bypass___advanced_payload_encoding",
    "subdomain_takeover___dns-based_attack",
    "prototype_pollution___remote_code_execution",
    "http_request_smuggling___cache_poisoning___credential_theft",
    "cors_misconfiguration___cross-origin_data_theft",
    "clickjacking___account_actions_via_ui_redressing",
    "api_key_extraction___client-side_secret_exposure",
})

# Legacy category display names (YAML `category:` values / MITRE map keys)
# -> new domain slug, for the MITRE map rebuild and DB migration.
LEGACY_NAME_TO_DOMAIN: dict[str, str] = {
    "AI / ML Security": "ai_ml",
    "Advanced Persistent Threats": "advanced",
    "Cloud Security": "cloud",
    "Cryptographic Attacks": "endpoint",
    "Mobile Security": "endpoint",
    "Network Attacks": "network",
    "Social Engineering": "identity",
    "Supply Chain Attacks": "advanced",
    "System Exploitation": "endpoint",
    "Web Application Attacks": "web_app",
    # removed entirely
    "IoT / OT Security": None,
    "Physical Security": None,
}


# --------------------------------------------------------------------------- #
# Lookup API
# --------------------------------------------------------------------------- #

def domain_for(category_dir: str, stem: str) -> str | None:
    """Return the new domain slug for a YAML file, or None if it must be deleted.

    None is returned for files that are deleted outright — never for files
    that should be kept. Raises KeyError for unexpected input so the curation
    tool fails loudly instead of silently dropping scenarios.
    """
    if stem in FILE_REDIRECTS:
        return FILE_REDIRECTS[stem]
    if category_dir in DOMAIN_BY_SLUG:
        return category_dir
    if category_dir in DELETE_CATEGORIES:
        return None
    if stem in DELETED_FILES:
        return None
    try:
        slug = OLD_DIR_TO_DOMAIN[category_dir]
    except KeyError:
        raise KeyError(
            f"Unknown category dir {category_dir!r} for file {stem!r} — "
            "add it to core/taxonomy.py OLD_DIR_TO_DOMAIN"
        )
    if slug is None:
        raise KeyError(
            f"Category dir {category_dir!r} has no default domain and {stem!r} "
            "is not in FILE_REDIRECTS or DELETED_FILES — fix core/taxonomy.py"
        )
    return slug


def domain_name_for(category_dir: str, stem: str) -> str | None:
    """Display name of the destination domain, or None if deleted."""
    slug = domain_for(category_dir, stem)
    return DOMAIN_BY_SLUG[slug].name if slug else None


def is_deleted(category_dir: str, stem: str) -> bool:
    """True if the file should be removed during curation."""
    return domain_for(category_dir, stem) is None


def domain_slug_from_legacy_name(name: str) -> str | None:
    """Map a legacy YAML `category:` value (or MITRE map key) to a new slug."""
    if name in DOMAIN_BY_NAME:
        return DOMAIN_BY_NAME[name].slug
    slug = LEGACY_NAME_TO_DOMAIN.get(name)
    if slug is None and name not in LEGACY_NAME_TO_DOMAIN:
        raise KeyError(f"Unknown legacy domain name {name!r} — add to LEGACY_NAME_TO_DOMAIN")
    return slug


def all_slugs() -> list[str]:
    return [d.slug for d in DOMAINS]


def all_names() -> list[str]:
    return [d.name for d in DOMAINS]
