"""
core/response_scorer.py
Offline free-text scorer for format-v2 phases (Layer 1 of dual-layer grading).

No API key, no network: scores an answer 0-10 against the phase's reference
answer and/or `ideal_concepts`.

Why v2
------
The first implementation required *every* word of every two-word concept to
appear verbatim. The concept lists were mechanically derived by sliding a
two-word window over the reference answer, so correct paraphrases routinely
scored 2-4/10 while copying the reference scored 10/10.

v2 scores **weighted concept coverage** instead of exact bigrams:

- multi-word synonyms are normalized before tokenization ("command and
  control" -> c2, "right away" -> immediately, "off the network" -> contain);
- each reference content term gets a weight (identifier-like terms matter
  more, filler adverbs matter less);
- score = 10 * (0.70 * weighted term coverage + 0.30 * phrase coverage);
- per-concept partial credit is kept for backwards-compatible reporting.

Threshold stays 6.0: an answer that covers roughly two-thirds of the weighted
ideal action passes; a partial answer does not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# --------------------------------------------------------------------------- #
# Security synonym map: group name -> single-token synonyms.
# Multi-word phrases live in PHRASE_SYNONYMS below.
# --------------------------------------------------------------------------- #
SYNONYM_GROUPS: dict[str, tuple[str, ...]] = {
    "contain": (
        "contain", "containment", "isolate", "isolation", "quarantine",
        "sandbox", "disconnect", "sever", "segment", "segregate", "unplug",
        "offline", "contained",
    ),
    "block": (
        "block", "blocked", "blocklist", "deny", "denylist", "blacklist",
        "drop", "reject", "prevent", "filter",
    ),
    "firewall": (
        "firewall", "fw", "waf", "perimeter", "acl", "border", "edge",
    ),
    "logs": (
        "logs", "log", "logging", "siem", "splunk", "telemetry", "audit",
        "netflow", "journal", "records", "events", "entries",
    ),
    "review": (
        "review", "check", "inspect", "examine", "analyze", "investigate",
        "query", "pull", "retrieve", "verify", "validate", "confirm",
        "correlate", "hunt", "triage", "scope", "pivot",
    ),
    "creds": (
        "credentials", "credential", "password", "passwords", "passphrase",
        "secret", "secrets", "token", "tokens", "key", "keys", "hash",
        "ticket", "pin", "login", "logon", "signin", "sign-in", "ntlm",
        "sam", "lsass", "creds",
    ),
    "reset": (
        "reset", "rotate", "rotation", "reissue", "regenerate", "invalidate",
        "expire",
    ),
    "mfa": (
        "mfa", "2fa", "multifactor", "otp", "authenticator", "yubikey",
        "totp", "passkey", "passkeys",
    ),
    "patch": (
        "patch", "patching", "update", "upgrade", "hotfix", "fix", "cve",
        "vulnerability", "vulnerabilities", "mitigate", "mitigation",
    ),
    "scan": ("scan", "antivirus", "av", "sweep", "scanner"),
    "edr": (
        "edr", "xdr", "defender", "crowdstrike", "sentinelone", "cybereason",
    ),
    "backup": (
        "backup", "backups", "snapshot", "snapshots", "image", "retention",
        "vss",
    ),
    "restore": (
        "restore", "recovery", "recover", "rollback", "rebuild", "reimage",
        "restored",
    ),
    "ir": (
        "ir", "playbook", "runbook", "warroom", "bridge", "major",
    ),
    "intel": (
        "intel", "intelligence", "ioc", "indicators", "reputation",
        "virustotal", "vt", "osint", "feed", "feeds",
    ),
    "notify": (
        "notify", "contact", "escalate", "escalation", "inform", "alert",
        "page", "report", "legal", "counsel", "privacy", "regulator", "dpia",
        "dpo", "notification", "stakeholders", "management", "communicate",
        "communication", "brief", "briefing",
    ),
    "encrypt": (
        "encrypt", "encryption", "bitlocker", "cipher", "decrypt", "filevault",
    ),
    "dlp": ("dlp", "exfil", "exfiltration", "leak", "leakage"),
    "honeypot": (
        "honeypot", "canary", "decoy", "deception", "tarpit", "tripwire",
        "honeytoken",
    ),
    "pcap": ("pcap", "tcpdump", "wireshark", "packet", "packets", "capture"),
    "forensic": (
        "forensic", "forensics", "acquisition", "volatility", "autopsy",
        "ftk", "imaging", "timeline",
    ),
    "iam": (
        "iam", "identity", "ad", "entra", "sso", "ldap", "kerberos", "saml",
        "oauth", "oidc", "directory",
    ),
    "network": (
        "network", "router", "switch", "proxy", "gateway", "vpn", "dns",
        "port", "vlan", "egress", "ingress", "internet", "tcp", "udp",
        "traffic", "subnet", "lan", "wan", "nameserver", "nameservers",
    ),
    "email": (
        "email", "mail", "mailbox", "outlook", "exchange", "smtp", "dkim",
        "spf", "dmarc", "sender", "header", "attachment", "macro",
    ),
    "phishing": (
        "phishing", "spearphishing", "spam", "url", "click", "campaign",
        "bait", "lure",
    ),
    "user": ("user", "employee", "staff", "personnel", "workforce"),
    "account": (
        "account", "accounts", "svc", "admin", "administrator", "da",
    ),
    "group": ("group", "membership", "role", "roles"),
    "remove": (
        "remove", "delete", "uninstall", "purge", "clean", "eradicate",
        "wipe", "clear", "destroy", "disable", "disabled", "deactivate",
        "suspend", "revoke", "lock", "lockout", "shutdown",
    ),
    "monitor": (
        "monitor", "monitoring", "watch", "track", "alerting", "detect",
        "detection", "visibility", "baseline", "observe", "observability",
    ),
    "host": (
        "host", "machine", "endpoint", "workstation", "server", "laptop",
        "desktop", "device", "asset", "node",
    ),
    "process": (
        "process", "executable", "binary", "dll", "implant", "payload",
        "malware", "trojan", "ransomware", "backdoor", "stager", "loader",
        "powershell", "ps1", "script",
    ),
    "cloud": (
        "cloud", "aws", "azure", "gcp", "lambda", "s3", "ec2", "container",
        "kubernetes", "k8s", "instance", "bucket", "ecr", "eks", "gcs",
    ),
    "data": (
        "data", "records", "pii", "database", "db", "schema", "table",
        "column", "dataset",
    ),
    "access": (
        "access", "permissions", "authorization", "rbac", "entitlements",
        "privilege", "privileges", "allowlist", "whitelist", "policy",
        "policies",
    ),
    "remediate": (
        "remediate", "remediation", "hardening", "harden", "tighten",
        "correct",
    ),
    "watchlist": ("watchlist", "threshold", "anomaly", "behavioral", "rule"),
    "evidence": (
        "evidence", "custody", "integrity", "checksum", "timestamp",
        "screenshot", "artifact", "artefacts",
    ),
    "document": (
        "document", "documentation", "writeup", "rca", "postmortem",
        "rootcause",
    ),
    "preserve": (
        "preserve", "preservation", "retain", "keep", "safeguard", "save",
        "saved",
    ),
    "memory": ("memory", "ram"),
    "dump": ("dump", "dmp"),
    "c2": ("c2", "cnc", "callback", "beacon", "beacons"),
    "ip": ("ip", "ipv4", "ipv6", "address"),
    "immediately": (
        "immediately", "asap", "urgent", "urgently", "now", "promptly",
    ),
    "analysis": ("analysis", "findings", "assessment"),
}

# Multi-word phrases -> canonical token. Applied before tokenization.
# Patterns tolerate spaces, hyphens, and underscores between words.
PHRASE_SYNONYMS: dict[str, str] = {
    "command and control": "c2",
    "right away": "immediately",
    "at once": "immediately",
    "straight away": "immediately",
    "as soon as possible": "immediately",
    "ip address": "ip",
    "email address": "email",
    "off the network": "contain network",
    "cut off": "contain",
    "take offline": "contain",
    "pull the plug": "contain",
    "data exfiltration": "dlp",
    "data leakage": "dlp",
    "public read": "public-read",
    "publicly readable": "public-read",
    "threat intelligence": "intel",
    "active directory": "iam",
    "chain of custody": "evidence",
    "lessons learned": "document",
    "root cause": "document",
    "after action": "document",
    "war room": "ir",
    "bridge call": "ir",
    "incident response": "ir",
    "service account": "account",
    "domain admin": "account",
    "lateral movement": "network",
}

# Reverse map: synonym -> canonical group. First group wins on duplicates.
_SYNONYM_REVERSE: dict[str, str] = {}
for _canon, _syns in SYNONYM_GROUPS.items():
    for _syn in _syns:
        _SYNONYM_REVERSE.setdefault(_syn, _canon)

_SHORT_CANONICALS = frozenset({"ad", "av", "c2", "db", "ip", "ir"})

GENERIC_TERMS: frozenset[str] = frozenset({
    "immediately", "now", "right", "away", "first", "next", "then", "also",
    "ensure", "make", "sure", "need", "should", "would", "could", "time",
    "way", "quickly", "asap", "urgent", "urgently", "still", "even", "well",
    "thing", "things", "work", "working", "get", "take", "see", "saw",
    "seen", "look", "looking", "find", "found", "based", "use", "using",
    "utilize", "start", "begin", "continue", "keep", "proper", "properly",
    "correct", "correctly", "appropriate", "immediate", "recent", "recently",
})

STOPWORDS: frozenset[str] = frozenset({
    "a", "an", "the", "of", "to", "for", "on", "with", "and", "or", "in",
    "from", "by", "at", "via", "vs", "their", "its", "your", "our", "his",
    "her", "is", "are", "was", "were", "be", "been", "being", "has", "have",
    "had", "do", "does", "did", "i", "we", "you", "he", "she", "they", "it",
    "this", "that", "these", "those", "all", "any", "will", "would", "can",
    "could", "should", "must", "not", "no", "yes", "also", "only", "too",
    "very", "just", "so", "as", "but", "than", "then", "each", "some", "such",
    "which", "who", "whom", "what", "when", "where", "why", "how", "after",
    "before", "during", "into", "onto", "about", "again", "once", "here",
    "there", "them", "me", "us", "out", "up", "down", "off", "over",
    "under", "more", "most", "other", "own", "same", "now", "while", "if",
    "may", "might", "shall", "upon", "within", "without", "across", "per",
})

# Keep hyphens/underscores so hostnames such as ws-jmartinez-04 stay whole.
_PUNCT_RE = re.compile(r"[^a-z0-9\s\-_]")
_NUMBER_RE = re.compile(r"^\d+$")
_SECTION_RE = re.compile(
    r"(?i)(?:\bwhat (?:did you|did we|i|we) (?:get|see|observe|find|notice|receive)\b"
    r"|\bwhat (?:would|should|will|did) (?:you|i|we) do\b|\bwhat i would do\b"
    r"|\bwhat happened\b|\bwhat do we know\b"
    r"|\bwhat next\b|\bnext steps?\b|\baction\b"
    r"|\bwhy\b|\brationale\b|\breasoning\b|\bjustification\b|\bbecause\b)"
)

PART_WEIGHTS = {"what": 0.3, "action": 0.5, "why": 0.2}
COVERAGE_WEIGHT = 0.70
PHRASE_WEIGHT = 0.30
GOOD_THRESHOLD = 6.0

# Longest phrases first so "as soon as possible" beats "as".
_PHRASE_RE = re.compile(
    "|".join(
        r"\b" + r"[\s\-_]+".join(re.escape(part) for part in phrase.split()) + r"\b"
        for phrase in sorted(PHRASE_SYNONYMS, key=len, reverse=True)
    ),
    re.IGNORECASE,
) if PHRASE_SYNONYMS else None


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #
def has_substance(raw: str) -> bool:
    """True if the answer is a real response (not empty/gibberish)."""
    text = raw.strip()
    if len(text) < 8:
        return False
    if len({ch for ch in text.lower() if not ch.isspace()}) <= 2:
        return False
    if len(text.split()) < 2:
        return False
    return True


def normalize(text: str) -> str:
    """Lowercase, strip punctuation (keeping -/_), collapse whitespace."""
    t = text.lower()
    t = _PUNCT_RE.sub(" ", t)
    return re.sub(r"\s+", " ", t).strip()


def _apply_phrases(text: str) -> str:
    """Replace known multi-word phrases with their canonical token."""
    if _PHRASE_RE is None:
        return text

    def _replace(match: re.Match) -> str:
        raw = re.sub(r"[\s\-_]+", " ", match.group(0).lower()).strip()
        return PHRASE_SYNONYMS.get(raw, match.group(0))

    return _PHRASE_RE.sub(_replace, text)


def _strip_plural(word: str) -> str:
    if word.endswith("ss") or word.endswith("us") or word.endswith("is"):
        return word
    if word.endswith("s") and len(word) > 4 and not any(ch.isdigit() for ch in word):
        return word[:-1]
    return word


def _canonical_token(word: str) -> str:
    w = _strip_plural(word)
    return _SYNONYM_REVERSE.get(w, w)


def _looks_identifier(raw: str) -> bool:
    """Hostnames, IPs, hashes, CVE ids, and other specific tokens."""
    if not raw:
        return False
    if any(ch.isdigit() for ch in raw):
        return True
    if "-" in raw or "_" in raw:
        return True
    # Original casing is lost by normalize; long alphanumeric compounds are
    # still more specific than ordinary words.
    return len(raw) >= 12


def _content_tokens(text: str) -> list[tuple[str, str]]:
    """Return (canonical, raw) content tokens with stopwords removed."""
    normalized = _apply_phrases(normalize(text))
    out: list[tuple[str, str]] = []
    for raw in normalized.split():
        if not raw or raw in STOPWORDS or _NUMBER_RE.match(raw):
            continue
        canon = _canonical_token(raw)
        if not canon:
            continue
        if len(canon) < 3 and canon not in _SHORT_CANONICALS and not any(
            ch.isdigit() for ch in canon
        ):
            continue
        out.append((canon, raw))
    return out


def _term_weight(canonical: str, raw: str) -> float:
    if canonical in GENERIC_TERMS:
        return 0.35
    if _looks_identifier(raw):
        return 1.5
    return 1.0


def split_reference_answer(reference_answer: str) -> tuple[str, str]:
    """Split a reference answer into (action, why).

    Reference answers contain a second 'Why:' paragraph. Returns
    ``(action, why)`` with either side possibly empty.
    """
    if not reference_answer:
        return "", ""
    parts = re.split(
        r"\n\s*why\s*[:\-]", reference_answer, maxsplit=1, flags=re.IGNORECASE
    )
    action = parts[0].strip()
    why = parts[1].strip() if len(parts) > 1 else ""
    return action, why


def _ideal_action(reference_answer: str) -> str:
    """The actionable first paragraph of a reference answer.

    Reference answers contain a second 'Why:' paragraph; including it would
    require the learner to repeat the explanation to score well.
    """
    return split_reference_answer(reference_answer)[0]


# --------------------------------------------------------------------------- #
# Scoring profile
# --------------------------------------------------------------------------- #
@dataclass
class _Profile:
    terms: dict[str, float] = field(default_factory=dict)
    phrases: list[tuple[str, ...]] = field(default_factory=list)
    concepts: list[str] = field(default_factory=list)


def _build_profile(reference_answer: str, concepts: list[str]) -> _Profile:
    profile = _Profile(concepts=list(concepts or []))
    action = _ideal_action(reference_answer)

    if action:
        tokens = _content_tokens(action)
        for canonical, raw in tokens:
            weight = _term_weight(canonical, raw)
            profile.terms[canonical] = max(profile.terms.get(canonical, 0.0), weight)
        sequence = [canonical for canonical, _ in tokens]
        concept_phrases = [
            tuple(c for c, _ in _content_tokens(concept))
            for concept in (concepts or [])
        ]
        profile.phrases = [p for p in concept_phrases if p] or [
            (sequence[i], sequence[i + 1]) for i in range(len(sequence) - 1)
        ]
        return profile

    # No reference answer: fall back to the authored concept list.
    for concept in concepts or []:
        tokens = _content_tokens(concept)
        for canonical, raw in tokens:
            weight = _term_weight(canonical, raw)
            profile.terms[canonical] = max(profile.terms.get(canonical, 0.0), weight)
        if tokens:
            profile.phrases.append(tuple(canonical for canonical, _ in tokens))
    return profile


def _coverage(answer_terms: set[str], profile: _Profile) -> tuple[float, float, list[str], list[str]]:
    total_weight = sum(profile.terms.values())
    if total_weight <= 0:
        return 0.0, 0.0, [], []

    matched = sorted(t for t in profile.terms if t in answer_terms)
    missing = sorted(t for t in profile.terms if t not in answer_terms)
    coverage = sum(profile.terms[t] for t in matched) / total_weight

    if profile.phrases:
        phrase_hits = sum(1 for phrase in profile.phrases if all(t in answer_terms for t in phrase))
        phrase_coverage = phrase_hits / len(profile.phrases)
    else:
        phrase_coverage = coverage
    return coverage, phrase_coverage, matched, missing


def _score_from_terms(answer_terms: set[str], profile: _Profile) -> tuple[float, dict]:
    coverage, phrase_coverage, matched, missing = _coverage(answer_terms, profile)
    score = 10.0 * (COVERAGE_WEIGHT * coverage + PHRASE_WEIGHT * phrase_coverage)
    detail = {
        "coverage": round(coverage, 3),
        "phrase_coverage": round(phrase_coverage, 3),
        "matched_terms": matched,
        "missing_terms": missing,
    }
    return round(min(10.0, max(0.0, score)), 1), detail


def parse_three_parts(text: str) -> dict[str, str]:
    """Split the answer into what/action/why sections by guidance markers.

    Falls back to the whole answer for every part when no markers are found.
    """
    cleaned = re.sub(r"[\r\n]+", " \n ", text.strip())
    matches = list(_SECTION_RE.finditer(cleaned))
    if not matches:
        return {"what": text, "action": text, "why": text}

    label_of: list[str] = []
    for match in matches:
        seg = match.group(0).lower()
        if seg.startswith("what"):
            if seg.endswith("do") or "next" in seg:
                label_of.append("action")
            else:
                label_of.append("what")
        elif (
            seg.startswith("why")
            or seg.startswith("rationale")
            or seg.startswith("reasoning")
            or seg.startswith("justification")
            or seg.startswith("because")
        ):
            label_of.append("why")
        else:
            label_of.append("action")

    parts: dict[str, list[str]] = {"what": [], "action": [], "why": []}
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(cleaned)
        section = cleaned[start:end].strip(" :\n")
        parts[label_of[index]].append(section)

    return {key: " ".join(value).strip() for key, value in parts.items()}


def score_response(
    text: str,
    concepts: Optional[list[str]] = None,
    reference_answer: str = "",
) -> dict:
    """Score a free-text answer 0-10 against the phase's ideal action.

    Args:
        text: the learner's answer.
        concepts: authored `ideal_concepts` (used as the phrase checklist and
            as the fallback target when no reference answer is supplied).
        reference_answer: the full ideal response; its first paragraph is the
            scoring target.

    Returns:
        {
          "score": float, "good": bool, "matched": [...], "unmatched": [...],
          "total": int, "parts": {"what","action","why"},
          "coverage": float, "matched_terms": [...], "missing_terms": [...]
        }
    """
    concepts = list(concepts or [])

    if not has_substance(text):
        return {
            "score": 0.0,
            "good": False,
            "matched": [],
            "unmatched": concepts,
            "total": len(concepts),
            "parts": {"what": 0.0, "action": 0.0, "why": 0.0},
            "coverage": 0.0,
            "phrase_coverage": 0.0,
            "matched_terms": [],
            "missing_terms": [],
        }

    profile = _build_profile(reference_answer, concepts)
    if not profile.terms:
        # No scoring targets at all — neutral score, never a hard fail.
        return {
            "score": 5.0,
            "good": False,
            "matched": [],
            "unmatched": [],
            "total": 0,
            "parts": {"what": 5.0, "action": 5.0, "why": 5.0},
            "coverage": 0.0,
            "phrase_coverage": 0.0,
            "matched_terms": [],
            "missing_terms": [],
        }

    answer_tokens = _content_tokens(text)
    answer_terms = {canonical for canonical, _ in answer_tokens}
    score, detail = _score_from_terms(answer_terms, profile)

    # Per-part coverage (informational; feeds the AI rubric + student model).
    parts: dict[str, float] = {}
    for label, section in parse_three_parts(text).items():
        part_terms = {canonical for canonical, _ in _content_tokens(section)}
        part_score, _ = _score_from_terms(part_terms, profile)
        parts[label] = part_score

    # Backwards-compatible concept match lists (full-phrase coverage).
    matched: list[str] = []
    unmatched: list[str] = []
    for concept in concepts:
        concept_terms = {canonical for canonical, _ in _content_tokens(concept)}
        if concept_terms and concept_terms <= answer_terms:
            matched.append(concept)
        else:
            unmatched.append(concept)

    return {
        "score": score,
        "good": score >= GOOD_THRESHOLD,
        "matched": matched,
        "unmatched": unmatched,
        "total": len(concepts) or len(profile.phrases),
        "parts": parts,
        "coverage": detail["coverage"],
        "phrase_coverage": detail["phrase_coverage"],
        "matched_terms": detail["matched_terms"],
        "missing_terms": detail["missing_terms"],
    }


__all__ = [
    "SYNONYM_GROUPS",
    "PHRASE_SYNONYMS",
    "GOOD_THRESHOLD",
    "has_substance",
    "normalize",
    "parse_three_parts",
    "score_response",
]
