from __future__ import annotations

import re
from typing import Pattern

SensitivePattern = tuple[str, str, str, str]  # (name, severity, category, regex)


def _c(name: str, severity: str, category: str, regex: str) -> SensitivePattern:
    return (name, severity, category, regex)


PATTERNS: list[SensitivePattern] = [
    # === PII ===
    _c("Email Address", "medium", "PII",
      r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    _c("Phone Number", "medium", "PII",
      r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    _c("SSN (US)", "high", "PII",
      r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    _c("Passport (Generic)", "high", "PII",
      r"\b[A-Z]{1,2}\d{6,9}\b"),
    _c("PAN (India)", "high", "PII",
      r"\b[A-Z]{5}\d{4}[A-Z]\b"),
    _c("Aadhaar (India)", "high", "PII",
      r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
    _c("Bank Account (Generic)", "high", "Financial",
      r"\b\d{9,18}\b(?=.*(?:account|acct|a/c|bank))"),
    _c("Credit Card", "high", "Financial",
      r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    _c("IFSC Code (India)", "medium", "Financial",
      r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
    _c("SWIFT / BIC", "medium", "Financial",
      r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"),

    # === Credentials ===
    _c("Password", "critical", "Credentials",
      r"(?i)(?:password|passwd|pwd|secret)\s*[=:]\s*\S+"),
    _c("API Key (Generic)", "critical", "Credentials",
      r"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*\S+"),
    _c("Bearer Token", "critical", "Credentials",
      r"(?i)bearer\s+[A-Za-z0-9._\-+/=]{20,}"),
    _c("JWT Token", "critical", "Credentials",
      r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    _c("OAuth Token", "critical", "Credentials",
      r"(?i)(?:oauth|access_token|refresh_token)\s*[=:]\s*\S+"),
    _c("Session Cookie", "high", "Credentials",
      r"(?i)(?:session|connect\.sid|auth_token|cookie)\s*[=:]\s*\S+"),

    # === Cloud Credentials ===
    _c("AWS Access Key", "critical", "Cloud",
      r"\bAKIA[0-9A-Z]{16}\b"),
    _c("AWS Secret Key", "critical", "Cloud",
      r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*\S+"),
    _c("GCP Service Account", "critical", "Cloud",
      r"\b[0-9]{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com\b"),
    _c("GCP JSON Key (Service Account)", "critical", "Cloud",
      r'"type"\s*:\s*"service_account"'),
    _c("Azure Connection String", "critical", "Cloud",
      r"(?i)(?:DefaultEndpointsProtocol|AccountName|AccountKey)\s*=\s*\S+"),
    _c("Azure Subscription Key", "critical", "Cloud",
      r"(?i)(?:subscription[_-]?key|ocp-apim-subscription-key)\s*[=:]\s*\S+"),

    # === Private Keys & Certificates ===
    _c("RSA Private Key", "critical", "Crypto",
      r"-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----"),
    _c("DSA Private Key", "critical", "Crypto",
      r"-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----"),
    _c("EC Private Key", "critical", "Crypto",
      r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----"),
    _c("OpenSSH Private Key", "critical", "Crypto",
      r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----"),
    _c("PGP Private Key", "critical", "Crypto",
      r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----"),
    _c("Certificate (PEM)", "high", "Crypto",
      r"-----BEGIN\s+CERTIFICATE-----"),
    _c("Mnemonic Phrase (BIP39)", "critical", "Crypto",
      r"\b(?:abandon|ability|able|about|above|absent|absorb|abstract|abuse|account|accuse|achieve|acid|acoustic|acquire|across|act|action|actor|actress|actual|adapt|add|addict|address|adjust|admit|adult|advance|advice|aerobic|affair|afford|afraid|again|age)\s+(?:\w+\s+){11,23}\w+\b"),

    # === Infrastructure ===
    _c("Database Connection String", "critical", "Infrastructure",
      r"(?i)(?:mongodb|postgresql|mysql|redis|jdbc|sqlite):\/\/\S+"),
    _c("SSH Connection String", "high", "Infrastructure",
      r"(?i)ssh\s+\S+@\S+"),
    _c("Internal IP Address", "high", "Infrastructure",
      r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"),
    _c("Private Hostname", "medium", "Infrastructure",
      r"\b(?:localhost|docker[_-]?\w*|dev[_-]?\w*|staging[_-]?\w*|test[_-]?\w*)\.?\w*\b"),
    _c("Slack Token", "critical", "Credentials",
      r"(?i)xox[baprs]-[0-9A-Za-z-]{10,}"),
    _c("GitHub Token", "critical", "Credentials",
      r"(?i)(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}"),
    _c("Gitlab Token", "critical", "Credentials",
      r"(?i)glpat-[0-9A-Za-z_-]{20,}"),
    _c("Docker Config (auths)", "high", "Infrastructure",
      r'"auths"\s*:\s*\{'),
    _c("Kubernetes Token", "critical", "Infrastructure",
      r"(?i)kubectl\s+.*--token\s+\S+"),

    # === URLs & Networking ===
    _c("Internal URL (HTTP)", "medium", "Network",
      r"\bhttp://(?:localhost|127\.0\.0\.1|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\S+"),
    _c("Webhook URL", "high", "Network",
      r"(?i)https?://[^\s/]+/webhook[s]?/[^\s]+"),
    _c("Callback URL", "medium", "Network",
      r"(?i)(?:callback|redirect|return_url|redirect_uri)\s*[=:]\s*\S+"),

    # === Technology-specific ===
    _c("SQL Query (SELECT)", "medium", "Technical",
      r"(?i)\bSELECT\s+.+\s+FROM\b"),
    _c("SQL Query (INSERT)", "medium", "Technical",
      r"(?i)\bINSERT\s+INTO\b"),
    _c("Shell Command (dangerous)", "high", "Technical",
      r"(?i)(?:rm\s+-rf\s+[/*]|curl\s+.*\||wget\s+.*\||chmod\s+777|dd\s+if=)"),
    _c("PowerShell Command", "medium", "Technical",
      r"(?i)(?:Invoke-Expression|Invoke-Command|Start-Process|Get-WmiObject|Invoke-WebRequest)"),
    _c("Registry Path (Windows)", "medium", "Technical",
      r"\bHKEY_[A-Z_]+\\\S+"),
    _c("Environment Variable", "medium", "Technical",
      r"(?i)(?:export\s+|set\s+|env\s+)[A-Z_]+="),

    _c("Base64 (high entropy, long)", "medium", "Technical",
      r"\b(?:[A-Za-z0-9+/]{40,}={0,2})\b"),
]


def compile_patterns() -> list[tuple[str, str, str, Pattern[str]]]:
    compiled: list[tuple[str, str, str, Pattern[str]]] = []
    for name, severity, category, regex in PATTERNS:
        try:
            compiled.append((name, severity, category, re.compile(regex)))
        except re.error:
            pass
    return compiled
