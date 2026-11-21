from __future__ import annotations

import re
from typing import Any, Optional

from app.core.logging import get_logger
from app.services.detector.patterns import compile_patterns

logger = get_logger(__name__)

SENSITIVITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
}

SENSITIVITY_LEVELS = ["Public", "Internal", "Confidential", "Highly Confidential", "Critical"]


class SensitiveDataDetector:
    def __init__(self):
        self.patterns = compile_patterns()

    def analyze(self, text: Optional[str], filename: str = "") -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        matched_categories: set[str] = set()
        matched_severities: dict[str, int] = {}
        matched_names: dict[str, int] = {}

        if not text:
            return self._build_result([], 0, "Public", 0, "No content to analyze")

        for name, severity, category, pattern in self.patterns:
            try:
                matches = pattern.findall(text)
                if not matches:
                    continue

                count = len(matches)
                context_window = 80

                for match_value in list(set(matches))[:3]:
                    idx = text.find(str(match_value))
                    start = max(0, idx - context_window)
                    end = min(len(text), idx + len(str(match_value)) + context_window)
                    context = text[start:end].replace("\n", " ").strip()

                    if match_value and len(str(match_value).strip()) >= 3:
                        findings.append({
                            "finding_type": name,
                            "value": str(match_value)[:200],
                            "context": str(context)[:300],
                            "count": count,
                            "severity": severity,
                            "category": category,
                        })

                matched_categories.add(category)
                matched_severities[severity] = matched_severities.get(severity, 0) + count
                matched_names[name] = matched_names.get(name, 0) + count

            except re.error:
                continue

        risk_score, sensitivity_level, explanation = self._calculate_risk(
            matched_severities, matched_categories, matched_names
        )

        findings.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2}.get(x["severity"], 3))

        return self._build_result(
            findings, risk_score, sensitivity_level, len(findings), explanation
        )

    def _calculate_risk(
        self,
        severities: dict[str, int],
        categories: set[str],
        names: dict[str, int],
    ) -> tuple[float, str, str]:
        score = 0.0
        reasons: list[str] = []

        for sev, count in severities.items():
            weight = SENSITIVITY_WEIGHTS.get(sev, 5)
            score += min(weight * count * 0.5, 40.0)

        unique_types = len(names)
        score += min(unique_types * 5, 20.0)

        if "Credentials" in categories or "Crypto" in categories:
            score += 15.0
            reasons.append("Contains credentials or cryptographic keys")

        if "Cloud" in categories:
            score += 10.0
            reasons.append("Contains cloud infrastructure credentials")

        if "Financial" in categories:
            score += 10.0
            reasons.append("Contains financial information")

        if "PII" in categories:
            score += 10.0
            reasons.append("Contains personally identifiable information")

        if "Infrastructure" in categories:
            score += 5.0
            reasons.append("Contains infrastructure configuration details")

        score = min(score, 100.0)

        if score >= 70:
            level = "Critical"
        elif score >= 45:
            level = "Highly Confidential"
        elif score >= 25:
            level = "Confidential"
        elif score >= 10:
            level = "Internal"
        else:
            level = "Public"

        if not reasons:
            if score > 0:
                reasons.append(f"Contains {int(unique_types)} type(s) of sensitive data")
            else:
                reasons.append("No sensitive data patterns detected")

        explanation = "; ".join(reasons)

        return round(score, 1), level, explanation

    def _build_result(
        self,
        findings: list[dict],
        risk_score: float,
        sensitivity_level: str,
        finding_count: int,
        explanation: str,
    ) -> dict[str, Any]:
        return {
            "findings": findings,
            "risk_score": risk_score,
            "sensitivity_level": sensitivity_level,
            "finding_count": finding_count,
            "explanation": explanation,
        }
