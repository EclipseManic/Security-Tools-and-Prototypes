from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.file import FileCategory, FileRecord
from app.models.insight import ScanInsight

logger = get_logger(__name__)

SIZE_RANGES = [
    (1024, "tiny"),
    (102400, "small"),
    (1048576, "medium"),
    (10485760, "large"),
    (104857600, "xlarge"),
]

FINDING_CATEGORIES = {
    "email": "Email Address",
    "phone": "Phone Number",
    "ip": "IP Address",
    "url": "URL",
    "api_key": "API Key",
    "password": "Password",
    "credit_card": "Credit Card",
    "ssn": "SSN",
    "crypto": "Cryptocurrency Address",
    "secret": "Secret Key",
    "token": "Auth Token",
    "jwt": "JWT Token",
    "private_key": "Private Key",
    "aws_key": "AWS Access Key",
    "gcp_key": "GCP Service Key",
    "github_token": "GitHub Token",
    "slack_token": "Slack Token",
    "generic_secret": "Generic Secret",
}


def _size_to_range(size: int) -> str:
    for threshold, label in SIZE_RANGES:
        if size < threshold:
            return label
    return "xlarge"


BATCH_ANALYSIS_PROMPT = """You are a file intelligence analyst reviewing anonymized file metadata from a security scan. Your task is to analyze patterns across all files and provide insights that purely local analysis cannot.

You will receive a JSON array of anonymized file summaries. Each entry has:
- `id`: Dummy identifier (use this in your response)
- `ext`: File extension
- `size_range`: File size category (tiny/small/medium/large/xlarge)
- `category`: Category determined by local analysis
- `sha256`: SHA256 hash of the file (use this to check against known malware, malicious files, or identify known software/OS files based on your training data)
- `analyzer_type`: Type of local analyzer used
- `findings_types`: TYPES of sensitive data found (not actual values) - e.g., ["Email Address", "API Key"]
- `has_text`: Whether extractable text was found in the file
- `mime_group`: Broad MIME type category

Use the SHA256 hashes to:
- Flag any hashes that match known malware, ransomware, or malicious files
- Identify known system/OS files that can be safely ignored
- Detect duplicate files (same hash across multiple entries)
- Cross-reference file extensions with known file type signatures

Return ONLY valid JSON with this exact structure:
{{
  "executive_summary": "2-3 sentence natural language summary of the overall scan findings, highlighting key risks and patterns",
  "threats_found": [
    {{
      "id": "file dummy id",
      "threat_type": "malware/known_malicious/suspicious/ransomware/trojan",
      "confidence": "low/medium/high",
      "details": "what this threat indicator means"
    }}
  ],
  "known_safe_files": [
    {{
      "id": "file dummy id",
      "description": "what this known file is (e.g. Windows system file, common application)",
      "confidence": "low/medium/high"
    }}
  ],
  "priority_ranking": [
    {{
      "id": "file dummy id",
      "priority_score": 0-10,
      "reason": "why this file needs attention"
    }}
  ],
  "refined_subcategories": [
    {{
      "id": "file dummy id",
      "subcategory": "suggested subcategory for this file type",
      "confidence": 0.0-1.0
    }}
  ],
  "anomalies": [
    {{
      "description": "description of unusual pattern",
      "file_ids": ["list of relevant file dummy ids"],
      "severity": "low/medium/high"
    }}
  ],
  "recommendations": [
    {{
      "recommendation": "actionable security or organization recommendation",
      "priority": "low/medium/high",
      "context": "why this matters"
    }}
  ]
}}

Focus on actionable insights. Use the SHA256 hashes to identify known threats or safe files based on your training knowledge.
If no sensitive data or threats were found, note that as a positive finding.
Do NOT include any raw file content, real filenames, or actual sensitive values in your response.

Anonymized File Data:
{file_data}
"""


def _is_quota_error(msg: str) -> bool:
    return any(kw in msg.lower() for kw in ["quota", "exhausted", "resource_exhausted", "429", "rate_limit"])


def _parse_retry_delay(msg: str) -> float:
    m = re.search(r'retryDelay["\']?\s*:\s*["\']?(\d+(?:\.\d+)?)\s*s', msg)
    if m:
        return float(m.group(1))
    m = re.search(r'retry\s+in\s+(\d+(?:\.\d+)?)\s*s', msg, re.IGNORECASE)
    if m:
        return float(m.group(1))
    return 30.0


class AnonymizedBatchAnalyzer:
    def __init__(self, db: AsyncSession, intelligence_service, backup_intelligence=None):
        self.db = db
        self.intelligence = intelligence_service
        self.backup_intelligence = backup_intelligence

    def build_anonymized_payload(self, file_summaries: list[dict]) -> str:
        anonymized = []
        for fs in file_summaries:
            finding_labels = [
                FINDING_CATEGORIES.get(f, f) for f in fs.get("findings_types", [])
            ]
            anonymized.append({
                "id": fs.get("dummy_id", "unknown"),
                "ext": fs.get("ext", ""),
                "size_range": fs.get("size_range", "unknown"),
                "category": fs.get("category", "Unknown"),
                "sha256": fs.get("sha256"),
                "analyzer_type": fs.get("analyzer_type", "unknown"),
                "findings_types": finding_labels,
                "has_text": fs.get("has_text", False),
                "mime_group": fs.get("mime_group", "unknown"),
            })
        return json.dumps(anonymized, indent=2)

    async def analyze(
        self,
        file_summaries: list[dict],
        scan_job_id: int,
    ) -> dict[str, Any]:
        if not file_summaries:
            logger.info("No files to analyze in batch")
            return {}

        anonymized_data = self.build_anonymized_payload(file_summaries)
        prompt = BATCH_ANALYSIS_PROMPT.format(file_data=anonymized_data)

        result = await self._call_with_retry(prompt)
        if not result:
            return {}

        parsed = result.get("parsed", {})
        if not parsed:
            logger.warning("Batch AI returned empty response")
            return {}

        dummy_name_map = {fs["dummy_id"]: fs.get("name", fs["dummy_id"]) for fs in file_summaries}
        self._map_dummy_ids(parsed, dummy_name_map)

        await self._store_results(parsed, file_summaries, scan_job_id)
        return parsed

    def _map_dummy_ids(self, parsed: dict, name_map: dict[str, str]) -> None:
        for key in ("threats_found", "known_safe_files", "priority_ranking"):
            for item in parsed.get(key, []):
                did = item.get("id")
                if did in name_map:
                    item["id"] = name_map[did]
                    item["file_name"] = name_map[did]

        for anomaly in parsed.get("anomalies", []):
            mapped = []
            for fid in anomaly.get("file_ids", []):
                mapped.append(name_map.get(fid, fid))
            if mapped:
                anomaly["file_ids"] = mapped

    async def _call_with_retry(self, prompt: str) -> dict[str, Any]:
        providers = [("primary", self.intelligence)]
        if self.backup_intelligence:
            providers.append(("backup", self.backup_intelligence))

        for label, svc in providers:
            for attempt in range(2):
                try:
                    result = await svc.batch_analyze(prompt)
                except Exception as e:
                    logger.warning("Batch AI %s failed (attempt %d/2): %s", label, attempt + 1, e)
                    if attempt == 0:
                        retry_secs = _parse_retry_delay(str(e))
                        if retry_secs > 0:
                            logger.info("Retrying %s batch AI in %.0f seconds...", label, retry_secs)
                            await asyncio.sleep(retry_secs)
                            continue
                    break

                if not result.get("error"):
                    return result

                err_msg = result["error"]
                logger.warning("Batch AI %s error (attempt %d/2): %s", label, attempt + 1, err_msg)

                if attempt == 0 and _is_quota_error(err_msg):
                    retry_secs = _parse_retry_delay(err_msg)
                    if retry_secs > 0:
                        logger.info("Quota exceeded, retrying %s batch AI in %.0f seconds...", label, retry_secs)
                        await asyncio.sleep(retry_secs)
                        continue

                break

            if label == "primary" and self.backup_intelligence:
                logger.info("Primary AI failed, falling back to Gemini backup...")

        return {}

    async def _store_results(
        self,
        parsed: dict,
        file_summaries: list[dict],
        scan_job_id: int,
    ) -> None:
        dummy_to_record_id: dict[str, int] = {}

        for fs in file_summaries:
            real_path = fs.get("path")
            if real_path:
                r = await self.db.execute(
                    select(FileRecord.id).where(FileRecord.path == real_path)
                )
                row = r.scalar_one_or_none()
                if row:
                    dummy_to_record_id[fs["dummy_id"]] = row

        executive_summary = parsed.get("executive_summary", "")
        if executive_summary:
            insight = ScanInsight(
                scan_job_id=scan_job_id,
                insight_type="executive_summary",
                content={"summary": executive_summary},
            )
            self.db.add(insight)

        recommendations = parsed.get("recommendations", [])
        if recommendations:
            insight = ScanInsight(
                scan_job_id=scan_job_id,
                insight_type="recommendations",
                content={"items": recommendations},
            )
            self.db.add(insight)

        anomalies = parsed.get("anomalies", [])
        if anomalies:
            insight = ScanInsight(
                scan_job_id=scan_job_id,
                insight_type="anomalies",
                content={"items": anomalies},
            )
            self.db.add(insight)

        threats_found = parsed.get("threats_found", [])
        if threats_found:
            insight = ScanInsight(
                scan_job_id=scan_job_id,
                insight_type="threats_found",
                content={"items": threats_found},
            )
            self.db.add(insight)

        known_safe_files = parsed.get("known_safe_files", [])
        if known_safe_files:
            insight = ScanInsight(
                scan_job_id=scan_job_id,
                insight_type="known_safe_files",
                content={"items": known_safe_files},
            )
            self.db.add(insight)

        priority_ranking = parsed.get("priority_ranking", [])
        if priority_ranking:
            insight = ScanInsight(
                scan_job_id=scan_job_id,
                insight_type="priority_ranking",
                content={"items": priority_ranking},
            )
            self.db.add(insight)

        refined_subcategories = parsed.get("refined_subcategories", [])
        for item in refined_subcategories:
            did = item.get("id")
            subcategory = item.get("subcategory")
            confidence = item.get("confidence", 0.0)
            if did and subcategory and did in dummy_to_record_id:
                file_id = dummy_to_record_id[did]
                await self.db.execute(
                    FileCategory.__table__.update()
                    .where(FileCategory.file_id == file_id)
                    .values(
                        subcategory=subcategory,
                        confidence=confidence,
                        explanation=f"AI-refined: {item.get('explanation', '')}",
                    )
                )

        logger.info(
            "Stored batch AI insights for scan %d: summary=%s, threats=%d, safe=%d, recs=%d, anomalies=%d, priority=%d, refined=%d",
            scan_job_id,
            bool(executive_summary),
            len(threats_found),
            len(known_safe_files),
            len(recommendations),
            len(anomalies),
            len(priority_ranking),
            len(refined_subcategories),
        )
