from __future__ import annotations


from app.services.detector.sensitive_data_detector import SensitiveDataDetector


def test_detect_empty():
    detector = SensitiveDataDetector()
    result = detector.analyze("")
    assert result["risk_score"] == 0
    assert result["sensitivity_level"] == "Public"


def test_detect_email():
    detector = SensitiveDataDetector()
    text = "Contact me at john.doe@example.com for details."
    result = detector.analyze(text)
    assert result["finding_count"] >= 1
    types = [f["finding_type"] for f in result["findings"]]
    assert "Email Address" in types


def test_detect_api_key():
    detector = SensitiveDataDetector()
    text = "api_key = sk-abc123def456ghi789jkl"
    result = detector.analyze(text)
    assert result["finding_count"] >= 1
    assert result["risk_score"] > 0


def test_detect_aws_key():
    detector = SensitiveDataDetector()
    text = "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE"
    result = detector.analyze(text)
    assert result["finding_count"] >= 1


def test_detect_private_key():
    detector = SensitiveDataDetector()
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA"
    result = detector.analyze(text)
    assert result["finding_count"] >= 1
    assert result["risk_score"] > 25
    assert result["sensitivity_level"] in ("Confidential", "Highly Confidential", "Critical")


def test_detect_password():
    detector = SensitiveDataDetector()
    text = "password = SuperSecret123!"
    result = detector.analyze(text)
    assert result["finding_count"] >= 1


def test_detect_credit_card():
    detector = SensitiveDataDetector()
    text = "My card is 4111-1111-1111-1111"
    result = detector.analyze(text)
    assert result["finding_count"] >= 1


def test_detect_no_false_positives():
    detector = SensitiveDataDetector()
    text = "The quick brown fox jumps over the lazy dog. Today is a sunny day."
    result = detector.analyze(text)
    assert result["finding_count"] == 0
    assert result["risk_score"] == 0
    assert result["sensitivity_level"] == "Public"


def test_risk_score_public():
    detector = SensitiveDataDetector()
    result = detector.analyze("This is a public document with no sensitive information.")
    assert result["sensitivity_level"] == "Public"
    assert result["risk_score"] == 0
