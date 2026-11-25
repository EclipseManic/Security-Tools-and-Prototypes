"""Offline response scorer: paraphrase tolerance and failure modes."""

from __future__ import annotations

import pytest

from core.response_scorer import (
    GOOD_THRESHOLD,
    has_substance,
    score_response,
    split_reference_answer,
)
from scenarios.loader import SCENARIO_BY_ID

RANSOMWARE_ID = "ransomware___file_server_encryption"
VPN_ID = "vpn_credential_stuffing"


@pytest.fixture(scope="module")
def ransomware_phase():
    return SCENARIO_BY_ID[RANSOMWARE_ID].phases[0]


@pytest.fixture(scope="module")
def vpn_phase():
    return SCENARIO_BY_ID[VPN_ID].phases[0]


def _score(phase, answer: str) -> dict:
    return score_response(answer, phase.ideal_concepts, phase.reference_answer)


def test_reference_answer_scores_ten(ransomware_phase) -> None:
    action, _why = split_reference_answer(ransomware_phase.reference_answer)
    result = _score(ransomware_phase, action)
    assert result["score"] == 10.0
    assert result["good"] is True


@pytest.mark.parametrize(
    "answer",
    [
        "Isolate WS-JMARTINEZ-04 from the network immediately, block the C2 IP "
        "at the firewall, and capture a memory dump for forensics.",
        "Take the workstation off the network right away, block the attacker's "
        "command-and-control address at the perimeter, and preserve host memory "
        "for analysis.",
    ],
)
def test_good_paraphrases_pass(ransomware_phase, answer: str) -> None:
    result = _score(ransomware_phase, answer)
    assert result["score"] >= GOOD_THRESHOLD, result
    assert result["good"] is True


@pytest.mark.parametrize(
    "answer",
    [
        "Disconnect the endpoint, stop the beacon reaching the internet, and "
        "save a forensic image of RAM.",
        "Reset the user's password and tell them to be more careful about phishing.",
        "Patch the server.",
    ],
)
def test_partial_or_wrong_answers_fail(ransomware_phase, answer: str) -> None:
    result = _score(ransomware_phase, answer)
    assert result["score"] < GOOD_THRESHOLD, result
    assert result["good"] is False


def test_vpn_log_answer_passes(vpn_phase) -> None:
    answer = (
        "Query Splunk for GlobalProtect authentication logs between 02:00 and "
        "04:00 UTC, focus on successful sign-ins from Tor or foreign IP addresses, "
        "and compare with Active Directory group membership to identify compromised "
        "accounts and their privileges."
    )
    result = _score(vpn_phase, answer)
    assert result["score"] >= GOOD_THRESHOLD, result


def test_vpn_weak_answer_fails(vpn_phase) -> None:
    result = _score(vpn_phase, "Check the VPN logs and reset the affected user password.")
    assert result["score"] < GOOD_THRESHOLD, result


@pytest.mark.parametrize("answer", ["", "   ", "idk", "???", "ok"])
def test_no_substance_scores_zero(ransomware_phase, answer: str) -> None:
    result = _score(ransomware_phase, answer)
    assert result["score"] == 0.0
    assert result["good"] is False
    assert has_substance(answer) is False


def test_split_reference_answer() -> None:
    action, why = split_reference_answer(
        "Do the thing.\n\nWhy: because it stops the bleeding."
    )
    assert action == "Do the thing."
    assert why == "because it stops the bleeding."
    assert split_reference_answer("") == ("", "")
    assert split_reference_answer("Only an action.") == ("Only an action.", "")


def test_result_shape(ransomware_phase) -> None:
    result = _score(ransomware_phase, "Isolate the host and preserve memory.")
    for key in (
        "score", "good", "matched", "unmatched", "total", "parts",
        "coverage", "phrase_coverage", "matched_terms", "missing_terms",
    ):
        assert key in result
    assert 0.0 <= result["score"] <= 10.0
    assert set(result["parts"]) == {"what", "action", "why"}
