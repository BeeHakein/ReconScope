"""
Tests for the Risk Scoring engine.

Validates context-aware score calculation for various combinations of
CVSS score, Internet exposure, asset type, exploit availability, and
the score-to-severity mapping function.
"""

from __future__ import annotations

import pytest

from app.engine.risk_scoring import RiskScorer


@pytest.fixture()
def scorer() -> RiskScorer:
    """Return a fresh RiskScorer instance for each test."""
    return RiskScorer()


def test_high_cvss_internet_facing(scorer: RiskScorer) -> None:
    """A CVSS 9.8 Internet-facing finding should produce a high risk score."""
    finding = {
        "cvss_score": 9.8,
        "internet_facing": True,
        "asset": "www.example.com",
        "has_public_exploit": False,
        "service_type": "web",
    }
    score = scorer.calculate_score(finding)

    assert score >= 60.0, f"Expected score >= 60 for high CVSS + internet-facing, got {score}"
    assert score <= 100.0


def test_low_cvss_internal(scorer: RiskScorer) -> None:
    """A CVSS 2.0 internal asset should produce a low risk score."""
    finding = {
        "cvss_score": 2.0,
        "internet_facing": False,
        "asset": "internal.corp.local",
        "has_public_exploit": False,
        "service_type": "web",
    }
    score = scorer.calculate_score(finding)

    assert score < 60.0, f"Expected score < 60 for low CVSS + internal, got {score}"


def test_staging_asset_increases_score(scorer: RiskScorer) -> None:
    """A finding on a staging asset should score higher than the same finding on a generic asset."""
    base_finding = {
        "cvss_score": 5.0,
        "internet_facing": True,
        "has_public_exploit": False,
        "service_type": "web",
    }

    finding_staging = {**base_finding, "asset": "staging.example.com"}
    finding_generic = {**base_finding, "asset": "www.example.com"}

    score_staging = scorer.calculate_score(finding_staging)
    score_generic = scorer.calculate_score(finding_generic)

    assert score_staging > score_generic, (
        f"Staging ({score_staging}) should score higher than generic ({score_generic})"
    )


def test_exploit_available_increases_score(scorer: RiskScorer) -> None:
    """A finding with a public exploit should score higher than one without."""
    base = {
        "cvss_score": 7.0,
        "internet_facing": True,
        "asset": "www.example.com",
        "service_type": "web",
    }

    score_with_exploit = scorer.calculate_score({**base, "has_public_exploit": True})
    score_without_exploit = scorer.calculate_score({**base, "has_public_exploit": False})

    assert score_with_exploit > score_without_exploit, (
        f"With exploit ({score_with_exploit}) should exceed without ({score_without_exploit})"
    )


def test_score_boundaries(scorer: RiskScorer) -> None:
    """Risk score must always be between 0 and 100 inclusive."""
    # Minimum scenario.
    min_finding = {
        "cvss_score": 0.0,
        "internet_facing": False,
        "asset": "safe.internal",
        "has_public_exploit": False,
        "service_type": "unknown",
    }
    min_score = scorer.calculate_score(min_finding)
    assert 0.0 <= min_score <= 100.0, f"Min score out of range: {min_score}"

    # Maximum scenario.
    max_finding = {
        "cvss_score": 10.0,
        "internet_facing": True,
        "asset": "staging.dev.example.com",
        "has_public_exploit": True,
        "service_type": "database",
    }
    max_score = scorer.calculate_score(max_finding)
    assert 0.0 <= max_score <= 100.0, f"Max score out of range: {max_score}"


def test_score_to_severity_mapping(scorer: RiskScorer) -> None:
    """All severity levels should be reachable via score_to_severity."""
    assert scorer.score_to_severity(100.0) == "critical"
    assert scorer.score_to_severity(80.0) == "critical"
    assert scorer.score_to_severity(79.9) == "high"
    assert scorer.score_to_severity(60.0) == "high"
    assert scorer.score_to_severity(59.9) == "medium"
    assert scorer.score_to_severity(40.0) == "medium"
    assert scorer.score_to_severity(39.9) == "low"
    assert scorer.score_to_severity(20.0) == "low"
    assert scorer.score_to_severity(19.9) == "info"
    assert scorer.score_to_severity(0.0) == "info"
