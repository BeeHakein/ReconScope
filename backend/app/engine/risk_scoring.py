"""
Context-aware risk scoring for ReconScope findings.

Unlike a raw CVSS score, the :class:`RiskScorer` combines vulnerability
severity with environmental context -- asset type, Internet exposure,
exploit availability, service criticality, and patch age -- to produce a
weighted score on a 0--100 scale.
"""

from __future__ import annotations

from typing import Any


class RiskScorer:
    """Calculate a context-aware risk score (0--100) for a finding.

    The scorer applies six weighted factors defined in :attr:`WEIGHTS` to
    produce a single numeric score.  The factors and their default weights
    are:

    ============== ======= =============================================
    Factor         Weight  Description
    ============== ======= =============================================
    cvss_base        0.35  CVSS Base Score normalised to 0--100
    internet_exposure 0.20 Whether the asset is Internet-facing
    asset_type       0.15  Dev/staging assets score higher
    exploit_availability 0.15 Public exploit existence
    service_criticality 0.10 Business criticality of the service
    patch_age        0.05  Age of the vulnerability
    ============== ======= =============================================

    Example::

        scorer = RiskScorer()
        score = scorer.calculate_score({
            "cvss_score": 9.8,
            "internet_facing": True,
            "asset": "staging.acme-corp.de",
            "has_public_exploit": True,
            "service_type": "database",
        })
        severity = scorer.score_to_severity(score)
    """

    WEIGHTS: dict[str, float] = {
        "cvss_base": 0.35,
        "internet_exposure": 0.20,
        "asset_type": 0.15,
        "exploit_availability": 0.15,
        "service_criticality": 0.10,
        "patch_age": 0.05,
    }

    def calculate_score(self, finding: dict[str, Any]) -> float:
        """Compute the weighted risk score for a single finding.

        Args:
            finding: A dictionary describing the finding.  Recognised keys:

                * ``cvss_score`` (float | None) -- raw CVSS 0--10
                * ``internet_facing`` (bool) -- ``True`` if directly exposed
                * ``asset`` (str) -- subdomain or asset identifier
                * ``has_public_exploit`` (bool) -- ``True`` when a PoC exists
                * ``service_type`` (str) -- e.g. ``"database"``, ``"mail"``

        Returns:
            A float in the range 0.0--100.0, rounded to one decimal place.
        """
        scores: dict[str, float] = {}

        # 1. CVSS Base Score normalised to 0--100.
        cvss: float = finding.get("cvss_score") or 0.0
        scores["cvss_base"] = (cvss / 10.0) * 100.0

        # 2. Internet Exposure.
        scores["internet_exposure"] = (
            100.0 if finding.get("internet_facing", True) else 30.0
        )

        # 3. Asset Type -- forgotten / dev assets are more likely unpatched.
        asset_name: str = (finding.get("asset") or "").lower()
        if any(
            keyword in asset_name
            for keyword in ("staging", "dev", "test", "old")
        ):
            scores["asset_type"] = 90.0
        elif any(
            keyword in asset_name for keyword in ("mail", "vpn", "api")
        ):
            scores["asset_type"] = 70.0
        else:
            scores["asset_type"] = 50.0

        # 4. Exploit Availability.
        scores["exploit_availability"] = (
            95.0 if finding.get("has_public_exploit") else 40.0
        )

        # 5. Service Criticality.
        critical_services: list[str] = ["database", "mail", "vpn", "admin"]
        service_type: str = (finding.get("service_type") or "").lower()
        scores["service_criticality"] = (
            90.0
            if any(svc in service_type for svc in critical_services)
            else 50.0
        )

        # 6. Patch Age -- default heuristic, to be refined with CVE dates.
        scores["patch_age"] = 80.0

        # Weighted sum.
        total: float = sum(
            scores.get(factor, 50.0) * weight
            for factor, weight in self.WEIGHTS.items()
        )

        return round(min(100.0, max(0.0, total)), 1)

    @staticmethod
    def score_to_severity(score: float) -> str:
        """Map a numeric risk score to a severity label.

        Args:
            score: A risk score in the range 0--100.

        Returns:
            One of ``"critical"``, ``"high"``, ``"medium"``, ``"low"``,
            or ``"info"``.
        """
        if score >= 80.0:
            return "critical"
        if score >= 60.0:
            return "high"
        if score >= 40.0:
            return "medium"
        if score >= 20.0:
            return "low"
        return "info"
