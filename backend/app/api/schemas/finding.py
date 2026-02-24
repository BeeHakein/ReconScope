"""
Pydantic v2 schemas for findings, attack paths, and correlations.

These schemas serialise the post-processing results produced by the
Correlation Engine, Risk Scorer, and Attack Path Inference Engine.
"""

from __future__ import annotations

from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class FindingResponse(BaseModel):
    """A prioritised finding generated during post-processing.

    Attributes:
        id: Primary key of the finding record.
        severity: Textual severity level (``critical``, ``high``,
            ``medium``, ``low``, ``info``).
        title: Short human-readable title.
        description: Detailed explanation of the finding.
        asset: The affected asset identifier (e.g.
            ``staging.acme-corp.de:443``).
        risk_score: Weighted risk score (0 -- 100) computed by the
            :class:`~app.engine.risk_scoring.RiskScorer`.
        cvss_score: Raw CVSS base score if the finding is CVE-related.
        evidence: Arbitrary evidence payload (headers, banners, etc.).
    """

    id: UUID
    severity: str
    title: str
    description: Optional[str] = None
    asset: Optional[str] = None
    risk_score: Optional[float] = None
    cvss_score: Optional[float] = None
    evidence: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class AttackPathStepSchema(BaseModel):
    """A single step inside an inferred attack path.

    Attributes:
        description: Human-readable explanation of what the attacker
            would do at this step.
        node_id: Identifier of the graph node associated with this step.
        technique: MITRE ATT&CK technique ID (e.g. ``T1190``).
    """

    description: str
    node_id: str
    technique: str

    model_config = ConfigDict(from_attributes=True)


class AttackPathResponse(BaseModel):
    """An inferred attack path linking multiple assets.

    Attributes:
        id: Primary key of the attack-path record.
        severity: Overall severity of the path (``critical``, ``high``,
            ``medium``, ``low``).
        title: Short descriptive title.
        steps: Ordered sequence of attack steps.
        affected_nodes: List of graph-node identifiers touched by this
            path.
    """

    id: UUID
    severity: str
    title: Optional[str] = None
    steps: list[AttackPathStepSchema] = Field(default_factory=list)
    affected_nodes: list[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class CorrelationResponse(BaseModel):
    """An insight produced by the Correlation Engine.

    Attributes:
        id: Primary key of the correlation record.
        correlation_type: Category of the correlation (``subnet``,
            ``forgotten_asset``, ``exposure``, ``cert``,
            ``tech_inconsistency``).
        severity: Severity level of the insight.
        message: Detailed human-readable explanation.
        affected_assets: List of asset identifiers involved.
    """

    id: UUID
    correlation_type: Optional[str] = None
    severity: Optional[str] = None
    message: Optional[str] = None
    affected_assets: list[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)
