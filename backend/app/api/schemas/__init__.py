"""
Pydantic v2 schemas for the ReconScope REST API.

Re-exports every public schema so consumers can do::

    from app.api.schemas import ScanCreate, ScanResponse, GraphData  # etc.
"""

from app.api.schemas.scan import (
    CVEResponse,
    DeltaResponse,
    ScanCreate,
    ScanDetail,
    ScanListItem,
    ScanProgress,
    ScanResponse,
    ScanStats,
    ServiceResponse,
    SubdomainResponse,
    TechnologyResponse,
)
from app.api.schemas.finding import (
    AttackPathResponse,
    AttackPathStepSchema,
    CorrelationResponse,
    FindingResponse,
)
from app.api.schemas.graph import (
    GraphData,
    GraphEdge,
    GraphNode,
)

__all__: list[str] = [
    # scan
    "ScanCreate",
    "ScanResponse",
    "ScanProgress",
    "ScanStats",
    "ScanDetail",
    "ScanListItem",
    "SubdomainResponse",
    "ServiceResponse",
    "TechnologyResponse",
    "CVEResponse",
    "DeltaResponse",
    # finding
    "FindingResponse",
    "AttackPathStepSchema",
    "AttackPathResponse",
    "CorrelationResponse",
    # graph
    "GraphNode",
    "GraphEdge",
    "GraphData",
]
