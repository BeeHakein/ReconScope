"""
Pydantic v2 schemas for the attack-surface graph visualisation.

The frontend renders these structures with Cytoscape.js.  Each scan
produces a set of **nodes** (assets) and **edges** (relationships)
that together form the interactive network graph.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class GraphNode(BaseModel):
    """A single node in the attack-surface graph.

    Attributes:
        id: Unique identifier (typically a UUID string or FQDN).
        label: Human-readable label rendered inside the node.
        type: Semantic type used for colouring and filtering.
        risk_level: Qualitative risk level derived from the node's score.
        risk_score: Numeric risk score (0.0 -- 100.0).
        metadata: Arbitrary key/value pairs shown in the detail panel
            (e.g. ``{"ip": "185.23.45.20", "source": "crtsh"}``).
    """

    id: str
    label: str
    type: Literal["domain", "subdomain", "service", "technology", "cve"]
    risk_level: str = "info"
    risk_score: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class GraphEdge(BaseModel):
    """A directed edge connecting two graph nodes.

    Attributes:
        source: ID of the source node.
        target: ID of the target node.
        type: Semantic relationship type rendered as the edge label.
    """

    source: str
    target: str
    type: Literal["resolves_to", "runs_on", "has_vuln", "uses_tech"]

    model_config = ConfigDict(from_attributes=True)


class GraphData(BaseModel):
    """Complete graph payload returned by ``GET /scans/{scan_id}/graph``.

    Attributes:
        nodes: All nodes in the graph.
        edges: All edges in the graph.
    """

    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)
