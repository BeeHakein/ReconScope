"""
Correlation model.

Represents an insight discovered by the correlation engine during scan
post-processing.  Correlations identify patterns across multiple assets
such as shared subnets, forgotten staging environments, certificate issues,
or technology exposure patterns.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Optional

from sqlalchemy import ForeignKey, JSON, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.scan import Scan


class Correlation(Base):
    """A cross-asset correlation insight from the correlation engine.

    The correlation engine analyses all scan data to surface relationships and
    patterns that individual modules cannot detect in isolation.

    Attributes:
        id: UUID primary key, auto-generated.
        scan_id: Foreign key to the parent :class:`~app.models.scan.Scan`.
        correlation_type: Category of the correlation (``subnet``,
            ``forgotten_asset``, ``exposure``, ``cert``, ``tech``).
        severity: Qualitative severity of the insight (``critical``, ``high``,
            ``medium``, ``low``, ``info``).
        message: Human-readable explanation of the correlation finding.
        affected_assets: JSON list of asset identifiers involved in this
            correlation.
        scan: Parent :class:`~app.models.scan.Scan` relationship.
    """

    __tablename__ = "correlations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    correlation_type: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )
    severity: Mapped[Optional[str]] = mapped_column(
        String(20),
        nullable=True,
    )
    message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    affected_assets: Mapped[Optional[list]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
        server_default="[]",
    )

    # -- Relationships ---------------------------------------------------------
    scan: Mapped[Scan] = relationship(
        "Scan",
        back_populates="correlations",
        lazy="joined",
    )

    def __repr__(self) -> str:
        return (
            f"<Correlation type={self.correlation_type!r} "
            f"severity={self.severity!r} scan_id={self.scan_id}>"
        )
