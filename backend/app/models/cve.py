"""
CVEMatch model.

Represents a CVE (Common Vulnerabilities and Exposures) entry matched to a
:class:`~app.models.service.Service` based on its technology fingerprint and
version information.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.service import Service


class CVEMatch(Base):
    """A CVE matched against a detected service or technology.

    Stores the full CVE identifier, CVSS scoring information, severity
    classification, and a human-readable description.

    Attributes:
        id: UUID primary key, auto-generated.
        service_id: Foreign key to the parent :class:`~app.models.service.Service`.
        cve_id: Official CVE identifier (e.g. ``CVE-2021-41773``), indexed for
            efficient querying across scans.
        cvss_score: CVSS base score (0.0--10.0).
        cvss_vector: Full CVSS vector string
            (e.g. ``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``).
        severity: Qualitative severity label (``critical``, ``high``, ``medium``,
            ``low``, ``info``).
        description: Human-readable description of the vulnerability.
        published_date: Date the CVE was originally published by the issuing
            authority.
        service: Parent :class:`~app.models.service.Service` relationship.
    """

    __tablename__ = "cve_matches"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    service_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("services.id", ondelete="CASCADE"),
        nullable=False,
    )
    cve_id: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )
    cvss_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    cvss_vector: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    severity: Mapped[Optional[str]] = mapped_column(
        String(20),
        nullable=True,
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    published_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    epss_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    epss_percentile: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )

    # -- Relationships ---------------------------------------------------------
    service: Mapped[Service] = relationship(
        "Service",
        back_populates="cves",
        lazy="joined",
    )

    def __repr__(self) -> str:
        return (
            f"<CVEMatch {self.cve_id} cvss={self.cvss_score} "
            f"severity={self.severity!r} service_id={self.service_id}>"
        )
