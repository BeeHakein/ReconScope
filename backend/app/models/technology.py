"""
Technology model.

Represents a technology component (web server, framework, CMS, language, etc.)
detected on a :class:`~app.models.service.Service`.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Optional

from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.service import Service


class Technology(Base):
    """A technology stack component detected on a service.

    Detection confidence is expressed as an integer percentage (0-100) where
    100 means the technology was positively fingerprinted and lower values
    indicate heuristic or partial matches.

    Attributes:
        id: UUID primary key, auto-generated.
        service_id: Foreign key to the parent :class:`~app.models.service.Service`.
        name: Technology name (e.g. ``nginx``, ``WordPress``, ``jQuery``).
        version: Detected version string, if available.
        category: Classification bucket (``web_server``, ``framework``, ``cms``,
            ``language``, ``js_library``, ``cdn``, etc.).
        confidence: Detection confidence as an integer percentage (0--100).
        service: Parent :class:`~app.models.service.Service` relationship.
    """

    __tablename__ = "technologies"

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
    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    version: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )
    category: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )
    confidence: Mapped[int] = mapped_column(
        Integer,
        default=50,
        nullable=False,
        server_default="50",
    )

    # -- Relationships ---------------------------------------------------------
    service: Mapped[Service] = relationship(
        "Service",
        back_populates="technologies",
        lazy="joined",
    )

    def __repr__(self) -> str:
        version_str = f"/{self.version}" if self.version else ""
        return (
            f"<Technology {self.name}{version_str} "
            f"confidence={self.confidence}% service_id={self.service_id}>"
        )
