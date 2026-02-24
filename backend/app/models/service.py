"""
Service model.

Represents a network service discovered on a
:class:`~app.models.subdomain.Subdomain`.  Each service may host
:class:`~app.models.technology.Technology` stacks and match known
:class:`~app.models.cve.CVEMatch` vulnerabilities.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Optional

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.cve import CVEMatch
    from app.models.subdomain import Subdomain
    from app.models.technology import Technology


class Service(Base):
    """A network service running on a subdomain.

    Captures the port, protocol, identified service name, version, and raw
    banner.  Serves as the parent for technology detection results and CVE
    matches.

    Attributes:
        id: UUID primary key, auto-generated.
        subdomain_id: Foreign key to the parent :class:`~app.models.subdomain.Subdomain`.
        port: TCP/UDP port number the service listens on.
        protocol: Transport protocol (``tcp`` or ``udp``).
        service_name: Human-readable service identifier (e.g. ``nginx``, ``openssh``).
        version: Detected version string.
        banner: Raw service banner captured during probing.
        subdomain: Parent :class:`~app.models.subdomain.Subdomain` relationship.
        technologies: Technology stacks detected on this service.
        cves: CVE matches associated with this service.
    """

    __tablename__ = "services"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    subdomain_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("subdomains.id", ondelete="CASCADE"),
        nullable=False,
    )
    port: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    protocol: Mapped[str] = mapped_column(
        String(10),
        default="tcp",
        nullable=False,
        server_default="tcp",
    )
    service_name: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    version: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    banner: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # -- Relationships ---------------------------------------------------------
    subdomain: Mapped[Subdomain] = relationship(
        "Subdomain",
        back_populates="services",
        lazy="joined",
    )
    technologies: Mapped[list[Technology]] = relationship(
        "Technology",
        back_populates="service",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    cves: Mapped[list[CVEMatch]] = relationship(
        "CVEMatch",
        back_populates="service",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return (
            f"<Service {self.service_name}:{self.port}/{self.protocol} "
            f"subdomain_id={self.subdomain_id}>"
        )
