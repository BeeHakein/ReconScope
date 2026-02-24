"""
Subdomain model.

Represents a subdomain discovered during a reconnaissance scan.  Each
subdomain belongs to exactly one :class:`~app.models.scan.Scan` and may
host zero or more :class:`~app.models.service.Service` instances.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.scan import Scan
    from app.models.service import Service


class Subdomain(Base):
    """A subdomain discovered during a scan.

    Stores DNS resolution data, WHOIS information, and liveness status.
    Acts as the parent for :class:`~app.models.service.Service` records
    that describe what is running on this subdomain.

    Attributes:
        id: UUID primary key, auto-generated.
        scan_id: Foreign key to the parent :class:`~app.models.scan.Scan`.
        name: The fully-qualified subdomain name (indexed for fast lookup).
        ip_address: Resolved IPv4 or IPv6 address (up to 45 characters).
        source: Name of the recon module that discovered this subdomain.
        is_alive: Whether the subdomain responds to probes.
        dns_records: JSON blob with A, AAAA, CNAME, MX, TXT, etc. records.
        whois_data: JSON blob with parsed WHOIS information.
        discovered_at: Timestamp when the subdomain was first recorded.
        scan: Parent :class:`~app.models.scan.Scan` relationship.
        services: Services running on this subdomain.
    """

    __tablename__ = "subdomains"

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
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )
    source: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )
    is_alive: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        server_default="false",
    )
    dns_records: Mapped[Optional[dict]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
        server_default="{}",
    )
    whois_data: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
    )
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # -- Relationships ---------------------------------------------------------
    scan: Mapped[Scan] = relationship(
        "Scan",
        back_populates="subdomains",
        lazy="joined",
    )
    services: Mapped[list[Service]] = relationship(
        "Service",
        back_populates="subdomain",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<Subdomain name={self.name!r} ip={self.ip_address} scan_id={self.scan_id}>"
