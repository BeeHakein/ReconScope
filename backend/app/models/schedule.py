"""
ScanSchedule model for recurring scan scheduling.

Stores cron-like schedule definitions that trigger periodic scans
of configured targets.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, String, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ScanSchedule(Base):
    """A recurring scan schedule.

    Attributes:
        id: UUID primary key, auto-generated.
        target: Domain to scan (e.g. ``acme-corp.de``).
        modules: JSON list of module identifiers to execute.
        cron_expression: Cron schedule string (e.g. ``"0 2 * * 1"``
            for every Monday at 02:00 UTC).
        is_active: Whether the schedule is enabled.
        last_run_at: Timestamp of the most recent execution.
        next_run_at: Timestamp of the next scheduled execution.
        created_at: When the schedule was created.
    """

    __tablename__ = "scan_schedules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    target: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
    )
    modules: Mapped[Optional[list]] = mapped_column(
        JSON,
        nullable=True,
    )
    cron_expression: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="0 2 * * 1",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    last_run_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    next_run_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return (
            f"<ScanSchedule target={self.target!r} "
            f"cron={self.cron_expression!r} active={self.is_active}>"
        )
