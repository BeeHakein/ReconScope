"""
Pydantic schemas for scan schedule endpoints.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ScheduleCreate(BaseModel):
    """Payload for creating a new scan schedule."""

    target: str = Field(
        ...,
        min_length=4,
        max_length=253,
        examples=["acme-corp.de"],
        description="Domain to scan on schedule.",
    )
    modules: list[str] = Field(
        default_factory=list,
        description="Module identifiers. Empty = all modules.",
    )
    cron_expression: str = Field(
        default="0 2 * * 1",
        description="Cron schedule (min hour dom mon dow).",
        examples=["0 2 * * 1", "0 0 * * *", "0 6 1 * *"],
    )

    model_config = ConfigDict(from_attributes=True)


class ScheduleUpdate(BaseModel):
    """Payload for updating a scan schedule."""

    is_active: Optional[bool] = None
    cron_expression: Optional[str] = None
    modules: Optional[list[str]] = None

    model_config = ConfigDict(from_attributes=True)


class ScheduleResponse(BaseModel):
    """Response schema for a scan schedule."""

    id: UUID
    target: str
    modules: Optional[list[str]] = None
    cron_expression: str
    is_active: bool
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
