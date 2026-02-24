"""
Tests for the Celery scan task.

Validates that the run_scan task delegates to the ScanOrchestrator,
that errors are handled by setting the scan status to FAILED, that
failure events are published via Redis, and that the synchronous
Celery entry point manages the event loop correctly.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helper: build a mock async session context manager
# ---------------------------------------------------------------------------

def _make_async_session(mock_session: AsyncMock | None = None) -> tuple[MagicMock, AsyncMock]:
    """Build a mock async_session_factory that yields the given session.

    Returns:
        A tuple of (mock_session_factory, mock_session).
    """
    if mock_session is None:
        mock_session = AsyncMock()

    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    mock_session.commit = AsyncMock()
    mock_session.get = AsyncMock(return_value=None)

    mock_session_factory = MagicMock(return_value=mock_session)
    return mock_session_factory, mock_session


# ---------------------------------------------------------------------------
# Test: _execute_scan delegates to ScanOrchestrator
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_execute_scan_calls_orchestrator() -> None:
    """The _execute_scan coroutine creates an orchestrator and calls run_scan."""
    mock_orchestrator_instance = MagicMock()
    mock_orchestrator_instance.run_scan = AsyncMock()

    mock_session_factory, mock_session = _make_async_session()
    fake_scan_id = "12345678-1234-1234-1234-123456789abc"

    with patch(
        "app.tasks.scan_tasks.async_session_factory",
        mock_session_factory,
    ), patch(
        "app.tasks.scan_tasks.ScanOrchestrator",
        return_value=mock_orchestrator_instance,
    ):
        from app.tasks.scan_tasks import _execute_scan

        await _execute_scan(fake_scan_id)

    mock_orchestrator_instance.run_scan.assert_awaited_once_with(
        scan_id=fake_scan_id,
        db_session=mock_session,
    )


# ---------------------------------------------------------------------------
# Test: _execute_scan marks scan as FAILED and publishes event on error
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_execute_scan_marks_scan_failed_on_error() -> None:
    """When the orchestrator raises an exception, the scan status is set to FAILED."""
    mock_orchestrator_instance = MagicMock()
    mock_orchestrator_instance.run_scan = AsyncMock(
        side_effect=RuntimeError("Module failed catastrophically")
    )

    # Build a mock scan object that will be fetched via db_session.get().
    mock_scan = MagicMock()
    mock_scan.status = "running"
    mock_scan.started_at = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    mock_scan.completed_at = None

    mock_session_factory, mock_session = _make_async_session()
    mock_session.get = AsyncMock(return_value=mock_scan)

    fake_scan_id = "12345678-1234-1234-1234-123456789abc"

    with patch(
        "app.tasks.scan_tasks.async_session_factory",
        mock_session_factory,
    ), patch(
        "app.tasks.scan_tasks.ScanOrchestrator",
        return_value=mock_orchestrator_instance,
    ), patch(
        "app.tasks.scan_tasks._publish_failure_event",
        new_callable=AsyncMock,
    ):
        from app.tasks.scan_tasks import _execute_scan

        with pytest.raises(RuntimeError, match="Module failed catastrophically"):
            await _execute_scan(fake_scan_id)

    # Verify the scan was marked as FAILED.
    from app.models.scan import ScanStatus

    assert mock_scan.status == ScanStatus.FAILED
    assert mock_scan.completed_at is not None
    assert mock_scan.duration_seconds is not None
    mock_session.commit.assert_awaited()


# ---------------------------------------------------------------------------
# Test: failure event is published on scan error
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_execute_scan_publishes_failure_event() -> None:
    """When the orchestrator fails, a scan_failed event is published via Redis."""
    mock_orchestrator_instance = MagicMock()
    mock_orchestrator_instance.run_scan = AsyncMock(
        side_effect=ValueError("DNS timeout")
    )

    mock_scan = MagicMock()
    mock_scan.status = "running"
    mock_scan.started_at = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    mock_scan.completed_at = None

    mock_session_factory, mock_session = _make_async_session()
    mock_session.get = AsyncMock(return_value=mock_scan)

    fake_scan_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    with patch(
        "app.tasks.scan_tasks.async_session_factory",
        mock_session_factory,
    ), patch(
        "app.tasks.scan_tasks.ScanOrchestrator",
        return_value=mock_orchestrator_instance,
    ), patch(
        "app.tasks.scan_tasks._publish_failure_event",
        new_callable=AsyncMock,
    ) as mock_publish:
        from app.tasks.scan_tasks import _execute_scan

        with pytest.raises(ValueError, match="DNS timeout"):
            await _execute_scan(fake_scan_id)

    mock_publish.assert_awaited_once()
    call_args = mock_publish.call_args
    assert call_args[0][0] == fake_scan_id
    assert "DNS timeout" in call_args[0][1]


# ---------------------------------------------------------------------------
# Test: scan not found in DB during error handling does not crash
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_execute_scan_handles_missing_scan_on_error() -> None:
    """When the scan is not found in the database during error handling, no crash occurs."""
    mock_orchestrator_instance = MagicMock()
    mock_orchestrator_instance.run_scan = AsyncMock(
        side_effect=RuntimeError("Connection lost")
    )

    mock_session_factory, mock_session = _make_async_session()
    # db_session.get returns None (scan not found).
    mock_session.get = AsyncMock(return_value=None)

    fake_scan_id = "12345678-aaaa-bbbb-cccc-123456789abc"

    with patch(
        "app.tasks.scan_tasks.async_session_factory",
        mock_session_factory,
    ), patch(
        "app.tasks.scan_tasks.ScanOrchestrator",
        return_value=mock_orchestrator_instance,
    ), patch(
        "app.tasks.scan_tasks._publish_failure_event",
        new_callable=AsyncMock,
    ) as mock_publish:
        from app.tasks.scan_tasks import _execute_scan

        with pytest.raises(RuntimeError, match="Connection lost"):
            await _execute_scan(fake_scan_id)

    # commit should still be called (the branch where scan is None skips updates).
    # The failure event is still published even if the scan object was not found.
    mock_publish.assert_awaited_once()


# ---------------------------------------------------------------------------
# Test: synchronous run_scan Celery task calls _execute_scan
# ---------------------------------------------------------------------------

def test_run_scan_celery_task_success() -> None:
    """The synchronous run_scan task creates an event loop and returns a success dict."""
    fake_scan_id = "12345678-1234-1234-1234-123456789abc"

    with patch(
        "app.tasks.scan_tasks._execute_scan",
        new_callable=AsyncMock,
    ) as mock_execute, patch(
        "app.tasks.scan_tasks.asyncio",
    ) as mock_asyncio:
        # Configure the mock event loop.
        mock_loop = MagicMock()
        mock_asyncio.new_event_loop.return_value = mock_loop

        from app.tasks.scan_tasks import run_scan

        # Call the underlying function directly (bypass Celery decorator).
        result = run_scan(fake_scan_id)

    assert result == {"scan_id": fake_scan_id, "status": "completed"}
    mock_asyncio.new_event_loop.assert_called_once()
    mock_asyncio.set_event_loop.assert_called_once_with(mock_loop)
    mock_loop.run_until_complete.assert_called_once()
    mock_loop.close.assert_called_once()


def test_run_scan_celery_task_closes_loop_on_failure() -> None:
    """The synchronous run_scan task closes the event loop even when the scan fails."""
    fake_scan_id = "12345678-1234-1234-1234-123456789abc"

    with patch(
        "app.tasks.scan_tasks.asyncio",
    ) as mock_asyncio:
        mock_loop = MagicMock()
        mock_loop.run_until_complete.side_effect = RuntimeError("Scan exploded")
        mock_asyncio.new_event_loop.return_value = mock_loop

        from app.tasks.scan_tasks import run_scan

        with pytest.raises(RuntimeError, match="Scan exploded"):
            run_scan(fake_scan_id)

    # The loop must be closed even after failure (finally block).
    mock_loop.close.assert_called_once()


# ---------------------------------------------------------------------------
# Test: _publish_failure_event constructs and publishes correct message
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_publish_failure_event_message_format() -> None:
    """The _publish_failure_event function sends a correctly structured JSON message."""
    fake_scan_id = "abcdef00-1111-2222-3333-444444444444"
    error_msg = "Timeout connecting to target"

    mock_redis_client = AsyncMock()
    mock_redis_client.__aenter__ = AsyncMock(return_value=mock_redis_client)
    mock_redis_client.__aexit__ = AsyncMock(return_value=False)
    mock_redis_client.publish = AsyncMock()

    mock_settings = MagicMock()
    mock_settings.REDIS_URL = "redis://localhost:6379/0"

    with patch(
        "app.tasks.scan_tasks.aioredis.from_url",
        return_value=mock_redis_client,
    ) as mock_from_url, patch(
        "app.tasks.scan_tasks.get_settings",
        return_value=mock_settings,
    ):
        from app.tasks.scan_tasks import _publish_failure_event

        await _publish_failure_event(fake_scan_id, error_msg)

    # Verify Redis client was created with the correct URL.
    mock_from_url.assert_called_once_with("redis://localhost:6379/0")

    # Verify publish was called on the correct channel.
    mock_redis_client.publish.assert_awaited_once()
    call_args = mock_redis_client.publish.call_args
    channel = call_args[0][0]
    message_raw = call_args[0][1]

    assert channel == f"scan:{fake_scan_id}"

    message = json.loads(message_raw)
    assert message["event"] == "scan_failed"
    assert message["module"] is None
    assert message["data"]["error"] == error_msg
    assert "timestamp" in message


# ---------------------------------------------------------------------------
# Test: database error during failure handling does not prevent event publish
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_execute_scan_db_error_during_failure_still_publishes() -> None:
    """If updating the scan status to FAILED raises, the failure event is still published."""
    mock_orchestrator_instance = MagicMock()
    mock_orchestrator_instance.run_scan = AsyncMock(
        side_effect=RuntimeError("Primary failure")
    )

    mock_session_factory, mock_session = _make_async_session()
    # Simulate a DB error when trying to fetch the scan during error handling.
    mock_session.get = AsyncMock(side_effect=ConnectionError("DB connection lost"))

    fake_scan_id = "12345678-1234-1234-1234-123456789abc"

    with patch(
        "app.tasks.scan_tasks.async_session_factory",
        mock_session_factory,
    ), patch(
        "app.tasks.scan_tasks.ScanOrchestrator",
        return_value=mock_orchestrator_instance,
    ), patch(
        "app.tasks.scan_tasks._publish_failure_event",
        new_callable=AsyncMock,
    ) as mock_publish:
        from app.tasks.scan_tasks import _execute_scan

        with pytest.raises(RuntimeError, match="Primary failure"):
            await _execute_scan(fake_scan_id)

    # Even though the DB update failed, the failure event should still be published.
    mock_publish.assert_awaited_once()
    assert mock_publish.call_args[0][0] == fake_scan_id
