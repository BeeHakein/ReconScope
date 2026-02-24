"""
WebSocket handler for real-time scan progress updates.

Clients connect to ``/ws/scans/{scan_id}`` to receive live events as
modules start, complete, or produce findings.  The handler subscribes to a
Redis Pub/Sub channel for the given scan and forwards every message to the
connected WebSocket client.

Message format (server -> client)::

    {
        "event": "module_started",
        "module": "crtsh",
        "data": { ... },
        "timestamp": "2026-02-23T14:30:05Z"
    }

Recognised event types:
    - ``module_started`` -- a recon module has begun execution.
    - ``module_completed`` -- a module finished successfully.
    - ``finding`` -- a new finding was generated mid-scan.
    - ``scan_completed`` -- the entire scan pipeline has finished.
    - ``error`` -- an error occurred in the pipeline.
"""

from __future__ import annotations

import asyncio
import json
import logging
from uuid import UUID

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Redis helpers
# ---------------------------------------------------------------------------


def _channel_name(scan_id: UUID) -> str:
    """Return the Redis Pub/Sub channel name for a given scan.

    Args:
        scan_id: The UUID of the scan.

    Returns:
        A string of the form ``scan:<uuid>``.
    """
    return f"scan:{scan_id}"


async def _get_redis_client():  # type: ignore[no-untyped-def]
    """Create and return an async Redis client.

    Uses the ``REDIS_URL`` from application settings.  The caller is
    responsible for closing the connection when it is no longer needed.

    Returns:
        An ``redis.asyncio.Redis`` client instance.
    """
    import redis.asyncio as aioredis  # noqa: WPS433 (local import)

    settings = get_settings()
    return aioredis.from_url(
        settings.REDIS_URL,
        decode_responses=True,
    )


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------


@router.websocket("/ws/scans/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: UUID) -> None:
    """Accept a WebSocket connection and stream scan updates in real time.

    The handler performs the following steps:

    1. Accept the incoming WebSocket handshake.
    2. Open a Redis connection and subscribe to the scan's Pub/Sub channel.
    3. Enter a loop that reads messages from Redis and forwards them to the
       WebSocket client as JSON text frames.
    4. Cleanly unsubscribe and close both Redis and the WebSocket on
       disconnection, cancellation, or error.

    The loop also listens for incoming WebSocket messages (e.g. a client
    ``ping``) so that disconnections are detected promptly.

    Args:
        websocket: The FastAPI WebSocket connection.
        scan_id: The UUID of the scan to subscribe to.
    """
    await websocket.accept()
    logger.info("WebSocket connected for scan %s", scan_id)

    redis_client = None
    pubsub = None

    try:
        redis_client = await _get_redis_client()
        pubsub = redis_client.pubsub()
        channel = _channel_name(scan_id)
        await pubsub.subscribe(channel)
        logger.info("Subscribed to Redis channel %s", channel)

        # Run two concurrent tasks:
        #   1) Read from Redis pubsub and push to WebSocket
        #   2) Read from WebSocket (to detect disconnect)
        await asyncio.gather(
            _relay_redis_to_ws(pubsub, websocket, channel),
            _listen_for_ws_disconnect(websocket),
        )

    except WebSocketDisconnect:
        logger.info("WebSocket disconnected for scan %s", scan_id)

    except asyncio.CancelledError:
        logger.info("WebSocket task cancelled for scan %s", scan_id)

    except Exception:
        logger.exception("WebSocket error for scan %s", scan_id)

    finally:
        if pubsub is not None:
            try:
                await pubsub.unsubscribe(_channel_name(scan_id))
                await pubsub.close()
            except Exception:
                logger.debug("Error closing pubsub for scan %s", scan_id, exc_info=True)

        if redis_client is not None:
            try:
                await redis_client.close()
            except Exception:
                logger.debug("Error closing Redis for scan %s", scan_id, exc_info=True)

        try:
            await websocket.close()
        except Exception:
            pass

        logger.info("WebSocket cleanup completed for scan %s", scan_id)


# ---------------------------------------------------------------------------
# Internal coroutines
# ---------------------------------------------------------------------------


async def _relay_redis_to_ws(
    pubsub,  # type: ignore[no-untyped-def]
    websocket: WebSocket,
    channel: str,
) -> None:
    """Read messages from Redis Pub/Sub and forward them to the WebSocket.

    Messages of type ``message`` are decoded from JSON (if possible) and
    re-serialised before sending.  Subscribe/unsubscribe control messages
    are silently ignored.

    The loop yields control every 100 ms when no message is available to
    avoid busy-waiting.

    Args:
        pubsub: The subscribed Redis Pub/Sub instance.
        websocket: The connected WebSocket.
        channel: The channel name (for logging).
    """
    while True:
        message = await pubsub.get_message(
            ignore_subscribe_messages=True,
            timeout=0.1,
        )

        if message is not None and message.get("type") == "message":
            raw_data = message.get("data", "")

            try:
                parsed = json.loads(raw_data)
                payload = json.dumps(parsed)
            except (json.JSONDecodeError, TypeError):
                payload = json.dumps({"event": "raw", "data": str(raw_data)})

            await websocket.send_text(payload)

        else:
            # Yield control to the event loop when there is nothing to send.
            await asyncio.sleep(0.1)


async def _listen_for_ws_disconnect(websocket: WebSocket) -> None:
    """Block until the WebSocket client disconnects or sends a message.

    Any message received from the client is silently discarded.  The purpose
    of this coroutine is solely to detect disconnection so that the parent
    ``gather`` can be cancelled.

    Args:
        websocket: The connected WebSocket.

    Raises:
        WebSocketDisconnect: Propagated when the client disconnects.
    """
    while True:
        try:
            await websocket.receive_text()
        except WebSocketDisconnect:
            raise
