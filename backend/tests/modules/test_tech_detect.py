"""
Tests for the Technology Detection module.

Validates header-based fingerprinting for Nginx, Apache, PHP, and
multiple technologies; connection error handling; and the HTTPS-first
fallback behaviour using mocked HTTP responses.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.modules.tech_detect import TechDetectModule


def _make_response(headers: dict[str, str]) -> MagicMock:
    """Create a mock httpx.Response with the given HTTP headers."""
    mock = MagicMock(spec=httpx.Response)
    mock.headers = httpx.Headers(headers)
    mock.status_code = 200
    # Ensure the stream/ssl_object path does not trigger.
    mock.stream = MagicMock()
    mock.stream.ssl_object = None
    return mock


@pytest.mark.asyncio
async def test_detect_nginx() -> None:
    """TechDetectModule identifies Nginx from the Server response header."""
    mock_response = _make_response({"Server": "nginx/1.21.0"})

    with patch("app.modules.tech_detect.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        module = TechDetectModule()
        result = await module.execute("example.com", {})

    assert result.success is True
    tech_names = [t["name"] for t in result.data["technologies"]]
    assert "Nginx" in tech_names
    nginx_tech = next(t for t in result.data["technologies"] if t["name"] == "Nginx")
    assert nginx_tech["version"] == "1.21.0"
    assert nginx_tech["category"] == "web_server"
    assert nginx_tech["confidence"] == 90


@pytest.mark.asyncio
async def test_detect_apache() -> None:
    """TechDetectModule identifies Apache HTTPD from the Server response header."""
    mock_response = _make_response({"Server": "Apache/2.4.51"})

    with patch("app.modules.tech_detect.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        module = TechDetectModule()
        result = await module.execute("example.com", {})

    assert result.success is True
    tech_names = [t["name"] for t in result.data["technologies"]]
    assert "Apache" in tech_names
    apache = next(t for t in result.data["technologies"] if t["name"] == "Apache")
    assert apache["version"] == "2.4.51"
    assert apache["category"] == "web_server"


@pytest.mark.asyncio
async def test_detect_php() -> None:
    """TechDetectModule identifies PHP from the X-Powered-By response header."""
    mock_response = _make_response({"X-Powered-By": "PHP/8.1"})

    with patch("app.modules.tech_detect.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        module = TechDetectModule()
        result = await module.execute("example.com", {})

    assert result.success is True
    tech_names = [t["name"] for t in result.data["technologies"]]
    assert "PHP" in tech_names
    php = next(t for t in result.data["technologies"] if t["name"] == "PHP")
    assert php["version"] == "8.1"
    assert php["category"] == "language"


@pytest.mark.asyncio
async def test_detect_multiple_techs() -> None:
    """TechDetectModule identifies multiple technologies from a single response."""
    mock_response = _make_response({
        "Server": "nginx/1.24.0",
        "X-Powered-By": "PHP/8.2.5",
    })

    with patch("app.modules.tech_detect.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        module = TechDetectModule()
        result = await module.execute("example.com", {})

    assert result.success is True
    tech_names = {t["name"] for t in result.data["technologies"]}
    assert "Nginx" in tech_names
    assert "PHP" in tech_names
    assert len(result.data["technologies"]) >= 2


@pytest.mark.asyncio
async def test_handles_connection_error() -> None:
    """TechDetectModule returns success=True with empty technologies on connection error."""
    with patch("app.modules.tech_detect.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectError("Connection refused")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        module = TechDetectModule()
        result = await module.execute("unreachable.example.com", {})

    assert result.success is True
    assert result.data["technologies"] == []


@pytest.mark.asyncio
async def test_tries_https_then_http() -> None:
    """TechDetectModule attempts HTTPS first and falls back to HTTP on failure."""
    mock_response = _make_response({"Server": "Apache/2.4.52"})
    call_urls: list[str] = []

    with patch("app.modules.tech_detect.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            """Track which URLs are attempted and fail HTTPS."""
            call_urls.append(url)
            if url.startswith("https://"):
                raise httpx.ConnectError("SSL handshake failed")
            return mock_response

        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        module = TechDetectModule()
        result = await module.execute("fallback.example.com", {})

    assert result.success is True
    # HTTPS should be attempted first, then HTTP.
    assert call_urls[0].startswith("https://"), "HTTPS must be tried first"
    assert call_urls[1].startswith("http://"), "HTTP should be tried as fallback"
    tech_names = [t["name"] for t in result.data["technologies"]]
    assert "Apache" in tech_names
