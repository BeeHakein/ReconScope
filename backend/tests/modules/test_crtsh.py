"""
Tests for the crt.sh Certificate Transparency module.

Validates subdomain parsing, wildcard stripping, deduplication, empty
response handling, and timeout error handling with mocked HTTP responses.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.modules.crtsh import CrtshModule


@pytest.mark.asyncio
async def test_crtsh_parse_subdomains_success() -> None:
    """CrtshModule extracts and returns unique subdomains from a valid crt.sh JSON response."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = [
        {"name_value": "sub1.example.com\nsub2.example.com"},
        {"name_value": "api.example.com"},
    ]

    with patch("app.modules.crtsh.httpx.AsyncClient") as MockClient:
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client_instance

        module = CrtshModule()
        result = await module.execute("example.com", {})

    assert result.success is True
    assert result.module_name == "crtsh"
    names = {sub["name"] for sub in result.data["subdomains"]}
    assert "sub1.example.com" in names
    assert "sub2.example.com" in names
    assert "api.example.com" in names
    assert result.errors is None


@pytest.mark.asyncio
async def test_crtsh_handles_empty_response() -> None:
    """CrtshModule returns an empty subdomain list when crt.sh responds with an empty array."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = []

    with patch("app.modules.crtsh.httpx.AsyncClient") as MockClient:
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client_instance

        module = CrtshModule()
        result = await module.execute("example.com", {})

    assert result.success is True
    assert result.data["subdomains"] == []


@pytest.mark.asyncio
async def test_crtsh_handles_timeout() -> None:
    """CrtshModule records an error and returns success=False on a timeout exception."""
    with patch("app.modules.crtsh.httpx.AsyncClient") as MockClient:
        mock_client_instance = AsyncMock()
        mock_client_instance.get.side_effect = httpx.TimeoutException("Connection timed out")
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client_instance

        module = CrtshModule()
        result = await module.execute("example.com", {})

    assert result.success is False
    assert result.errors is not None
    assert len(result.errors) >= 1
    assert "timed out" in result.errors[0].lower()


@pytest.mark.asyncio
async def test_crtsh_removes_wildcards() -> None:
    """CrtshModule strips the leading '*.' from wildcard certificate entries."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = [
        {"name_value": "*.example.com"},
        {"name_value": "*.api.example.com"},
    ]

    with patch("app.modules.crtsh.httpx.AsyncClient") as MockClient:
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client_instance

        module = CrtshModule()
        result = await module.execute("example.com", {})

    assert result.success is True
    names = {sub["name"] for sub in result.data["subdomains"]}
    # Wildcard '*.example.com' should be stripped to 'example.com'.
    assert "example.com" in names
    # '*.api.example.com' should become 'api.example.com'.
    assert "api.example.com" in names
    # No entries should start with '*.'.
    for sub in result.data["subdomains"]:
        assert not sub["name"].startswith("*.")


@pytest.mark.asyncio
async def test_crtsh_deduplicates_subdomains() -> None:
    """CrtshModule returns each unique subdomain only once, even with duplicate entries."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = [
        {"name_value": "sub1.example.com\nsub2.example.com"},
        {"name_value": "sub1.example.com"},
        {"name_value": "Sub1.example.com"},  # Case variation.
        {"name_value": "sub2.example.com\nsub2.example.com"},
    ]

    with patch("app.modules.crtsh.httpx.AsyncClient") as MockClient:
        mock_client_instance = AsyncMock()
        mock_client_instance.get.return_value = mock_response
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client_instance

        module = CrtshModule()
        result = await module.execute("example.com", {})

    assert result.success is True
    names = [sub["name"] for sub in result.data["subdomains"]]
    # All names should be lowercase and unique.
    assert len(names) == len(set(names)), "Subdomain list contains duplicates"
    assert "sub1.example.com" in names
    assert "sub2.example.com" in names
