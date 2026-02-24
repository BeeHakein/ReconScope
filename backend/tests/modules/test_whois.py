"""
Tests for the WHOIS Lookup module.

Validates successful data extraction, graceful failure handling, and
handling of partial/missing fields from the WHOIS response.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from app.modules.whois_lookup import WhoisModule


def _make_whois_response(**kwargs) -> MagicMock:
    """Build a mock whois response object with the given fields."""
    mock = MagicMock()
    mock.registrar = kwargs.get("registrar", "Test Registrar Inc.")
    mock.creation_date = kwargs.get("creation_date", datetime(2020, 1, 15))
    mock.expiration_date = kwargs.get("expiration_date", datetime(2026, 1, 15))
    mock.updated_date = kwargs.get("updated_date", datetime(2025, 6, 1))
    mock.name_servers = kwargs.get("name_servers", ["ns1.example.com", "ns2.example.com"])
    mock.org = kwargs.get("org", "Example Corporation")
    mock.country = kwargs.get("country", "DE")
    mock.dnssec = kwargs.get("dnssec", "unsigned")
    return mock


@pytest.mark.asyncio
async def test_whois_extracts_data() -> None:
    """WhoisModule extracts registrar, dates, name servers, org, country, and dnssec."""
    mock_response = _make_whois_response()

    with patch("app.modules.whois_lookup.whois.whois", return_value=mock_response):
        module = WhoisModule()
        result = await module.execute("example.com", {})

    assert result.success is True
    assert result.module_name == "whois"
    data = result.data

    assert data["registrar"] == "Test Registrar Inc."
    assert data["creation_date"] == "2020-01-15T00:00:00"
    assert data["expiration_date"] == "2026-01-15T00:00:00"
    assert data["updated_date"] == "2025-06-01T00:00:00"
    assert data["name_servers"] == ["ns1.example.com", "ns2.example.com"]
    assert data["org"] == "Example Corporation"
    assert data["country"] == "DE"
    assert data["dnssec"] == "unsigned"
    assert result.errors is None


@pytest.mark.asyncio
async def test_whois_handles_failure() -> None:
    """WhoisModule returns success=False with an error message when the lookup fails."""
    with patch(
        "app.modules.whois_lookup.whois.whois",
        side_effect=Exception("WHOIS server unreachable"),
    ):
        module = WhoisModule()
        result = await module.execute("unreachable.com", {})

    assert result.success is False
    assert result.data == {}
    assert result.errors is not None
    assert len(result.errors) == 1
    assert "unreachable" in result.errors[0].lower()


@pytest.mark.asyncio
async def test_whois_handles_missing_fields() -> None:
    """WhoisModule gracefully handles a WHOIS response with None fields."""
    mock_response = _make_whois_response(
        registrar=None,
        creation_date=None,
        expiration_date=None,
        updated_date=None,
        name_servers=None,
        org=None,
        country=None,
        dnssec=None,
    )

    with patch("app.modules.whois_lookup.whois.whois", return_value=mock_response):
        module = WhoisModule()
        result = await module.execute("sparse.com", {})

    assert result.success is True
    data = result.data
    assert data["registrar"] is None
    assert data["creation_date"] is None
    assert data["expiration_date"] is None
    assert data["updated_date"] is None
    assert data["name_servers"] == []
    assert data["org"] is None
    assert data["country"] is None
    assert data["dnssec"] is None
