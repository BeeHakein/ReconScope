"""
Tests for the DNS Enumeration module.

Validates A record resolution, NXDOMAIN handling, timeout handling,
subdomain resolution from context, and record-type enumeration with
mocked dnspython resolver calls.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from app.modules.dns_enum import DnsEnumModule


def _make_answer(values: list[str]) -> MagicMock:
    """Create a mock dns.resolver.Answer containing the given string values."""
    mock_rdatas = []
    for v in values:
        rdata = MagicMock()
        rdata.__str__ = MagicMock(return_value=v)
        mock_rdatas.append(rdata)
    answer = MagicMock()
    answer.__iter__ = MagicMock(return_value=iter(mock_rdatas))
    return answer


@pytest.mark.asyncio
async def test_dns_resolve_a_record() -> None:
    """DnsEnumModule correctly extracts A records and populates resolved_ips."""
    with patch.object(DnsEnumModule, "_resolve_record") as mock_resolve:
        def side_effect(resolver, domain, rtype):
            """Return a mock A record answer for the target domain."""
            if domain == "example.com" and rtype == "A":
                return _make_answer(["93.184.216.34"])
            return None

        mock_resolve.side_effect = side_effect

        module = DnsEnumModule()
        result = await module.execute("example.com", {})

    assert result.success is True
    assert "records" in result.data
    assert "resolved_ips" in result.data
    assert "example.com" in result.data["resolved_ips"]
    assert result.data["resolved_ips"]["example.com"] == "93.184.216.34"
    assert "A" in result.data["records"]["example.com"]
    assert "93.184.216.34" in result.data["records"]["example.com"]["A"]


@pytest.mark.asyncio
async def test_dns_handles_nxdomain() -> None:
    """DnsEnumModule gracefully handles NXDOMAIN by returning None from _resolve_record."""
    with patch.object(DnsEnumModule, "_resolve_record") as mock_resolve:
        mock_resolve.return_value = None  # Simulates NXDOMAIN.

        module = DnsEnumModule()
        result = await module.execute("nonexistent.example.com", {})

    assert result.success is True
    assert result.data["records"]["nonexistent.example.com"] == {}
    assert result.data["resolved_ips"] == {}


@pytest.mark.asyncio
async def test_dns_handles_timeout() -> None:
    """DnsEnumModule logs an error but continues when a DNS query times out."""
    with patch.object(DnsEnumModule, "_resolve_record") as mock_resolve:
        def side_effect(resolver, domain, rtype):
            """Raise a generic exception to simulate a timeout."""
            raise dns.exception.Timeout("DNS query timed out")

        mock_resolve.side_effect = side_effect

        module = DnsEnumModule()
        result = await module.execute("timeout.example.com", {})

    # Module should still report success (non-fatal errors).
    assert result.success is True
    assert result.errors is not None
    assert len(result.errors) > 0
    assert any("Timeout" in err or "timeout" in err.lower() for err in result.errors)


@pytest.mark.asyncio
async def test_dns_resolves_subdomains_from_context() -> None:
    """DnsEnumModule resolves all subdomains passed via the context dictionary."""
    context = {
        "subdomains": [
            {"name": "www.example.com"},
            {"name": "api.example.com"},
        ],
    }

    resolved_domains: set[str] = set()

    with patch.object(DnsEnumModule, "_resolve_record") as mock_resolve:
        def side_effect(resolver, domain, rtype):
            """Track which domains are being resolved."""
            resolved_domains.add(domain)
            if rtype == "A":
                return _make_answer(["10.0.0.1"])
            return None

        mock_resolve.side_effect = side_effect

        module = DnsEnumModule()
        result = await module.execute("example.com", context)

    assert result.success is True
    # All three domains should have been resolved.
    assert "example.com" in resolved_domains
    assert "www.example.com" in resolved_domains
    assert "api.example.com" in resolved_domains


@pytest.mark.asyncio
async def test_dns_all_record_types() -> None:
    """DnsEnumModule attempts resolution for all 7 defined record types."""
    queried_types: set[str] = set()

    with patch.object(DnsEnumModule, "_resolve_record") as mock_resolve:
        def side_effect(resolver, domain, rtype):
            """Record which record types are queried."""
            queried_types.add(rtype)
            return None

        mock_resolve.side_effect = side_effect

        module = DnsEnumModule()
        await module.execute("example.com", {})

    expected_types = {"A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA"}
    assert queried_types == expected_types, (
        f"Expected all 7 record types to be queried. Got: {queried_types}"
    )
