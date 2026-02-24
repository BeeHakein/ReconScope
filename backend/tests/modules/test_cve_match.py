"""
Tests for the CVE Matching module.

Validates NVD API response parsing, version filtering, API error handling,
and the CVSS-to-severity score mapping with mocked HTTP responses.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.modules.cve_match import CveMatchModule


SAMPLE_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-41773",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "A flaw was found in a change made to path "
                            "normalization in Apache HTTP Server 2.4.49."
                        ),
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        }
                    ]
                },
                "published": "2021-10-05T09:15:00.000",
            }
        },
        {
            "cve": {
                "id": "CVE-2021-42013",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Incomplete fix for CVE-2021-41773.",
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 7.5,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            }
                        }
                    ]
                },
                "published": "2021-10-07T12:15:00.000",
            }
        },
    ]
}


@pytest.mark.asyncio
async def test_cve_match_finds_vulnerabilities() -> None:
    """CveMatchModule parses NVD API response and returns structured CVE data."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = SAMPLE_NVD_RESPONSE

    context = {
        "technologies": [
            {
                "name": "Apache",
                "version": "2.4.49",
                "domain": "www.example.com",
            }
        ]
    }

    with patch("app.modules.cve_match.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        with patch("app.modules.cve_match.asyncio.sleep", new_callable=AsyncMock):
            module = CveMatchModule()
            result = await module.execute("example.com", context)

    assert result.success is True
    assert result.module_name == "cvematch"
    cves = result.data["cves"]
    assert len(cves) == 2

    cve_ids = {cve["cve_id"] for cve in cves}
    assert "CVE-2021-41773" in cve_ids
    assert "CVE-2021-42013" in cve_ids

    critical_cve = next(c for c in cves if c["cve_id"] == "CVE-2021-41773")
    assert critical_cve["cvss_score"] == 9.8
    assert critical_cve["severity"] == "critical"
    assert critical_cve["affected_tech"] == "Apache"
    assert critical_cve["affected_version"] == "2.4.49"
    assert critical_cve["affected_domain"] == "www.example.com"
    assert "CVSS:3.1" in critical_cve["cvss_vector"]
    assert "path normalization" in critical_cve["description"].lower()


@pytest.mark.asyncio
async def test_cve_match_skips_unknown_versions() -> None:
    """CveMatchModule skips technologies whose version is 'unknown'."""
    context = {
        "technologies": [
            {"name": "Cloudflare", "version": "unknown", "domain": "cdn.example.com"},
            {"name": "Nginx", "version": "1.21.0", "domain": "www.example.com"},
        ]
    }

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"vulnerabilities": []}

    call_count = 0

    with patch("app.modules.cve_match.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()

        async def mock_get(url, **kwargs):
            """Count how many API calls are made."""
            nonlocal call_count
            call_count += 1
            return mock_response

        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        with patch("app.modules.cve_match.asyncio.sleep", new_callable=AsyncMock):
            module = CveMatchModule()
            result = await module.execute("example.com", context)

    assert result.success is True
    # Only Nginx (version="1.21.0") should trigger an API call.
    assert call_count == 1, (
        f"Expected 1 API call (skipping unknown version), got {call_count}"
    )


@pytest.mark.asyncio
async def test_cve_match_handles_api_error() -> None:
    """CveMatchModule records an error when the NVD API returns an HTTP error."""
    context = {
        "technologies": [
            {"name": "Nginx", "version": "1.21.0", "domain": "www.example.com"},
        ]
    }

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 503
    mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "Service Unavailable",
        request=MagicMock(spec=httpx.Request),
        response=mock_response,
    )

    with patch("app.modules.cve_match.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        with patch("app.modules.cve_match.asyncio.sleep", new_callable=AsyncMock):
            module = CveMatchModule()
            result = await module.execute("example.com", context)

    # The module still returns success=True but with errors recorded.
    assert result.success is True
    assert result.errors is not None
    assert len(result.errors) >= 1
    assert "503" in result.errors[0] or "Service Unavailable" in result.errors[0]


def test_score_to_severity_critical() -> None:
    """A CVSS score >= 9.0 maps to severity 'critical'."""
    module = CveMatchModule()
    assert module._score_to_severity(9.0) == "critical"
    assert module._score_to_severity(10.0) == "critical"
    assert module._score_to_severity(9.8) == "critical"


def test_score_to_severity_high() -> None:
    """A CVSS score >= 7.0 and < 9.0 maps to severity 'high'."""
    module = CveMatchModule()
    assert module._score_to_severity(7.0) == "high"
    assert module._score_to_severity(8.9) == "high"
    assert module._score_to_severity(7.5) == "high"


def test_score_to_severity_medium() -> None:
    """A CVSS score >= 4.0 and < 7.0 maps to severity 'medium'."""
    module = CveMatchModule()
    assert module._score_to_severity(4.0) == "medium"
    assert module._score_to_severity(6.9) == "medium"
    assert module._score_to_severity(5.5) == "medium"


def test_score_to_severity_low() -> None:
    """A CVSS score < 4.0 maps to severity 'low'."""
    module = CveMatchModule()
    assert module._score_to_severity(0.0) == "low"
    assert module._score_to_severity(3.9) == "low"
    assert module._score_to_severity(1.5) == "low"
