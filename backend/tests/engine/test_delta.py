"""
Tests for the scan delta comparison engine.

Validates detection of new subdomains, removed subdomains, new and resolved
CVEs, added and removed services, risk change tracking, and identical-scan
scenarios using mock ORM objects.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.engine.delta import compute_delta


# ---------------------------------------------------------------------------
# Mock factories
# ---------------------------------------------------------------------------

def _make_subdomain(name: str, services=None) -> MagicMock:
    """Create a mock Subdomain ORM object."""
    sub = MagicMock()
    sub.name = name
    sub.services = services or []
    return sub


def _make_service(port: int, service_name: str, cves=None) -> MagicMock:
    """Create a mock Service ORM object."""
    svc = MagicMock()
    svc.port = port
    svc.service_name = service_name
    svc.cves = cves or []
    return svc


def _make_cve(cve_id: str) -> MagicMock:
    """Create a mock CVEMatch ORM object."""
    cve = MagicMock()
    cve.cve_id = cve_id
    return cve


def _make_scan(subdomains=None, overall_risk=None) -> MagicMock:
    """Create a mock Scan ORM object with the given subdomains and risk."""
    scan = MagicMock()
    scan.subdomains = subdomains or []
    scan.overall_risk = overall_risk
    return scan


# ---------------------------------------------------------------------------
# Subdomain tests
# ---------------------------------------------------------------------------

def test_new_subdomains_detected() -> None:
    """compute_delta identifies subdomains present in the new scan but not the old."""
    scan_old = _make_scan(
        subdomains=[
            _make_subdomain("www.example.com"),
            _make_subdomain("api.example.com"),
        ],
        overall_risk="medium",
    )

    scan_new = _make_scan(
        subdomains=[
            _make_subdomain("www.example.com"),
            _make_subdomain("api.example.com"),
            _make_subdomain("staging.example.com"),
            _make_subdomain("new.example.com"),
        ],
        overall_risk="high",
    )

    delta = compute_delta(scan_old, scan_new)

    assert "new.example.com" in delta["subdomains"]["added"]
    assert "staging.example.com" in delta["subdomains"]["added"]
    assert len(delta["subdomains"]["added"]) == 2
    assert "www.example.com" in delta["subdomains"]["unchanged"]
    assert "api.example.com" in delta["subdomains"]["unchanged"]


def test_removed_subdomains_detected() -> None:
    """compute_delta identifies subdomains present in the old scan but not the new."""
    scan_old = _make_scan(
        subdomains=[
            _make_subdomain("www.example.com"),
            _make_subdomain("old.example.com"),
            _make_subdomain("deprecated.example.com"),
        ],
    )

    scan_new = _make_scan(
        subdomains=[
            _make_subdomain("www.example.com"),
        ],
    )

    delta = compute_delta(scan_old, scan_new)

    assert "old.example.com" in delta["subdomains"]["removed"]
    assert "deprecated.example.com" in delta["subdomains"]["removed"]
    assert len(delta["subdomains"]["removed"]) == 2
    assert "www.example.com" in delta["subdomains"]["unchanged"]


def test_subdomains_added_and_removed_simultaneously() -> None:
    """compute_delta correctly handles both added and removed subdomains in a single comparison."""
    scan_old = _make_scan(
        subdomains=[
            _make_subdomain("www.example.com"),
            _make_subdomain("retired.example.com"),
        ],
        overall_risk="low",
    )

    scan_new = _make_scan(
        subdomains=[
            _make_subdomain("www.example.com"),
            _make_subdomain("new-api.example.com"),
        ],
        overall_risk="medium",
    )

    delta = compute_delta(scan_old, scan_new)

    assert delta["subdomains"]["added"] == ["new-api.example.com"]
    assert delta["subdomains"]["removed"] == ["retired.example.com"]
    assert delta["subdomains"]["unchanged"] == ["www.example.com"]


# ---------------------------------------------------------------------------
# Service tests
# ---------------------------------------------------------------------------

def test_new_services_detected() -> None:
    """compute_delta identifies services present in the new scan but not the old."""
    svc_old = _make_service(443, "nginx")
    svc_new_1 = _make_service(443, "nginx")
    svc_new_2 = _make_service(8080, "tomcat")

    scan_old = _make_scan(
        subdomains=[_make_subdomain("www.example.com", services=[svc_old])],
    )
    scan_new = _make_scan(
        subdomains=[_make_subdomain("www.example.com", services=[svc_new_1, svc_new_2])],
    )

    delta = compute_delta(scan_old, scan_new)

    assert len(delta["services"]["added"]) == 1
    added_service = delta["services"]["added"][0]
    assert added_service[0] == "www.example.com"
    assert added_service[1] == 8080
    assert added_service[2] == "tomcat"
    assert len(delta["services"]["removed"]) == 0


def test_removed_services_detected() -> None:
    """compute_delta identifies services that were removed between scans."""
    svc_old_1 = _make_service(443, "nginx")
    svc_old_2 = _make_service(22, "openssh")
    svc_new = _make_service(443, "nginx")

    scan_old = _make_scan(
        subdomains=[_make_subdomain("www.example.com", services=[svc_old_1, svc_old_2])],
    )
    scan_new = _make_scan(
        subdomains=[_make_subdomain("www.example.com", services=[svc_new])],
    )

    delta = compute_delta(scan_old, scan_new)

    assert len(delta["services"]["removed"]) == 1
    removed_service = delta["services"]["removed"][0]
    assert removed_service[0] == "www.example.com"
    assert removed_service[1] == 22
    assert removed_service[2] == "openssh"
    assert len(delta["services"]["added"]) == 0


# ---------------------------------------------------------------------------
# CVE tests
# ---------------------------------------------------------------------------

def test_new_cves_detected() -> None:
    """compute_delta identifies CVEs present in the new scan but not the old."""
    svc_old = _make_service(443, "nginx", cves=[
        _make_cve("CVE-2021-1111"),
    ])
    svc_new = _make_service(443, "nginx", cves=[
        _make_cve("CVE-2021-1111"),
        _make_cve("CVE-2024-9999"),
        _make_cve("CVE-2024-8888"),
    ])

    scan_old = _make_scan(
        subdomains=[_make_subdomain("www.example.com", services=[svc_old])],
    )
    scan_new = _make_scan(
        subdomains=[_make_subdomain("www.example.com", services=[svc_new])],
    )

    delta = compute_delta(scan_old, scan_new)

    assert "CVE-2024-9999" in delta["cves"]["new"]
    assert "CVE-2024-8888" in delta["cves"]["new"]
    assert len(delta["cves"]["new"]) == 2
    assert len(delta["cves"]["resolved"]) == 0


def test_resolved_cves_detected() -> None:
    """compute_delta identifies CVEs that were in the old scan but are gone in the new."""
    svc_old = _make_service(443, "nginx", cves=[
        _make_cve("CVE-2021-41773"),
        _make_cve("CVE-2021-42013"),
    ])
    svc_new = _make_service(443, "nginx", cves=[
        _make_cve("CVE-2021-41773"),
    ])

    scan_old = _make_scan(
        subdomains=[_make_subdomain("www.example.com", services=[svc_old])],
    )
    scan_new = _make_scan(
        subdomains=[_make_subdomain("www.example.com", services=[svc_new])],
    )

    delta = compute_delta(scan_old, scan_new)

    assert "CVE-2021-42013" in delta["cves"]["resolved"]
    assert len(delta["cves"]["resolved"]) == 1
    assert len(delta["cves"]["new"]) == 0


def test_cves_added_and_resolved_simultaneously() -> None:
    """compute_delta correctly reports new and resolved CVEs in the same comparison."""
    svc_old = _make_service(443, "nginx", cves=[
        _make_cve("CVE-2021-1111"),
        _make_cve("CVE-2021-2222"),
    ])
    svc_new = _make_service(443, "nginx", cves=[
        _make_cve("CVE-2021-1111"),
        _make_cve("CVE-2024-3333"),
    ])

    scan_old = _make_scan(
        subdomains=[_make_subdomain("www.example.com", services=[svc_old])],
    )
    scan_new = _make_scan(
        subdomains=[_make_subdomain("www.example.com", services=[svc_new])],
    )

    delta = compute_delta(scan_old, scan_new)

    assert delta["cves"]["new"] == ["CVE-2024-3333"]
    assert delta["cves"]["resolved"] == ["CVE-2021-2222"]


# ---------------------------------------------------------------------------
# Risk change
# ---------------------------------------------------------------------------

def test_risk_change_tracked() -> None:
    """compute_delta reports the risk level change between old and new scans."""
    scan_old = _make_scan(subdomains=[], overall_risk="low")
    scan_new = _make_scan(subdomains=[], overall_risk="critical")

    delta = compute_delta(scan_old, scan_new)

    assert delta["risk_change"]["old_score"] == "low"
    assert delta["risk_change"]["new_score"] == "critical"


# ---------------------------------------------------------------------------
# Identical scans
# ---------------------------------------------------------------------------

def test_identical_scans_no_changes() -> None:
    """compute_delta reports no changes when both scans have identical data."""
    cve = _make_cve("CVE-2021-41773")
    svc = _make_service(443, "nginx", cves=[cve])

    scan_old = _make_scan(
        subdomains=[
            _make_subdomain("www.example.com", services=[svc]),
            _make_subdomain("api.example.com", services=[]),
        ],
        overall_risk="high",
    )

    # Create identical scan (same structure).
    cve2 = _make_cve("CVE-2021-41773")
    svc2 = _make_service(443, "nginx", cves=[cve2])

    scan_new = _make_scan(
        subdomains=[
            _make_subdomain("www.example.com", services=[svc2]),
            _make_subdomain("api.example.com", services=[]),
        ],
        overall_risk="high",
    )

    delta = compute_delta(scan_old, scan_new)

    assert delta["subdomains"]["added"] == []
    assert delta["subdomains"]["removed"] == []
    assert len(delta["subdomains"]["unchanged"]) == 2
    assert delta["cves"]["new"] == []
    assert delta["cves"]["resolved"] == []
    assert delta["services"]["added"] == []
    assert delta["services"]["removed"] == []
    assert delta["risk_change"]["old_score"] == "high"
    assert delta["risk_change"]["new_score"] == "high"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_empty_scans_produce_empty_delta() -> None:
    """Two scans with no subdomains produce a delta with all empty lists."""
    scan_old = _make_scan(subdomains=[], overall_risk=None)
    scan_new = _make_scan(subdomains=[], overall_risk=None)

    delta = compute_delta(scan_old, scan_new)

    assert delta["subdomains"]["added"] == []
    assert delta["subdomains"]["removed"] == []
    assert delta["subdomains"]["unchanged"] == []
    assert delta["services"]["added"] == []
    assert delta["services"]["removed"] == []
    assert delta["cves"]["new"] == []
    assert delta["cves"]["resolved"] == []
    assert delta["risk_change"]["old_score"] is None
    assert delta["risk_change"]["new_score"] is None


def test_delta_results_are_sorted() -> None:
    """All list results in the delta should be sorted alphabetically."""
    scan_old = _make_scan(
        subdomains=[
            _make_subdomain("z.example.com"),
            _make_subdomain("a.example.com"),
        ],
    )
    scan_new = _make_scan(
        subdomains=[
            _make_subdomain("m.example.com"),
            _make_subdomain("b.example.com"),
        ],
    )

    delta = compute_delta(scan_old, scan_new)

    assert delta["subdomains"]["added"] == ["b.example.com", "m.example.com"]
    assert delta["subdomains"]["removed"] == ["a.example.com", "z.example.com"]


def test_cves_across_multiple_subdomains() -> None:
    """CVEs are collected across all subdomains, not per-subdomain."""
    svc1_old = _make_service(443, "nginx", cves=[_make_cve("CVE-2021-0001")])
    svc2_old = _make_service(80, "apache", cves=[_make_cve("CVE-2021-0002")])

    svc1_new = _make_service(443, "nginx", cves=[_make_cve("CVE-2021-0001")])
    svc2_new = _make_service(80, "apache", cves=[
        _make_cve("CVE-2021-0002"),
        _make_cve("CVE-2024-0003"),
    ])
    svc3_new = _make_service(8080, "tomcat", cves=[_make_cve("CVE-2024-0004")])

    scan_old = _make_scan(
        subdomains=[
            _make_subdomain("www.example.com", services=[svc1_old]),
            _make_subdomain("api.example.com", services=[svc2_old]),
        ],
    )
    scan_new = _make_scan(
        subdomains=[
            _make_subdomain("www.example.com", services=[svc1_new]),
            _make_subdomain("api.example.com", services=[svc2_new, svc3_new]),
        ],
    )

    delta = compute_delta(scan_old, scan_new)

    assert sorted(delta["cves"]["new"]) == ["CVE-2024-0003", "CVE-2024-0004"]
    assert delta["cves"]["resolved"] == []
