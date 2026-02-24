"""
Scan comparison (delta detection) for ReconScope.

Compares two :class:`~app.models.scan.Scan` ORM instances and returns a
structured dictionary describing what changed between them: new or removed
subdomains, added or removed services, new or resolved CVEs, and the
overall risk-level shift.

The comparison is designed for the ``GET /scans/{id}/delta/{compare_id}``
API endpoint and for the frontend *DeltaComparison* component.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.scan import Scan
    from app.models.service import Service
    from app.models.cve import CVEMatch


def compute_delta(scan_old: Scan, scan_new: Scan) -> dict[str, Any]:
    """Compare two scans and return a dictionary of changes.

    Both parameters are fully loaded :class:`~app.models.scan.Scan` ORM
    objects with their ``subdomains`` -> ``services`` -> ``cves``
    relationships eagerly loaded.

    Args:
        scan_old: The earlier (baseline) scan.
        scan_new: The later (current) scan.

    Returns:
        A dictionary with the following structure::

            {
                "subdomains": {
                    "added":     ["new.acme.de", ...],
                    "removed":   ["gone.acme.de", ...],
                    "unchanged": ["www.acme.de", ...],
                },
                "services": {
                    "added":   [("sub.acme.de", 443, "nginx"), ...],
                    "removed": [("sub.acme.de", 8080, "tomcat"), ...],
                },
                "cves": {
                    "new":      ["CVE-2024-1234", ...],
                    "resolved": ["CVE-2023-5678", ...],
                },
                "risk_change": {
                    "old_score": "high",
                    "new_score": "critical",
                },
            }
    """
    # -- Subdomain comparison -------------------------------------------------
    old_subdomain_names: set[str] = {sub.name for sub in scan_old.subdomains}
    new_subdomain_names: set[str] = {sub.name for sub in scan_new.subdomains}

    subdomains_added: list[str] = sorted(new_subdomain_names - old_subdomain_names)
    subdomains_removed: list[str] = sorted(old_subdomain_names - new_subdomain_names)
    subdomains_unchanged: list[str] = sorted(old_subdomain_names & new_subdomain_names)

    # -- Service comparison ---------------------------------------------------
    old_service_tuples: set[tuple[str, int, str | None]] = _get_services(scan_old)
    new_service_tuples: set[tuple[str, int, str | None]] = _get_services(scan_new)

    services_added: list[tuple[str, int, str | None]] = sorted(
        new_service_tuples - old_service_tuples
    )
    services_removed: list[tuple[str, int, str | None]] = sorted(
        old_service_tuples - new_service_tuples
    )

    # -- CVE comparison -------------------------------------------------------
    old_cve_ids: set[str] = _get_cves(scan_old)
    new_cve_ids: set[str] = _get_cves(scan_new)

    cves_new: list[str] = sorted(new_cve_ids - old_cve_ids)
    cves_resolved: list[str] = sorted(old_cve_ids - new_cve_ids)

    # -- Risk change ----------------------------------------------------------
    return {
        "subdomains": {
            "added": subdomains_added,
            "removed": subdomains_removed,
            "unchanged": subdomains_unchanged,
        },
        "services": {
            "added": [list(s) for s in services_added],
            "removed": [list(s) for s in services_removed],
        },
        "cves": {
            "new": cves_new,
            "resolved": cves_resolved,
        },
        "risk_change": {
            "old_score": scan_old.overall_risk,
            "new_score": scan_new.overall_risk,
        },
    }


# -- Helper functions --------------------------------------------------------

def _get_services(scan: Scan) -> set[tuple[str, int, str | None]]:
    """Extract a set of (subdomain_name, port, service_name) tuples.

    Traverses the scan -> subdomains -> services hierarchy and returns
    a set of 3-tuples suitable for set arithmetic.

    Args:
        scan: A fully loaded :class:`~app.models.scan.Scan` ORM instance.

    Returns:
        A set of ``(subdomain_name, port, service_name)`` tuples.
    """
    service_tuples: set[tuple[str, int, str | None]] = set()
    for subdomain in scan.subdomains:
        for service in subdomain.services:
            service_tuples.add(
                (subdomain.name, service.port, service.service_name)
            )
    return service_tuples


def _get_cves(scan: Scan) -> set[str]:
    """Extract a set of unique CVE IDs from a scan.

    Traverses the scan -> subdomains -> services -> cves hierarchy.

    Args:
        scan: A fully loaded :class:`~app.models.scan.Scan` ORM instance.

    Returns:
        A set of CVE identifier strings (e.g. ``{"CVE-2021-41773"}``).
    """
    cve_ids: set[str] = set()
    for subdomain in scan.subdomains:
        for service in subdomain.services:
            for cve in service.cves:
                cve_ids.add(cve.cve_id)
    return cve_ids
