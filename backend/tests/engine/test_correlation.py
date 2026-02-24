"""
Tests for the Correlation Engine.

Validates subnet relationship detection, forgotten asset identification,
exposed database detection, technology inconsistency detection, and
threshold behaviours.
"""

from __future__ import annotations

import pytest

from app.engine.correlation import CorrelationEngine


@pytest.fixture()
def engine() -> CorrelationEngine:
    """Return a fresh CorrelationEngine instance for each test."""
    return CorrelationEngine()


def test_subnet_relationship_detected(engine: CorrelationEngine) -> None:
    """Three or more assets in the same /24 subnet produce a 'subnet' insight."""
    scan_data = {
        "subdomains": [
            {"name": "host1.example.com", "ip_address": "10.0.1.10", "services": []},
            {"name": "host2.example.com", "ip_address": "10.0.1.11", "services": []},
            {"name": "host3.example.com", "ip_address": "10.0.1.12", "services": []},
        ]
    }

    insights = engine.analyze(scan_data)

    subnet_insights = [i for i in insights if i.type == "subnet"]
    assert len(subnet_insights) == 1
    assert subnet_insights[0].severity == "high"
    assert "lateral movement" in subnet_insights[0].message.lower()
    assert len(subnet_insights[0].affected_assets) == 3


def test_subnet_below_threshold_no_insight(engine: CorrelationEngine) -> None:
    """Only two assets in the same /24 subnet should not produce a subnet insight."""
    scan_data = {
        "subdomains": [
            {"name": "host1.example.com", "ip_address": "10.0.1.10", "services": []},
            {"name": "host2.example.com", "ip_address": "10.0.1.11", "services": []},
        ]
    }

    insights = engine.analyze(scan_data)

    subnet_insights = [i for i in insights if i.type == "subnet"]
    assert len(subnet_insights) == 0


def test_forgotten_asset_staging(engine: CorrelationEngine) -> None:
    """A subdomain with 'staging' in its name and outdated software is flagged as forgotten."""
    scan_data = {
        "subdomains": [
            {
                "name": "staging.example.com",
                "ip_address": "10.0.1.20",
                "services": [
                    {
                        "port": 443,
                        "service_name": "nginx",
                        "version": "1.18.0",
                        "technologies": [
                            {"name": "Nginx", "version": "1.18.0", "category": "web_server"}
                        ],
                        "cves": [],
                    }
                ],
            }
        ]
    }

    insights = engine.analyze(scan_data)

    forgotten = [i for i in insights if i.type == "forgotten_asset"]
    assert len(forgotten) == 1
    assert forgotten[0].severity == "critical"
    assert "staging.example.com" in forgotten[0].affected_assets
    assert "suspicious hostname" in forgotten[0].message.lower() or "staging" in forgotten[0].message.lower()


def test_forgotten_asset_single_indicator(engine: CorrelationEngine) -> None:
    """A subdomain with only a suspicious name but no outdated software is not flagged."""
    scan_data = {
        "subdomains": [
            {
                "name": "staging.example.com",
                "ip_address": "10.0.1.20",
                "services": [
                    {
                        "port": 443,
                        "service_name": "nginx",
                        "version": "1.25.0",
                        "technologies": [
                            {"name": "Nginx", "version": "1.25.0", "category": "web_server"}
                        ],
                        "cves": [],
                    }
                ],
            }
        ]
    }

    insights = engine.analyze(scan_data)

    forgotten = [i for i in insights if i.type == "forgotten_asset"]
    assert len(forgotten) == 0, (
        "A single indicator (hostname pattern) should not trigger the forgotten-asset rule"
    )


def test_exposed_database_mysql(engine: CorrelationEngine) -> None:
    """Port 3306 (MySQL) exposed on a subdomain produces a critical 'exposure' insight."""
    scan_data = {
        "subdomains": [
            {
                "name": "db.example.com",
                "ip_address": "10.0.1.30",
                "services": [
                    {"port": 3306, "service_name": "mysql", "version": "8.0", "technologies": [], "cves": []},
                ],
            }
        ]
    }

    insights = engine.analyze(scan_data)

    exposure = [i for i in insights if i.type == "exposure"]
    assert len(exposure) == 1
    assert exposure[0].severity == "critical"
    assert "mysql" in exposure[0].message.lower()
    assert "3306" in exposure[0].message
    assert "db.example.com" in exposure[0].affected_assets


def test_exposed_redis(engine: CorrelationEngine) -> None:
    """Port 6379 (Redis) exposed on a subdomain produces a critical 'exposure' insight."""
    scan_data = {
        "subdomains": [
            {
                "name": "cache.example.com",
                "ip_address": "10.0.1.40",
                "services": [
                    {"port": 6379, "service_name": "redis", "version": "7.0", "technologies": [], "cves": []},
                ],
            }
        ]
    }

    insights = engine.analyze(scan_data)

    exposure = [i for i in insights if i.type == "exposure"]
    assert len(exposure) == 1
    assert exposure[0].severity == "critical"
    assert "redis" in exposure[0].message.lower()
    assert "6379" in exposure[0].message


def test_tech_inconsistency(engine: CorrelationEngine) -> None:
    """Three or more different web servers produce a 'tech_inconsistency' insight."""
    scan_data = {
        "subdomains": [
            {
                "name": "www.example.com",
                "ip_address": "10.0.1.1",
                "services": [
                    {
                        "port": 443,
                        "technologies": [
                            {"name": "Nginx", "version": "1.24.0", "category": "web_server"},
                        ],
                        "cves": [],
                    },
                ],
            },
            {
                "name": "api.example.com",
                "ip_address": "10.0.1.2",
                "services": [
                    {
                        "port": 443,
                        "technologies": [
                            {"name": "Apache", "version": "2.4.57", "category": "web_server"},
                        ],
                        "cves": [],
                    },
                ],
            },
            {
                "name": "admin.example.com",
                "ip_address": "10.0.2.1",
                "services": [
                    {
                        "port": 443,
                        "technologies": [
                            {"name": "IIS", "version": "10.0", "category": "web_server"},
                        ],
                        "cves": [],
                    },
                ],
            },
        ]
    }

    insights = engine.analyze(scan_data)

    inconsistency = [i for i in insights if i.type == "tech_inconsistency"]
    assert len(inconsistency) == 1
    assert inconsistency[0].severity == "low"
    assert "web_server" in inconsistency[0].message
    assert "3" in inconsistency[0].message


def test_no_inconsistency_below_threshold(engine: CorrelationEngine) -> None:
    """Only two different web servers should not trigger tech_inconsistency."""
    scan_data = {
        "subdomains": [
            {
                "name": "www.example.com",
                "ip_address": "10.0.1.1",
                "services": [
                    {
                        "port": 443,
                        "technologies": [
                            {"name": "Nginx", "version": "1.24.0", "category": "web_server"},
                        ],
                        "cves": [],
                    },
                ],
            },
            {
                "name": "api.example.com",
                "ip_address": "10.0.1.2",
                "services": [
                    {
                        "port": 443,
                        "technologies": [
                            {"name": "Apache", "version": "2.4.57", "category": "web_server"},
                        ],
                        "cves": [],
                    },
                ],
            },
        ]
    }

    insights = engine.analyze(scan_data)

    inconsistency = [i for i in insights if i.type == "tech_inconsistency"]
    assert len(inconsistency) == 0
