"""
Tests for the Attack Path Inference engine.

Validates forgotten-asset RCE paths, exposed database paths, service chain
exploitation, mail server compromise, clean-scan behaviour, severity ordering,
lateral movement detection, and risk level assignment.
"""

from __future__ import annotations

import pytest

from app.engine.attack_paths import (
    AttackPathEngine,
    AttackPathStep,
    InferredAttackPath,
    _SEVERITY_ORDER,
)


@pytest.fixture()
def engine() -> AttackPathEngine:
    """Return a fresh AttackPathEngine instance for each test."""
    return AttackPathEngine()


# ---------------------------------------------------------------------------
# Rule: forgotten_asset_rce
# ---------------------------------------------------------------------------

def test_forgotten_asset_rce_path(engine: AttackPathEngine) -> None:
    """A staging subdomain with a high-CVSS CVE produces a critical RCE attack path."""
    scan_data = {
        "subdomains": [
            {
                "name": "staging.example.com",
                "ip_address": "185.23.45.20",
                "services": [
                    {
                        "port": 443,
                        "service_name": "nginx",
                        "version": "1.18.0",
                        "technologies": [
                            {"name": "Nginx", "version": "1.18.0", "category": "web_server"}
                        ],
                        "cves": [
                            {
                                "cve_id": "CVE-2021-23017",
                                "cvss_score": 9.8,
                                "severity": "critical",
                                "description": "1-byte memory overwrite in resolver",
                            }
                        ],
                    }
                ],
            }
        ]
    }

    paths = engine.infer(scan_data)

    rce_paths = [p for p in paths if "rce" in p.title.lower() or "forgotten" in p.title.lower()]
    assert len(rce_paths) >= 1, "Expected at least one RCE/forgotten-asset attack path"
    path = rce_paths[0]
    assert path.severity == "critical"
    assert len(path.steps) >= 3, "Expected at least 3 steps: discovery, fingerprint, exploit"
    assert "staging.example.com" in path.affected_nodes

    # Verify step techniques reference MITRE ATT&CK IDs.
    techniques = {step.technique for step in path.steps}
    assert "T1190" in techniques, "Exploit step should reference T1190 (Exploit Public-Facing Application)"


def test_forgotten_asset_skips_non_indicator_hostname(engine: AttackPathEngine) -> None:
    """A subdomain without forgotten-asset indicators does not trigger the RCE rule."""
    scan_data = {
        "subdomains": [
            {
                "name": "www.example.com",
                "ip_address": "185.23.45.10",
                "services": [
                    {
                        "port": 443,
                        "service_name": "nginx",
                        "version": "1.18.0",
                        "technologies": [],
                        "cves": [
                            {
                                "cve_id": "CVE-2021-23017",
                                "cvss_score": 9.8,
                                "severity": "critical",
                            }
                        ],
                    }
                ],
            }
        ]
    }

    paths = engine.infer(scan_data)

    rce_paths = [p for p in paths if "forgotten" in p.title.lower()]
    assert len(rce_paths) == 0, "Non-indicator hostname should not produce forgotten-asset paths"


def test_forgotten_asset_requires_high_cvss(engine: AttackPathEngine) -> None:
    """A forgotten asset with only low-CVSS CVEs does not trigger the RCE rule."""
    scan_data = {
        "subdomains": [
            {
                "name": "dev.example.com",
                "ip_address": "185.23.45.20",
                "services": [
                    {
                        "port": 443,
                        "service_name": "nginx",
                        "version": "1.18.0",
                        "technologies": [],
                        "cves": [
                            {
                                "cve_id": "CVE-2022-0001",
                                "cvss_score": 3.5,
                                "severity": "low",
                            }
                        ],
                    }
                ],
            }
        ]
    }

    paths = engine.infer(scan_data)

    rce_paths = [p for p in paths if "rce" in p.title.lower() or "forgotten" in p.title.lower()]
    assert len(rce_paths) == 0, "Low-CVSS CVE should not trigger forgotten-asset RCE rule"


def test_forgotten_asset_picks_highest_cvss(engine: AttackPathEngine) -> None:
    """When multiple high-CVSS CVEs exist, the rule picks the one with the highest score."""
    scan_data = {
        "subdomains": [
            {
                "name": "test.example.com",
                "ip_address": "185.23.45.20",
                "services": [
                    {
                        "port": 443,
                        "service_name": "nginx",
                        "version": "1.18.0",
                        "technologies": [],
                        "cves": [
                            {"cve_id": "CVE-2021-0001", "cvss_score": 7.5},
                            {"cve_id": "CVE-2021-0002", "cvss_score": 9.8},
                            {"cve_id": "CVE-2021-0003", "cvss_score": 8.0},
                        ],
                    }
                ],
            }
        ]
    }

    paths = engine.infer(scan_data)

    rce_paths = [p for p in paths if "forgotten" in p.title.lower() or "rce" in p.title.lower()]
    assert len(rce_paths) >= 1
    path = rce_paths[0]

    # Find the exploit step that references a CVE.
    exploit_steps = [s for s in path.steps if s.technique == "T1190"]
    assert len(exploit_steps) == 1
    assert "CVE-2021-0002" in exploit_steps[0].description, (
        "The highest-CVSS CVE (9.8) should be chosen for the exploit step"
    )
    assert "9.8" in exploit_steps[0].description


# ---------------------------------------------------------------------------
# Rule: exposed_database
# ---------------------------------------------------------------------------

def test_exposed_database_path(engine: AttackPathEngine) -> None:
    """An exposed MySQL port (3306) produces a critical database attack path."""
    scan_data = {
        "subdomains": [
            {
                "name": "db.example.com",
                "ip_address": "10.0.1.30",
                "services": [
                    {
                        "port": 3306,
                        "service_name": "mysql",
                        "version": "8.0",
                        "technologies": [],
                        "cves": [],
                    }
                ],
            }
        ]
    }

    paths = engine.infer(scan_data)

    db_paths = [
        p for p in paths
        if "mysql" in p.title.lower() or "database" in p.title.lower() or "exposed" in p.title.lower()
    ]
    assert len(db_paths) >= 1, "Expected at least one exposed-database attack path"
    path = db_paths[0]
    assert path.severity == "critical"
    assert len(path.steps) >= 2, "Expected at least 2 steps: discovery, brute-force"
    assert "db.example.com" in path.affected_nodes


def test_exposed_database_all_db_ports(engine: AttackPathEngine) -> None:
    """All known database ports (3306, 5432, 27017, 6379) trigger the exposed-database rule."""
    db_ports = {3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis"}

    for port, db_name in db_ports.items():
        scan_data = {
            "subdomains": [
                {
                    "name": "host.example.com",
                    "ip_address": "10.0.1.1",
                    "services": [
                        {
                            "port": port,
                            "service_name": db_name.lower(),
                            "version": "1.0",
                            "technologies": [],
                            "cves": [],
                        }
                    ],
                }
            ]
        }

        paths = engine.infer(scan_data)

        db_paths = [p for p in paths if db_name in p.title]
        assert len(db_paths) >= 1, f"Expected exposed-database path for {db_name} on port {port}"
        assert db_paths[0].severity == "critical"

        # Verify brute-force technique is present.
        techniques = {s.technique for s in db_paths[0].steps}
        assert "T1110" in techniques, f"Brute-force technique T1110 missing for {db_name}"
        assert "T1041" in techniques, f"Data exfiltration technique T1041 missing for {db_name}"


def test_non_database_port_not_flagged(engine: AttackPathEngine) -> None:
    """Standard web ports should not trigger the exposed-database rule."""
    scan_data = {
        "subdomains": [
            {
                "name": "web.example.com",
                "ip_address": "10.0.1.1",
                "services": [
                    {
                        "port": 443,
                        "service_name": "nginx",
                        "version": "1.25.0",
                        "technologies": [],
                        "cves": [],
                    },
                    {
                        "port": 80,
                        "service_name": "nginx",
                        "version": "1.25.0",
                        "technologies": [],
                        "cves": [],
                    },
                ],
            }
        ]
    }

    paths = engine.infer(scan_data)

    db_paths = [p for p in paths if "exposed" in p.title.lower() and ("mysql" in p.title.lower() or "postgresql" in p.title.lower() or "mongodb" in p.title.lower() or "redis" in p.title.lower())]
    assert len(db_paths) == 0, "Standard web ports should not produce exposed-database paths"


# ---------------------------------------------------------------------------
# Rule: service_chain_exploitation
# ---------------------------------------------------------------------------

def test_service_chain_exploitation(engine: AttackPathEngine) -> None:
    """A host with two or more vulnerable services produces a high-severity chain exploitation path."""
    scan_data = {
        "subdomains": [
            {
                "name": "app.example.com",
                "ip_address": "10.0.1.50",
                "services": [
                    {
                        "port": 443,
                        "service_name": "nginx",
                        "version": "1.18.0",
                        "technologies": [],
                        "cves": [
                            {"cve_id": "CVE-2021-23017", "cvss_score": 9.8},
                        ],
                    },
                    {
                        "port": 8080,
                        "service_name": "tomcat",
                        "version": "9.0.0",
                        "technologies": [],
                        "cves": [
                            {"cve_id": "CVE-2022-1234", "cvss_score": 7.5},
                        ],
                    },
                ],
            }
        ]
    }

    paths = engine.infer(scan_data)

    chain_paths = [p for p in paths if "chain" in p.title.lower() or "service chain" in p.title.lower()]
    assert len(chain_paths) >= 1, "Expected a service chain exploitation path"
    path = chain_paths[0]
    assert path.severity == "high"

    # Should contain enumeration + one step per vulnerable service + escalation.
    assert len(path.steps) >= 4, (
        "Expected at least 4 steps: enumeration, 2 exploits, privilege escalation"
    )

    # Check that both CVEs are referenced.
    step_descriptions = " ".join(s.description for s in path.steps)
    assert "CVE-2021-23017" in step_descriptions
    assert "CVE-2022-1234" in step_descriptions

    # Privilege escalation step should be present.
    techniques = {s.technique for s in path.steps}
    assert "T1068" in techniques, "Chain exploitation should include T1068 (Exploitation for Privilege Escalation)"

    # Affected nodes should include the host and both service ports.
    assert "app.example.com" in path.affected_nodes
    assert "app.example.com:443" in path.affected_nodes
    assert "app.example.com:8080" in path.affected_nodes


def test_service_chain_requires_two_vulnerable_services(engine: AttackPathEngine) -> None:
    """A host with only one vulnerable service does not trigger the chain exploitation rule."""
    scan_data = {
        "subdomains": [
            {
                "name": "app.example.com",
                "ip_address": "10.0.1.50",
                "services": [
                    {
                        "port": 443,
                        "service_name": "nginx",
                        "version": "1.18.0",
                        "technologies": [],
                        "cves": [
                            {"cve_id": "CVE-2021-23017", "cvss_score": 9.8},
                        ],
                    },
                    {
                        "port": 80,
                        "service_name": "apache",
                        "version": "2.4.0",
                        "technologies": [],
                        "cves": [],
                    },
                ],
            }
        ]
    }

    paths = engine.infer(scan_data)

    chain_paths = [p for p in paths if "chain" in p.title.lower()]
    assert len(chain_paths) == 0, (
        "A host with only one vulnerable service should not trigger chain exploitation"
    )


# ---------------------------------------------------------------------------
# Rule: mail_server_compromise
# ---------------------------------------------------------------------------

def test_mail_server_compromise(engine: AttackPathEngine) -> None:
    """A subdomain that is an MX target with vulnerable services produces a high-severity path."""
    scan_data = {
        "subdomains": [
            {
                "name": "example.com",
                "ip_address": "10.0.1.1",
                "services": [],
                "dns_records": {
                    "MX": ["10 mail.example.com."],
                },
            },
            {
                "name": "mail.example.com",
                "ip_address": "10.0.1.50",
                "services": [
                    {
                        "port": 25,
                        "service_name": "postfix",
                        "version": "3.5.6",
                        "technologies": [],
                        "cves": [
                            {"cve_id": "CVE-2023-51764", "cvss_score": 7.0},
                        ],
                    }
                ],
            },
        ]
    }

    paths = engine.infer(scan_data)

    mail_paths = [p for p in paths if "mail" in p.title.lower()]
    assert len(mail_paths) >= 1, "Expected a mail server compromise path"
    path = mail_paths[0]
    assert path.severity == "high"
    assert "mail.example.com" in path.affected_nodes

    # Should reference the mail interception technique.
    techniques = {s.technique for s in path.steps}
    assert "T1114" in techniques, "Mail compromise should include T1114 (Email Collection)"
    assert "T1589.002" in techniques, "Should include T1589.002 (Gather Victim Identity: Email)"


def test_mail_server_no_cves_no_path(engine: AttackPathEngine) -> None:
    """An MX target without vulnerable services does not trigger the mail compromise rule."""
    scan_data = {
        "subdomains": [
            {
                "name": "example.com",
                "ip_address": "10.0.1.1",
                "services": [],
                "dns_records": {
                    "MX": ["10 mail.example.com."],
                },
            },
            {
                "name": "mail.example.com",
                "ip_address": "10.0.1.50",
                "services": [
                    {
                        "port": 25,
                        "service_name": "postfix",
                        "version": "3.7.0",
                        "technologies": [],
                        "cves": [],
                    }
                ],
            },
        ]
    }

    paths = engine.infer(scan_data)

    mail_paths = [p for p in paths if "mail" in p.title.lower()]
    assert len(mail_paths) == 0, "MX target without CVEs should not produce a mail compromise path"


# ---------------------------------------------------------------------------
# General: empty data, severity ordering, lateral movement
# ---------------------------------------------------------------------------

def test_no_paths_for_clean_scan(engine: AttackPathEngine) -> None:
    """A scan with no vulnerable assets should produce no attack paths."""
    scan_data = {
        "subdomains": [
            {
                "name": "www.example.com",
                "ip_address": "10.0.1.1",
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

    paths = engine.infer(scan_data)

    assert len(paths) == 0, f"Expected no attack paths for a clean scan, got {len(paths)}"


def test_empty_scan_data(engine: AttackPathEngine) -> None:
    """Completely empty scan data produces no attack paths and does not raise."""
    paths = engine.infer({"subdomains": []})
    assert paths == []

    paths_no_key = engine.infer({})
    assert paths_no_key == []


def test_paths_sorted_by_severity(engine: AttackPathEngine) -> None:
    """Attack paths must be sorted by severity: critical before high before medium."""
    scan_data = {
        "subdomains": [
            {
                "name": "staging.example.com",
                "ip_address": "185.23.45.20",
                "services": [
                    {
                        "port": 443,
                        "service_name": "nginx",
                        "version": "1.18.0",
                        "technologies": [
                            {"name": "Nginx", "version": "1.18.0", "category": "web_server"}
                        ],
                        "cves": [
                            {"cve_id": "CVE-2021-23017", "cvss_score": 9.8, "severity": "critical"},
                        ],
                    },
                    {
                        "port": 3306,
                        "service_name": "mysql",
                        "version": "5.7",
                        "technologies": [],
                        "cves": [],
                    },
                    {
                        "port": 8080,
                        "service_name": "tomcat",
                        "version": "9.0",
                        "technologies": [],
                        "cves": [
                            {"cve_id": "CVE-2022-1234", "cvss_score": 7.5, "severity": "high"},
                        ],
                    },
                ],
            }
        ]
    }

    paths = engine.infer(scan_data)

    assert len(paths) >= 2, "Expected at least 2 paths (critical + high) for severity ordering test"
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for i in range(len(paths) - 1):
        current_rank = severity_order.get(paths[i].severity, 99)
        next_rank = severity_order.get(paths[i + 1].severity, 99)
        assert current_rank <= next_rank, (
            f"Path at index {i} ({paths[i].severity}) should come before "
            f"path at index {i+1} ({paths[i+1].severity})"
        )


def test_lateral_movement_detection(engine: AttackPathEngine) -> None:
    """A forgotten asset sharing a /24 subnet with other hosts includes a lateral movement step."""
    scan_data = {
        "subdomains": [
            {
                "name": "staging.example.com",
                "ip_address": "10.0.1.10",
                "services": [
                    {
                        "port": 443,
                        "service_name": "nginx",
                        "version": "1.18.0",
                        "technologies": [],
                        "cves": [
                            {"cve_id": "CVE-2021-23017", "cvss_score": 9.8, "severity": "critical"},
                        ],
                    }
                ],
            },
            {
                "name": "www.example.com",
                "ip_address": "10.0.1.11",
                "services": [
                    {
                        "port": 443,
                        "service_name": "nginx",
                        "version": "1.25.0",
                        "technologies": [],
                        "cves": [],
                    }
                ],
            },
            {
                "name": "api.example.com",
                "ip_address": "10.0.1.12",
                "services": [
                    {
                        "port": 443,
                        "service_name": "nginx",
                        "version": "1.25.0",
                        "technologies": [],
                        "cves": [],
                    }
                ],
            },
        ]
    }

    paths = engine.infer(scan_data)

    rce_paths = [p for p in paths if "staging" in p.title.lower()]
    assert len(rce_paths) >= 1

    path = rce_paths[0]
    step_descriptions = " ".join(s.description.lower() for s in path.steps)
    assert "lateral" in step_descriptions or "same subnet" in step_descriptions, (
        "Expected a lateral movement step referencing same-subnet neighbours"
    )

    # The affected nodes should include the neighbour hosts.
    assert len(path.affected_nodes) > 1, (
        "Lateral movement path should affect more than just the staging host"
    )

    # Verify the lateral movement technique T1021 is used.
    techniques = {s.technique for s in path.steps}
    assert "T1021" in techniques, "Lateral movement step should reference T1021"


def test_lateral_movement_no_neighbours_different_subnet(engine: AttackPathEngine) -> None:
    """A forgotten asset with no same-subnet neighbours does not include a lateral movement step."""
    scan_data = {
        "subdomains": [
            {
                "name": "old.example.com",
                "ip_address": "10.0.1.10",
                "services": [
                    {
                        "port": 443,
                        "service_name": "nginx",
                        "version": "1.18.0",
                        "technologies": [],
                        "cves": [
                            {"cve_id": "CVE-2021-23017", "cvss_score": 9.8},
                        ],
                    }
                ],
            },
            {
                "name": "www.example.com",
                "ip_address": "192.168.1.1",
                "services": [],
            },
        ]
    }

    paths = engine.infer(scan_data)

    rce_paths = [p for p in paths if "old.example.com" in p.title.lower()]
    assert len(rce_paths) >= 1
    path = rce_paths[0]

    techniques = {s.technique for s in path.steps}
    assert "T1021" not in techniques, (
        "No lateral movement step expected when neighbours are on a different subnet"
    )
    assert path.affected_nodes == ["old.example.com"], (
        "Only the target host should be affected without same-subnet neighbours"
    )


def test_inferred_attack_path_dataclass() -> None:
    """Verify InferredAttackPath and AttackPathStep dataclass construction."""
    step = AttackPathStep(
        description="Test step",
        node_id="test-node",
        technique="T0000",
    )
    path = InferredAttackPath(
        title="Test path",
        severity="high",
        steps=[step],
        affected_nodes=["test-node"],
    )

    assert path.title == "Test path"
    assert path.severity == "high"
    assert len(path.steps) == 1
    assert path.steps[0].description == "Test step"
    assert path.steps[0].node_id == "test-node"
    assert path.steps[0].technique == "T0000"
    assert path.affected_nodes == ["test-node"]


def test_severity_order_mapping() -> None:
    """The internal severity ordering dictionary has the expected ranking."""
    assert _SEVERITY_ORDER["critical"] < _SEVERITY_ORDER["high"]
    assert _SEVERITY_ORDER["high"] < _SEVERITY_ORDER["medium"]
    assert _SEVERITY_ORDER["medium"] < _SEVERITY_ORDER["low"]
    assert _SEVERITY_ORDER["low"] < _SEVERITY_ORDER["info"]
