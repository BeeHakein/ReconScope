"""
Attack Path Inference engine for ReconScope.

Uses a rule-based approach to construct plausible multi-step attack
scenarios from aggregated scan data.  Each rule models a well-known
attacker workflow (e.g. *forgotten asset -> RCE -> lateral movement*) and
emits an :class:`InferredAttackPath` when the required preconditions are
satisfied.

Rules reference `MITRE ATT&CK`_ technique IDs so the frontend can link
to authoritative documentation.

.. _MITRE ATT&CK: https://attack.mitre.org/
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address as parse_ip_address, ip_network
from typing import Any


# -- Severity ordering used for sorting paths ----------------------------------
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

# -- Hostname fragments that mark non-production assets -----------------------
_FORGOTTEN_INDICATORS: list[str] = ["staging", "dev", "test", "old", "demo"]

# -- Database ports and their human-readable names ----------------------------
_DB_PORTS: dict[int, str] = {
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
}

# Providers whose CNAME records are commonly vulnerable to subdomain takeover.
_TAKEOVER_CNAME_PROVIDERS: list[str] = [
    "herokuapp.com", "s3.amazonaws.com", "azurewebsites.net",
    "cloudfront.net", "github.io", "netlify.app", "shopify.com",
    "fastly.net", "ghost.io", "wordpress.com", "pantheonsite.io",
    "surge.sh", "bitbucket.io", "zendesk.com", "readme.io",
    "tumblr.com", "cargo.site",
]

# Admin/management ports.
_ADMIN_PORTS: set[int] = {8080, 8443, 9090, 9443, 2082, 2083, 2086, 2087, 8888, 10000}

# Hostname fragments indicating admin/management panels.
_ADMIN_HOSTNAMES: list[str] = [
    "admin", "cpanel", "webmin", "phpmyadmin", "panel",
    "dashboard", "manage", "console", "portal", "backoffice",
]

# Direct-access authentication services.
_AUTH_PORTS: dict[int, str] = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC"}

# API-related hostname fragments.
_API_HOSTNAMES: list[str] = ["api", "graphql", "rest", "gateway", "backend", "ws"]

# Ports used for lateral movement in ransomware campaigns.
_RANSOMWARE_LATERAL_PORTS: set[int] = {445, 3389, 5985, 5986}

# Remote access ports.
_REMOTE_ACCESS_PORTS: dict[int, str] = {
    22: "SSH", 3389: "RDP", 1194: "OpenVPN",
    500: "IKE", 4500: "IPSec", 5900: "VNC",
}

# Mail-related ports.
_MAIL_PORTS: set[int] = {25, 110, 143, 465, 587, 993, 995}


@dataclass
class AttackPathStep:
    """A single step within an inferred attack path.

    Attributes:
        description: Human-readable explanation of what the attacker does.
        node_id: Identifier of the graph node involved (subdomain, port,
            CVE ID, ...).
        technique: MITRE ATT&CK technique ID (e.g. ``T1190``).
    """

    description: str
    node_id: str
    technique: str


@dataclass
class InferredAttackPath:
    """A complete multi-step attack scenario.

    Attributes:
        title: Short summary of the attack path.
        severity: Overall severity -- ``critical``, ``high``, ``medium``,
            ``low``, or ``info``.
        steps: Ordered list of :class:`AttackPathStep` instances.
        affected_nodes: Graph node identifiers affected by this path.
    """

    title: str
    severity: str
    steps: list[AttackPathStep] = field(default_factory=list)
    affected_nodes: list[str] = field(default_factory=list)


class AttackPathEngine:
    """Rule-based attack-path inference engine.

    The engine maintains an ordered list of rule names in :attr:`RULES`.
    For each name ``rule``, the engine looks up ``_rule_{rule}`` as an
    instance method and invokes it with the aggregated scan data.

    Rules may return a single :class:`InferredAttackPath`, a list, or
    ``None``.  All results are collected, flattened, and sorted by
    severity (critical first).

    Expected *scan_data* shape::

        {
            "subdomains": [
                {
                    "name": "staging.acme-corp.de",
                    "ip_address": "185.23.45.20",
                    "services": [
                        {
                            "port": 443,
                            "service_name": "nginx",
                            "version": "1.18.0",
                            "technologies": [...],
                            "cves": [
                                {"cve_id": "CVE-2021-41773", "cvss_score": 9.8, ...}
                            ]
                        }
                    ]
                }
            ]
        }
    """

    RULES: list[str] = [
        "forgotten_asset_rce",
        "exposed_database",
        "service_chain_exploitation",
        "mail_server_compromise",
        "web_app_exploitation",
        "shared_tech_blast_radius",
        "subdomain_takeover",
        "admin_panel_exposure",
        "dns_zone_transfer",
        "tls_downgrade_mitm",
        "credential_stuffing_chain",
        "ransomware_deployment",
        "api_data_exfiltration",
        "phishing_infrastructure",
        "epss_priority_exploitation",
        "network_pivot_via_vpn_ssh",
        "aging_vulnerability_exploitation",
    ]

    def infer(self, scan_data: dict[str, Any]) -> list[InferredAttackPath]:
        """Run all rules against *scan_data* and return inferred paths.

        Args:
            scan_data: Aggregated scan results.

        Returns:
            A list of :class:`InferredAttackPath` instances sorted by
            severity (critical first).  May be empty.
        """
        paths: list[InferredAttackPath] = []

        for rule_name in self.RULES:
            method = getattr(self, f"_rule_{rule_name}", None)
            if method is None:
                continue
            result = method(scan_data)
            if result is None:
                continue
            if isinstance(result, list):
                paths.extend(result)
            else:
                paths.append(result)

        paths.sort(key=lambda p: _SEVERITY_ORDER.get(p.severity, 99))
        return paths

    # -- Rule implementations -------------------------------------------------

    def _rule_forgotten_asset_rce(
        self, data: dict[str, Any]
    ) -> list[InferredAttackPath]:
        """Forgotten asset with a high-CVSS CVE leading to RCE.

        Workflow:
        1. Attacker discovers a non-production subdomain via CT logs.
        2. Service fingerprinting reveals an outdated service.
        3. A known CVE with CVSS >= 7.0 is exploitable.
        4. If other assets share the same /24 subnet, lateral movement
           is possible.

        Args:
            data: Aggregated scan data.

        Returns:
            A list of critical-severity attack paths.
        """
        paths: list[InferredAttackPath] = []

        for sub in data.get("subdomains", []):
            name_lower: str = sub["name"].lower()
            if not any(frag in name_lower for frag in _FORGOTTEN_INDICATORS):
                continue

            for svc in sub.get("services", []):
                high_cvss_cves: list[dict[str, Any]] = [
                    cve
                    for cve in svc.get("cves", [])
                    if (cve.get("cvss_score") or 0.0) >= 7.0
                ]
                if not high_cvss_cves:
                    continue

                # Pick the highest-scoring CVE.
                cve = max(high_cvss_cves, key=lambda c: c.get("cvss_score", 0.0))

                steps: list[AttackPathStep] = [
                    AttackPathStep(
                        description=(
                            f"Attacker discovers {sub['name']} via "
                            f"Certificate Transparency"
                        ),
                        node_id=sub["name"],
                        technique="T1596.003",
                    ),
                    AttackPathStep(
                        description=(
                            f"{svc.get('service_name', 'Service')} "
                            f"{svc.get('version', '')} identified on "
                            f"port {svc['port']}"
                        ),
                        node_id=f"{sub['name']}:{svc['port']}",
                        technique="T1046",
                    ),
                    AttackPathStep(
                        description=(
                            f"{cve['cve_id']} (CVSS {cve['cvss_score']}) "
                            f"is exploitable"
                        ),
                        node_id=cve["cve_id"],
                        technique="T1190",
                    ),
                ]

                # Check for lateral-movement potential via same subnet.
                same_subnet: list[str] = self._find_same_subnet(
                    sub, data.get("subdomains", [])
                )
                if same_subnet:
                    limited_subnet = same_subnet[:3]
                    steps.append(
                        AttackPathStep(
                            description=(
                                f"Lateral movement to "
                                f"{', '.join(limited_subnet)} possible "
                                f"(same subnet)"
                            ),
                            node_id=limited_subnet[0],
                            technique="T1021",
                        )
                    )

                affected: list[str] = [sub["name"]] + same_subnet[:3]

                paths.append(
                    InferredAttackPath(
                        title=f"RCE on forgotten asset {sub['name']}",
                        severity="critical",
                        steps=steps,
                        affected_nodes=affected,
                    )
                )

        return paths

    def _rule_exposed_database(
        self, data: dict[str, Any]
    ) -> list[InferredAttackPath]:
        """Exposed database service leading to data exfiltration.

        Workflow:
        1. A database port is open on a publicly resolved subdomain.
        2. Attacker attempts brute-force or default credentials.
        3. Successful access enables data exfiltration.

        Args:
            data: Aggregated scan data.

        Returns:
            A list of critical-severity attack paths.
        """
        paths: list[InferredAttackPath] = []

        for sub in data.get("subdomains", []):
            for svc in sub.get("services", []):
                port: int = svc.get("port", 0)
                if port not in _DB_PORTS:
                    continue

                db_name: str = _DB_PORTS[port]
                paths.append(
                    InferredAttackPath(
                        title=f"Exposed {db_name} on {sub['name']}",
                        severity="critical",
                        steps=[
                            AttackPathStep(
                                description=(
                                    f"{db_name} open on port {port}"
                                ),
                                node_id=f"{sub['name']}:{port}",
                                technique="T1046",
                            ),
                            AttackPathStep(
                                description=(
                                    "Brute-force or default credential "
                                    "testing"
                                ),
                                node_id=f"{sub['name']}:{port}",
                                technique="T1110",
                            ),
                            AttackPathStep(
                                description="Data exfiltration on success",
                                node_id=sub["name"],
                                technique="T1041",
                            ),
                        ],
                        affected_nodes=[sub["name"]],
                    )
                )

        return paths

    def _rule_service_chain_exploitation(
        self, data: dict[str, Any]
    ) -> list[InferredAttackPath]:
        """Chain exploitation across multiple vulnerable services on a host.

        When a subdomain exposes two or more services that each carry at
        least one CVE, an attacker can chain vulnerabilities to escalate
        privileges or pivot between services.

        Args:
            data: Aggregated scan data.

        Returns:
            A list of high-severity attack paths.
        """
        paths: list[InferredAttackPath] = []

        for sub in data.get("subdomains", []):
            vulnerable_services: list[dict[str, Any]] = [
                svc
                for svc in sub.get("services", [])
                if svc.get("cves")
            ]

            if len(vulnerable_services) < 2:
                continue

            steps: list[AttackPathStep] = [
                AttackPathStep(
                    description=(
                        f"Attacker enumerates services on {sub['name']}"
                    ),
                    node_id=sub["name"],
                    technique="T1046",
                ),
            ]

            affected_nodes: list[str] = [sub["name"]]

            for svc in vulnerable_services:
                top_cve: dict[str, Any] = max(
                    svc["cves"],
                    key=lambda c: c.get("cvss_score", 0.0),
                )
                svc_label = svc.get("service_name") or f"port-{svc['port']}"
                node_id = f"{sub['name']}:{svc['port']}"
                affected_nodes.append(node_id)

                steps.append(
                    AttackPathStep(
                        description=(
                            f"Exploit {top_cve['cve_id']} on {svc_label} "
                            f"(port {svc['port']}, CVSS "
                            f"{top_cve.get('cvss_score', 'N/A')})"
                        ),
                        node_id=node_id,
                        technique="T1190",
                    )
                )

            steps.append(
                AttackPathStep(
                    description=(
                        "Chain compromised services to escalate privileges"
                    ),
                    node_id=sub["name"],
                    technique="T1068",
                )
            )

            paths.append(
                InferredAttackPath(
                    title=(
                        f"Service chain exploitation on {sub['name']} "
                        f"({len(vulnerable_services)} vulnerable services)"
                    ),
                    severity="high",
                    steps=steps,
                    affected_nodes=affected_nodes,
                )
            )

        return paths

    def _rule_mail_server_compromise(
        self, data: dict[str, Any]
    ) -> list[InferredAttackPath]:
        """Compromise path through a vulnerable mail server.

        If a subdomain that acts as an MX record target also carries
        known vulnerabilities, an attacker can exploit the mail server to
        intercept communications, exfiltrate data, or use it as a pivot
        point for further attacks.

        The rule examines DNS MX records and cross-references them with
        the subdomain list to find hosts that both receive mail **and**
        expose vulnerable services.

        Args:
            data: Aggregated scan data.

        Returns:
            A list of high-severity attack paths.
        """
        paths: list[InferredAttackPath] = []

        # Build a set of subdomain names that serve as MX targets.
        mx_targets: set[str] = set()
        for sub in data.get("subdomains", []):
            dns_records: dict[str, Any] = sub.get("dns_records") or {}
            for mx_value in dns_records.get("MX", []):
                # MX values may have a priority prefix ("10 mail.acme.de.").
                mx_host = mx_value.split()[-1].rstrip(".")
                mx_targets.add(mx_host.lower())

        # Match MX targets to subdomains with vulnerabilities.
        for sub in data.get("subdomains", []):
            if sub["name"].lower() not in mx_targets:
                continue

            vulnerable_services: list[dict[str, Any]] = [
                svc
                for svc in sub.get("services", [])
                if svc.get("cves")
            ]
            if not vulnerable_services:
                continue

            steps: list[AttackPathStep] = [
                AttackPathStep(
                    description=(
                        f"Attacker identifies {sub['name']} as an MX "
                        f"record target"
                    ),
                    node_id=sub["name"],
                    technique="T1589.002",
                ),
            ]

            affected_nodes: list[str] = [sub["name"]]

            for svc in vulnerable_services:
                top_cve = max(
                    svc["cves"],
                    key=lambda c: c.get("cvss_score", 0.0),
                )
                node_id = f"{sub['name']}:{svc['port']}"
                affected_nodes.append(node_id)

                steps.append(
                    AttackPathStep(
                        description=(
                            f"Exploit {top_cve['cve_id']} on "
                            f"{svc.get('service_name', 'service')} "
                            f"(port {svc['port']}, CVSS "
                            f"{top_cve.get('cvss_score', 'N/A')})"
                        ),
                        node_id=node_id,
                        technique="T1190",
                    )
                )

            steps.append(
                AttackPathStep(
                    description=(
                        "Intercept mail communications or use mail "
                        "server as pivot"
                    ),
                    node_id=sub["name"],
                    technique="T1114",
                )
            )

            paths.append(
                InferredAttackPath(
                    title=(
                        f"Mail server compromise via {sub['name']}"
                    ),
                    severity="high",
                    steps=steps,
                    affected_nodes=affected_nodes,
                )
            )

        return paths

    def _rule_web_app_exploitation(
        self, data: dict[str, Any]
    ) -> list[InferredAttackPath]:
        """Standard web-app exploitation for hosts with critical CVEs.

        Any subdomain (not already caught by forgotten_asset_rce) that
        exposes a service with a high-CVSS CVE gets a standard
        exploitation attack path.

        Workflow:
        1. Attacker discovers the subdomain via passive recon.
        2. Service fingerprinting reveals technology and version.
        3. A known CVE with CVSS >= 7.0 is exploited.
        4. Attacker gains access to the application or underlying host.

        Args:
            data: Aggregated scan data.

        Returns:
            A list of high-severity attack paths.
        """
        paths: list[InferredAttackPath] = []

        # Skip hosts already covered by forgotten_asset_rce.
        forgotten_names: set[str] = set()
        for sub in data.get("subdomains", []):
            name_lower = sub["name"].lower()
            if any(frag in name_lower for frag in _FORGOTTEN_INDICATORS):
                forgotten_names.add(sub["name"])

        for sub in data.get("subdomains", []):
            if sub["name"] in forgotten_names:
                continue

            for svc in sub.get("services", []):
                high_cves = [
                    cve for cve in svc.get("cves", [])
                    if (cve.get("cvss_score") or 0.0) >= 7.0
                ]
                if not high_cves:
                    continue

                top_cve = max(high_cves, key=lambda c: c.get("cvss_score", 0))
                svc_label = svc.get("service_name") or f"port-{svc['port']}"

                severity = (
                    "critical"
                    if (top_cve.get("cvss_score") or 0) >= 9.0
                    else "high"
                )

                paths.append(
                    InferredAttackPath(
                        title=(
                            f"Web app exploitation on {sub['name']} via "
                            f"{top_cve['cve_id']}"
                        ),
                        severity=severity,
                        steps=[
                            AttackPathStep(
                                description=(
                                    f"Attacker discovers {sub['name']} via "
                                    f"passive reconnaissance"
                                ),
                                node_id=sub["name"],
                                technique="T1596",
                            ),
                            AttackPathStep(
                                description=(
                                    f"{svc_label} {svc.get('version', '')} "
                                    f"identified on port {svc['port']}"
                                ),
                                node_id=f"{sub['name']}:{svc['port']}",
                                technique="T1046",
                            ),
                            AttackPathStep(
                                description=(
                                    f"Exploit {top_cve['cve_id']} "
                                    f"(CVSS {top_cve.get('cvss_score', 'N/A')})"
                                ),
                                node_id=top_cve["cve_id"],
                                technique="T1190",
                            ),
                            AttackPathStep(
                                description=(
                                    "Gain application-level or OS-level access"
                                ),
                                node_id=sub["name"],
                                technique="T1059",
                            ),
                        ],
                        affected_nodes=[
                            sub["name"],
                            f"{sub['name']}:{svc['port']}",
                            top_cve["cve_id"],
                        ],
                    )
                )

        return paths

    def _rule_shared_tech_blast_radius(
        self, data: dict[str, Any]
    ) -> list[InferredAttackPath]:
        """Shared vulnerable technology across multiple hosts.

        When the same vulnerable technology+version is found on 3+ hosts,
        a single exploit has a wide blast radius — effectively a supply
        chain risk within the organisation's estate.

        Args:
            data: Aggregated scan data.

        Returns:
            A list of high-severity attack paths.
        """
        paths: list[InferredAttackPath] = []

        # Map: (tech_name, version) -> [(host, cve_list)]
        tech_hosts: dict[tuple[str, str], list[tuple[str, list[dict]]]] = {}

        for sub in data.get("subdomains", []):
            for svc in sub.get("services", []):
                for tech in svc.get("technologies", []):
                    tech_name = tech.get("name", "")
                    tech_version = tech.get("version", "")
                    if tech_name and tech_version:
                        key = (tech_name, tech_version)
                        tech_hosts.setdefault(key, []).append(
                            (sub["name"], svc.get("cves", []))
                        )

        for (tech_name, tech_version), host_entries in tech_hosts.items():
            unique_hosts = sorted({h for h, _ in host_entries})
            # Collect all CVEs for this tech
            all_cves = [
                cve
                for _, cves in host_entries
                for cve in cves
            ]
            if len(unique_hosts) < 3 or not all_cves:
                continue

            top_cve = max(all_cves, key=lambda c: c.get("cvss_score", 0))

            steps = [
                AttackPathStep(
                    description=(
                        f"Attacker identifies {tech_name} {tech_version} "
                        f"on {len(unique_hosts)} hosts"
                    ),
                    node_id=tech_name,
                    technique="T1592",
                ),
                AttackPathStep(
                    description=(
                        f"Develop or obtain exploit for "
                        f"{top_cve['cve_id']} "
                        f"(CVSS {top_cve.get('cvss_score', 'N/A')})"
                    ),
                    node_id=top_cve["cve_id"],
                    technique="T1588.005",
                ),
                AttackPathStep(
                    description=(
                        f"Deploy exploit against all {len(unique_hosts)} "
                        f"hosts simultaneously"
                    ),
                    node_id=unique_hosts[0],
                    technique="T1190",
                ),
                AttackPathStep(
                    description=(
                        "Wide-scale compromise — single vulnerability "
                        "yields access to multiple systems"
                    ),
                    node_id="blast_radius",
                    technique="T1072",
                ),
            ]

            paths.append(
                InferredAttackPath(
                    title=(
                        f"Blast radius: {tech_name} {tech_version} "
                        f"vulnerable on {len(unique_hosts)} hosts"
                    ),
                    severity="critical",
                    steps=steps,
                    affected_nodes=unique_hosts[:10],
                )
            )

        return paths

    def _rule_subdomain_takeover(
        self, data: dict[str, Any]
    ) -> list[InferredAttackPath]:
        """Subdomain takeover via dangling CNAME records."""
        paths: list[InferredAttackPath] = []

        for sub in data.get("subdomains", []):
            dns_records = sub.get("dns_records") or {}
            for cname_value in dns_records.get("CNAME", []):
                cname_lower = cname_value.lower().rstrip(".")
                for provider in _TAKEOVER_CNAME_PROVIDERS:
                    if cname_lower.endswith(provider):
                        paths.append(
                            InferredAttackPath(
                                title=f"Subdomain takeover: {sub['name']} → {provider}",
                                severity="critical",
                                steps=[
                                    AttackPathStep(
                                        description=(
                                            f"Discover dangling CNAME: {sub['name']} → "
                                            f"{cname_value}"
                                        ),
                                        node_id=sub["name"],
                                        technique="T1596",
                                    ),
                                    AttackPathStep(
                                        description=(
                                            f"Claim unconfigured resource on {provider}"
                                        ),
                                        node_id=cname_value,
                                        technique="T1584.001",
                                    ),
                                    AttackPathStep(
                                        description=(
                                            f"Control {sub['name']} subdomain — "
                                            f"serve arbitrary content"
                                        ),
                                        node_id=sub["name"],
                                        technique="T1584.006",
                                    ),
                                    AttackPathStep(
                                        description=(
                                            "Deploy credential harvester or malware "
                                            "on trusted domain"
                                        ),
                                        node_id=sub["name"],
                                        technique="T1189",
                                    ),
                                ],
                                affected_nodes=[sub["name"]],
                            )
                        )
                        break
        return paths

    def _rule_admin_panel_exposure(
        self, data: dict[str, Any]
    ) -> list[InferredAttackPath]:
        """Exposed admin panels via hostname or management ports."""
        paths: list[InferredAttackPath] = []

        for sub in data.get("subdomains", []):
            name_lower = sub["name"].lower()
            is_admin_host = any(frag in name_lower for frag in _ADMIN_HOSTNAMES)

            admin_ports_found: list[int] = []
            has_cves = False
            for svc in sub.get("services", []):
                port = svc.get("port", 0)
                if port in _ADMIN_PORTS:
                    admin_ports_found.append(port)
                if svc.get("cves"):
                    has_cves = True

            if not is_admin_host and not admin_ports_found:
                continue

            severity = "critical" if has_cves else "high"
            steps = [
                AttackPathStep(
                    description=(
                        f"Discover admin panel on {sub['name']}"
                        f"{' (admin hostname)' if is_admin_host else ''}"
                        f"{' ports: ' + ', '.join(str(p) for p in admin_ports_found) if admin_ports_found else ''}"
                    ),
                    node_id=sub["name"],
                    technique="T1046",
                ),
                AttackPathStep(
                    description="Attempt brute-force or default credentials",
                    node_id=sub["name"],
                    technique="T1110.001",
                ),
                AttackPathStep(
                    description="Gain administrative access to management interface",
                    node_id=sub["name"],
                    technique="T1078",
                ),
            ]
            if has_cves:
                steps.append(
                    AttackPathStep(
                        description="Exploit known CVEs on admin panel for deeper access",
                        node_id=sub["name"],
                        technique="T1190",
                    )
                )

            paths.append(
                InferredAttackPath(
                    title=f"Admin panel exposure on {sub['name']}",
                    severity=severity,
                    steps=steps,
                    affected_nodes=[sub["name"]],
                )
            )
        return paths

    def _rule_dns_zone_transfer(
        self, data: dict[str, Any]
    ) -> list[InferredAttackPath]:
        """DNS zone transfer risk from exposed NS records."""
        paths: list[InferredAttackPath] = []
        ns_hosts: set[str] = set()

        for sub in data.get("subdomains", []):
            dns_records = sub.get("dns_records") or {}
            for ns_value in dns_records.get("NS", []):
                ns_host = ns_value.lower().rstrip(".")
                if ns_host and ns_host not in ns_hosts:
                    ns_hosts.add(ns_host)

        if ns_hosts:
            ns_list = sorted(ns_hosts)[:5]
            paths.append(
                InferredAttackPath(
                    title=f"DNS zone transfer risk ({len(ns_hosts)} NS servers)",
                    severity="high",
                    steps=[
                        AttackPathStep(
                            description=(
                                f"Identify NS servers: {', '.join(ns_list)}"
                            ),
                            node_id=ns_list[0],
                            technique="T1596.001",
                        ),
                        AttackPathStep(
                            description="Attempt AXFR zone transfer on each NS",
                            node_id=ns_list[0],
                            technique="T1590.002",
                        ),
                        AttackPathStep(
                            description=(
                                "If successful: full subdomain inventory "
                                "disclosure reveals internal assets"
                            ),
                            node_id="dns_zone",
                            technique="T1018",
                        ),
                        AttackPathStep(
                            description="Map internal network topology from DNS data",
                            node_id="dns_zone",
                            technique="T1595",
                        ),
                    ],
                    affected_nodes=ns_list,
                )
            )
        return paths

    def _rule_tls_downgrade_mitm(
        self, data: dict[str, Any]
    ) -> list[InferredAttackPath]:
        """TLS downgrade / SSL stripping when HTTP+HTTPS both open."""
        paths: list[InferredAttackPath] = []

        for sub in data.get("subdomains", []):
            ports = {svc.get("port", 0) for svc in sub.get("services", [])}
            if 80 not in ports or 443 not in ports:
                continue

            has_cves = any(
                svc.get("cves") for svc in sub.get("services", [])
            )
            severity = "high" if has_cves else "medium"

            paths.append(
                InferredAttackPath(
                    title=f"TLS downgrade / MITM on {sub['name']}",
                    severity=severity,
                    steps=[
                        AttackPathStep(
                            description=(
                                f"{sub['name']} serves both HTTP (:80) and "
                                f"HTTPS (:443)"
                            ),
                            node_id=f"{sub['name']}:80",
                            technique="T1046",
                        ),
                        AttackPathStep(
                            description=(
                                "SSL stripping attack — downgrade HTTPS → HTTP "
                                "via MITM"
                            ),
                            node_id=sub["name"],
                            technique="T1557",
                        ),
                        AttackPathStep(
                            description="Capture credentials and session tokens in cleartext",
                            node_id=sub["name"],
                            technique="T1040",
                        ),
                        AttackPathStep(
                            description="Use captured credentials for account takeover",
                            node_id=sub["name"],
                            technique="T1552.001",
                        ),
                    ],
                    affected_nodes=[sub["name"]],
                )
            )
        return paths

    def _rule_credential_stuffing_chain(
        self, data: dict[str, Any]
    ) -> list[InferredAttackPath]:
        """Credential stuffing across multiple authentication surfaces."""
        paths: list[InferredAttackPath] = []
        auth_surfaces: list[tuple[str, str]] = []  # (host:port, service_label)

        for sub in data.get("subdomains", []):
            name_lower = sub["name"].lower()
            for svc in sub.get("services", []):
                port = svc.get("port", 0)
                if port in _AUTH_PORTS:
                    auth_surfaces.append(
                        (f"{sub['name']}:{port}", _AUTH_PORTS[port])
                    )

            # Check hostname for auth patterns
            auth_keywords = ["login", "auth", "sso", "accounts", "signin", "vpn"]
            if any(kw in name_lower for kw in auth_keywords):
                auth_surfaces.append((sub["name"], "Web Auth"))

        if len(auth_surfaces) >= 2:
            severity = "critical" if len(auth_surfaces) >= 3 else "high"
            steps = [
                AttackPathStep(
                    description=(
                        f"Collect leaked credentials from public breach "
                        f"databases"
                    ),
                    node_id="credential_db",
                    technique="T1589.001",
                ),
                AttackPathStep(
                    description=(
                        f"Identify {len(auth_surfaces)} authentication "
                        f"surfaces: {', '.join(l for _, l in auth_surfaces[:5])}"
                    ),
                    node_id=auth_surfaces[0][0],
                    technique="T1046",
                ),
                AttackPathStep(
                    description="Automated credential stuffing across all surfaces",
                    node_id=auth_surfaces[0][0],
                    technique="T1110.004",
                ),
                AttackPathStep(
                    description="Gain valid access via password reuse",
                    node_id=auth_surfaces[0][0],
                    technique="T1078.001",
                ),
            ]
            paths.append(
                InferredAttackPath(
                    title=(
                        f"Credential stuffing chain across "
                        f"{len(auth_surfaces)} auth surfaces"
                    ),
                    severity=severity,
                    steps=steps,
                    affected_nodes=[n for n, _ in auth_surfaces[:10]],
                )
            )
        return paths

    def _rule_ransomware_deployment(
        self, data: dict[str, Any]
    ) -> list[InferredAttackPath]:
        """Ransomware deployment via exploit + lateral movement ports."""
        paths: list[InferredAttackPath] = []

        for sub in data.get("subdomains", []):
            # Check for high-CVSS CVEs
            high_cves: list[dict] = []
            lateral_ports: list[int] = []

            for svc in sub.get("services", []):
                port = svc.get("port", 0)
                if port in _RANSOMWARE_LATERAL_PORTS:
                    lateral_ports.append(port)
                for cve in svc.get("cves", []):
                    if (cve.get("cvss_score") or 0) >= 7.0:
                        high_cves.append(cve)

            if not high_cves or not lateral_ports:
                continue

            top_cve = max(high_cves, key=lambda c: c.get("cvss_score", 0))
            port_labels = {445: "SMB", 3389: "RDP", 5985: "WinRM", 5986: "WinRM-S"}

            paths.append(
                InferredAttackPath(
                    title=f"Ransomware deployment via {sub['name']}",
                    severity="critical",
                    steps=[
                        AttackPathStep(
                            description=(
                                f"Exploit {top_cve['cve_id']} "
                                f"(CVSS {top_cve.get('cvss_score', '?')})"
                            ),
                            node_id=top_cve["cve_id"],
                            technique="T1190",
                        ),
                        AttackPathStep(
                            description="Deploy remote access trojan (RAT)",
                            node_id=sub["name"],
                            technique="T1021.001",
                        ),
                        AttackPathStep(
                            description=(
                                f"Lateral movement via "
                                f"{', '.join(port_labels.get(p, str(p)) for p in lateral_ports)}"
                            ),
                            node_id=f"{sub['name']}:{lateral_ports[0]}",
                            technique="T1570",
                        ),
                        AttackPathStep(
                            description="Encrypt data and deploy ransomware note",
                            node_id=sub["name"],
                            technique="T1486",
                        ),
                    ],
                    affected_nodes=[sub["name"]],
                )
            )
        return paths

    def _rule_api_data_exfiltration(
        self, data: dict[str, Any]
    ) -> list[InferredAttackPath]:
        """API endpoint exploitation leading to data exfiltration."""
        paths: list[InferredAttackPath] = []

        for sub in data.get("subdomains", []):
            name_lower = sub["name"].lower()
            is_api = any(frag in name_lower for frag in _API_HOSTNAMES)
            if not is_api:
                continue

            all_cves: list[dict] = []
            for svc in sub.get("services", []):
                all_cves.extend(svc.get("cves", []))

            if not all_cves:
                continue

            top_cve = max(all_cves, key=lambda c: c.get("cvss_score", 0))
            severity = (
                "critical" if (top_cve.get("cvss_score") or 0) >= 9.0
                else "high"
            )

            paths.append(
                InferredAttackPath(
                    title=f"API data exfiltration via {sub['name']}",
                    severity=severity,
                    steps=[
                        AttackPathStep(
                            description=(
                                f"Discover API endpoint: {sub['name']}"
                            ),
                            node_id=sub["name"],
                            technique="T1595.002",
                        ),
                        AttackPathStep(
                            description="Enumerate API routes and data models",
                            node_id=sub["name"],
                            technique="T1087",
                        ),
                        AttackPathStep(
                            description=(
                                f"Exploit {top_cve['cve_id']} "
                                f"(CVSS {top_cve.get('cvss_score', '?')}) "
                                f"to bypass authentication/authorization"
                            ),
                            node_id=top_cve["cve_id"],
                            technique="T1190",
                        ),
                        AttackPathStep(
                            description="Exfiltrate sensitive data via API",
                            node_id=sub["name"],
                            technique="T1041",
                        ),
                    ],
                    affected_nodes=[sub["name"], top_cve["cve_id"]],
                )
            )
        return paths

    def _rule_phishing_infrastructure(
        self, data: dict[str, Any]
    ) -> list[InferredAttackPath]:
        """Phishing from trusted infrastructure: vulnerable mail + web."""
        paths: list[InferredAttackPath] = []

        # Find mail servers and web servers with CVEs
        mail_hosts: list[str] = []
        web_hosts_with_cves: list[str] = []

        for sub in data.get("subdomains", []):
            has_mail = False
            has_web_cves = False
            for svc in sub.get("services", []):
                port = svc.get("port", 0)
                if port in _MAIL_PORTS:
                    has_mail = True
                if port in (80, 443) and svc.get("cves"):
                    has_web_cves = True

            # Also check MX records
            dns_records = sub.get("dns_records") or {}
            if dns_records.get("MX"):
                has_mail = True

            if has_mail:
                mail_hosts.append(sub["name"])
            if has_web_cves:
                web_hosts_with_cves.append(sub["name"])

        if mail_hosts and web_hosts_with_cves:
            paths.append(
                InferredAttackPath(
                    title=(
                        f"Phishing from trusted infrastructure "
                        f"({len(mail_hosts)} mail + {len(web_hosts_with_cves)} web)"
                    ),
                    severity="high",
                    steps=[
                        AttackPathStep(
                            description=(
                                f"Compromise vulnerable web app on "
                                f"{web_hosts_with_cves[0]}"
                            ),
                            node_id=web_hosts_with_cves[0],
                            technique="T1190",
                        ),
                        AttackPathStep(
                            description=(
                                f"Leverage mail infrastructure on "
                                f"{mail_hosts[0]} to send phishing emails "
                                f"from trusted domain"
                            ),
                            node_id=mail_hosts[0],
                            technique="T1566.002",
                        ),
                        AttackPathStep(
                            description=(
                                "Host credential harvester on compromised "
                                "web server under trusted domain"
                            ),
                            node_id=web_hosts_with_cves[0],
                            technique="T1189",
                        ),
                        AttackPathStep(
                            description=(
                                "Victims trust the domain — high success rate "
                                "for credential theft"
                            ),
                            node_id="phishing_campaign",
                            technique="T1078",
                        ),
                    ],
                    affected_nodes=mail_hosts[:3] + web_hosts_with_cves[:3],
                )
            )
        return paths

    def _rule_epss_priority_exploitation(
        self, data: dict[str, Any]
    ) -> list[InferredAttackPath]:
        """CVEs with high EPSS scores — actively exploited in the wild."""
        paths: list[InferredAttackPath] = []

        for sub in data.get("subdomains", []):
            for svc in sub.get("services", []):
                for cve in svc.get("cves", []):
                    epss = cve.get("epss_score") or 0.0
                    if epss < 0.5:
                        continue

                    severity = "critical" if epss >= 0.7 else "high"
                    paths.append(
                        InferredAttackPath(
                            title=(
                                f"Actively exploited: {cve['cve_id']} "
                                f"(EPSS {epss:.0%}) on {sub['name']}"
                            ),
                            severity=severity,
                            steps=[
                                AttackPathStep(
                                    description=(
                                        f"Attacker identifies {cve['cve_id']} "
                                        f"in exploit databases (EPSS {epss:.0%})"
                                    ),
                                    node_id=cve["cve_id"],
                                    technique="T1595.002",
                                ),
                                AttackPathStep(
                                    description=(
                                        "Obtain weaponized exploit — high "
                                        "probability of public availability"
                                    ),
                                    node_id=cve["cve_id"],
                                    technique="T1588.005",
                                ),
                                AttackPathStep(
                                    description=(
                                        f"Deploy exploit against {sub['name']}:"
                                        f"{svc.get('port', '?')}"
                                    ),
                                    node_id=f"{sub['name']}:{svc.get('port', '?')}",
                                    technique="T1190",
                                ),
                                AttackPathStep(
                                    description="Establish persistent access",
                                    node_id=sub["name"],
                                    technique="T1505",
                                ),
                            ],
                            affected_nodes=[sub["name"], cve["cve_id"]],
                        )
                    )
        return paths

    def _rule_network_pivot_via_vpn_ssh(
        self, data: dict[str, Any]
    ) -> list[InferredAttackPath]:
        """Network perimeter breach via exposed SSH/VPN/RDP with CVEs."""
        paths: list[InferredAttackPath] = []

        for sub in data.get("subdomains", []):
            for svc in sub.get("services", []):
                port = svc.get("port", 0)
                if port not in _REMOTE_ACCESS_PORTS:
                    continue

                cves = svc.get("cves", [])
                if not cves:
                    continue

                top_cve = max(cves, key=lambda c: c.get("cvss_score", 0))
                svc_name = _REMOTE_ACCESS_PORTS[port]
                severity = (
                    "critical" if (top_cve.get("cvss_score") or 0) >= 9.0
                    else "high"
                )

                paths.append(
                    InferredAttackPath(
                        title=(
                            f"Network pivot via {svc_name} on {sub['name']}"
                        ),
                        severity=severity,
                        steps=[
                            AttackPathStep(
                                description=(
                                    f"Exposed {svc_name} on port {port}"
                                ),
                                node_id=f"{sub['name']}:{port}",
                                technique="T1046",
                            ),
                            AttackPathStep(
                                description=(
                                    f"Exploit {top_cve['cve_id']} "
                                    f"(CVSS {top_cve.get('cvss_score', '?')})"
                                ),
                                node_id=top_cve["cve_id"],
                                technique="T1190",
                            ),
                            AttackPathStep(
                                description=(
                                    f"Tunnel through compromised {svc_name} "
                                    f"into internal network"
                                ),
                                node_id=sub["name"],
                                technique="T1572",
                            ),
                            AttackPathStep(
                                description=(
                                    "Discover and enumerate internal network "
                                    "from pivot point"
                                ),
                                node_id=sub["name"],
                                technique="T1018",
                            ),
                        ],
                        affected_nodes=[sub["name"], top_cve["cve_id"]],
                    )
                )
        return paths

    def _rule_aging_vulnerability_exploitation(
        self, data: dict[str, Any]
    ) -> list[InferredAttackPath]:
        """Exploitation of CVEs published 2+ years ago (mature exploits)."""
        from datetime import datetime, timezone

        paths: list[InferredAttackPath] = []
        now = datetime.now(timezone.utc)

        for sub in data.get("subdomains", []):
            for svc in sub.get("services", []):
                for cve in svc.get("cves", []):
                    published = cve.get("published")
                    if not published:
                        continue
                    try:
                        pub_dt = datetime.fromisoformat(
                            str(published).replace("Z", "+00:00")
                        )
                        age_years = (now - pub_dt).days / 365.25
                    except (ValueError, TypeError):
                        continue

                    if age_years < 2.0:
                        continue

                    paths.append(
                        InferredAttackPath(
                            title=(
                                f"Aging CVE: {cve['cve_id']} "
                                f"({age_years:.0f}y old) on {sub['name']}"
                            ),
                            severity="high",
                            steps=[
                                AttackPathStep(
                                    description=(
                                        f"{cve['cve_id']} published "
                                        f"{age_years:.1f} years ago — mature "
                                        f"exploits widely available"
                                    ),
                                    node_id=cve["cve_id"],
                                    technique="T1592",
                                ),
                                AttackPathStep(
                                    description=(
                                        "Obtain reliable, battle-tested exploit "
                                        "from public repositories"
                                    ),
                                    node_id=cve["cve_id"],
                                    technique="T1588.005",
                                ),
                                AttackPathStep(
                                    description=(
                                        f"Exploit unpatched {svc.get('service_name', 'service')} "
                                        f"on {sub['name']}:{svc.get('port', '?')}"
                                    ),
                                    node_id=f"{sub['name']}:{svc.get('port', '?')}",
                                    technique="T1190",
                                ),
                                AttackPathStep(
                                    description="Establish persistent backdoor",
                                    node_id=sub["name"],
                                    technique="T1505",
                                ),
                            ],
                            affected_nodes=[sub["name"], cve["cve_id"]],
                        )
                    )

        return paths

    # -- Helpers ---------------------------------------------------------------

    @staticmethod
    def _find_same_subnet(
        target_sub: dict[str, Any],
        all_subs: list[dict[str, Any]],
    ) -> list[str]:
        """Find other subdomains that share the same /24 subnet.

        Args:
            target_sub: The reference subdomain dictionary (must have
                an ``ip_address`` key).
            all_subs: All subdomain dictionaries to search.

        Returns:
            A list of subdomain names in the same /24 (excluding
            *target_sub* itself).  Empty if the target has no IP or no
            neighbours are found.
        """
        target_ip: str | None = target_sub.get("ip_address")
        if not target_ip:
            return []

        try:
            target_network = ip_network(f"{target_ip}/24", strict=False)
        except ValueError:
            return []

        neighbours: list[str] = []
        for sub in all_subs:
            if sub["name"] == target_sub["name"]:
                continue
            sub_ip: str | None = sub.get("ip_address")
            if not sub_ip:
                continue
            try:
                if parse_ip_address(sub_ip) in target_network:
                    neighbours.append(sub["name"])
            except ValueError:
                continue

        return neighbours
