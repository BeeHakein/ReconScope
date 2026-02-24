"""
Correlation Engine for ReconScope post-processing pipeline.

Analyses aggregated scan data using a rule-based approach to surface
cross-asset relationships, forgotten assets, misconfigured services,
inconsistent technology stacks, and SSL certificate issues.

The engine runs after all recon modules have completed.  Its output is
a list of :class:`CorrelationInsight` instances that are persisted as
:class:`~app.models.correlation.Correlation` rows and surfaced in the
frontend Insights panel.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from typing import Any


# -- Known outdated versions -------------------------------------------------
# Maps lowercase software names to a list of version prefixes considered
# end-of-life or dangerously outdated.

KNOWN_OUTDATED: dict[str, list[str]] = {
    "nginx": ["1.14", "1.16", "1.18"],
    "apache": ["2.4.49", "2.4.48", "2.2"],
    "openssh": ["7.4", "7.2", "6."],
    "php": ["5.", "7.0", "7.1", "7.2", "7.3"],
}

# Hostname fragments that suggest a non-production asset.
_FORGOTTEN_INDICATORS: list[str] = [
    "staging",
    "dev",
    "test",
    "old",
    "backup",
    "temp",
    "demo",
]

# Ports whose direct Internet exposure is almost always a critical
# misconfiguration.
_CRITICAL_PORTS: dict[int, str] = {
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
}

# Providers whose CNAME records are vulnerable to subdomain takeover.
_TAKEOVER_CNAME_PROVIDERS: list[str] = [
    "herokuapp.com", "s3.amazonaws.com", "azurewebsites.net",
    "cloudfront.net", "github.io", "netlify.app", "shopify.com",
    "fastly.net", "ghost.io", "wordpress.com", "pantheonsite.io",
    "surge.sh", "bitbucket.io", "zendesk.com", "readme.io",
    "tumblr.com", "cargo.site",
]

# Admin/management ports that should not be publicly reachable.
_ADMIN_PORTS: set[int] = {8080, 8443, 9090, 9443, 2082, 2083, 2086, 2087, 8888, 10000}

# Hostname fragments indicating admin or management panels.
_ADMIN_HOSTNAMES: list[str] = [
    "admin", "cpanel", "webmin", "phpmyadmin", "panel",
    "dashboard", "manage", "console", "portal", "backoffice",
]

# Direct-access authentication services.
_AUTH_PORTS: dict[int, str] = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC"}

# Hostname fragments suggesting authentication endpoints.
_AUTH_HOSTNAMES: list[str] = ["login", "auth", "sso", "accounts", "signin", "vpn", "remote"]

# API hostname fragments.
_API_HOSTNAMES: list[str] = ["api", "graphql", "rest", "gateway", "backend", "ws"]

# Shadow-IT indicators (hosting panels and website builders).
_SHADOW_IT_TECHS: list[str] = [
    "plesk", "cpanel", "wix", "squarespace", "weebly",
    "webflow", "godaddy", "jimdo", "strikingly",
]


@dataclass
class CorrelationInsight:
    """A single insight produced by the correlation engine.

    Attributes:
        type: Category label -- ``subnet``, ``forgotten_asset``,
            ``exposure``, ``cert``, ``tech_inconsistency``, or
            ``version_spread``.
        severity: ``critical``, ``high``, ``medium``, ``low``, or ``info``.
        message: Human-readable description of the finding.
        affected_assets: List of subdomain names or identifiers involved.
    """

    type: str
    severity: str
    message: str
    affected_assets: list[str] = field(default_factory=list)


class CorrelationEngine:
    """Rule-based correlation engine for post-processing scan results.

    Given a *scan_data* dictionary produced by the scan orchestrator, the
    engine iterates over a battery of checks and returns a flat list of
    :class:`CorrelationInsight` instances.

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
                            "technologies": [
                                {"name": "Nginx", "version": "1.18.0", "category": "web_server"}
                            ],
                            "cves": [...]
                        }
                    ]
                }
            ]
        }
    """

    def analyze(self, scan_data: dict[str, Any]) -> list[CorrelationInsight]:
        """Run every correlation check and return combined insights.

        Args:
            scan_data: Aggregated scan results keyed by data type.

        Returns:
            A list of :class:`CorrelationInsight` instances (may be empty).
        """
        insights: list[CorrelationInsight] = []
        insights += self._check_subnet_relationships(scan_data)
        insights += self._check_forgotten_assets(scan_data)
        insights += self._check_exposed_services(scan_data)
        insights += self._check_ssl_certificates(scan_data)
        insights += self._check_tech_inconsistencies(scan_data)
        insights += self._check_version_spread(scan_data)
        insights += self._check_cve_clustering(scan_data)
        insights += self._check_shared_vulnerability(scan_data)
        insights += self._check_dangling_cname(scan_data)
        insights += self._check_email_security(scan_data)
        insights += self._check_epss_underestimated_threats(scan_data)
        insights += self._check_network_attack_surface(scan_data)
        insights += self._check_single_point_of_failure(scan_data)
        insights += self._check_service_sprawl(scan_data)
        insights += self._check_admin_exposure(scan_data)
        insights += self._check_auth_service_exposure(scan_data)
        insights += self._check_aging_infrastructure(scan_data)
        insights += self._check_shadow_it(scan_data)
        insights += self._check_wildcard_dns(scan_data)
        insights += self._check_no_complexity_barrier(scan_data)
        insights += self._check_dns_ns_diversity(scan_data)
        return insights

    # -- Individual checks ----------------------------------------------------

    def _check_subnet_relationships(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Flag /24 subnets that contain three or more discovered assets.

        Multiple assets sharing the same Class-C network significantly
        increase the lateral-movement risk if any single host is
        compromised.

        Args:
            data: Aggregated scan data.

        Returns:
            A list of insights for subnets that exceed the threshold.
        """
        ips: dict[str, str] = {}
        for sub in data.get("subdomains", []):
            ip_value: str | None = sub.get("ip_address")
            if ip_value:
                ips[sub["name"]] = ip_value

        # Group hostnames by their /24 subnet.
        subnets: dict[str, list[str]] = {}
        for hostname, ip_str in ips.items():
            try:
                subnet_key = str(ip_network(f"{ip_str}/24", strict=False))
                subnets.setdefault(subnet_key, []).append(hostname)
            except ValueError:
                # Skip malformed IP addresses.
                continue

        insights: list[CorrelationInsight] = []
        for subnet_key, hosts in subnets.items():
            if len(hosts) >= 3:
                insights.append(
                    CorrelationInsight(
                        type="subnet",
                        severity="high",
                        message=(
                            f"{len(hosts)} assets reside in the same subnet "
                            f"({subnet_key}) -- lateral movement after "
                            f"compromise is highly probable"
                        ),
                        affected_assets=sorted(hosts),
                    )
                )
        return insights

    def _check_forgotten_assets(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Detect likely forgotten assets (dev/staging hosts with outdated software).

        An asset is considered *forgotten* when **two or more** indicators
        are present:

        * The subdomain name contains a suspicious fragment (staging, dev,
          test, old, backup, temp, demo).
        * At least one detected technology runs an outdated version (see
          :data:`KNOWN_OUTDATED`).

        Severity is ``critical`` when the threshold is met, because
        forgotten assets are typically unpatched and unmonitored.

        Args:
            data: Aggregated scan data.

        Returns:
            A list of insights for each probable forgotten asset.
        """
        insights: list[CorrelationInsight] = []

        for sub in data.get("subdomains", []):
            indicators: list[str] = []
            name_lower: str = sub["name"].lower()

            # Check hostname pattern.
            if any(indicator in name_lower for indicator in _FORGOTTEN_INDICATORS):
                indicators.append("Suspicious hostname pattern")

            # Check for outdated software on any service.
            for svc in sub.get("services", []):
                for tech in svc.get("technologies", []):
                    tech_version: str | None = tech.get("version")
                    if tech_version and self._is_outdated(
                        tech["name"], tech_version
                    ):
                        indicators.append(
                            f"Outdated software: {tech['name']} {tech_version}"
                        )

            if len(indicators) >= 2:
                insights.append(
                    CorrelationInsight(
                        type="forgotten_asset",
                        severity="critical",
                        message=(
                            f"{sub['name']} is likely a forgotten asset: "
                            f"{', '.join(indicators)}"
                        ),
                        affected_assets=[sub["name"]],
                    )
                )
            elif len(indicators) == 1 and "Outdated software" in indicators[0]:
                insights.append(
                    CorrelationInsight(
                        type="forgotten_asset",
                        severity="high",
                        message=(
                            f"{sub['name']} runs outdated software: "
                            f"{indicators[0]} — may be unmaintained"
                        ),
                        affected_assets=[sub["name"]],
                    )
                )

        return insights

    def _check_exposed_services(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Flag database and cache services directly exposed to the Internet.

        Any of the ports in :data:`_CRITICAL_PORTS` being open on a
        publicly resolved subdomain is a critical misconfiguration.

        Args:
            data: Aggregated scan data.

        Returns:
            A list of critical-severity insights.
        """
        insights: list[CorrelationInsight] = []

        for sub in data.get("subdomains", []):
            for svc in sub.get("services", []):
                port: int = svc.get("port", 0)
                if port in _CRITICAL_PORTS:
                    db_name = _CRITICAL_PORTS[port]
                    insights.append(
                        CorrelationInsight(
                            type="exposure",
                            severity="critical",
                            message=(
                                f"{db_name} (port {port}) on {sub['name']} "
                                f"is directly reachable from the Internet "
                                f"-- critical misconfiguration"
                            ),
                            affected_assets=[sub["name"]],
                        )
                    )

        return insights

    def _check_ssl_certificates(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Flag subdomains with services but no HTTPS (port 443).

        Args:
            data: Aggregated scan data.

        Returns:
            Insights for hosts that lack HTTPS services.
        """
        insights: list[CorrelationInsight] = []

        for sub in data.get("subdomains", []):
            services = sub.get("services", [])
            if not services:
                continue
            has_https = any(svc.get("port") == 443 for svc in services)
            has_http = any(svc.get("port") == 80 for svc in services)
            if has_http and not has_https:
                insights.append(
                    CorrelationInsight(
                        type="cert",
                        severity="medium",
                        message=(
                            f"{sub['name']} serves HTTP on port 80 but has "
                            f"no HTTPS service detected — data in transit "
                            f"may be unencrypted"
                        ),
                        affected_assets=[sub["name"]],
                    )
                )

        return insights

    def _check_tech_inconsistencies(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Detect inconsistent technology stacks across the estate.

        When three or more distinct technologies of the *same* category
        (e.g. web_server) are found, the organisation likely has an
        inconsistent infrastructure that is harder to patch and monitor.

        Args:
            data: Aggregated scan data.

        Returns:
            Low-severity insights for each inconsistent category.
        """
        tech_by_category: dict[str, set[str]] = {}

        for sub in data.get("subdomains", []):
            for svc in sub.get("services", []):
                for tech in svc.get("technologies", []):
                    category: str | None = tech.get("category")
                    if category:
                        tech_by_category.setdefault(category, set()).add(
                            tech["name"]
                        )

        insights: list[CorrelationInsight] = []
        for category, tech_names in tech_by_category.items():
            if len(tech_names) >= 3:
                sorted_names = sorted(tech_names)
                insights.append(
                    CorrelationInsight(
                        type="tech_inconsistency",
                        severity="low",
                        message=(
                            f"{len(tech_names)} different {category} "
                            f"technologies in use ({', '.join(sorted_names)}) "
                            f"-- inconsistent infrastructure is harder to "
                            f"patch and monitor"
                        ),
                        affected_assets=sorted_names,
                    )
                )

        return insights

    def _check_version_spread(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Detect different versions of the same software across hosts.

        When the same software runs in 2+ different versions across
        hosts, the organisation likely has inconsistent patching.

        Args:
            data: Aggregated scan data.

        Returns:
            Insights for each technology with version spread.
        """
        # Map: tech_name -> { version -> [hosts] }
        tech_versions: dict[str, dict[str, list[str]]] = {}

        for sub in data.get("subdomains", []):
            for svc in sub.get("services", []):
                for tech in svc.get("technologies", []):
                    name = tech.get("name", "").lower()
                    version = tech.get("version")
                    if name and version:
                        tech_versions.setdefault(name, {}).setdefault(
                            version, []
                        ).append(sub["name"])

        insights: list[CorrelationInsight] = []
        for tech_name, versions in tech_versions.items():
            if len(versions) >= 2:
                version_details = ", ".join(
                    f"v{v} on {len(hosts)} host(s)"
                    for v, hosts in sorted(versions.items())
                )
                all_hosts = sorted(
                    {h for hosts in versions.values() for h in hosts}
                )
                insights.append(
                    CorrelationInsight(
                        type="version_spread",
                        severity="medium",
                        message=(
                            f"{tech_name.title()} runs in "
                            f"{len(versions)} different versions: "
                            f"{version_details} — inconsistent patching "
                            f"increases attack surface"
                        ),
                        affected_assets=all_hosts[:10],
                    )
                )

        return insights

    def _check_cve_clustering(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Flag hosts that accumulate multiple CVEs.

        A single host with 3+ CVEs represents a high-value target
        for attackers because vulnerability chaining becomes likely.

        Args:
            data: Aggregated scan data.

        Returns:
            Insights for hosts with high CVE concentration.
        """
        insights: list[CorrelationInsight] = []

        for sub in data.get("subdomains", []):
            cve_ids: list[str] = []
            max_cvss: float = 0.0
            for svc in sub.get("services", []):
                for cve in svc.get("cves", []):
                    cve_ids.append(cve.get("cve_id", "unknown"))
                    cvss = cve.get("cvss_score") or 0.0
                    if cvss > max_cvss:
                        max_cvss = cvss

            if len(cve_ids) >= 3:
                severity = "critical" if max_cvss >= 9.0 else "high"
                insights.append(
                    CorrelationInsight(
                        type="cve_clustering",
                        severity=severity,
                        message=(
                            f"{sub['name']} has {len(cve_ids)} CVEs "
                            f"(max CVSS {max_cvss}) — high-value target "
                            f"for vulnerability chaining: "
                            f"{', '.join(cve_ids[:5])}"
                            f"{' ...' if len(cve_ids) > 5 else ''}"
                        ),
                        affected_assets=[sub["name"]],
                    )
                )

        return insights

    def _check_shared_vulnerability(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Detect the same CVE affecting multiple hosts.

        A single CVE present on 2+ hosts means a single exploit can
        compromise multiple systems — essentially a supply-chain risk.

        Args:
            data: Aggregated scan data.

        Returns:
            Insights for CVEs that span multiple hosts.
        """
        # Map: cve_id -> [host_names]
        cve_hosts: dict[str, list[str]] = {}

        for sub in data.get("subdomains", []):
            for svc in sub.get("services", []):
                for cve in svc.get("cves", []):
                    cve_id = cve.get("cve_id", "")
                    if cve_id:
                        cve_hosts.setdefault(cve_id, []).append(sub["name"])

        insights: list[CorrelationInsight] = []
        for cve_id, hosts in cve_hosts.items():
            unique_hosts = sorted(set(hosts))
            if len(unique_hosts) >= 2:
                insights.append(
                    CorrelationInsight(
                        type="shared_vulnerability",
                        severity="high",
                        message=(
                            f"{cve_id} affects {len(unique_hosts)} hosts "
                            f"({', '.join(unique_hosts[:5])}) — a single "
                            f"exploit compromises multiple systems"
                        ),
                        affected_assets=unique_hosts[:10],
                    )
                )

        return insights

    def _check_dangling_cname(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Flag CNAME records pointing to takeover-vulnerable providers."""
        insights: list[CorrelationInsight] = []

        for sub in data.get("subdomains", []):
            dns_records = sub.get("dns_records") or {}
            for cname_value in dns_records.get("CNAME", []):
                cname_lower = cname_value.lower().rstrip(".")
                for provider in _TAKEOVER_CNAME_PROVIDERS:
                    if cname_lower.endswith(provider):
                        insights.append(
                            CorrelationInsight(
                                type="dns_anomaly",
                                severity="critical",
                                message=(
                                    f"{sub['name']} has a CNAME pointing to "
                                    f"{cname_value} ({provider}) — potential "
                                    f"subdomain takeover if the resource is unclaimed"
                                ),
                                affected_assets=[sub["name"]],
                            )
                        )
                        break

        return insights

    def _check_email_security(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Check TXT records for missing or weak SPF/DMARC configuration.

        Only checks root-level domains (no dots before the TLD) and
        MX hosts to avoid spamming insights for every subdomain.
        """
        insights: list[CorrelationInsight] = []

        # Collect MX targets so we also check them.
        mx_hosts: set[str] = set()
        for sub in data.get("subdomains", []):
            dns_records = sub.get("dns_records") or {}
            for mx_val in dns_records.get("MX", []):
                mx_host = mx_val.split()[-1].rstrip(".").lower()
                mx_hosts.add(mx_host)

        for sub in data.get("subdomains", []):
            name = sub["name"]
            # Only check root-level domains (≤2 parts) and MX hosts.
            parts = name.split(".")
            is_root = len(parts) <= 2
            is_mx = name.lower() in mx_hosts
            if not is_root and not is_mx:
                continue

            dns_records = sub.get("dns_records") or {}
            txt_records = dns_records.get("TXT", [])
            if not txt_records and not dns_records:
                continue  # No DNS data — skip, don't guess

            txt_blob = " ".join(str(r) for r in txt_records).lower()

            has_spf = "v=spf1" in txt_blob
            has_dmarc = "v=dmarc1" in txt_blob

            issues: list[str] = []
            if not has_spf:
                issues.append("no SPF record")
            elif "+all" in txt_blob or "~all" in txt_blob:
                issues.append("permissive SPF policy (+all or ~all)")
            if not has_dmarc:
                issues.append("no DMARC record")
            elif "p=none" in txt_blob:
                issues.append("DMARC policy set to p=none (monitor only)")

            if issues:
                severity = "high" if not has_spf or not has_dmarc else "medium"
                insights.append(
                    CorrelationInsight(
                        type="email_security",
                        severity=severity,
                        message=(
                            f"{name} email security issues: "
                            f"{'; '.join(issues)} — vulnerable to email "
                            f"spoofing and phishing"
                        ),
                        affected_assets=[name],
                    )
                )

        return insights

    def _check_epss_underestimated_threats(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Flag CVEs with high EPSS but low CVSS (underestimated threats)."""
        insights: list[CorrelationInsight] = []

        for sub in data.get("subdomains", []):
            for svc in sub.get("services", []):
                for cve in svc.get("cves", []):
                    epss = cve.get("epss_score") or 0.0
                    cvss = cve.get("cvss_score") or 0.0
                    if epss >= 0.3 and cvss < 7.0:
                        severity = "critical" if epss >= 0.7 else "high"
                        insights.append(
                            CorrelationInsight(
                                type="epss_risk",
                                severity=severity,
                                message=(
                                    f"{cve['cve_id']} on {sub['name']} has "
                                    f"EPSS {epss:.0%} but CVSS only {cvss} — "
                                    f"actively exploited in the wild despite "
                                    f"moderate CVSS rating"
                                ),
                                affected_assets=[sub["name"]],
                            )
                        )

        return insights

    def _check_network_attack_surface(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Flag when most CVEs are network-reachable (AV:N in CVSS vector)."""
        total_cves = 0
        network_cves = 0

        for sub in data.get("subdomains", []):
            for svc in sub.get("services", []):
                for cve in svc.get("cves", []):
                    total_cves += 1
                    vector = cve.get("cvss_vector") or ""
                    if "AV:N" in vector:
                        network_cves += 1

        if total_cves >= 3 and network_cves / total_cves > 0.5:
            return [
                CorrelationInsight(
                    type="network_exposure",
                    severity="high",
                    message=(
                        f"{network_cves}/{total_cves} CVEs "
                        f"({network_cves*100//total_cves}%) are network-"
                        f"reachable (AV:N) — the attack surface is "
                        f"heavily concentrated on network-facing services"
                    ),
                    affected_assets=[],
                )
            ]
        return []

    def _check_single_point_of_failure(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Flag IPs hosting 3+ subdomains (single point of failure)."""
        ip_to_hosts: dict[str, list[str]] = {}
        for sub in data.get("subdomains", []):
            ip_val = sub.get("ip_address")
            if ip_val:
                ip_to_hosts.setdefault(ip_val, []).append(sub["name"])

        insights: list[CorrelationInsight] = []
        for ip_val, hosts in ip_to_hosts.items():
            if len(hosts) >= 3:
                insights.append(
                    CorrelationInsight(
                        type="single_point_of_failure",
                        severity="high",
                        message=(
                            f"{len(hosts)} subdomains share IP {ip_val} — "
                            f"a single server compromise affects all: "
                            f"{', '.join(sorted(hosts)[:5])}"
                        ),
                        affected_assets=sorted(hosts)[:10],
                    )
                )
        return insights

    def _check_service_sprawl(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Flag hosts with 5+ open services (excessive attack surface)."""
        insights: list[CorrelationInsight] = []

        for sub in data.get("subdomains", []):
            svc_count = len(sub.get("services", []))
            if svc_count >= 5:
                ports = sorted(svc.get("port", 0) for svc in sub.get("services", []))
                insights.append(
                    CorrelationInsight(
                        type="service_sprawl",
                        severity="medium",
                        message=(
                            f"{sub['name']} exposes {svc_count} services "
                            f"(ports: {', '.join(str(p) for p in ports)}) — "
                            f"excessive attack surface increases risk"
                        ),
                        affected_assets=[sub["name"]],
                    )
                )
        return insights

    def _check_admin_exposure(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Flag exposed admin panels (by port or hostname)."""
        insights: list[CorrelationInsight] = []

        for sub in data.get("subdomains", []):
            name_lower = sub["name"].lower()

            # Check admin hostname
            hostname_match = any(
                frag in name_lower for frag in _ADMIN_HOSTNAMES
            )

            # Check admin ports
            admin_ports_found: list[int] = []
            has_cves = False
            for svc in sub.get("services", []):
                port = svc.get("port", 0)
                if port in _ADMIN_PORTS:
                    admin_ports_found.append(port)
                if svc.get("cves"):
                    has_cves = True

            if hostname_match or admin_ports_found:
                severity = "critical" if has_cves else "high"
                reasons: list[str] = []
                if hostname_match:
                    reasons.append(f"admin hostname pattern ({sub['name']})")
                if admin_ports_found:
                    reasons.append(
                        f"admin ports ({', '.join(str(p) for p in admin_ports_found)})"
                    )
                insights.append(
                    CorrelationInsight(
                        type="admin_exposure",
                        severity=severity,
                        message=(
                            f"Admin panel exposed on {sub['name']}: "
                            f"{'; '.join(reasons)}"
                            f"{' — WITH known CVEs' if has_cves else ''}"
                        ),
                        affected_assets=[sub["name"]],
                    )
                )

        return insights

    def _check_auth_service_exposure(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Flag SSH, RDP, FTP, Telnet, VNC directly reachable."""
        insights: list[CorrelationInsight] = []

        for sub in data.get("subdomains", []):
            exposed: list[str] = []
            for svc in sub.get("services", []):
                port = svc.get("port", 0)
                if port in _AUTH_PORTS:
                    exposed.append(f"{_AUTH_PORTS[port]} (:{port})")

            # Also check hostname for auth patterns
            name_lower = sub["name"].lower()
            hostname_auth = any(frag in name_lower for frag in _AUTH_HOSTNAMES)

            if exposed:
                insights.append(
                    CorrelationInsight(
                        type="auth_exposure",
                        severity="high",
                        message=(
                            f"{sub['name']} exposes authentication services "
                            f"directly to the Internet: {', '.join(exposed)}"
                            f"{' (auth-related hostname)' if hostname_auth else ''}"
                            f" — brute-force and credential stuffing risk"
                        ),
                        affected_assets=[sub["name"]],
                    )
                )
        return insights

    def _check_aging_infrastructure(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Flag CVEs published 2+ years ago still present (unpatched)."""
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        old_cves: list[tuple[str, str, float]] = []  # (cve_id, host, age_years)

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
                        if age_years >= 2.0:
                            old_cves.append(
                                (cve.get("cve_id", "?"), sub["name"], age_years)
                            )
                    except (ValueError, TypeError):
                        continue

        if old_cves:
            avg_age = sum(a for _, _, a in old_cves) / len(old_cves)
            severity = "high" if avg_age > 3.0 else "medium"
            hosts = sorted({h for _, h, _ in old_cves})
            return [
                CorrelationInsight(
                    type="aging_infrastructure",
                    severity=severity,
                    message=(
                        f"{len(old_cves)} CVEs are 2+ years old (avg "
                        f"{avg_age:.1f} years) — mature exploits likely "
                        f"available, patching severely overdue"
                    ),
                    affected_assets=hosts[:10],
                )
            ]
        return []

    def _check_shadow_it(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Detect shadow IT: hosting panels or website builders alongside enterprise infra."""
        insights: list[CorrelationInsight] = []
        shadow_hosts: list[tuple[str, str]] = []  # (host, tech)

        for sub in data.get("subdomains", []):
            for svc in sub.get("services", []):
                for tech in svc.get("technologies", []):
                    tech_name = (tech.get("name") or "").lower()
                    for shadow_indicator in _SHADOW_IT_TECHS:
                        if shadow_indicator in tech_name:
                            shadow_hosts.append((sub["name"], tech.get("name", shadow_indicator)))
                            break

        if shadow_hosts:
            hosts = sorted({h for h, _ in shadow_hosts})
            techs = sorted({t for _, t in shadow_hosts})
            insights.append(
                CorrelationInsight(
                    type="shadow_it",
                    severity="medium",
                    message=(
                        f"Shadow IT detected: {', '.join(techs)} found on "
                        f"{', '.join(hosts[:5])} — unmanaged services may "
                        f"bypass security controls"
                    ),
                    affected_assets=hosts[:10],
                )
            )
        return insights

    def _check_wildcard_dns(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Detect likely wildcard DNS (multiple subs -> same IP + same services)."""
        ip_services: dict[str, list[str]] = {}  # ip -> [host_names]
        ip_ports: dict[str, set[int]] = {}

        for sub in data.get("subdomains", []):
            ip_val = sub.get("ip_address")
            if not ip_val:
                continue
            ip_services.setdefault(ip_val, []).append(sub["name"])
            ports = {svc.get("port", 0) for svc in sub.get("services", [])}
            if ip_val in ip_ports:
                ip_ports[ip_val] &= ports
            else:
                ip_ports[ip_val] = ports

        insights: list[CorrelationInsight] = []
        for ip_val, hosts in ip_services.items():
            common_ports = ip_ports.get(ip_val, set())
            if len(hosts) >= 4 and len(common_ports) >= 1:
                insights.append(
                    CorrelationInsight(
                        type="dns_anomaly",
                        severity="medium",
                        message=(
                            f"{len(hosts)} subdomains resolve to {ip_val} with "
                            f"identical services — likely wildcard DNS. "
                            f"Real subdomain count may be lower."
                        ),
                        affected_assets=sorted(hosts)[:10],
                    )
                )
        return insights

    def _check_no_complexity_barrier(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Flag zero-click CVEs: AV:N + AC:L + PR:N + UI:N in CVSS vector."""
        insights: list[CorrelationInsight] = []

        zero_click_cves: list[tuple[str, str, float]] = []
        for sub in data.get("subdomains", []):
            for svc in sub.get("services", []):
                for cve in svc.get("cves", []):
                    vector = cve.get("cvss_vector") or ""
                    if all(
                        token in vector
                        for token in ("AV:N", "AC:L", "PR:N", "UI:N")
                    ):
                        zero_click_cves.append(
                            (cve.get("cve_id", "?"), sub["name"], cve.get("cvss_score", 0))
                        )

        if zero_click_cves:
            hosts = sorted({h for _, h, _ in zero_click_cves})
            cve_list = ", ".join(c for c, _, _ in zero_click_cves[:5])
            insights.append(
                CorrelationInsight(
                    type="low_complexity_exposure",
                    severity="critical",
                    message=(
                        f"{len(zero_click_cves)} CVEs require zero user "
                        f"interaction and no authentication (AV:N/AC:L/PR:N/"
                        f"UI:N): {cve_list}"
                        f"{'...' if len(zero_click_cves) > 5 else ''}"
                        f" — trivially exploitable from the Internet"
                    ),
                    affected_assets=hosts[:10],
                )
            )
        return insights

    def _check_dns_ns_diversity(
        self, data: dict[str, Any]
    ) -> list[CorrelationInsight]:
        """Flag when all NS records come from a single provider."""
        ns_providers: dict[str, set[str]] = {}

        for sub in data.get("subdomains", []):
            dns_records = sub.get("dns_records") or {}
            for ns_value in dns_records.get("NS", []):
                ns_lower = ns_value.lower().rstrip(".")
                # Extract provider domain (last two parts)
                parts = ns_lower.split(".")
                provider = ".".join(parts[-2:]) if len(parts) >= 2 else ns_lower
                ns_providers.setdefault(sub["name"], set()).add(provider)

        insights: list[CorrelationInsight] = []
        for hostname, providers in ns_providers.items():
            if len(providers) == 1:
                provider = next(iter(providers))
                insights.append(
                    CorrelationInsight(
                        type="dns_config",
                        severity="low",
                        message=(
                            f"{hostname} uses a single NS provider "
                            f"({provider}) — DNS single point of failure"
                        ),
                        affected_assets=[hostname],
                    )
                )
        return insights

    # -- Helpers --------------------------------------------------------------

    @staticmethod
    def _is_outdated(name: str, version: str) -> bool:
        """Determine whether a software version is considered outdated.

        Uses a simple prefix-matching heuristic against the
        :data:`KNOWN_OUTDATED` dictionary.

        Args:
            name: Technology name (e.g. ``"Nginx"``).
            version: Detected version string (e.g. ``"1.18.0"``).

        Returns:
            ``True`` if the version matches a known-outdated prefix.
        """
        name_lower = name.lower()
        for software_key, outdated_prefixes in KNOWN_OUTDATED.items():
            if software_key in name_lower:
                return any(version.startswith(prefix) for prefix in outdated_prefixes)
        return False
