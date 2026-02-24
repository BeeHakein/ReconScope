"""
Subdomain Bruteforce module for ReconScope.

Resolves a curated wordlist of common subdomain prefixes via DNS A-record
lookups to discover subdomains that are not present in passive certificate
transparency or OSINT sources.  This is an **active** module that generates
DNS traffic against the target's authoritative nameservers.
"""

from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import dns.exception
import dns.resolver

from app.modules.base import BaseReconModule, ModulePhase, ModuleResult
from app.modules.registry import ModuleRegistry

logger = logging.getLogger(__name__)

_CONCURRENCY = 50

# ~500 common subdomain prefixes used for bruteforce discovery.
WORDLIST: list[str] = [
    "www", "mail", "ftp", "admin", "dev", "staging", "api", "vpn",
    "test", "beta", "internal", "intranet", "gateway", "proxy", "cdn",
    "app", "apps", "auth", "backup", "blog", "board", "calendar",
    "chat", "ci", "cloud", "cms", "code", "conference", "config",
    "connect", "console", "cp", "cpanel", "crm", "css", "data",
    "database", "db", "demo", "deploy", "desktop", "dev1", "dev2",
    "developer", "dns", "dns1", "dns2", "doc", "docs", "download",
    "downloads", "email", "exchange", "extern", "external", "file",
    "files", "firewall", "forum", "forums", "ftp2", "git", "gitlab",
    "grafana", "graphql", "help", "helpdesk", "home", "host", "hosting",
    "hr", "hub", "id", "imap", "img", "images", "info", "infra",
    "jenkins", "jira", "jobs", "kb", "ldap", "legacy", "lib", "link",
    "linux", "list", "lists", "live", "local", "log", "login", "logs",
    "m", "manage", "management", "manager", "map", "maps", "media",
    "meet", "meeting", "metrics", "mirror", "mobile", "monitor",
    "monitoring", "mqtt", "mx", "mx1", "mx2", "mysql", "nas", "net",
    "network", "new", "news", "nexus", "node", "ns", "ns1", "ns2",
    "ns3", "ns4", "ntp", "office", "old", "ops", "oracle", "order",
    "origin", "owa", "panel", "partner", "partners", "pay", "payment",
    "pgsql", "phone", "phpmyadmin", "pip", "platform", "plesk", "pma",
    "pop", "pop3", "portal", "postgres", "preprod", "preview", "print",
    "prod", "production", "profile", "prometheus", "push", "qa",
    "queue", "rabbit", "rabbitmq", "rdp", "redis", "register",
    "relay", "remote", "repo", "report", "reports", "rest", "review",
    "root", "router", "rss", "s3", "sandbox", "schedule", "search",
    "secure", "security", "sentry", "server", "service", "services",
    "sftp", "shop", "signin", "signup", "site", "sites", "sms",
    "smtp", "soa", "sonar", "sonarqube", "splunk", "sql", "srv",
    "ssh", "ssl", "sso", "staff", "stage", "static", "stats",
    "status", "storage", "store", "stream", "sub", "support", "svn",
    "syslog", "system", "team", "teams", "terminal", "ticket",
    "tickets", "tools", "tracker", "traffic", "transfer", "tunnel",
    "uat", "update", "upload", "uploads", "v1", "v2", "vault",
    "video", "vip", "vm", "voip", "vpn2", "vps", "w", "web",
    "webapp", "webdisk", "webmail", "webmin", "webservice", "wiki",
    "win", "windows", "work", "ws", "wss", "www1", "www2", "www3",
    "xml", "zabbix", "zimbra", "zone",
    # Additional common cloud/DevOps prefixes
    "aws", "azure", "gcp", "k8s", "kubernetes", "docker", "registry",
    "artifact", "argocd", "airflow", "ansible", "terraform",
    "consul", "nomad", "vault", "keycloak", "minio", "elastic",
    "elasticsearch", "kibana", "logstash", "fluentd", "kafka",
    "zookeeper", "cassandra", "mongo", "mongodb", "couchdb",
    "influxdb", "telegraf", "clickhouse", "memcached", "haproxy",
    "traefik", "envoy", "istio", "linkerd", "nginx", "apache",
    "tomcat", "wildfly", "weblogic", "websphere",
    # Additional common subdomain patterns
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l",
    "n", "o", "p", "q", "r", "s", "t", "u", "v", "x", "y", "z",
    "api1", "api2", "api3", "app1", "app2", "app3", "web1", "web2",
    "web3", "srv1", "srv2", "node1", "node2", "worker", "worker1",
    "worker2", "cron", "batch", "async", "sync", "webhook", "hooks",
    "callback", "notify", "notification", "alert", "alerts",
    "dashboard", "admin2", "backend", "frontend", "client", "clients",
    "customer", "customers", "user", "users", "account", "accounts",
    "billing", "invoice", "tax", "finance", "analytics", "tracking",
    "pixel", "tag", "tags", "asset", "assets", "res", "resources",
    "public", "private", "secret", "secrets", "cert", "certs",
    "pki", "ca", "ocsp", "crl", "acme", "letsencrypt",
    "autodiscover", "autoconfig", "wpad", "pac",
    "exchange2", "mail2", "mail3", "smtp2", "imap2",
    "mx3", "ns5", "ns6", "dns3", "dns4",
    "vpn3", "remote2", "rdp2", "citrix", "ica",
    "sap", "erp", "bi", "dwh", "etl", "datalake",
    "spark", "hadoop", "hive", "presto", "superset",
    "jupyter", "notebook", "lab", "rstudio", "mlflow",
    "model", "inference", "predict", "train", "gpu",
]


@ModuleRegistry.register
class SubBusterModule(BaseReconModule):
    """Subdomain bruteforce discovery via DNS A-record resolution.

    Resolves ~500 common subdomain prefixes against the target domain
    to discover hosts not found by passive OSINT sources.
    """

    name: str = "subbuster"
    description: str = "Subdomain Bruteforce via DNS Resolution"
    phase: ModulePhase = ModulePhase.DISCOVERY

    async def execute(self, target: str, context: dict[str, Any]) -> ModuleResult:
        """Bruteforce subdomains by resolving ``{prefix}.{target}`` A records.

        Args:
            target:  Root domain (e.g. ``"acme-corp.de"``).
            context: Aggregated results from previously completed modules.

        Returns:
            A :class:`ModuleResult` with ``data["subdomains"]`` containing
            discovered subdomain dicts.
        """
        start: float = time.monotonic()
        discovered: list[dict[str, Any]] = []
        errors: list[str] = []

        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 3.0

        loop = asyncio.get_running_loop()
        semaphore = asyncio.Semaphore(_CONCURRENCY)
        executor = ThreadPoolExecutor(max_workers=_CONCURRENCY)

        async def _check_prefix(prefix: str) -> None:
            fqdn = f"{prefix}.{target}"
            async with semaphore:
                try:
                    answers = await loop.run_in_executor(
                        executor, self._resolve_a, resolver, fqdn
                    )
                    if answers:
                        discovered.append({"name": fqdn, "source": "subbuster"})
                except Exception as exc:
                    errors.append(f"subbuster {fqdn}: {exc}")

        await asyncio.gather(
            *(_check_prefix(prefix) for prefix in WORDLIST),
            return_exceptions=True,
        )

        executor.shutdown(wait=False)

        duration: float = time.monotonic() - start
        logger.info(
            "Subbuster discovered %d subdomains in %.1fs",
            len(discovered),
            duration,
        )

        return ModuleResult(
            module_name=self.name,
            success=True,
            data={"subdomains": discovered},
            errors=errors if errors else None,
            duration_seconds=round(duration, 3),
        )

    @staticmethod
    def _resolve_a(
        resolver: dns.resolver.Resolver, fqdn: str
    ) -> dns.resolver.Answer | None:
        """Attempt to resolve an A record for *fqdn*.

        Returns ``None`` on NXDOMAIN, NoAnswer, timeout, etc.
        """
        try:
            return resolver.resolve(fqdn, "A")
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            return None
