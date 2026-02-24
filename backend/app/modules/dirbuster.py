"""
Directory/Path Discovery module for ReconScope.

Probes alive subdomains for common sensitive paths (admin panels, exposed
configuration files, backup directories, etc.) via HTTP requests.  This is
an **active** module that sends HTTP requests to the target infrastructure.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from app.modules.base import BaseReconModule, ModulePhase, ModuleResult
from app.modules.registry import ModuleRegistry

logger = logging.getLogger(__name__)

_CONCURRENCY_PER_DOMAIN = 10

# ~200 common paths to probe.
WORDLIST: list[str] = [
    "/admin", "/administrator", "/api", "/api/v1", "/api/v2",
    "/login", "/signin", "/signup", "/register", "/auth",
    "/.git/HEAD", "/.git/config", "/.gitignore",
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/backup", "/backups", "/backup.zip", "/backup.tar.gz",
    "/db", "/database", "/dump.sql", "/data.sql",
    "/wp-admin", "/wp-login.php", "/wp-config.php.bak",
    "/wp-content/uploads", "/wp-includes",
    "/phpmyadmin", "/pma", "/adminer", "/adminer.php",
    "/server-status", "/server-info",
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/.well-known/security.txt", "/.well-known/openid-configuration",
    "/favicon.ico", "/humans.txt",
    "/config", "/config.php", "/config.yml", "/config.json",
    "/configuration", "/settings", "/settings.json",
    "/console", "/debug", "/debug/pprof", "/trace",
    "/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/openapi.json", "/openapi.yaml", "/redoc",
    "/graphql", "/graphiql", "/playground",
    "/health", "/healthz", "/readyz", "/livez",
    "/status", "/info", "/version", "/metrics", "/prometheus",
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/beans", "/actuator/configprops",
    "/.htaccess", "/.htpasswd", "/.DS_Store",
    "/web.config", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/elmah.axd", "/trace.axd",
    "/cgi-bin/", "/cgi-bin/test-cgi",
    "/test", "/test.php", "/info.php", "/phpinfo.php",
    "/tmp", "/temp", "/cache", "/logs", "/log",
    "/uploads", "/upload", "/files", "/download", "/downloads",
    "/assets", "/static", "/public", "/media", "/images",
    "/docs", "/documentation", "/help", "/faq",
    "/panel", "/cpanel", "/webmail", "/mail",
    "/dashboard", "/portal", "/manager", "/management",
    "/install", "/setup", "/installer",
    "/xmlrpc.php", "/xmlrpc",
    "/readme.html", "/readme.txt", "/README.md",
    "/changelog", "/CHANGELOG.md", "/changelog.txt",
    "/license", "/LICENSE", "/license.txt",
    "/package.json", "/composer.json", "/Gemfile",
    "/Makefile", "/Dockerfile", "/docker-compose.yml",
    "/.dockerenv", "/Procfile",
    "/.svn/entries", "/.svn/wc.db",
    "/.hg/", "/CVS/Entries",
    "/node_modules/", "/vendor/",
    "/cron", "/crontab", "/jobs",
    "/socket", "/ws", "/websocket",
    "/proxy", "/gateway", "/redirect",
    "/oauth", "/oauth2", "/token", "/authorize",
    "/saml", "/sso", "/cas",
    "/ldap", "/kerberos",
    "/jenkins", "/hudson", "/bamboo", "/teamcity",
    "/sonar", "/sonarqube",
    "/grafana", "/kibana", "/elasticsearch",
    "/nagios", "/zabbix", "/munin", "/cacti",
    "/solr", "/lucene",
    "/.aws/credentials", "/.ssh/id_rsa",
    "/id_rsa", "/id_rsa.pub",
    "/secret", "/secrets", "/private",
    "/internal", "/hidden",
    "/error", "/errors", "/404", "/500",
    "/nginx.conf", "/httpd.conf",
    "/php.ini", "/my.cnf", "/pg_hba.conf",
    "/etc/passwd", "/etc/shadow",
    "/wp-json/wp/v2/users",
    "/.vscode/", "/.idea/",
    "/Thumbs.db", "/desktop.ini",
    "/app.js", "/main.js", "/bundle.js",
    "/service-worker.js", "/manifest.json",
    "/feed", "/feed.xml", "/atom.xml", "/rss",
]


@ModuleRegistry.register
class DirBusterModule(BaseReconModule):
    """Directory and path discovery via HTTP probing.

    Checks alive subdomains for ~200 common sensitive paths and reports
    interesting responses (200, 401, 403).
    """

    name: str = "dirbuster"
    description: str = "Directory Discovery — sensitive path enumeration"
    phase: ModulePhase = ModulePhase.ENRICHMENT
    depends_on: list[str] = ["dns"]

    async def execute(self, target: str, context: dict[str, Any]) -> ModuleResult:
        """Probe alive subdomains for sensitive paths.

        Args:
            target:  Root domain (e.g. ``"acme-corp.de"``).
            context: Must contain ``"subdomains"`` and ``"resolved_ips"``.

        Returns:
            A :class:`ModuleResult` with ``data["discovered_paths"]``.
        """
        start: float = time.monotonic()
        discovered_paths: list[dict[str, Any]] = []
        errors: list[str] = []

        resolved_ips: dict[str, str] = context.get("resolved_ips", {})

        # Collect alive domains
        alive_domains: list[str] = []
        for sub_dict in context.get("subdomains", []):
            name = sub_dict.get("name", "")
            if name in resolved_ips:
                alive_domains.append(name)

        if not alive_domains:
            alive_domains = [target]

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=8.0, write=5.0, pool=5.0),
            follow_redirects=False,
            verify=False,  # noqa: S501
        ) as client:
            for domain in alive_domains:
                semaphore = asyncio.Semaphore(_CONCURRENCY_PER_DOMAIN)

                async def _check_path(path: str, dom: str = domain) -> None:
                    async with semaphore:
                        for scheme in ("https", "http"):
                            url = f"{scheme}://{dom}{path}"
                            try:
                                resp = await client.get(url)
                                if resp.status_code in (200, 401, 403):
                                    redirect_url = None
                                    if resp.status_code in (301, 302, 307, 308):
                                        redirect_url = resp.headers.get("location")
                                    discovered_paths.append({
                                        "domain": dom,
                                        "path": path,
                                        "status_code": resp.status_code,
                                        "content_length": len(resp.content),
                                        "redirect_url": redirect_url,
                                    })
                                break  # Don't try HTTP if HTTPS worked
                            except (httpx.ConnectError, httpx.TimeoutException):
                                continue
                            except Exception:
                                break

                await asyncio.gather(
                    *(_check_path(path) for path in WORDLIST),
                    return_exceptions=True,
                )

        duration: float = time.monotonic() - start
        logger.info(
            "Dirbuster found %d paths across %d domains in %.1fs",
            len(discovered_paths),
            len(alive_domains),
            duration,
        )

        return ModuleResult(
            module_name=self.name,
            success=True,
            data={"discovered_paths": discovered_paths},
            errors=errors if errors else None,
            duration_seconds=round(duration, 3),
        )
