"""
Technology Detection module for ReconScope.

Fingerprints web technologies by inspecting HTTP response headers,
HTML body content, cookies, and meta tags against a library of 50+
known signature patterns.  Scans the target domain plus every
subdomain discovered by upstream modules, preferring HTTPS and
falling back to plain HTTP.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

import httpx

from app.modules.base import BaseReconModule, ModulePhase, ModuleResult
from app.modules.registry import ModuleRegistry

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Signature database
# ---------------------------------------------------------------------------
# Each entry: (regex_pattern, tech_name, category)
# If the regex has a capture group, group(1) is used as the version string.

HEADER_SIGNATURES: list[tuple[str, str, str, str]] = [
    # (header_name, regex, tech_name, category)
    # -- Server header --------------------------------------------------------
    ("Server", r"nginx/([\d.]+)", "Nginx", "web_server"),
    ("Server", r"Apache/([\d.]+)", "Apache", "web_server"),
    ("Server", r"Microsoft-IIS/([\d.]+)", "IIS", "web_server"),
    ("Server", r"LiteSpeed(?:/([\d.]+))?", "LiteSpeed", "web_server"),
    ("Server", r"openresty/([\d.]+)", "OpenResty", "web_server"),
    ("Server", r"cloudflare", "Cloudflare", "cdn"),
    ("Server", r"AmazonS3", "Amazon S3", "cdn"),
    ("Server", r"gws", "Google Web Server", "web_server"),
    ("Server", r"Kestrel", "Kestrel", "web_server"),
    ("Server", r"Caddy", "Caddy", "web_server"),
    ("Server", r"gunicorn/([\d.]+)", "Gunicorn", "web_server"),
    ("Server", r"Cowboy", "Cowboy (Erlang)", "web_server"),
    ("Server", r"Tengine/([\d.]+)", "Tengine", "web_server"),
    ("Server", r"Jetty\(?([\d.]*)\)?", "Jetty", "web_server"),
    ("Server", r"Varnish", "Varnish", "cache"),
    # -- X-Powered-By ---------------------------------------------------------
    ("X-Powered-By", r"Express", "Express.js", "framework"),
    ("X-Powered-By", r"PHP/([\d.]+)", "PHP", "language"),
    ("X-Powered-By", r"ASP\.NET", "ASP.NET", "framework"),
    ("X-Powered-By", r"Next\.js\s*([\d.]*)", "Next.js", "framework"),
    ("X-Powered-By", r"Servlet/([\d.]+)", "Java Servlet", "framework"),
    ("X-Powered-By", r"Phusion Passenger", "Phusion Passenger", "web_server"),
    ("X-Powered-By", r"PleskLin", "Plesk", "hosting_panel"),
    ("X-Powered-By", r"JBoss", "JBoss", "app_server"),
    ("X-Powered-By", r"WPEngine", "WP Engine", "hosting"),
    # -- Other headers --------------------------------------------------------
    ("X-AspNet-Version", r"([\d.]+)", "ASP.NET", "framework"),
    ("X-AspNetMvc-Version", r"([\d.]+)", "ASP.NET MVC", "framework"),
    ("X-Generator", r"Drupal\s*([\d.]*)", "Drupal", "cms"),
    ("X-Generator", r"WordPress\s*([\d.]*)", "WordPress", "cms"),
    ("X-Generator", r"Joomla", "Joomla", "cms"),
    ("X-Drupal-Cache", r".", "Drupal", "cms"),
    ("X-Varnish", r".", "Varnish", "cache"),
    ("X-Fastly-Request-ID", r".", "Fastly", "cdn"),
    ("Via", r"varnish", "Varnish", "cache"),
    ("Via", r"cloudfront", "CloudFront", "cdn"),
    ("Via", r"akamai", "Akamai", "cdn"),
    ("CF-RAY", r".", "Cloudflare", "cdn"),
    ("X-Sucuri-ID", r".", "Sucuri", "waf"),
    ("X-CDN", r"Incapsula", "Imperva Incapsula", "cdn"),
    ("X-Amz-Cf-Id", r".", "CloudFront", "cdn"),
    ("X-Powered-CMS", r"(.*)", "Unknown CMS", "cms"),
    ("X-Shopify-Stage", r".", "Shopify", "ecommerce"),
    ("X-GitHub-Request-Id", r".", "GitHub Pages", "hosting"),
    ("X-Vercel-Id", r".", "Vercel", "hosting"),
    ("X-Netlify-.*", r".", "Netlify", "hosting"),
    ("X-Firebase-.*", r".", "Firebase", "hosting"),
]

COOKIE_SIGNATURES: list[tuple[str, str, str]] = [
    # (cookie_name_pattern, tech_name, category)
    (r"PHPSESSID", "PHP", "language"),
    (r"JSESSIONID", "Java", "language"),
    (r"csrftoken", "Django", "framework"),
    (r"django_language", "Django", "framework"),
    (r"laravel_session", "Laravel", "framework"),
    (r"XSRF-TOKEN", "Angular/Laravel", "framework"),
    (r"rack\.session", "Ruby Rack", "framework"),
    (r"_rails_session", "Ruby on Rails", "framework"),
    (r"connect\.sid", "Express.js", "framework"),
    (r"ci_session", "CodeIgniter", "framework"),
    (r"wp-settings-", "WordPress", "cms"),
    (r"wordpress_", "WordPress", "cms"),
    (r"Drupal\.", "Drupal", "cms"),
    (r"joomla_", "Joomla", "cms"),
    (r"PrestaShop-", "PrestaShop", "ecommerce"),
    (r"__cfduid", "Cloudflare", "cdn"),
    (r"ASP\.NET_SessionId", "ASP.NET", "framework"),
    (r"AWSALB", "AWS ALB", "load_balancer"),
    (r"SERVERID", "HAProxy", "load_balancer"),
]

BODY_SIGNATURES: list[tuple[str, str, str, int]] = [
    # (regex, tech_name, category, confidence)
    # -- CMS ------------------------------------------------------------------
    (r"/wp-content/", "WordPress", "cms", 95),
    (r"/wp-includes/", "WordPress", "cms", 95),
    (r'name="generator"\s+content="WordPress\s*([\d.]*)"', "WordPress", "cms", 100),
    (r"sites/default/files", "Drupal", "cms", 90),
    (r'name="generator"\s+content="Drupal\s*([\d.]*)"', "Drupal", "cms", 100),
    (r'name="generator"\s+content="Joomla', "Joomla", "cms", 100),
    (r"/media/jui/", "Joomla", "cms", 85),
    (r'name="generator"\s+content="TYPO3', "TYPO3", "cms", 100),
    (r"content=\"Hugo\s*([\d.]*)", "Hugo", "ssg", 100),
    (r"/ghost/api/", "Ghost", "cms", 90),
    (r"Powered by.*Shopify", "Shopify", "ecommerce", 85),
    (r"cdn\.shopify\.com", "Shopify", "ecommerce", 90),
    (r"/skin/frontend/", "Magento", "ecommerce", 85),
    (r'content="Wix\.com', "Wix", "website_builder", 95),
    (r"squarespace\.com", "Squarespace", "website_builder", 85),
    # -- JavaScript frameworks ------------------------------------------------
    (r"__NEXT_DATA__", "Next.js", "framework", 95),
    (r"/_next/static/", "Next.js", "framework", 90),
    (r"__NUXT__", "Nuxt.js", "framework", 95),
    (r"/_nuxt/", "Nuxt.js", "framework", 85),
    (r'ng-version="([\d.]+)"', "Angular", "framework", 95),
    (r"ng-app", "AngularJS", "framework", 80),
    (r'data-reactroot', "React", "framework", 85),
    (r"__REACT_DEVTOOLS", "React", "framework", 80),
    (r"__VUE__", "Vue.js", "framework", 80),
    (r"/app\.[\w]+\.js", "SPA Framework", "framework", 50),
    (r"gatsby-", "Gatsby", "ssg", 85),
    (r"__remixContext", "Remix", "framework", 95),
    (r"__sveltekit", "SvelteKit", "framework", 95),
    (r"svelte", "Svelte", "framework", 60),
    (r"ember-cli", "Ember.js", "framework", 85),
    # -- Analytics & tracking -------------------------------------------------
    (r"google-analytics\.com/analytics\.js", "Google Analytics", "analytics", 95),
    (r"googletagmanager\.com", "Google Tag Manager", "analytics", 95),
    (r"gtag\(", "Google Analytics 4", "analytics", 85),
    (r"hotjar\.com", "Hotjar", "analytics", 90),
    (r"cdn\.segment\.com", "Segment", "analytics", 90),
    (r"matomo\.js", "Matomo", "analytics", 90),
    # -- Other ----------------------------------------------------------------
    (r"jquery(?:\.min)?\.js", "jQuery", "javascript_library", 70),
    (r"bootstrap(?:\.min)?\.(?:css|js)", "Bootstrap", "css_framework", 70),
    (r"tailwindcss", "Tailwind CSS", "css_framework", 70),
    (r"fonts\.googleapis\.com", "Google Fonts", "font_service", 60),
    (r"recaptcha/api", "reCAPTCHA", "security", 90),
    (r"hcaptcha\.com", "hCaptcha", "security", 90),
    (r"cloudflare-static", "Cloudflare", "cdn", 80),
    (r"use\.fontawesome\.com", "Font Awesome", "icon_library", 70),
]


@ModuleRegistry.register
class TechDetectModule(BaseReconModule):
    """Multi-source technology fingerprinting.

    Analyses HTTP response headers, body content, cookies, and meta tags
    against 50+ signature patterns to identify server software,
    frameworks, CMS platforms, and JavaScript libraries.
    """

    name: str = "techdetect"
    description: str = "Technology Fingerprinting via HTTP Headers, Body & Cookie Analysis"
    phase: ModulePhase = ModulePhase.ENRICHMENT
    depends_on: list[str] = ["crtsh", "dns"]

    async def execute(self, target: str, context: dict[str, Any]) -> ModuleResult:
        """Scan *target* and all known subdomains for technology signatures.

        Args:
            target:  Root domain (e.g. ``"acme-corp.de"``).
            context: Must contain ``"subdomains"`` (list of dicts with a
                     ``"name"`` key) when subdomains have been discovered.

        Returns:
            A :class:`ModuleResult` whose ``data["technologies"]`` list
            contains dicts with keys ``domain``, ``name``, ``version``,
            ``category``, ``confidence``, and ``source``.
        """
        start: float = time.monotonic()
        technologies: list[dict[str, Any]] = []
        errors: list[str] = []

        # Collect all domains to probe
        domains: list[str] = [target]
        for sub in context.get("subdomains", []):
            name = sub.get("name")
            if name and name != target:
                domains.append(name)

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0),
            follow_redirects=True,
            verify=False,  # noqa: S501 -- some targets use self-signed certs
        ) as client:
            for domain in domains:
                for scheme in ("https", "http"):
                    url = f"{scheme}://{domain}"
                    try:
                        response = await client.get(url)
                        port = 443 if scheme == "https" else 80
                        techs = self._analyze_response(domain, response, port)
                        technologies.extend(techs)
                        # If HTTPS works, also probe HTTP to detect both ports
                        if scheme == "https":
                            try:
                                http_resp = await client.get(f"http://{domain}")
                                http_techs = self._analyze_response(domain, http_resp, 80)
                                technologies.extend(http_techs)
                            except Exception:  # noqa: BLE001
                                pass
                        break
                    except httpx.TimeoutException:
                        logger.debug("Timeout connecting to %s", url)
                        continue
                    except httpx.ConnectError:
                        logger.debug("Connection refused for %s", url)
                        continue
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("Error probing %s: %s", url, exc)
                        continue

        # De-duplicate: same (domain, tech_name) keeps highest confidence
        seen: dict[tuple[str, str], dict[str, Any]] = {}
        for tech in technologies:
            key = (tech["domain"], tech["name"])
            existing = seen.get(key)
            if not existing or tech["confidence"] > existing["confidence"]:
                seen[key] = tech
        technologies = list(seen.values())

        duration: float = time.monotonic() - start

        return ModuleResult(
            module_name=self.name,
            success=True,
            data={"technologies": technologies},
            errors=errors if errors else None,
            duration_seconds=round(duration, 3),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _analyze_response(
        self, domain: str, response: httpx.Response, port: int = 443
    ) -> list[dict[str, Any]]:
        """Analyse response headers, body, and cookies for technology signatures.

        Args:
            domain:   The domain that was probed.
            response: The :class:`httpx.Response` object to analyse.
            port:     The port the response came from (443 or 80).

        Returns:
            A list of technology dicts ready for inclusion in the module
            result.
        """
        techs: list[dict[str, Any]] = []

        # -- Header analysis --------------------------------------------------
        techs.extend(self._match_headers(domain, response))

        # -- Cookie analysis --------------------------------------------------
        techs.extend(self._match_cookies(domain, response))

        # -- Body / HTML analysis ---------------------------------------------
        try:
            body = response.text[:200_000]  # limit to 200KB
        except Exception:  # noqa: BLE001
            body = ""

        if body:
            techs.extend(self._match_body(domain, body))

        # -- TLS info ---------------------------------------------------------
        techs.extend(self._extract_tls(domain, response))

        # Assign port to all detected technologies
        for tech in techs:
            tech["port"] = port

        return techs

    @staticmethod
    def _match_headers(
        domain: str, response: httpx.Response
    ) -> list[dict[str, Any]]:
        """Match HTTP response headers against known signatures."""
        techs: list[dict[str, Any]] = []
        headers = response.headers

        for header_pattern, regex, tech_name, category in HEADER_SIGNATURES:
            # Support regex in header names (e.g. X-Netlify-.*)
            matched_headers = []
            if "*" in header_pattern or "\\" in header_pattern:
                for h in headers:
                    if re.match(header_pattern, h, re.IGNORECASE):
                        matched_headers.append(headers[h])
            else:
                val = headers.get(header_pattern, "")
                if val:
                    matched_headers.append(val)

            for header_value in matched_headers:
                match = re.search(regex, header_value, re.IGNORECASE)
                if match:
                    version = (
                        match.group(1)
                        if match.lastindex and match.group(1)
                        else "unknown"
                    )
                    techs.append({
                        "domain": domain,
                        "name": tech_name,
                        "version": version,
                        "category": category,
                        "confidence": 90,
                        "source": f"header:{header_pattern}",
                    })

        return techs

    @staticmethod
    def _match_cookies(
        domain: str, response: httpx.Response
    ) -> list[dict[str, Any]]:
        """Detect technologies from cookie names."""
        techs: list[dict[str, Any]] = []
        cookie_header = response.headers.get("set-cookie", "")
        # Also include cookies from the jar
        all_cookies = cookie_header
        for cookie in response.cookies.jar:
            all_cookies += f" {cookie.name}"

        if not all_cookies:
            return techs

        for pattern, tech_name, category in COOKIE_SIGNATURES:
            if re.search(pattern, all_cookies, re.IGNORECASE):
                techs.append({
                    "domain": domain,
                    "name": tech_name,
                    "version": "unknown",
                    "category": category,
                    "confidence": 75,
                    "source": "cookie",
                })

        return techs

    @staticmethod
    def _match_body(
        domain: str, body: str
    ) -> list[dict[str, Any]]:
        """Detect technologies from HTML body patterns."""
        techs: list[dict[str, Any]] = []

        for pattern, tech_name, category, confidence in BODY_SIGNATURES:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                version = (
                    match.group(1)
                    if match.lastindex and match.group(1)
                    else "unknown"
                )
                techs.append({
                    "domain": domain,
                    "name": tech_name,
                    "version": version,
                    "category": category,
                    "confidence": confidence,
                    "source": "body",
                })

        return techs

    @staticmethod
    def _extract_tls(
        domain: str, response: httpx.Response
    ) -> list[dict[str, Any]]:
        """Extract TLS version information if available."""
        techs: list[dict[str, Any]] = []
        try:
            if (
                hasattr(response, "stream")
                and hasattr(response.stream, "ssl_object")
                and response.stream.ssl_object is not None
            ):
                ssl_obj = response.stream.ssl_object
                tls_version = (
                    ssl_obj.version()
                    if hasattr(ssl_obj, "version")
                    else "unknown"
                )
                techs.append({
                    "domain": domain,
                    "name": "TLS",
                    "version": tls_version,
                    "category": "security",
                    "confidence": 100,
                    "source": "ssl",
                })
        except Exception:  # noqa: BLE001
            pass
        return techs
