"""
Pydantic v2 schemas for scan-related API requests and responses.

Every model uses ``ConfigDict(from_attributes=True)`` so that ORM objects
can be serialised directly via ``Model.model_validate(orm_instance)``.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALL_MODULES: list[str] = [
    "crtsh", "alienvault", "hackertarget", "anubis", "webarchive",
    "dns", "whois", "techdetect", "cvematch",
]
"""The nine default reconnaissance modules shipped with ReconScope v1."""

ACTIVE_MODULES: list[str] = [
    "subbuster", "portscan", "dirbuster", "sslaudit", "headeraudit",
]
"""Active scanning modules that directly probe target infrastructure."""

_DOMAIN_RE = re.compile(
    r"^(?!-)"                          # label must not start with hyphen
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"  # sub-labels
    r"[A-Za-z]{2,63}$"                 # TLD
)

# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class ScanCreate(BaseModel):
    """Payload for ``POST /api/v1/scans/``.

    Attributes:
        target: A fully-qualified domain name to scan (e.g. ``acme-corp.de``).
        modules: Optional list of module identifiers.  When omitted every
            registered passive module is executed.
        scope_confirmed: The caller must explicitly confirm that they are
            authorised to scan the target domain.  Requests with
            ``scope_confirmed=false`` are rejected with *403 Forbidden*.
        scan_mode: Either ``"passive"`` (default) or ``"active"``.  Active
            mode enables additional modules that directly probe the target.
    """

    target: str = Field(
        ...,
        min_length=4,
        max_length=253,
        examples=["acme-corp.de"],
        description="Fully-qualified domain name to scan.",
    )
    modules: list[str] = Field(
        default_factory=lambda: list(ALL_MODULES),
        description="Modules to execute.  Defaults to all passive modules.",
    )
    scope_confirmed: bool = Field(
        ...,
        description=(
            "Explicit confirmation that the caller is authorised to scan "
            "the target domain."
        ),
    )
    scan_mode: str = Field(
        default="passive",
        description="Scan mode: 'passive' (default) or 'active'.",
    )

    model_config = ConfigDict(from_attributes=True)

    # -- validators --------------------------------------------------------

    @field_validator("target", mode="after")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        """Ensure *target* looks like a valid domain name.

        Strips leading/trailing whitespace, lowercases the value, and
        validates it against a simplified domain-name regex.

        Raises:
            ValueError: If the value does not match the expected pattern.
        """
        cleaned = value.strip().lower().rstrip(".")
        if not _DOMAIN_RE.match(cleaned):
            raise ValueError(
                f"'{cleaned}' is not a valid fully-qualified domain name."
            )
        return cleaned

    @field_validator("scan_mode", mode="after")
    @classmethod
    def validate_scan_mode(cls, value: str) -> str:
        """Ensure scan_mode is either 'passive' or 'active'."""
        if value not in ("passive", "active"):
            raise ValueError("scan_mode must be 'passive' or 'active'.")
        return value

    @model_validator(mode="after")
    def validate_modules_for_mode(self) -> "ScanCreate":
        """Validate modules against the selected scan mode.

        In passive mode only passive modules are allowed.  In active mode
        both passive and active modules are valid.
        """
        valid = set(ALL_MODULES)
        if self.scan_mode == "active":
            valid |= set(ACTIVE_MODULES)
        unknown = set(self.modules) - valid
        if unknown:
            raise ValueError(
                f"Unknown module(s): {', '.join(sorted(unknown))}. "
                f"Valid modules for '{self.scan_mode}' mode are: "
                f"{', '.join(sorted(valid))}"
            )
        return self


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class ScanResponse(BaseModel):
    """Returned by ``POST /api/v1/scans/`` on successful creation (201).

    Attributes:
        scan_id: The UUID of the newly created scan.
        target: The normalised domain that will be scanned.
        status: Initial scan status (typically ``queued``).
        created_at: UTC timestamp when the scan record was persisted.
        modules: The list of modules that will be executed.
    """

    scan_id: UUID
    target: str
    status: str
    created_at: datetime
    modules: list[str]

    model_config = ConfigDict(from_attributes=True)


class ScanProgress(BaseModel):
    """Real-time progress information for a running scan.

    Attributes:
        current_module: The module currently being executed, or ``None``
            when the scan is queued or already completed.
        modules_completed: Modules that have finished successfully.
        modules_pending: Modules that have not yet started.
        percentage: Completion percentage (0 -- 100).
    """

    current_module: Optional[str] = None
    modules_completed: list[str] = Field(default_factory=list)
    modules_pending: list[str] = Field(default_factory=list)
    percentage: int = 0

    model_config = ConfigDict(from_attributes=True)


class ScanStats(BaseModel):
    """Aggregate counters for a scan's current findings.

    Attributes:
        subdomains_found: Number of discovered subdomains.
        services_found: Number of detected services.
        cves_found: Number of matched CVEs.
    """

    subdomains_found: int = 0
    services_found: int = 0
    cves_found: int = 0

    model_config = ConfigDict(from_attributes=True)


class ScanDetail(BaseModel):
    """Full scan detail returned by ``GET /api/v1/scans/{scan_id}``.

    Attributes:
        scan_id: Primary key of the scan.
        target: The scanned domain.
        status: Current scan status.
        progress: Granular progress information.
        stats: Aggregate counters.
        created_at: UTC creation timestamp.
        completed_at: UTC completion timestamp (``None`` while running).
        duration_seconds: Wall-clock seconds from start to finish.
        overall_risk: Textual risk rating (e.g. ``critical``).
    """

    scan_id: UUID
    target: str
    status: str
    progress: ScanProgress
    stats: ScanStats
    created_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    overall_risk: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ScanListItem(BaseModel):
    """Compact scan representation used in list endpoints.

    Attributes:
        scan_id: Primary key.
        target: Domain that was scanned.
        status: Current status string.
        created_at: UTC creation timestamp.
        total_subdomains: Number of subdomains discovered.
        total_services: Number of services detected.
        total_cves: Number of CVEs matched.
    """

    scan_id: UUID
    target: str
    status: str
    created_at: datetime
    total_subdomains: int = 0
    total_services: int = 0
    total_cves: int = 0
    overall_risk: str | None = None
    duration_seconds: float | None = None

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Result detail schemas
# ---------------------------------------------------------------------------


class SubdomainResponse(BaseModel):
    """A single subdomain discovered during a scan.

    Attributes:
        id: Primary key.
        name: FQDN of the subdomain.
        ip_address: Resolved IP address (may be ``None``).
        source: Module that discovered the subdomain.
        is_alive: Whether the host responded to probing.
    """

    id: UUID
    name: str
    ip_address: Optional[str] = None
    source: Optional[str] = None
    is_alive: bool = False

    model_config = ConfigDict(from_attributes=True)


class ServiceResponse(BaseModel):
    """A network service detected on a subdomain.

    Attributes:
        id: Primary key.
        port: TCP/UDP port number.
        protocol: Transport protocol (``tcp`` or ``udp``).
        service_name: Human-readable service identifier (e.g. ``http``).
        version: Detected version string.
    """

    id: UUID
    port: int
    protocol: str = "tcp"
    service_name: Optional[str] = None
    version: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class TechnologyResponse(BaseModel):
    """A technology fingerprint associated with a service.

    Attributes:
        id: Primary key.
        name: Technology name (e.g. ``Nginx``).
        version: Detected version string.
        category: Technology category (e.g. ``web_server``).
        confidence: Detection confidence (0 -- 100).
    """

    id: UUID
    name: str
    version: Optional[str] = None
    category: Optional[str] = None
    confidence: int = 50

    model_config = ConfigDict(from_attributes=True)


class CVEResponse(BaseModel):
    """A CVE match associated with a service.

    Attributes:
        id: Primary key.
        cve_id: Official CVE identifier (e.g. ``CVE-2021-41773``).
        cvss_score: CVSS base score (0.0 -- 10.0).
        severity: Textual severity (``critical``, ``high``, ``medium``, ``low``).
        description: Short vulnerability description.
        affected_domain: The domain/subdomain affected by this CVE.
    """

    id: UUID
    cve_id: str
    cvss_score: Optional[float] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    affected_domain: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Delta comparison
# ---------------------------------------------------------------------------


class _SubdomainDelta(BaseModel):
    """Changes in subdomain inventory between two scans."""

    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    unchanged: list[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class _ServiceDelta(BaseModel):
    """Changes in service inventory between two scans."""

    added: list[list[str]] = Field(default_factory=list)
    removed: list[list[str]] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class _CveDelta(BaseModel):
    """Changes in CVE inventory between two scans."""

    new: list[str] = Field(default_factory=list)
    resolved: list[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class _RiskChange(BaseModel):
    """Overall risk score change between two scans."""

    old_score: Optional[str] = None
    new_score: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class DeltaResponse(BaseModel):
    """Result of comparing two scans via ``GET /scans/{id}/delta/{compare_id}``.

    Attributes:
        subdomains: Added, removed, and unchanged subdomains.
        services: Added and removed services (each entry is a triple of
            ``[subdomain, port, service_name]``).
        cves: Newly appeared and resolved CVE identifiers.
        risk_change: Overall risk rating of each scan.
    """

    subdomains: _SubdomainDelta
    services: _ServiceDelta
    cves: _CveDelta
    risk_change: _RiskChange

    model_config = ConfigDict(from_attributes=True)
