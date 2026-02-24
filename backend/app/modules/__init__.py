"""
Recon Module Registry -- import all modules for auto-registration.

Importing this package causes every concrete module class to be loaded
and, through the :func:`@ModuleRegistry.register <ModuleRegistry.register>`
decorator, automatically registered in the central module registry.
Downstream code (e.g. the scan orchestrator) only needs to
``import app.modules`` to have the full catalogue available.
"""

from app.modules.registry import ModuleRegistry
from app.modules.crtsh import CrtshModule
from app.modules.dns_enum import DnsEnumModule
from app.modules.whois_lookup import WhoisModule
from app.modules.tech_detect import TechDetectModule
from app.modules.cve_match import CveMatchModule
from app.modules.alienvault import AlienVaultModule
from app.modules.hackertarget import HackerTargetModule
from app.modules.anubis import AnubisModule
from app.modules.webarchive import WebArchiveModule

# Active scanning modules
from app.modules.subbuster import SubBusterModule
from app.modules.portscan import PortScanModule
from app.modules.dirbuster import DirBusterModule
from app.modules.sslaudit import SSLAuditModule
from app.modules.headeraudit import HeaderAuditModule

__all__: list[str] = [
    "ModuleRegistry",
    "CrtshModule",
    "DnsEnumModule",
    "WhoisModule",
    "TechDetectModule",
    "CveMatchModule",
    "AlienVaultModule",
    "HackerTargetModule",
    "AnubisModule",
    "WebArchiveModule",
    # Active modules
    "SubBusterModule",
    "PortScanModule",
    "DirBusterModule",
    "SSLAuditModule",
    "HeaderAuditModule",
]
