"""
ReconScope ORM models package.

Re-exports every model class so that consumers can import directly from
``app.models`` instead of reaching into individual submodules::

    from app.models import Target, Scan, ScanStatus, Subdomain
"""

from app.models.scan import Target, Scan, ScanStatus
from app.models.subdomain import Subdomain
from app.models.service import Service
from app.models.technology import Technology
from app.models.cve import CVEMatch
from app.models.finding import Finding
from app.models.attack_path import AttackPath
from app.models.correlation import Correlation
from app.models.schedule import ScanSchedule

__all__: list[str] = [
    "Target",
    "Scan",
    "ScanStatus",
    "Subdomain",
    "Service",
    "Technology",
    "CVEMatch",
    "Finding",
    "AttackPath",
    "Correlation",
    "ScanSchedule",
]
