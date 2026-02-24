# ReconScope – Vollständiger Architekturplan
## Attack Surface Mapper | Version 1.0

---

## 1. Executive Summary

ReconScope ist ein Attack Surface Mapping Tool, das die externe Angriffsfläche einer Organisation automatisiert analysiert, korreliert und visuell darstellt. Im Gegensatz zu bestehenden Tools wie reconftw, Amass oder SpiderFoot bietet ReconScope eine intelligente Correlation Engine, kontextbewusstes Risk-Scoring und Attack Path Inference – visualisiert über einen interaktiven Netzwerk-Graphen.

**Kernprinzipien:**
- Solo-Projekt, flexibel deploybar (lokal + Server)
- Phase 1: Rein passive Reconnaissance (API-Abfragen)
- Modulare Plugin-Architektur für spätere Erweiterung (Active Scanning)
- Event-Driven Design inspiriert von SpiderFoot's bewährter Architektur

---

## 2. System-Übersicht

### 2.1 High-Level Architektur

```
┌─────────────────────────────────────────────────────────┐
│                    FRONTEND (React)                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐ │
│  │  Scan UI  │ │  Attack  │ │ Findings │ │  Insights  │ │
│  │          │ │  Graph   │ │  Table   │ │  Panel     │ │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └─────┬──────┘ │
│       └─────────────┴────────────┴──────────────┘       │
│                        │ WebSocket + REST                │
└────────────────────────┼────────────────────────────────┘
                         │
┌────────────────────────┼────────────────────────────────┐
│              BACKEND (FastAPI)                           │
│  ┌──────────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │  REST API    │  │WebSocket │  │  Scan Orchestrator │  │
│  │  Endpoints   │  │  Server  │  │                   │  │
│  └──────┬───────┘  └────┬─────┘  └────────┬──────────┘  │
│         └───────────────┴─────────────────┘              │
│                         │                                │
│  ┌──────────────────────┼──────────────────────────┐     │
│  │         RECON MODULE REGISTRY                   │     │
│  │  ┌─────┐ ┌─────┐ ┌──────┐ ┌─────┐ ┌──────┐    │     │
│  │  │CT/  │ │ DNS │ │WHOIS │ │Tech │ │ CVE  │    │     │
│  │  │crt.sh│ │     │ │      │ │Det. │ │Match │    │     │
│  │  └─────┘ └─────┘ └──────┘ └─────┘ └──────┘    │     │
│  └─────────────────────────────────────────────────┘     │
│                         │                                │
│  ┌──────────────────────┼──────────────────────────┐     │
│  │         POST-PROCESSING PIPELINE                │     │
│  │  ┌────────────┐ ┌──────────┐ ┌──────────────┐   │     │
│  │  │Correlation │ │  Risk    │ │ Attack Path  │   │     │
│  │  │  Engine    │ │ Scoring  │ │  Inference   │   │     │
│  │  └────────────┘ └──────────┘ └──────────────┘   │     │
│  └─────────────────────────────────────────────────┘     │
└──────────────────────────┬──────────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
┌────────▼───────┐ ┌──────▼──────┐ ┌────────▼───────┐
│   PostgreSQL   │ │    Redis    │ │  Celery Worker │
│   (Scan Data)  │ │  (Broker +  │ │  (Task Queue)  │
│                │ │   Cache)    │ │                │
└────────────────┘ └─────────────┘ └────────────────┘
```

### 2.2 Datenfluss: Vom Input zum Ergebnis

```
1. User gibt Domain ein (z.B. "acme-corp.de")
   │
2. Frontend → POST /api/v1/scans/ → Backend erstellt Scan-Objekt in DB
   │
3. Scan Orchestrator startet Celery Task-Chain:
   │
   ├─ Phase 1 (Parallel): CT Lookup + DNS Enum + WHOIS
   │   └─ Ergebnisse streamen via WebSocket zum Frontend
   │
   ├─ Phase 2 (Abhängig von Phase 1): Tech Detection auf entdeckten Subdomains
   │   └─ Ergebnisse streamen via WebSocket
   │
   ├─ Phase 3 (Abhängig von Phase 2): CVE Matching gegen erkannte Services
   │   └─ Ergebnisse streamen via WebSocket
   │
   └─ Phase 4 (Post-Processing): 
       ├─ Correlation Engine analysiert alle Daten
       ├─ Risk-Scoring berechnet gewichtete Scores
       └─ Attack Path Inference generiert Angriffspfade
   │
4. Scan-Status → COMPLETED, Frontend zeigt vollständiges Ergebnis
```

---

## 3. Backend-Architektur (FastAPI)

### 3.1 API-Endpunkte

```
BASE_URL: /api/v1

# ─── Scans ───────────────────────────────────────────────
POST   /scans/                    → Neuen Scan starten
GET    /scans/                    → Alle Scans auflisten
GET    /scans/{scan_id}           → Scan-Details + Status
GET    /scans/{scan_id}/results   → Vollständige Ergebnisse
DELETE /scans/{scan_id}           → Scan löschen

# ─── Scan-Ergebnisse (Detail-Abfragen) ──────────────────
GET    /scans/{scan_id}/subdomains     → Entdeckte Subdomains
GET    /scans/{scan_id}/services       → Erkannte Services
GET    /scans/{scan_id}/technologies   → Tech-Stack pro Asset
GET    /scans/{scan_id}/cves           → Gematchte CVEs
GET    /scans/{scan_id}/findings       → Priorisierte Findings
GET    /scans/{scan_id}/attack-paths   → Generierte Attack Paths
GET    /scans/{scan_id}/correlations   → Correlation Insights
GET    /scans/{scan_id}/graph          → Graph-Daten (Nodes + Edges)

# ─── Delta / Vergleich ───────────────────────────────────
GET    /scans/{scan_id}/delta/{compare_scan_id}  → Scan-Vergleich

# ─── Targets ─────────────────────────────────────────────
GET    /targets/                  → Alle gescannten Domains
GET    /targets/{domain}/history  → Scan-History einer Domain

# ─── WebSocket ───────────────────────────────────────────
WS     /ws/scans/{scan_id}       → Live Scan-Updates
```

### 3.2 Request/Response Schemas

```python
# ─── Scan starten ────────────────────────────────────────
# POST /api/v1/scans/
{
    "target": "acme-corp.de",
    "modules": ["crtsh", "dns", "whois", "techdetect", "cvematch"],  # optional, default: all
    "scope_confirmed": true  # Pflichtfeld: User bestätigt Berechtigung
}

# Response: 201 Created
{
    "scan_id": "550e8400-e29b-41d4-a716-446655440000",
    "target": "acme-corp.de",
    "status": "queued",
    "created_at": "2026-02-23T14:30:00Z",
    "modules": ["crtsh", "dns", "whois", "techdetect", "cvematch"]
}

# ─── Scan-Status ─────────────────────────────────────────
# GET /api/v1/scans/{scan_id}
{
    "scan_id": "...",
    "target": "acme-corp.de",
    "status": "running",  # queued | running | post_processing | completed | failed
    "progress": {
        "current_module": "techdetect",
        "modules_completed": ["crtsh", "dns", "whois"],
        "modules_pending": ["techdetect", "cvematch"],
        "percentage": 60
    },
    "stats": {
        "subdomains_found": 12,
        "services_found": 0,
        "cves_found": 0
    },
    "created_at": "2026-02-23T14:30:00Z",
    "completed_at": null,
    "duration_seconds": null
}

# ─── Graph-Daten ─────────────────────────────────────────
# GET /api/v1/scans/{scan_id}/graph
{
    "nodes": [
        {
            "id": "node_uuid",
            "label": "staging.acme-corp.de",
            "type": "subdomain",     # domain | subdomain | service | technology | cve
            "risk_level": "critical", # critical | high | medium | low | info
            "risk_score": 87.5,
            "metadata": { "ip": "185.23.45.20", "source": "crtsh" }
        }
    ],
    "edges": [
        { "source": "node_1", "target": "node_2", "type": "resolves_to" }
    ]
}

# ─── WebSocket Messages ──────────────────────────────────
# WS /ws/scans/{scan_id}
# Server → Client:
{
    "event": "module_started",    # module_started | module_completed | finding | scan_completed | error
    "module": "crtsh",
    "data": { ... },
    "timestamp": "2026-02-23T14:30:05Z"
}
```

### 3.3 Backend-Projektstruktur

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py                    # FastAPI App Entry Point
│   ├── config.py                  # Settings (Pydantic BaseSettings)
│   │
│   ├── api/
│   │   ├── __init__.py
│   │   ├── deps.py                # Dependency Injection (DB Session, etc.)
│   │   ├── v1/
│   │   │   ├── __init__.py
│   │   │   ├── router.py          # API Router aggregation
│   │   │   ├── scans.py           # Scan CRUD Endpoints
│   │   │   ├── targets.py         # Target/History Endpoints
│   │   │   └── websocket.py       # WebSocket Handler
│   │   └── schemas/
│   │       ├── __init__.py
│   │       ├── scan.py            # Pydantic Models für Scans
│   │       ├── finding.py         # Pydantic Models für Findings
│   │       └── graph.py           # Pydantic Models für Graph-Daten
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── celery_app.py          # Celery Konfiguration
│   │   ├── database.py            # SQLAlchemy Engine + Session
│   │   └── security.py            # Scope Validation, Rate Limiting
│   │
│   ├── models/                    # SQLAlchemy ORM Models
│   │   ├── __init__.py
│   │   ├── scan.py
│   │   ├── target.py
│   │   ├── subdomain.py
│   │   ├── service.py
│   │   ├── technology.py
│   │   ├── cve.py
│   │   ├── finding.py
│   │   ├── attack_path.py
│   │   └── correlation.py
│   │
│   ├── modules/                   # Recon Module Registry
│   │   ├── __init__.py
│   │   ├── base.py                # BaseReconModule (Abstract)
│   │   ├── registry.py            # Module Discovery + Registration
│   │   ├── crtsh.py               # Certificate Transparency
│   │   ├── dns_enum.py            # DNS Enumeration
│   │   ├── whois_lookup.py        # WHOIS Lookup
│   │   ├── tech_detect.py         # Technology Detection
│   │   └── cve_match.py           # CVE Matching (NVD)
│   │
│   ├── engine/                    # Post-Processing Pipeline
│   │   ├── __init__.py
│   │   ├── orchestrator.py        # Scan Orchestration (Celery Chains)
│   │   ├── correlation.py         # Correlation Engine
│   │   ├── risk_scoring.py        # Risk-Scoring Algorithmus
│   │   └── attack_paths.py        # Attack Path Inference
│   │
│   └── tasks/                     # Celery Tasks
│       ├── __init__.py
│       └── scan_tasks.py          # Task Definitions
│
├── alembic/                       # Database Migrations
│   ├── versions/
│   └── env.py
├── alembic.ini
├── requirements.txt
├── Dockerfile
└── pytest.ini
```

---

## 4. Recon-Module (Plugin-Architektur)

### 4.1 Base Module Interface

Inspiriert von SpiderFoot's event-driven Architektur, aber vereinfacht für unseren Use Case:

```python
# backend/app/modules/base.py
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any

class ModulePhase(Enum):
    """Bestimmt die Ausführungsreihenfolge."""
    DISCOVERY = 1      # Phase 1: Subdomain/Asset Discovery
    ENRICHMENT = 2     # Phase 2: Service/Tech Detection
    ANALYSIS = 3       # Phase 3: CVE Matching, Vuln Assessment

@dataclass
class ModuleResult:
    """Standardisiertes Ergebnis eines Moduls."""
    module_name: str
    success: bool
    data: dict[str, Any]       # Modul-spezifische Daten
    errors: list[str] = None
    duration_seconds: float = 0
    raw_response: Any = None   # Für Debugging

class BaseReconModule(ABC):
    """Basis-Klasse für alle Recon-Module."""
    
    name: str = "base"
    description: str = ""
    phase: ModulePhase = ModulePhase.DISCOVERY
    # Welche Daten dieses Modul braucht (Output anderer Module)
    depends_on: list[str] = []
    # Rate Limiting
    rate_limit: int = 10        # Requests pro Minute
    rate_limit_window: int = 60 # Sekunden
    # Ob ein API-Key benötigt wird
    requires_api_key: bool = False
    api_key_env_var: str = ""
    
    @abstractmethod
    async def execute(self, target: str, context: dict) -> ModuleResult:
        """
        Führt das Modul aus.
        
        Args:
            target: Die Ziel-Domain
            context: Ergebnisse vorheriger Module
                     z.B. {"subdomains": [...], "services": [...]}
        
        Returns:
            ModuleResult mit den Ergebnissen
        """
        pass
    
    def validate_config(self) -> bool:
        """Prüft ob alle Voraussetzungen erfüllt sind (API Keys etc.)."""
        if self.requires_api_key:
            import os
            return bool(os.getenv(self.api_key_env_var))
        return True
```

### 4.2 Module Registry

```python
# backend/app/modules/registry.py
from typing import Type
from .base import BaseReconModule, ModulePhase

class ModuleRegistry:
    """Verwaltet alle verfügbaren Recon-Module."""
    
    _modules: dict[str, Type[BaseReconModule]] = {}
    
    @classmethod
    def register(cls, module_class: Type[BaseReconModule]):
        """Decorator zum Registrieren eines Moduls."""
        cls._modules[module_class.name] = module_class
        return module_class
    
    @classmethod
    def get_module(cls, name: str) -> BaseReconModule:
        return cls._modules[name]()
    
    @classmethod
    def get_all(cls) -> list[BaseReconModule]:
        return [m() for m in cls._modules.values()]
    
    @classmethod
    def get_by_phase(cls, phase: ModulePhase) -> list[BaseReconModule]:
        return [m() for m in cls._modules.values() if m.phase == phase]
    
    @classmethod
    def get_execution_order(cls, selected: list[str] = None) -> list[list[BaseReconModule]]:
        """
        Gibt Module gruppiert nach Phase zurück.
        Module in der gleichen Phase können parallel laufen.
        """
        modules = cls.get_all() if not selected else [
            cls.get_module(name) for name in selected
        ]
        phases = {}
        for m in modules:
            phases.setdefault(m.phase.value, []).append(m)
        return [phases[k] for k in sorted(phases.keys())]
```

### 4.3 Modul-Implementierungen

#### Certificate Transparency (crt.sh)

```python
# backend/app/modules/crtsh.py
import httpx
from .base import BaseReconModule, ModuleResult, ModulePhase
from .registry import ModuleRegistry

@ModuleRegistry.register
class CrtshModule(BaseReconModule):
    name = "crtsh"
    description = "Subdomain Discovery via Certificate Transparency Logs"
    phase = ModulePhase.DISCOVERY
    rate_limit = 5  # crt.sh ist rate-limited
    
    CRTSH_URL = "https://crt.sh/"
    
    async def execute(self, target: str, context: dict) -> ModuleResult:
        import time
        start = time.time()
        subdomains = set()
        errors = []
        
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    self.CRTSH_URL,
                    params={"q": f"%.{target}", "output": "json"}
                )
                response.raise_for_status()
                
                for entry in response.json():
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name.endswith(f".{target}") or name == target:
                            # Wildcards entfernen
                            name = name.lstrip("*.")
                            subdomains.add(name)
        except Exception as e:
            errors.append(f"crt.sh query failed: {str(e)}")
        
        return ModuleResult(
            module_name=self.name,
            success=len(errors) == 0,
            data={
                "subdomains": [
                    {"name": s, "source": "crtsh"}
                    for s in sorted(subdomains)
                ]
            },
            errors=errors,
            duration_seconds=time.time() - start
        )
```

#### DNS Enumeration

```python
# backend/app/modules/dns_enum.py
import dns.resolver
import dns.reversename
from .base import BaseReconModule, ModuleResult, ModulePhase
from .registry import ModuleRegistry

@ModuleRegistry.register
class DnsEnumModule(BaseReconModule):
    name = "dns"
    description = "DNS Record Enumeration (A, AAAA, MX, TXT, CNAME, NS, SOA)"
    phase = ModulePhase.DISCOVERY
    
    RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA"]
    
    async def execute(self, target: str, context: dict) -> ModuleResult:
        import time, asyncio
        start = time.time()
        results = {"records": {}, "resolved_ips": {}}
        errors = []
        
        # DNS Records für Hauptdomain + alle bekannten Subdomains
        domains_to_resolve = {target}
        
        # Subdomains aus vorherigen Modulen holen
        if "subdomains" in context:
            for sub in context["subdomains"]:
                domains_to_resolve.add(sub["name"])
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10
        
        for domain in domains_to_resolve:
            results["records"][domain] = {}
            
            for rtype in self.RECORD_TYPES:
                try:
                    answers = resolver.resolve(domain, rtype)
                    records = []
                    for rdata in answers:
                        value = str(rdata)
                        records.append(value)
                        # IP-Adressen merken für Service Detection
                        if rtype in ("A", "AAAA"):
                            results["resolved_ips"][domain] = value
                    
                    if records:
                        results["records"][domain][rtype] = records
                        
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                        dns.resolver.NoNameservers, dns.exception.Timeout):
                    pass
                except Exception as e:
                    errors.append(f"DNS {rtype} for {domain}: {str(e)}")
        
        return ModuleResult(
            module_name=self.name,
            success=True,
            data=results,
            errors=errors if errors else None,
            duration_seconds=time.time() - start
        )
```

#### WHOIS Lookup

```python
# backend/app/modules/whois_lookup.py
import whois
from .base import BaseReconModule, ModuleResult, ModulePhase
from .registry import ModuleRegistry

@ModuleRegistry.register
class WhoisModule(BaseReconModule):
    name = "whois"
    description = "WHOIS Domain Registration Data"
    phase = ModulePhase.DISCOVERY
    rate_limit = 3
    
    async def execute(self, target: str, context: dict) -> ModuleResult:
        import time
        start = time.time()
        
        try:
            w = whois.whois(target)
            
            data = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "updated_date": str(w.updated_date) if w.updated_date else None,
                "name_servers": w.name_servers if w.name_servers else [],
                "org": w.org,
                "country": w.country,
                "dnssec": w.dnssec if hasattr(w, 'dnssec') else None,
            }
            
            return ModuleResult(
                module_name=self.name, success=True,
                data=data, duration_seconds=time.time() - start
            )
        except Exception as e:
            return ModuleResult(
                module_name=self.name, success=False,
                data={}, errors=[str(e)],
                duration_seconds=time.time() - start
            )
```

#### Technology Detection

```python
# backend/app/modules/tech_detect.py
import httpx
import re
from .base import BaseReconModule, ModuleResult, ModulePhase
from .registry import ModuleRegistry

@ModuleRegistry.register
class TechDetectModule(BaseReconModule):
    name = "techdetect"
    description = "Technology Fingerprinting via HTTP Headers & Response Analysis"
    phase = ModulePhase.ENRICHMENT
    depends_on = ["crtsh", "dns"]  # Braucht entdeckte Subdomains + IPs
    
    # Fingerprint-Patterns (erweiterbar)
    HEADER_SIGNATURES = {
        "Server": {
            r"nginx/([\d.]+)": ("Nginx", "web_server"),
            r"Apache/([\d.]+)": ("Apache", "web_server"),
            r"Microsoft-IIS/([\d.]+)": ("IIS", "web_server"),
        },
        "X-Powered-By": {
            r"Express": ("Express.js", "framework"),
            r"PHP/([\d.]+)": ("PHP", "language"),
            r"ASP\.NET": ("ASP.NET", "framework"),
        },
    }
    
    async def execute(self, target: str, context: dict) -> ModuleResult:
        import time
        start = time.time()
        technologies = []
        errors = []
        
        # Alle bekannten Subdomains + Hauptdomain scannen
        domains = [target]
        if "subdomains" in context:
            domains += [s["name"] for s in context["subdomains"]]
        
        async with httpx.AsyncClient(
            timeout=10, follow_redirects=True, verify=False
        ) as client:
            for domain in domains:
                for scheme in ["https", "http"]:
                    try:
                        resp = await client.get(f"{scheme}://{domain}")
                        techs = self._analyze_response(domain, resp)
                        technologies.extend(techs)
                        break  # HTTPS erfolgreich → kein HTTP nötig
                    except Exception:
                        continue
        
        return ModuleResult(
            module_name=self.name, success=True,
            data={"technologies": technologies},
            errors=errors if errors else None,
            duration_seconds=time.time() - start
        )
    
    def _analyze_response(self, domain, response):
        techs = []
        headers = response.headers
        
        for header_name, patterns in self.HEADER_SIGNATURES.items():
            value = headers.get(header_name, "")
            for pattern, (tech_name, category) in patterns.items():
                match = re.search(pattern, value, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.lastindex else "unknown"
                    techs.append({
                        "domain": domain,
                        "name": tech_name,
                        "version": version,
                        "category": category,
                        "confidence": 90,
                        "source": f"header:{header_name}"
                    })
        
        # SSL/TLS Info
        if hasattr(response, 'stream') and hasattr(response.stream, 'ssl_object'):
            ssl_info = response.stream.ssl_object
            if ssl_info:
                techs.append({
                    "domain": domain,
                    "name": "TLS",
                    "version": ssl_info.version() if hasattr(ssl_info, 'version') else "unknown",
                    "category": "security",
                    "confidence": 100,
                    "source": "ssl"
                })
        
        return techs
```

#### CVE Matching (NVD/NIST)

```python
# backend/app/modules/cve_match.py
import httpx
from .base import BaseReconModule, ModuleResult, ModulePhase
from .registry import ModuleRegistry

@ModuleRegistry.register
class CveMatchModule(BaseReconModule):
    name = "cvematch"
    description = "CVE Matching via NVD API"
    phase = ModulePhase.ANALYSIS
    depends_on = ["techdetect"]
    requires_api_key = True  # NVD API Key empfohlen (höheres Rate Limit)
    api_key_env_var = "NVD_API_KEY"
    rate_limit = 5  # Ohne API Key: 5 req/30s, mit Key: 50 req/30s
    
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    async def execute(self, target: str, context: dict) -> ModuleResult:
        import time, os
        start = time.time()
        cves = []
        errors = []
        api_key = os.getenv(self.api_key_env_var)
        
        # Technologies aus vorherigem Modul holen
        technologies = context.get("technologies", [])
        
        headers = {}
        if api_key:
            headers["apiKey"] = api_key
        
        async with httpx.AsyncClient(timeout=30) as client:
            for tech in technologies:
                if tech["version"] == "unknown":
                    continue
                
                # CPE-String konstruieren (vereinfacht)
                keyword = f"{tech['name']} {tech['version']}"
                
                try:
                    resp = await client.get(
                        self.NVD_API_URL,
                        params={"keywordSearch": keyword, "resultsPerPage": 10},
                        headers=headers
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    
                    for vuln in data.get("vulnerabilities", []):
                        cve_data = vuln.get("cve", {})
                        metrics = cve_data.get("metrics", {})
                        
                        # CVSS Score extrahieren (v3.1 bevorzugt)
                        cvss_score = None
                        cvss_vector = None
                        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                            if version in metrics:
                                cvss_data = metrics[version][0]["cvssData"]
                                cvss_score = cvss_data.get("baseScore")
                                cvss_vector = cvss_data.get("vectorString")
                                break
                        
                        cves.append({
                            "cve_id": cve_data.get("id"),
                            "description": cve_data.get("descriptions", [{}])[0].get("value", ""),
                            "cvss_score": cvss_score,
                            "cvss_vector": cvss_vector,
                            "severity": self._score_to_severity(cvss_score),
                            "affected_tech": tech["name"],
                            "affected_version": tech["version"],
                            "affected_domain": tech["domain"],
                            "published": cve_data.get("published"),
                        })
                    
                    # Rate Limiting respektieren
                    import asyncio
                    await asyncio.sleep(0.6 if not api_key else 0.1)
                    
                except Exception as e:
                    errors.append(f"NVD query for {keyword}: {str(e)}")
        
        return ModuleResult(
            module_name=self.name, success=True,
            data={"cves": cves},
            errors=errors if errors else None,
            duration_seconds=time.time() - start
        )
    
    @staticmethod
    def _score_to_severity(score):
        if not score: return "unknown"
        if score >= 9.0: return "critical"
        if score >= 7.0: return "high"
        if score >= 4.0: return "medium"
        return "low"
```

### 4.4 Neue Module hinzufügen (z.B. Shodan, Nmap)

Dank der Plugin-Architektur muss man nur die Base-Klasse implementieren und den `@ModuleRegistry.register` Decorator setzen. Beispiel für ein späteres Shodan-Modul:

```python
@ModuleRegistry.register
class ShodanModule(BaseReconModule):
    name = "shodan"
    description = "Shodan Internet-wide Scan Data"
    phase = ModulePhase.ENRICHMENT
    depends_on = ["dns"]
    requires_api_key = True
    api_key_env_var = "SHODAN_API_KEY"
    
    async def execute(self, target, context):
        # Implementation...
        pass
```

Das Modul wird automatisch erkannt und kann beim Scan aktiviert werden. Keine andere Datei muss geändert werden.

---

## 5. Datenbank-Schema (PostgreSQL)

### 5.1 Entity-Relationship Diagramm

```
┌──────────┐     ┌──────────────┐     ┌──────────────┐
│  Target   │ 1:N │    Scan      │ 1:N │  Subdomain   │
│───────────│────▶│──────────────│────▶│──────────────│
│ id (PK)   │     │ id (PK)      │     │ id (PK)      │
│ domain    │     │ target_id(FK)│     │ scan_id (FK) │
│ created_at│     │ status       │     │ name         │
│ notes     │     │ created_at   │     │ ip_address   │
└──────────┘     │ completed_at │     │ source       │
                 │ duration_s   │     │ is_alive     │
                 │ config (JSON)│     └──────┬───────┘
                 └──────────────┘            │ 1:N
                                     ┌──────▼───────┐
                                     │   Service    │
                                     │──────────────│
                                     │ id (PK)      │
                                     │ subdomain_id │
                                     │ port         │
                                     │ protocol     │
                                     │ service_name │
                                     │ version      │
                                     │ banner       │
                                     └──────┬───────┘
                                            │ 1:N
                              ┌─────────────┼─────────────┐
                              │             │             │
                      ┌───────▼──────┐ ┌───▼──────┐ ┌───▼──────────┐
                      │ Technology   │ │   CVE    │ │   Finding    │
                      │──────────────│ │──────────│ │──────────────│
                      │ id (PK)      │ │ id (PK)  │ │ id (PK)      │
                      │ service_id   │ │ cve_id   │ │ scan_id (FK) │
                      │ name         │ │ cvss     │ │ severity     │
                      │ version      │ │ severity │ │ title        │
                      │ category     │ │ desc     │ │ description  │
                      │ confidence   │ │ service_id│ │ asset        │
                      └──────────────┘ └──────────┘ │ risk_score   │
                                                    └──────────────┘
```

### 5.2 SQLAlchemy Models

```python
# backend/app/models/scan.py
from sqlalchemy import Column, String, Integer, Float, DateTime, JSON, 
                       ForeignKey, Enum as SQLEnum, Boolean, Text
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid
import enum
from datetime import datetime
from app.core.database import Base

class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    POST_PROCESSING = "post_processing"
    COMPLETED = "completed"
    FAILED = "failed"

class Target(Base):
    __tablename__ = "targets"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    notes = Column(Text, nullable=True)
    
    scans = relationship("Scan", back_populates="target")

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id = Column(UUID(as_uuid=True), ForeignKey("targets.id"), nullable=False)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.QUEUED)
    config = Column(JSON, default={})  # Modul-Auswahl, Optionen
    progress = Column(JSON, default={})
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    
    # Aggregierte Stats (für schnelle Abfragen)
    total_subdomains = Column(Integer, default=0)
    total_services = Column(Integer, default=0)
    total_cves = Column(Integer, default=0)
    overall_risk = Column(String(20), nullable=True)
    
    target = relationship("Target", back_populates="scans")
    subdomains = relationship("Subdomain", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    attack_paths = relationship("AttackPath", back_populates="scan", cascade="all, delete-orphan")
    correlations = relationship("Correlation", back_populates="scan", cascade="all, delete-orphan")

class Subdomain(Base):
    __tablename__ = "subdomains"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    name = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)  # IPv4 oder IPv6
    source = Column(String(50))  # Welches Modul hat es gefunden
    is_alive = Column(Boolean, default=False)
    dns_records = Column(JSON, default={})
    whois_data = Column(JSON, nullable=True)
    
    scan = relationship("Scan", back_populates="subdomains")
    services = relationship("Service", back_populates="subdomain", cascade="all, delete-orphan")

class Service(Base):
    __tablename__ = "services"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subdomain_id = Column(UUID(as_uuid=True), ForeignKey("subdomains.id"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")
    service_name = Column(String(100), nullable=True)
    version = Column(String(100), nullable=True)
    banner = Column(Text, nullable=True)
    
    subdomain = relationship("Subdomain", back_populates="services")
    technologies = relationship("Technology", back_populates="service", cascade="all, delete-orphan")
    cves = relationship("CVEMatch", back_populates="service", cascade="all, delete-orphan")

class Technology(Base):
    __tablename__ = "technologies"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    service_id = Column(UUID(as_uuid=True), ForeignKey("services.id"), nullable=False)
    name = Column(String(100), nullable=False)
    version = Column(String(50), nullable=True)
    category = Column(String(50))  # web_server, framework, cms, language, etc.
    confidence = Column(Integer, default=50)  # 0-100
    
    service = relationship("Service", back_populates="technologies")

class CVEMatch(Base):
    __tablename__ = "cve_matches"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    service_id = Column(UUID(as_uuid=True), ForeignKey("services.id"), nullable=False)
    cve_id = Column(String(20), nullable=False, index=True)  # CVE-2021-41773
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(100), nullable=True)
    severity = Column(String(20))
    description = Column(Text, nullable=True)
    published_date = Column(DateTime, nullable=True)
    
    service = relationship("Service", back_populates="cves")

class Finding(Base):
    __tablename__ = "findings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    asset = Column(String(255))  # z.B. "staging.acme-corp.de:443"
    risk_score = Column(Float)  # Gewichteter Score (0-100)
    cvss_score = Column(Float, nullable=True)
    evidence = Column(JSON, default={})  # Nachweise
    
    scan = relationship("Scan", back_populates="findings")

class AttackPath(Base):
    __tablename__ = "attack_paths"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    severity = Column(String(20), nullable=False)
    title = Column(String(255))
    steps = Column(JSON, default=[])  # Ordered list of steps
    affected_nodes = Column(JSON, default=[])  # Node-IDs im Graph
    
    scan = relationship("Scan", back_populates="attack_paths")

class Correlation(Base):
    __tablename__ = "correlations"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    correlation_type = Column(String(50))  # subnet, forgotten_asset, exposure, cert, tech
    severity = Column(String(20))
    message = Column(Text)
    affected_assets = Column(JSON, default=[])
    
    scan = relationship("Scan", back_populates="correlations")
```

### 5.3 Delta Detection

Für Scan-Vergleiche über Zeit nutzen wir einen dedizierten Endpoint der zwei Scans vergleicht:

```python
# backend/app/engine/delta.py
def compute_delta(scan_old, scan_new) -> dict:
    """Vergleicht zwei Scans und gibt Änderungen zurück."""
    
    old_subs = {s.name for s in scan_old.subdomains}
    new_subs = {s.name for s in scan_new.subdomains}
    
    old_services = {(s.subdomain.name, s.port, s.service_name) for s in _get_services(scan_old)}
    new_services = {(s.subdomain.name, s.port, s.service_name) for s in _get_services(scan_new)}
    
    old_cves = {c.cve_id for c in _get_cves(scan_old)}
    new_cves = {c.cve_id for c in _get_cves(scan_new)}
    
    return {
        "subdomains": {
            "added": list(new_subs - old_subs),
            "removed": list(old_subs - new_subs),
            "unchanged": list(old_subs & new_subs),
        },
        "services": {
            "added": list(new_services - old_services),
            "removed": list(old_services - new_services),
        },
        "cves": {
            "new": list(new_cves - old_cves),
            "resolved": list(old_cves - new_cves),
        },
        "risk_change": {
            "old_score": scan_old.overall_risk,
            "new_score": scan_new.overall_risk,
        }
    }
```

---

## 6. Correlation Engine

### 6.1 Architektur

Die Correlation Engine läuft als Post-Processing-Schritt nachdem alle Recon-Module fertig sind. Sie analysiert die gesammelten Daten modulweise nach vordefinierten Regeln.

```python
# backend/app/engine/correlation.py
from dataclasses import dataclass
from ipaddress import ip_network, ip_address

@dataclass
class CorrelationInsight:
    type: str        # subnet | forgotten_asset | exposure | cert | tech_inconsistency
    severity: str    # critical | high | medium | low
    message: str
    affected_assets: list[str]

class CorrelationEngine:
    """Regelbasierte Korrelations-Engine."""
    
    def analyze(self, scan_data: dict) -> list[CorrelationInsight]:
        insights = []
        insights += self._check_subnet_relationships(scan_data)
        insights += self._check_forgotten_assets(scan_data)
        insights += self._check_exposed_services(scan_data)
        insights += self._check_ssl_certificates(scan_data)
        insights += self._check_tech_inconsistencies(scan_data)
        insights += self._check_version_spread(scan_data)
        return insights
    
    def _check_subnet_relationships(self, data) -> list[CorrelationInsight]:
        """Prüft ob Assets im gleichen Subnet liegen → Lateral Movement Risiko."""
        ips = {}
        for sub in data["subdomains"]:
            if sub.get("ip_address"):
                ips[sub["name"]] = sub["ip_address"]
        
        # Gruppiere nach /24 Subnet
        subnets = {}
        for name, ip in ips.items():
            try:
                subnet = str(ip_network(f"{ip}/24", strict=False))
                subnets.setdefault(subnet, []).append(name)
            except ValueError:
                pass
        
        insights = []
        for subnet, hosts in subnets.items():
            if len(hosts) >= 3:
                insights.append(CorrelationInsight(
                    type="subnet",
                    severity="high",
                    message=f"{len(hosts)} Assets im gleichen Subnet ({subnet}) "
                            f"→ Lateral Movement bei Kompromittierung wahrscheinlich",
                    affected_assets=hosts
                ))
        return insights
    
    def _check_forgotten_assets(self, data) -> list[CorrelationInsight]:
        """Erkennt wahrscheinlich vergessene Assets (veraltete Software, Dev/Staging)."""
        insights = []
        FORGOTTEN_INDICATORS = ["staging", "dev", "test", "old", "backup", "temp", "demo"]
        
        for sub in data["subdomains"]:
            indicators = []
            name = sub["name"].lower()
            
            # Name deutet auf Dev/Staging hin
            if any(ind in name for ind in FORGOTTEN_INDICATORS):
                indicators.append(f"Verdächtiger Hostname-Pattern")
            
            # Veraltete Software
            for svc in sub.get("services", []):
                for tech in svc.get("technologies", []):
                    if tech.get("version") and self._is_outdated(tech["name"], tech["version"]):
                        indicators.append(f"Veraltete Software: {tech['name']} {tech['version']}")
            
            if len(indicators) >= 2:
                insights.append(CorrelationInsight(
                    type="forgotten_asset",
                    severity="critical",
                    message=f"{sub['name']} ist wahrscheinlich ein vergessenes Asset: "
                            f"{', '.join(indicators)}",
                    affected_assets=[sub["name"]]
                ))
        
        return insights
    
    def _check_exposed_services(self, data) -> list[CorrelationInsight]:
        """Erkennt kritisch exponierte Services (DB-Ports, Admin-Panels)."""
        CRITICAL_PORTS = {
            3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
            6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached"
        }
        insights = []
        
        for sub in data["subdomains"]:
            for svc in sub.get("services", []):
                if svc["port"] in CRITICAL_PORTS:
                    insights.append(CorrelationInsight(
                        type="exposure",
                        severity="critical",
                        message=f"{CRITICAL_PORTS[svc['port']]} (Port {svc['port']}) auf "
                                f"{sub['name']} direkt aus dem Internet erreichbar "
                                f"→ Kritische Fehlkonfiguration",
                        affected_assets=[sub["name"]]
                    ))
        
        return insights
    
    def _check_ssl_certificates(self, data) -> list[CorrelationInsight]:
        """Prüft SSL-Zertifikate auf Ablauf und Fehlkonfiguration."""
        # Implementation: Cert-Daten aus crt.sh auswerten
        return []
    
    def _check_tech_inconsistencies(self, data) -> list[CorrelationInsight]:
        """Erkennt inkonsistente Technologie-Stacks."""
        tech_types = {}
        for sub in data["subdomains"]:
            for svc in sub.get("services", []):
                for tech in svc.get("technologies", []):
                    if tech["category"] == "web_server":
                        tech_types.setdefault("web_server", set()).add(tech["name"])
        
        insights = []
        for category, techs in tech_types.items():
            if len(techs) >= 3:
                insights.append(CorrelationInsight(
                    type="tech_inconsistency",
                    severity="low",
                    message=f"{len(techs)} verschiedene {category}s im Einsatz "
                            f"({', '.join(techs)}) → Inkonsistente Infrastruktur, "
                            f"schwerer zu patchen und zu überwachen",
                    affected_assets=list(techs)
                ))
        return insights
    
    def _check_version_spread(self, data) -> list[CorrelationInsight]:
        """Erkennt verschiedene Versionen der gleichen Software."""
        return []
    
    def _is_outdated(self, name, version) -> bool:
        """Einfache Heuristik ob eine Version veraltet ist."""
        # Hier könnte man eine DB mit aktuellen Versionen pflegen
        # Für Phase 1: Einfache bekannte EOL-Versionen
        KNOWN_OUTDATED = {
            "nginx": ["1.14", "1.16", "1.18"],
            "apache": ["2.4.49", "2.4.48", "2.2"],
            "openssh": ["7.4", "7.2", "6."],
            "php": ["5.", "7.0", "7.1", "7.2", "7.3"],
        }
        name_lower = name.lower()
        for sw, versions in KNOWN_OUTDATED.items():
            if sw in name_lower:
                return any(version.startswith(v) for v in versions)
        return False
```

---

## 7. Risk-Scoring System

### 7.1 Gewichtungsfaktoren & Algorithmus

```python
# backend/app/engine/risk_scoring.py

class RiskScorer:
    """
    Berechnet einen kontextbewussten Risk-Score (0-100).
    Unterscheidet sich von reinem CVSS durch Kontextfaktoren.
    """
    
    # Gewichtung der Faktoren
    WEIGHTS = {
        "cvss_base": 0.35,           # CVSS Base Score (wenn vorhanden)
        "internet_exposure": 0.20,    # Direkt aus dem Internet erreichbar?
        "asset_type": 0.15,           # Ist es ein vergessenes/Dev Asset?
        "exploit_availability": 0.15, # Gibt es öffentliche Exploits?
        "service_criticality": 0.10,  # Wie kritisch ist der Service?
        "patch_age": 0.05,            # Wie alt ist die Schwachstelle?
    }
    
    def calculate_score(self, finding: dict) -> float:
        scores = {}
        
        # 1. CVSS Base Score normalisiert auf 0-100
        cvss = finding.get("cvss_score", 0) or 0
        scores["cvss_base"] = (cvss / 10.0) * 100
        
        # 2. Internet Exposure
        scores["internet_exposure"] = 100 if finding.get("internet_facing", True) else 30
        
        # 3. Asset Type (vergessene Assets = höheres Risiko)
        asset_name = finding.get("asset", "").lower()
        if any(x in asset_name for x in ["staging", "dev", "test", "old"]):
            scores["asset_type"] = 90  # Wahrscheinlich ungepatcht
        elif any(x in asset_name for x in ["mail", "vpn", "api"]):
            scores["asset_type"] = 70  # Business-kritisch
        else:
            scores["asset_type"] = 50
        
        # 4. Exploit Availability
        scores["exploit_availability"] = 95 if finding.get("has_public_exploit") else 40
        
        # 5. Service Criticality
        critical_services = ["database", "mail", "vpn", "admin"]
        svc_type = finding.get("service_type", "").lower()
        scores["service_criticality"] = 90 if any(s in svc_type for s in critical_services) else 50
        
        # 6. Patch Age (ältere CVEs = wahrscheinlich schon bekannt)
        # Neuere CVEs = gefährlicher weil evtl. noch nicht gepatcht
        scores["patch_age"] = 80  # Default, wird mit CVE-Datum verfeinert
        
        # Gewichteter Gesamtscore
        total = sum(
            scores.get(factor, 50) * weight
            for factor, weight in self.WEIGHTS.items()
        )
        
        return round(min(100, max(0, total)), 1)
    
    @staticmethod
    def score_to_severity(score: float) -> str:
        if score >= 80: return "critical"
        if score >= 60: return "high"
        if score >= 40: return "medium"
        if score >= 20: return "low"
        return "info"
```

---

## 8. Attack Path Inference

```python
# backend/app/engine/attack_paths.py
from dataclasses import dataclass

@dataclass
class AttackPathStep:
    description: str
    node_id: str
    technique: str  # MITRE ATT&CK Technique ID

@dataclass
class InferredAttackPath:
    title: str
    severity: str
    steps: list[AttackPathStep]
    affected_nodes: list[str]

class AttackPathEngine:
    """Regelbasierte Attack Path Inference Engine."""
    
    RULES = [
        "forgotten_asset_rce",
        "exposed_database",
        "service_chain_exploitation",
        "mail_server_compromise",
    ]
    
    def infer(self, scan_data: dict) -> list[InferredAttackPath]:
        paths = []
        for rule in self.RULES:
            method = getattr(self, f"_rule_{rule}", None)
            if method:
                result = method(scan_data)
                if result:
                    paths.extend(result if isinstance(result, list) else [result])
        
        # Sortiere nach Severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        paths.sort(key=lambda p: severity_order.get(p.severity, 99))
        return paths
    
    def _rule_forgotten_asset_rce(self, data) -> list[InferredAttackPath]:
        """Regel: Vergessenes Asset mit RCE-CVE → Kritischer Pfad."""
        paths = []
        FORGOTTEN = ["staging", "dev", "test", "old", "demo"]
        
        for sub in data["subdomains"]:
            if not any(f in sub["name"].lower() for f in FORGOTTEN):
                continue
            
            for svc in sub.get("services", []):
                rce_cves = [c for c in svc.get("cves", []) 
                           if c.get("cvss_score", 0) >= 7.0]
                
                if rce_cves:
                    cve = rce_cves[0]  # Kritischste zuerst
                    steps = [
                        AttackPathStep(
                            f"Angreifer entdeckt {sub['name']} via Certificate Transparency",
                            sub["name"], "T1596.003"
                        ),
                        AttackPathStep(
                            f"{svc.get('service_name', 'Service')} {svc.get('version', '')} "
                            f"auf Port {svc['port']} identifiziert",
                            f"{sub['name']}:{svc['port']}", "T1046"
                        ),
                        AttackPathStep(
                            f"{cve['cve_id']} (CVSS {cve['cvss_score']}) ausnutzbar",
                            cve["cve_id"], "T1190"
                        ),
                    ]
                    
                    # Prüfe ob Lateral Movement möglich ist
                    same_subnet = self._find_same_subnet(sub, data["subdomains"])
                    if same_subnet:
                        steps.append(AttackPathStep(
                            f"Lateral Movement zu {', '.join(same_subnet[:3])} "
                            f"möglich (gleiches Subnet)",
                            same_subnet[0], "T1021"
                        ))
                    
                    paths.append(InferredAttackPath(
                        title=f"RCE auf vergessem Asset {sub['name']}",
                        severity="critical",
                        steps=steps,
                        affected_nodes=[sub["name"]] + same_subnet[:3]
                    ))
        
        return paths
    
    def _rule_exposed_database(self, data) -> list[InferredAttackPath]:
        """Regel: Exponierte Datenbank → Datenexfiltration."""
        DB_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis"}
        paths = []
        
        for sub in data["subdomains"]:
            for svc in sub.get("services", []):
                if svc["port"] in DB_PORTS:
                    db_name = DB_PORTS[svc["port"]]
                    paths.append(InferredAttackPath(
                        title=f"Exponierte {db_name} auf {sub['name']}",
                        severity="critical",
                        steps=[
                            AttackPathStep(
                                f"{db_name} auf Port {svc['port']} offen",
                                f"{sub['name']}:{svc['port']}", "T1046"
                            ),
                            AttackPathStep(
                                f"Brute-Force oder Default Credentials testen",
                                f"{sub['name']}:{svc['port']}", "T1110"
                            ),
                            AttackPathStep(
                                f"Datenexfiltration bei Erfolg",
                                sub["name"], "T1041"
                            ),
                        ],
                        affected_nodes=[sub["name"]]
                    ))
        return paths
    
    def _find_same_subnet(self, target_sub, all_subs) -> list[str]:
        """Findet andere Subdomains im gleichen /24 Subnet."""
        from ipaddress import ip_network
        target_ip = target_sub.get("ip_address")
        if not target_ip: return []
        
        try:
            target_net = ip_network(f"{target_ip}/24", strict=False)
        except ValueError:
            return []
        
        same = []
        for sub in all_subs:
            if sub["name"] == target_sub["name"]: continue
            sub_ip = sub.get("ip_address")
            if sub_ip:
                try:
                    from ipaddress import ip_address as ip_addr
                    if ip_addr(sub_ip) in target_net:
                        same.append(sub["name"])
                except ValueError:
                    pass
        return same
```

---

## 9. Frontend-Architektur (React)

### 9.1 Empfehlung: Cytoscape.js

Nach der Recherche ist die klare Empfehlung **Cytoscape.js** statt D3.js:

- Cytoscape.js ist speziell für Netzwerk-/Graph-Visualisierung gebaut, D3.js ist ein allgemeines Daten-Visualisierungs-Toolkit
- Built-in Graph-Algorithmen (Shortest Path, Centrality) die wir für Attack Path Highlighting brauchen
- Eingebaute Interaktionen (Zoom, Pan, Node Selection) out-of-the-box
- Force-Directed Layouts (CoSE, Cola) automatisch – keine manuelle Positionierung nötig
- Bessere Performance bei mittleren Graphen (100-1000 Nodes)
- Einfachere Integration in React via `react-cytoscapejs`

### 9.2 Komponenten-Hierarchie

```
App
├── Layout
│   ├── Header (Logo, Scan-Input, Settings)
│   └── MainContent
│       ├── ScanView (aktiver Scan)
│       │   ├── ScanProgress (während Scan läuft)
│       │   ├── StatsBar (Übersichts-Zahlen)
│       │   ├── TabNavigation
│       │   │   ├── GraphTab
│       │   │   │   ├── CytoscapeGraph (Hauptgraph)
│       │   │   │   ├── GraphControls (Zoom, Filter, Layout)
│       │   │   │   └── NodeDetailPanel (Sidebar)
│       │   │   ├── FindingsTab
│       │   │   │   ├── FindingsFilter
│       │   │   │   └── FindingsTable
│       │   │   ├── AttackPathsTab
│       │   │   │   └── AttackPathCard (expandierbar)
│       │   │   └── InsightsTab
│       │   │       └── CorrelationCard
│       │   └── ScanFooter (Metadaten, Export)
│       │
│       ├── HistoryView (vergangene Scans)
│       │   ├── ScanList
│       │   └── DeltaComparison
│       │
│       └── EmptyState (kein Scan aktiv)
│
└── Providers
    ├── ScanContext (Zustand aktiver Scan)
    └── WebSocketProvider (Live-Updates)
```

### 9.3 State Management

Für ein Solo-Projekt ist **React Context + useReducer** ausreichend. Kein Redux/Zustand Overhead nötig:

```
ScanContext:
├── currentScan: { id, status, target, progress }
├── scanResults: { nodes, edges, findings, paths, correlations }
├── selectedNode: string | null
├── selectedPath: string | null  
├── filters: { severity, nodeType }
└── wsConnection: WebSocket instance
```

### 9.4 WebSocket für Live-Updates

```javascript
// frontend/src/hooks/useWebSocket.js
const useWebSocket = (scanId) => {
  const [messages, setMessages] = useState([]);
  
  useEffect(() => {
    if (!scanId) return;
    const ws = new WebSocket(`ws://localhost:8000/ws/scans/${scanId}`);
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setMessages(prev => [...prev, data]);
      
      // Dispatch to ScanContext based on event type
      switch(data.event) {
        case 'module_completed':
          // Update progress + partial results
          break;
        case 'finding':
          // Neues Finding live hinzufügen
          break;
        case 'scan_completed':
          // Lade finale Ergebnisse
          break;
      }
    };
    
    return () => ws.close();
  }, [scanId]);
  
  return messages;
};
```

---

## 10. Docker & Deployment

### 10.1 Docker Compose

```yaml
# docker-compose.yml
version: "3.9"

services:
  # ─── Frontend ────────────────────────────────
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    volumes:
      - ./frontend/src:/app/src  # Hot Reload in Dev
    environment:
      - REACT_APP_API_URL=http://localhost:8000
      - REACT_APP_WS_URL=ws://localhost:8000
    depends_on:
      - backend

  # ─── Backend (FastAPI) ───────────────────────
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    ports:
      - "8000:8000"
    volumes:
      - ./backend/app:/app/app  # Hot Reload in Dev
    environment:
      - DATABASE_URL=postgresql://reconscope:reconscope@postgres:5432/reconscope
      - REDIS_URL=redis://redis:6379/0
      - NVD_API_KEY=${NVD_API_KEY:-}
      - SHODAN_API_KEY=${SHODAN_API_KEY:-}
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

  # ─── Celery Worker ──────────────────────────
  worker:
    build:
      context: ./backend
      dockerfile: Dockerfile
    volumes:
      - ./backend/app:/app/app
    environment:
      - DATABASE_URL=postgresql://reconscope:reconscope@postgres:5432/reconscope
      - REDIS_URL=redis://redis:6379/0
      - NVD_API_KEY=${NVD_API_KEY:-}
    depends_on:
      - backend
      - redis
    command: celery -A app.core.celery_app.celery worker --loglevel=info --concurrency=4

  # ─── Celery Flower (Monitoring) ──────────────
  flower:
    build:
      context: ./backend
      dockerfile: Dockerfile
    ports:
      - "5555:5555"
    environment:
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - worker
    command: celery -A app.core.celery_app.celery flower --port=5555

  # ─── PostgreSQL ──────────────────────────────
  postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=reconscope
      - POSTGRES_PASSWORD=reconscope
      - POSTGRES_DB=reconscope
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U reconscope"]
      interval: 5s
      timeout: 5s
      retries: 5

  # ─── Redis ───────────────────────────────────
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    command: ["redis-server", "--appendonly", "yes"]
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  postgres_data:
  redis_data:
```

### 10.2 Lokal vs. Server

| Aspekt | Lokal (Mac) | Server |
|--------|-------------|--------|
| Start | `docker-compose up` | `docker-compose -f docker-compose.prod.yml up -d` |
| Frontend | localhost:3000 | domain:443 (Nginx Reverse Proxy) |
| DB Persist | Docker Volume | Docker Volume + Backup Cron |
| SSL | Nicht nötig | Let's Encrypt via Certbot |
| Resources | Docker Desktop Limits beachten | 4GB+ RAM empfohlen |

---

## 11. Projekt-Struktur (Monorepo)

```
reconscope/
├── README.md
├── docker-compose.yml
├── docker-compose.prod.yml
├── .env.example                    # Template für API Keys
├── .gitignore
│
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── alembic.ini
│   ├── alembic/
│   │   ├── env.py
│   │   └── versions/
│   └── app/
│       ├── (siehe 3.3 Backend-Projektstruktur)
│
├── frontend/
│   ├── Dockerfile
│   ├── package.json
│   ├── vite.config.js
│   ├── public/
│   └── src/
│       ├── App.jsx
│       ├── main.jsx
│       ├── components/
│       │   ├── layout/
│       │   ├── scan/
│       │   ├── graph/
│       │   ├── findings/
│       │   ├── attack-paths/
│       │   └── common/
│       ├── hooks/
│       │   ├── useWebSocket.js
│       │   └── useScan.js
│       ├── context/
│       │   └── ScanContext.jsx
│       ├── api/
│       │   └── client.js
│       └── utils/
│
└── docs/
    ├── architecture.md             # Dieses Dokument
    ├── api-reference.md
    └── module-development.md
```

---

## 12. Security & Legal

### 12.1 Scope Management

Jeder Scan erfordert die explizite Bestätigung des Users:

```python
# Im Frontend: Checkbox "Ich bestätige, dass ich berechtigt bin, diese Domain zu scannen"
# Im Backend: scope_confirmed muss True sein, sonst 403 Forbidden

@router.post("/scans/")
async def create_scan(scan_request: ScanCreate):
    if not scan_request.scope_confirmed:
        raise HTTPException(
            status_code=403,
            detail="Scope-Bestätigung erforderlich. Bestätige, dass du "
                   "berechtigt bist, diese Domain zu scannen."
        )
```

### 12.2 API Key Management

Alle API Keys werden via `.env` Datei konfiguriert, niemals im Code:

```bash
# .env.example
NVD_API_KEY=           # Empfohlen: https://nvd.nist.gov/developers/request-an-api-key
SHODAN_API_KEY=        # Optional: https://account.shodan.io/
SECRET_KEY=            # Für Session/JWT (generieren mit: openssl rand -hex 32)
```

---

## 13. Roadmap

### Phase 1: Passive Recon MVP (aktuell)
- [x] Architekturplan
- [ ] Projekt-Setup (Docker, DB, FastAPI Skeleton)
- [ ] Module: crt.sh, DNS, WHOIS, Tech Detection, CVE Match
- [ ] Correlation Engine (Basis-Regeln)
- [ ] Risk-Scoring
- [ ] Attack Path Inference
- [ ] Frontend: Graph, Findings, Attack Paths, Insights
- [ ] WebSocket Live-Updates
- [ ] Delta Detection

### Phase 2: Active Scanning
- [ ] Nmap Integration (Port Scanning)
- [ ] Service Banner Grabbing
- [ ] SSL/TLS Analyse (Cipher Suites, Cert-Details)
- [ ] Erweiterte Tech Detection (HTTP Response Body Analyse)

### Phase 3: AI-Features
- [ ] LLM-basierte Executive Summaries
- [ ] Natürliche Sprach-Queries ("Zeig mir alle Server mit veralteten SSL-Zertifikaten")
- [ ] Automatische Remediation-Vorschläge

### Phase 4: Team & Reporting
- [ ] Multi-User Support
- [ ] PDF Report Generation
- [ ] Scheduled Scans (Cron)
- [ ] Slack/Teams Notifications bei kritischen Findings
- [ ] Integration mit EagleEyes TI-Dashboard

---

## 14. Verwendete Libraries (Python)

| Library | Zweck | Version |
|---------|-------|---------|
| `fastapi` | Web-Framework | ≥0.100 |
| `uvicorn` | ASGI Server | ≥0.25 |
| `celery` | Task Queue | ≥5.3 |
| `redis` | Redis Client | ≥5.0 |
| `sqlalchemy` | ORM | ≥2.0 |
| `alembic` | DB Migrations | ≥1.12 |
| `asyncpg` | Async PostgreSQL Driver | ≥0.29 |
| `httpx` | Async HTTP Client | ≥0.25 |
| `dnspython` | DNS Resolution | ≥2.4 |
| `python-whois` | WHOIS Lookups | ≥0.9 |
| `pydantic` | Data Validation | ≥2.0 |
| `websockets` | WebSocket Support | ≥12.0 |
| `pycrtsh` | crt.sh API Client | ≥0.3 |

---

*Erstellt am 23.02.2026 | ReconScope v1.0 Architekturplan*
*Bereit für Umsetzung in Claude Code*
