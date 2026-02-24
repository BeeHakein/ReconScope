# ReconScope – Attack Surface Mapper

## Beschreibung
ReconScope ist ein Attack Surface Mapping Tool, das die externe Angriffsfläche einer Organisation automatisiert analysiert, korreliert und visuell darstellt. Es bietet eine intelligente Correlation Engine, kontextbewusstes Risk-Scoring und Attack Path Inference – visualisiert über einen interaktiven Netzwerk-Graphen.

## Architektur
Siehe `docs/architecture.md` für den vollständigen Architekturplan.

## Agent-Regeln
Siehe `.cursor/rules/` für spezialisierte Agent-Regeln:
- `global.mdc` – Globale Projektregeln
- `backend-agent.mdc` – Backend Engineer
- `frontend-agent.mdc` – Frontend Engineer
- `devops-agent.mdc` – DevOps / Infrastructure
- `security-agent.mdc` – Security & Compliance
- `planner-agent.mdc` – Project Planner & Architect
- `test-agent.mdc` – Quality Assurance & Testing

## Quickstart
```bash
docker-compose up --build
```

## Endpoints
| Service   | URL                          |
|-----------|------------------------------|
| Frontend  | http://localhost:3000         |
| Backend   | http://localhost:8000         |
| API Docs  | http://localhost:8000/docs    |
| Flower    | http://localhost:5555         |

## Tests
```bash
# Backend
cd backend && pytest --cov=app tests/

# Frontend
cd frontend && npx vitest run
```

## Coding Conventions
- **Clean Code:** SRP, DRY, KISS, meaningful names, kleine Funktionen, Docstrings
- **Secure Coding:** Input Validation, keine Secrets, parameterized queries, CORS, Rate Limiting
- **Test-Driven:** JEDE Funktion hat Tests. Code OHNE Tests ist NICHT fertig.

## Ordnerstruktur
```
reconscope/
├── CLAUDE.md                           # Dieses Dokument
├── docker-compose.yml                  # 6 Services (Frontend, Backend, Worker, Flower, PostgreSQL, Redis)
├── docker-compose.test.yml             # Isolierte Test-Umgebung
├── .env.example                        # Template für Environment Variables
├── .gitignore
│
├── docs/
│   └── architecture.md                 # Vollständiger Architekturplan
│
├── .cursor/rules/                      # Agent-Regeln
│   ├── global.mdc
│   ├── backend-agent.mdc
│   ├── frontend-agent.mdc
│   ├── devops-agent.mdc
│   ├── security-agent.mdc
│   ├── planner-agent.mdc
│   └── test-agent.mdc
│
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── pytest.ini
│   ├── alembic.ini
│   ├── alembic/
│   │   ├── env.py
│   │   ├── script.py.mako
│   │   └── versions/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                     # FastAPI App Entry Point
│   │   ├── config.py                   # Settings (Pydantic BaseSettings)
│   │   ├── core/
│   │   │   ├── __init__.py
│   │   │   ├── database.py             # SQLAlchemy Engine + Session
│   │   │   ├── celery_app.py           # Celery Konfiguration
│   │   │   ├── security.py             # Rate Limiter, Input Sanitization
│   │   │   └── logging.py              # Strukturiertes Logging
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── deps.py                 # Dependency Injection
│   │   │   ├── schemas/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── scan.py
│   │   │   │   ├── finding.py
│   │   │   │   └── graph.py
│   │   │   └── v1/
│   │   │       ├── __init__.py
│   │   │       ├── router.py
│   │   │       ├── scans.py
│   │   │       ├── targets.py
│   │   │       └── websocket.py
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── scan.py
│   │   │   ├── subdomain.py
│   │   │   ├── service.py
│   │   │   ├── technology.py
│   │   │   ├── cve.py
│   │   │   ├── finding.py
│   │   │   ├── attack_path.py
│   │   │   └── correlation.py
│   │   ├── modules/
│   │   │   ├── __init__.py
│   │   │   ├── base.py
│   │   │   ├── registry.py
│   │   │   ├── crtsh.py
│   │   │   ├── dns_enum.py
│   │   │   ├── whois_lookup.py
│   │   │   ├── tech_detect.py
│   │   │   └── cve_match.py
│   │   ├── engine/
│   │   │   ├── __init__.py
│   │   │   ├── orchestrator.py
│   │   │   ├── correlation.py
│   │   │   ├── risk_scoring.py
│   │   │   ├── attack_paths.py
│   │   │   └── delta.py
│   │   └── tasks/
│   │       ├── __init__.py
│   │       └── scan_tasks.py
│   └── tests/
│       ├── __init__.py
│       ├── conftest.py
│       ├── models/
│       │   ├── __init__.py
│       │   ├── test_scan.py
│       │   └── test_subdomain.py
│       ├── api/
│       │   ├── __init__.py
│       │   ├── test_scans.py
│       │   └── test_targets.py
│       ├── modules/
│       │   ├── __init__.py
│       │   ├── test_crtsh.py
│       │   ├── test_dns_enum.py
│       │   ├── test_whois.py
│       │   ├── test_tech_detect.py
│       │   ├── test_cve_match.py
│       │   └── test_registry.py
│       ├── engine/
│       │   ├── __init__.py
│       │   ├── test_correlation.py
│       │   ├── test_risk_scoring.py
│       │   ├── test_attack_paths.py
│       │   └── test_delta.py
│       └── tasks/
│           ├── __init__.py
│           └── test_scan_tasks.py
│
└── frontend/
    ├── Dockerfile
    ├── package.json
    ├── vite.config.js
    ├── vitest.config.js
    ├── tailwind.config.js
    ├── postcss.config.js
    ├── index.html
    ├── public/
    └── src/
        ├── main.jsx
        ├── App.jsx
        ├── index.css
        ├── constants/
        │   ├── colors.js
        │   └── config.js
        ├── api/
        │   └── client.js
        ├── context/
        │   └── ScanContext.jsx
        ├── hooks/
        │   ├── useWebSocket.js
        │   └── useScan.js
        ├── components/
        │   ├── layout/
        │   │   ├── Header.jsx
        │   │   └── Layout.jsx
        │   ├── scan/
        │   │   ├── ScanInput.jsx
        │   │   ├── ScanProgress.jsx
        │   │   └── StatsBar.jsx
        │   ├── graph/
        │   │   ├── AttackGraph.jsx
        │   │   ├── GraphControls.jsx
        │   │   └── NodeDetailPanel.jsx
        │   ├── findings/
        │   │   ├── FindingsTable.jsx
        │   │   └── FindingsFilter.jsx
        │   ├── attack-paths/
        │   │   └── AttackPathCard.jsx
        │   ├── insights/
        │   │   └── CorrelationCard.jsx
        │   └── common/
        │       ├── TabNavigation.jsx
        │       ├── SeverityBadge.jsx
        │       └── LoadingSpinner.jsx
        └── __tests__/
            ├── setup.js
            ├── components/
            │   ├── ScanInput.test.jsx
            │   ├── StatsBar.test.jsx
            │   ├── FindingsTable.test.jsx
            │   ├── SeverityBadge.test.jsx
            │   └── AttackGraph.test.jsx
            ├── hooks/
            │   ├── useWebSocket.test.js
            │   └── useScan.test.js
            └── context/
                └── ScanContext.test.jsx
```
