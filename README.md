# ReconScope — Attack Surface Mapper

ReconScope is an automated attack surface mapping tool that discovers, correlates, and visualizes an organization's external attack surface. It features an intelligent correlation engine, context-aware risk scoring, attack path inference, and an interactive network graph.

## Features

- **9 Passive Modules** — Certificate Transparency, Threat Intelligence, DNS Enumeration, WHOIS, Technology Detection, CVE Matching, and more
- **5 Active Modules** — Port Scanning (nmap), Subdomain Bruteforce, Directory Discovery, SSL/TLS Audit, Security Header Analysis
- **Correlation Engine** — Cross-module pattern detection and insight generation
- **Risk Scoring** — Context-aware severity classification based on CVSS, exposure, and asset criticality
- **Attack Path Inference** — Automated identification of multi-step attack chains
- **Interactive Graph** — Cytoscape-based network visualization of the entire attack surface
- **Real-time Updates** — WebSocket-driven live progress during scans
- **Scan Scheduling** — Cron-based recurring scans with delta comparison
- **Export** — JSON, CSV, and PDF report generation

## Architecture

| Service    | Technology                     | Port  |
|------------|--------------------------------|-------|
| Frontend   | React, Vite, TailwindCSS      | 3000  |
| Backend    | FastAPI, SQLAlchemy, Pydantic  | 8000  |
| Worker     | Celery                         | —     |
| Flower     | Celery Flower (monitoring)     | 5555  |
| Database   | PostgreSQL                     | 5432  |
| Cache      | Redis                          | 6379  |

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/) installed
- Git

## Quickstart

### 1. Clone the repository

```bash
git clone https://github.com/BeeHakein/ReconScope.git
cd ReconScope
```

### 2. Create your environment file

```bash
cp .env.example .env
```

Edit `.env` if you need to change any default values (database credentials, Redis URL, etc.). The defaults work out of the box for local development.

### 3. Start all services

```bash
docker compose up --build
```

This builds and starts all 6 services. First build takes a few minutes.

### 4. Open the app

| Service        | URL                                  |
|----------------|--------------------------------------|
| Frontend (UI)  | [http://localhost:3000](http://localhost:3000) |
| API Docs       | [http://localhost:8000/docs](http://localhost:8000/docs) |
| Flower (Tasks) | [http://localhost:5555](http://localhost:5555) |

## Usage

### Starting a Scan

1. Open [http://localhost:3000](http://localhost:3000)
2. Enter a target domain (e.g. `example.com`)
3. Select **Passive** or **Active** scan mode
4. Choose the modules you want to run
5. Click **Start Scan**

### Scan Modes

**Passive (default)** — Uses only public OSINT sources. No traffic is sent directly to the target infrastructure. Safe to run without explicit authorization.

**Active** — Sends requests directly to the target (port scans, path probing, TLS connections). A warning banner is displayed. **Only use with explicit authorization.**

| Active Module         | What it does                                      |
|-----------------------|---------------------------------------------------|
| Subdomain Bruteforce  | DNS A-record resolution of ~500 common prefixes   |
| Port Scanner (nmap)   | Top 100 TCP ports with service version detection   |
| Directory Discovery   | HTTP probing of ~200 common sensitive paths        |
| SSL/TLS Audit         | Certificate validity, expiry, protocol checks      |
| Security Headers      | Checks for 7 critical HTTP security headers        |

### Viewing Results

Once a scan completes, you can explore:

- **Graph** — Interactive network graph showing domains, subdomains, services, technologies, and CVEs
- **Findings** — Prioritized list of all findings with severity, filterable
- **Attack Paths** — Inferred multi-step attack chains
- **Insights** — Cross-module correlation patterns

### Scan History

The left sidebar shows all previous scans. Click any scan to view its results. The sidebar is collapsible via the arrow button.

### Scheduling

At the bottom of the sidebar, click **+ New** under Schedules to create recurring scans with cron expressions (daily, weekly, monthly, or custom).

### Export

Completed scans can be exported as JSON, CSV, or PDF via the export menu in the results view.

## Development

### Running without Docker

**Backend:**

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Requires PostgreSQL and Redis running locally (update `.env` accordingly).

**Frontend:**

```bash
cd frontend
npm install
npm run dev
```

### Running Tests

**Backend tests:**

```bash
cd backend
pytest --cov=app tests/
```

**Frontend tests:**

```bash
cd frontend
npx vitest run
```

### Project Structure

```
ReconScope/
├── backend/
│   ├── app/
│   │   ├── api/            # FastAPI routes and schemas
│   │   ├── core/           # Database, Celery, security, logging
│   │   ├── engine/         # Correlation, risk scoring, attack paths
│   │   ├── models/         # SQLAlchemy ORM models
│   │   ├── modules/        # All recon modules (passive + active)
│   │   └── tasks/          # Celery task definitions
│   └── tests/
├── frontend/
│   └── src/
│       ├── api/            # Axios HTTP client
│       ├── components/     # React components
│       ├── constants/      # Config and color constants
│       ├── context/        # React context (global state)
│       └── hooks/          # Custom React hooks
├── docker-compose.yml
└── .env.example
```

## Stopping the App

```bash
docker compose down
```

To also remove the database volume (deletes all scan data):

```bash
docker compose down -v
```

## License

This project is for educational and authorized security testing purposes only.
