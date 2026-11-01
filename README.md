# CyberGuard AI

A **simulated Security Operations Center (SOC)** built for the academic project *"Threat Detection & Enhanced Cybersecurity Using Agentic AI"*. It ingests synthetic security events, classifies them, passes each one through a five-agent workflow, opens incidents, records simulated responses, and shows everything on a real-time dashboard.

> **Safe by design:** `SAFE_MODE` is always on. No real firewall, account or system change is ever made, and no real network scanning is performed. This is a learning and demonstration project, not a production security tool.

## Features

- **Five-agent pipeline:** Monitoring → Detection → Analysis → Decision → Response, with an execution timeline for every event
- **Event classification:** labels activity such as Normal, DoS, Probe, Brute Force, U2R and R2L, with a confidence value, risk score (0-100) and severity
- **Live dashboard:** KPIs, threat timeline and threat distribution, updated in real time over WebSockets
- **Incident management:** threats with risk of 51 or more open incidents that analysts can update
- **Event simulator:** start, pause, resume and stop a stream of synthetic events
- **Analyze Event panel:** submit a custom event and get `THREAT PRESENT` or `NO THREAT` with an explanation
- **URL Checks:** passive checks on a public URL (DNS, TLS, headers, redirects) with protection against private and local network targets
- **Dataset management:** upload NSL-KDD-style CSV/TXT files and get a profile (features, classes, missing values, duplicates)
- **Reports:** summary view with CSV and PDF export
- **Audit log** of security-relevant actions
- **Authentication and roles:** JWT session cookie, `ADMIN` / `ANALYST` / `VIEWER` roles, and per-user data isolation
- **Automated tests:** pytest suite covering auth, roles, incidents, agents, simulator and account isolation

## How classification works (honest note)

Detection in this version is **rule-based**: events are matched against an event library and thresholds (failed attempts, traffic volume) to assign a class, confidence and risk. The agents apply deterministic policy rules. The *Models* page lists Random Forest, SVM and MLP entries with metrics computed on a small labeled demonstration set; **these models are not trained on real data**, and the numbers are not production or NSL-KDD benchmarks.

Planned next step: train real models on NSL-KDD using the dataset upload feature and replace the rule-based baseline.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, FastAPI, Motor (async MongoDB), Pydantic v2, JWT |
| Frontend | React 19, TypeScript, Vite, Tailwind CSS, shadcn/ui, Recharts |
| Database | MongoDB |
| Testing | pytest |

## Project Structure

```
backend/
  server.py          FastAPI app and startup
  routers/           auth and SOC API routes
  services/          pipeline, classifier, URL checks, reports
  models/            Pydantic models
  tests/             pytest suite
frontend/            React + TypeScript app
docs/SPEC.md         Detailed specification
```

## Getting Started

**Prerequisites:** Python 3.10+, Node.js 18+, MongoDB running locally.

### 1. Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS / Linux
pip install -r requirements.txt
cp .env.example .env           # then set JWT_SECRET
uvicorn server:app --port 8001 --reload
```

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:3000 (the dev server proxies `/api` to the backend on port 8001).

### Default development account

A development admin is created on first start: username `admin`, password `admin123`. **Change it before sharing or deploying this anywhere.** New users who sign up get a read-only `VIEWER` account.

## Author

**Vilas N** — Information Science Engineering student, Malnad College of Engineering, Hassan.
GitHub: [vilasvilas1052005-png](https://github.com/vilasvilas1052005-png)
