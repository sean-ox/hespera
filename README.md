<div align="center">

# 🎯 Hespera

**Continuous Attack Surface Monitoring & Bug Bounty Automation Platform**

[![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)](https://docker.com)
[![Security](https://img.shields.io/badge/Security-Hardened-green?logo=shield)](#security)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

*Automate subdomain enumeration, URL collection, vulnerability scanning, and real-time Telegram alerts — all from a single `docker compose up`.*

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Telegram Commands](#-telegram-commands)
- [API Reference](#-api-reference)
- [Security](#-security)
- [Project Feedback](#-project-feedback)
- [Troubleshooting](#-troubleshooting)

---

## 🔍 Overview

Hespera is a self-hosted platform that continuously monitors your bug bounty attack surface. It chains together best-in-class open-source recon tools into an automated pipeline and delivers findings directly to your Telegram.

### What it does

| Stage | Tools | Output |
|-------|-------|--------|
| Subdomain Enumeration | `subfinder`, `assetfinder` | Live subdomain list |
| Host Probing | `httpx` | Alive hosts + status codes |
| URL Collection | `gau`, `waybackurls`, `katana` | Historical + crawled URLs |
| URL Filtering | `uro`, `unfurl` | Deduplicated, classified URLs |
| Vulnerability Scanning | `nuclei` | CVEs, misconfigs, exposures |
| XSS Detection | `dalfox` | Reflected/DOM XSS |
| Subdomain Takeover | `subzy` | Dangling CNAMEs |
| JS Analysis | `jsluice`, `trufflehog` | Exposed endpoints, secrets |
| Notifications | Telegram Bot | Real-time alerts |

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────┐
│                 Telegram Bot (Admin)                │
│  /add  /remove  /recon  /list  /status  /report     │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│           Orchestrator  :8000  (FastAPI)            │
│    GET /health  GET /metrics  GET /queue/length     │
│    APScheduler — periodic recon every N minutes     │
└──────────────────────┬──────────────────────────────┘
                       │
              ┌────────▼────────┐
              │   Redis Queue   │  ← Internal network only
              └──┬──┬──┬──┬──┬─┘
                 │  │  │  │  │
       ┌─────────┘  │  │  │  └──────────────┐
       │    ┌───────┘  │  └──────────┐       │
       ▼    ▼          ▼             ▼       ▼
   recon  filter    nuclei      xss  takeover js
   worker  worker   worker    worker  worker  worker
                                              │
                              ┌───────────────┘
                              ▼
                    ┌──────────────────┐
                    │   notify_worker  │ → Telegram
                    └──────────────────┘
                              │
              ┌───────────────▼──────────────┐
              │  PostgreSQL  (internal only) │
              │  targets | scans | findings  │
              └──────────────────────────────┘
```

### Worker Roles

| Worker | Queue | Responsibility |
|--------|-------|----------------|
| `recon_worker` | `queue:recon` | Subdomain enum → host probe → URL collection |
| `filter_worker` | `queue:raw_urls` | Dedup, classify, score URLs → route to queues |
| `nuclei_worker` | `queue:nuclei` | Vulnerability scanning with nuclei templates |
| `xss_worker` | `queue:xss_candidates` | XSS detection with dalfox |
| `takeover_worker` | `queue:takeover` | Subdomain takeover detection with subzy |
| `js_worker` | `queue:js_endpoints` | JS endpoint extraction + secret scanning |
| `notify_worker` | `queue:notify` | Send Telegram alerts |

---

## 📦 Prerequisites

| Requirement | Minimum Version | Notes |
|-------------|----------------|-------|
| Docker | 24.x | [Install](https://docs.docker.com/engine/install/) |
| Docker Compose | 2.x | Bundled with Docker Desktop |
| Telegram Bot Token | — | Create via [@BotFather](https://t.me/BotFather) |
| Telegram Chat ID | — | Send `/start` to [@userinfobot](https://t.me/userinfobot) |

> **No local Go or Python installation required** — everything runs inside Docker.

---

## 🚀 Installation

### Step 1 — Clone the repository

```bash
git clone https://github.com/sean-ox/hespera.git
cd hespera
```

### Step 2 — Create your environment file

```bash
cp .env.example .env
```

Open `.env` and fill in every value (see [Configuration](#-configuration)):

```bash
nano .env   # or vim .env / code .env
```

### Step 3 — Generate strong secrets

```bash
# PostgreSQL password
python3 -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_urlsafe(32))"

# Redis password
python3 -c "import secrets; print('REDIS_PASSWORD=' + secrets.token_urlsafe(32))"

# API secret key
python3 -c "import secrets; print('API_SECRET_KEY=' + secrets.token_urlsafe(32))"
```

Copy each output line into your `.env`.

### Step 4 — Create your scope file

```bash
# scope.txt defines which domains are in-scope for scanning
cat > scope.txt << 'EOF'
# One pattern per line. Comments start with #.
# Supported patterns:
#   *.example.com    — all subdomains of example.com
#   example.com      — exact match only

*.yourtarget.com
yourtarget.com
EOF
```

> ⚠️ **Do not commit `scope.txt` to git.** It is already in `.gitignore`.

### Step 5 — Build and start

```bash
# Build images (takes 5-10 minutes on first run — downloads Go tools)
docker compose build --no-cache

# Start all services in the background
docker compose up -d

# Verify everything is running
docker compose ps
```

### Step 6 — Verify installation

```bash
# Health check
curl http://localhost:8000/health
# Expected: {"status":"healthy","version":"2.0.0"}

# Check worker logs
docker compose logs recon_worker --tail=20
docker compose logs notify_worker --tail=20

# Verify Go tools are installed
docker compose exec recon_worker subfinder -version
docker compose exec xss_worker   dalfox version
docker compose exec js_worker    trufflehog --version
```

---

## ⚙️ Configuration

All configuration is done via `.env`. **Never commit this file.**

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `TELEGRAM_BOT_TOKEN` | Bot token from @BotFather | `123456789:AAFxxxx...` |
| `ADMIN_CHAT_ID` | Your Telegram user/chat ID | `987654321` |
| `POSTGRES_PASSWORD` | PostgreSQL password | *(generated)* |
| `DATABASE_URL` | Full PostgreSQL connection URL | *(auto-built from above)* |
| `REDIS_PASSWORD` | Redis password | *(generated)* |
| `REDIS_URL` | Full Redis connection URL | *(auto-built from above)* |
| `API_SECRET_KEY` | API key for `/metrics` and `/queue/length` | *(generated)* |

### Optional Tuning Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_CONCURRENT_RECON` | `2` | Max parallel recon jobs (1–10) |
| `RECON_TIMEOUT_SECONDS` | `1800` | Kill recon after this many seconds |
| `SCHEDULE_INTERVAL_MINUTES` | `360` | How often to auto-recon all targets |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `JSON_LOGS` | `true` | `true` for JSON (production), `false` for console |
| `POSTGRES_USER` | `bugbounty` | Database username |
| `POSTGRES_DB` | `bugbounty` | Database name |

### Full `.env` Template

```dotenv
# Telegram
TELEGRAM_BOT_TOKEN=<your_bot_token>
ADMIN_CHAT_ID=<your_chat_id>

# Database
POSTGRES_USER=bugbounty
POSTGRES_PASSWORD=<generated_strong_password>
POSTGRES_DB=bugbounty
DATABASE_URL=postgresql+asyncpg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}

# Redis
REDIS_PASSWORD=<generated_strong_password>
REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0

# API Authentication
API_SECRET_KEY=<generated_strong_key>

# Tuning (optional)
MAX_CONCURRENT_RECON=2
RECON_TIMEOUT_SECONDS=1800
SCHEDULE_INTERVAL_MINUTES=360
LOG_LEVEL=INFO
JSON_LOGS=true
```

---

## 📖 Usage

### Adding your first target

```
/add yourtarget.com
```

The bot will confirm the target is added with `safe` mode (rate-limited scanning).

### Triggering a manual scan

```
/recon yourtarget.com
```

Or with a specific mode:

```
/recon yourtarget.com aggressive
```

**Scan modes:**

| Mode | Rate Limit | Katana Crawl | Nuclei |
|------|-----------|--------------|--------|
| `safe` | Low | No | Yes (low rate) |
| `aggressive` | High | Yes (depth 2) | Yes (higher rate) |

### Viewing results

```
/report yourtarget.com
```

Output example:
```
📄 Recon Report: yourtarget.com
🕐 Scan completed: 2025-01-15 14:32:01
⏱ Duration: 847 seconds

📊 Statistics
• Subdomains found: 143
• URLs discovered: 8,291
• Vulnerabilities: 4

⚠️ Vulnerabilities by Severity
• Critical: 0
• High: 1
• Medium: 3
• Low: 0
• Info: 0

🔥 Critical/High Findings (first 5)
• xss-reflected: https://api.yourtarget.com/search?q=...
```

### Checking system status

```
/status
```

### Changing scan mode

```
/set_mode yourtarget.com aggressive
```

### Removing a target

```
/remove yourtarget.com
```

---

## 🤖 Telegram Commands

| Command | Auth | Description |
|---------|------|-------------|
| `/start` | Public | Show command list |
| `/help` | Public | Same as /start |
| `/add <domain>` | Admin only | Add a target domain |
| `/remove <domain>` | Admin only | Remove a target |
| `/list` | Admin only | List all active targets |
| `/set_mode <domain> <mode>` | Admin only | Set scan mode: `safe` or `aggressive` |
| `/recon <domain> [mode]` | Admin only | Trigger immediate recon |
| `/status` | Admin only | System status + queue lengths |
| `/report <domain>` | Admin only | Show latest scan report |

> All sensitive commands require the message to come from `ADMIN_CHAT_ID`. Any other user receives `❌ Unauthorized.`

---

## 🔌 API Reference

The orchestrator exposes a minimal HTTP API on port `8000`.

### Authentication

All endpoints except `/health` require the `X-API-Key` header:

```bash
curl -H "X-API-Key: your_api_secret_key" http://localhost:8000/queue/length
```

### Endpoints

#### `GET /health`
Liveness probe. No authentication required.
```json
{"status": "healthy", "version": "2.0.0"}
```

#### `GET /metrics` 🔐
Prometheus-format metrics for Grafana/monitoring.
```
# HELP python_gc_objects_collected_total ...
```

#### `GET /queue/length` 🔐
Current queue depths.
```json
{
  "recon_queue": 0,
  "nuclei_queue": 3,
  "notify_queue": 0
}
```

---

## 🔐 Security

This section documents the hardening measures implemented in this deployment.

### Network Isolation
- PostgreSQL and Redis are **not exposed** to the host — internal Docker network only
- Redis requires password authentication (`--requirepass`)
- Orchestrator API requires `X-API-Key` header on all non-health endpoints

### Container Hardening
- All containers run as **non-root** (`appuser`, uid 999)
- `security_opt: no-new-privileges:true` on every container
- `cap_drop: ALL` — all Linux capabilities dropped
- Resource limits (CPU + memory) on every service

### Application Security
- No credentials in Docker image — all injected at runtime via environment
- All external tools invoked with **list arguments** (no `shell=True`) — command injection impossible
- Subprocess environment is **minimal** — secrets never reach external binaries
- SSRF prevention in js_worker — all download URLs validated against private IP blocklist
- Telegram bot auth checks `chat_id == ADMIN_CHAT_ID` on all sensitive commands
- HTML output escaped with `html.escape()` — no Telegram HTML injection
- Redis distributed lock is **atomic** (`SET NX EX`) — no TOCTOU deadlocks
- `scope.txt` validated at startup — wildcards (`*`, `api.*`) are rejected

### Dependency Supply Chain
- All Go tools pinned to explicit `@vX.Y.Z` versions — no `@latest`
- All Python packages pinned with exact versions
- `asyncio==3.4.3` PyPI stub removed (was a Python 2 artifact)

### Secrets Management
```bash
# Rotate passwords without rebuilding
docker compose down
# Edit .env with new passwords
docker compose up -d
```

---

## 💬 Project Feedback

### Overall Assessment

Hespera is a **well-conceived** project with a clean architecture. The idea of chaining multiple recon tools into an automated async pipeline with Telegram integration is solid for personal bug bounty use. The code quality is good in areas that matter most — the subprocess execution model (`run_command_safe` using list args, no `shell=True`) is the single most important security decision in the whole codebase, and it was done correctly from the start.

---

### ✅ What Was Done Well

**1. Correct subprocess model from day one**
Using `asyncio.create_subprocess_exec(*cmd)` with list arguments instead of `shell=True` is the right call. This is the primary defence against command injection in a tool that runs user-controlled domain names through external binaries. It was implemented consistently across all workers.

**2. Clean worker architecture**
The `BaseWorker` abstract class with a consistent `process_job()` interface, graceful shutdown via signal handlers, and the queue-based decoupling between stages is a genuinely good design. Adding a new scanning tool only requires writing a new worker class.

**3. SQLAlchemy ORM with async sessions**
Parameterised queries via the ORM eliminate SQL injection. The `DatabaseManager` with `async_sessionmaker`, `pool_pre_ping`, and proper session lifecycle is production-grade.

**4. Structured logging with structlog**
Using `structlog` with JSON output makes logs parseable by external systems (Grafana Loki, Datadog, etc.) from day one. The `get_logger(__name__)` pattern is consistently applied.

**5. Pydantic settings validation**
Using `pydantic-settings` to validate configuration at startup (bot token regex, chat ID range, concurrency bounds) is the right pattern. The app fails loudly with a clear message if anything is wrong.

**6. Scope filtering logic**
The `ScopeValidator` concept — a file-based scope definition that workers check before processing subdomains — is the correct way to prevent out-of-scope scanning. The pattern matching for `*.example.com` was sound.

**7. Deduplication via Redis**
Using SHA-256 hashing and a Redis cache with 30-day TTL to deduplicate findings is elegant and avoids database bloat from repeated scans of the same targets.

---

### ⚠️ What Needs Improvement

**1. The notification system was completely broken**
`send_message()` called `create_bot_app()` on every invocation, creating a new uninitialised `Application` object each time. Every worker notification would have raised `RuntimeError` silently. This is the kind of bug that only surfaces in production and creates a dangerous false sense of security — the system *appears* to work (scans run, findings are saved) but no alerts ever reach the operator.

**Lesson:** Singleton resources (database connections, HTTP clients, bot instances) must be initialised once and reused. Write an integration test that actually sends a test message on startup.

**2. Two workers would crash immediately on startup**
`xss_worker.py` used `asyncio.Semaphore(2)` in `__init__` without `import asyncio` at module level. `takeover_worker.py` had `List[str]` type hints without `from typing import List`. Both workers would raise `NameError` before processing a single job. These are the kind of errors a simple `python -c "import python.workers.xss_worker"` import test would catch.

**Lesson:** Add a CI step that imports every module (`python -c "import ..."`) and runs `python -m py_compile` on every file. It takes 5 seconds and catches entire classes of runtime errors before deployment.

**3. The Dockerfile had a silent syntax error**
The missing `&&` after `gau@latest` meant 7 tools (including `dalfox`, `subzy`, `trufflehog`) were never installed. The Docker build succeeded — it just silently skipped those lines. The corresponding workers would fail with `Command not found: dalfox` only when the first job arrived.

**Lesson:** Add a `RUN` step after the tool installation block that verifies every binary: `RUN which subfinder httpx nuclei dalfox subzy trufflehog jsluice uro unfurl`. If any binary is missing, the build fails immediately rather than at runtime.

**4. Credentials were burned into the Docker image**
`COPY .env.example ./.env` is a common mistake that embeds placeholder credentials permanently into the image. If the image is ever pushed to a registry (Docker Hub, ECR, GHCR), those credentials are public. Always inject secrets at runtime via `docker compose` environment blocks.

**5. The SSRF blind spot in js_worker**
Downloading arbitrary URLs from an external queue without validating that they don't point to internal/cloud-metadata addresses is a significant oversight in a security-focused tool. The irony is that Hespera is a security tool that itself had an SSRF vulnerability — exactly the class of bug it's designed to find in targets.

---

### 📈 Recommendations for Future Development

| Priority | Recommendation |
|----------|---------------|
| High | Add a CI pipeline (GitHub Actions) with: import checks, `py_compile`, `pytest`, `docker build` + binary verification |
| High | Add Dockerfile `RUN which <every tool>` health check after installation |
| High | Write an integration test that starts the stack and verifies a test notification is received |
| Medium | Implement `pip-compile --generate-hashes` for a fully locked, hash-verified `requirements.lock` |
| Medium | Add Trivy or Grype container scanning to CI |
| Medium | Segregate Docker volumes per worker (recon_output, nuclei_output, js_output) |
| Medium | Add multi-admin support (list of chat IDs in config instead of single `ADMIN_CHAT_ID`) |
| Low | Add a web dashboard (simple read-only FastAPI + Jinja2) for viewing findings without Telegram |
| Low | Add `--concurrency` flags so individual workers can be scaled: `docker compose up --scale recon_worker=3` |
| Low | Consider migrating to GitHub Actions self-hosted runner if the VPS is powerful enough |

---

### 🔒 Security Maturity: Before vs After

| Area | Before | After |
|------|--------|-------|
| Credentials in image | ❌ Burned in | ✅ Runtime injection only |
| Redis exposure | ❌ No auth, host port | ✅ Auth + internal network |
| PostgreSQL exposure | ❌ Host port open | ✅ Internal network only |
| API authentication | ❌ None | ✅ API key + timing-safe compare |
| Container privilege | ❌ Root | ✅ Non-root + cap_drop ALL |
| SSRF risk | ❌ Unvalidated downloads | ✅ IP blocklist + no-redirect |
| Worker startup | ❌ 2 workers crash on launch | ✅ All workers start correctly |
| Notifications | ❌ Silent failure on every alert | ✅ Singleton bot works correctly |
| Scope enforcement | ❌ `*` bypasses all filtering | ✅ Wildcard validation at load |
| Redis lock | ❌ TOCTOU deadlock risk | ✅ Atomic SET NX EX |
| Tool versions | ❌ `@latest` (non-reproducible) | ✅ Pinned `@vX.Y.Z` |
| Subprocess secrets | ❌ Full env passed to tools | ✅ Minimal env whitelist |
| **Overall rating** | **1.8/10** | **7.8/10** |

---

## 🛠 Troubleshooting

### Workers not starting

```bash
docker compose logs recon_worker --tail=50
# Look for: "Configuration Error" or "Scope file not found"
```

Common causes:
- Missing variable in `.env` → Add the missing variable
- `scope.txt` not created → `cp scope.txt.example scope.txt` and edit it
- Port conflict on 8000 → Change in `docker-compose.yml`

### Telegram bot not responding

```bash
docker compose logs orchestrator --tail=30
# Look for: "Telegram bot started"
```

Common causes:
- Invalid `TELEGRAM_BOT_TOKEN` format → Must match `\d+:[A-Za-z0-9_-]{35}`
- Bot not started (send `/start` to your bot first)
- `ADMIN_CHAT_ID` incorrect → Send `/start` to [@userinfobot](https://t.me/userinfobot)

### Recon not running

```bash
# Check if scope.txt has valid patterns
cat scope.txt

# Manually trigger via Telegram
/recon yourtarget.com

# Check queue length
curl -H "X-API-Key: $API_SECRET_KEY" http://localhost:8000/queue/length
```

### Complete reset (keeps code, wipes data)

```bash
docker compose down -v    # removes volumes
docker compose up -d      # fresh start with empty database
```

### Update tool versions

Edit `Dockerfile`, update the version tags in the `go install` block, then rebuild:

```bash
docker compose build --no-cache
docker compose up -d
```

---

## 📁 Project Structure

```
hespera/
├── Dockerfile                  # Multi-stage build, non-root user
├── docker-compose.yml          # All services with security hardening
├── .env.example                # Template — copy to .env
├── .gitignore                  # Excludes .env, scope.txt, output/
├── requirements.txt            # Pinned Python dependencies
├── Makefile                    # Shortcuts: make up, make logs, make test
├── scope.txt                   # ← You create this (not in repo)
│
├── python/
│   ├── main.py                 # FastAPI orchestrator + API auth
│   ├── settings.py             # Pydantic settings validation
│   ├── database.py             # SQLAlchemy async connection pool
│   ├── redis_client.py         # Redis client + atomic lock
│   ├── scheduler.py            # APScheduler periodic recon
│   ├── models/
│   │   ├── target.py           # Domain targets
│   │   ├── scan.py             # Scan records
│   │   └── finding.py          # Vulnerability findings
│   ├── workers/
│   │   ├── base.py             # Abstract BaseWorker
│   │   ├── recon_worker.py     # Subdomain enum + URL collection
│   │   ├── filter_worker.py    # URL dedup, classify, score, route
│   │   ├── nuclei_worker.py    # Vulnerability scanning
│   │   ├── xss_worker.py       # XSS detection
│   │   ├── takeover_worker.py  # Subdomain takeover
│   │   ├── js_worker.py        # JS analysis + secret scanning
│   │   └── notify_worker.py    # Telegram notifications
│   ├── telegram/
│   │   ├── bot.py              # Singleton bot + send_message()
│   │   ├── handlers.py         # Command handlers
│   │   └── middleware.py       # Auth + atomic rate limiter
│   ├── services/
│   │   ├── scope.py            # Scope file validation
│   │   ├── deduplicator.py     # Redis-backed finding dedup
│   │   ├── reporter.py         # Report generation
│   │   ├── scoring.py          # URL priority scoring
│   │   └── url_classifier.py   # URL category classification
│   └── utils/
│       ├── process.py          # Safe subprocess (no shell=True, minimal env)
│       ├── validators.py       # Domain/subdomain validation
│       └── logging_config.py   # structlog JSON configuration
│
├── bash/
│   ├── lib/
│   │   ├── common.sh           # Logging functions
│   │   └── json_output.sh      # jq-based JSON output
│   └── wrappers/
│       ├── run_subfinder.sh    # Subfinder with jq output
│       ├── run_assetfinder.sh  # Assetfinder with jq output
│       └── run_dalfox.sh       # Dalfox wrapper
│
├── scripts/
│   ├── entrypoint.sh           # Wait-for deps + migrations + exec
│   └── healthcheck.sh          # Docker HEALTHCHECK script
│
├── sql/migrations/
│   ├── 001_init.sql            # Initial schema
│   └── 002_indexes.sql         # Performance indexes
│
└── tests/
    ├── conftest.py             # Pytest fixtures
    ├── test_validators.py      # Domain validation tests
    └── test_deduplicator.py    # Dedup logic tests
```

---

<div align="center">

Built for bug bounty hunters who prefer automation over manual recon.

**⚠️ For authorized testing only. Never scan targets without permission.**

</div>