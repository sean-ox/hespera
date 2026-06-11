
================================================================================
SYSTEM OVERVIEW
================================================================================

Internal pipeline for continuous attack surface monitoring, automated recon,
and vulnerability discovery. Delivers findings via Telegram to security team.

Capabilities:
- Persistent monitoring of in-scope domains and subdomains
- Automated discovery of web apps, APIs, and endpoints
- Nuclei-based vulnerability scanning as secondary detection
- Prioritized alerting based on asset criticality

================================================================================
ARCHITECTURE (Simplified)
================================================================================

Scheduler → Redis Queue → Workers (recon, filter, nuclei, notify) → PostgreSQL
                                                                          ↓
                                                              Telegram alerts

Data flow:
1. Scheduler enqueues recon jobs per active target.
2. recon_worker enumerates subdomains, probes, collects URLs → raw URLs queue.
3. filter_worker deduplicates, classifies, scores → nuclei queue + notify queue.
4. nuclei_worker scans high-value URLs → findings to notify queue.
5. notify_worker sends aggregated notifications to Telegram.

================================================================================
THREAT DISCOVERY PIPELINE
================================================================================

Stage 1 – Asset Discovery: subfinder + assetfinder (passive), httpx (active probe)
Stage 2 – URL Intelligence: gau + waybackurls (archives), katana (crawling, aggressive)
Stage 3 – Filtering & Classification: dedup, classify (API, admin, JS, param), score
Stage 4 – Vulnerability Detection: Nuclei templates (misconfig, CVE, exposures)
Stage 5 – Triage & Notification: store findings, high severity → immediate alert

================================================================================
WORKER ARCHITECTURE
================================================================================

Worker         | Input Queue       | Function
---------------|-------------------|----------------------------------------
recon_worker   | queue:recon       | Asset discovery for one domain
filter_worker  | queue:raw_urls    | Dedup, classify, score, route
nuclei_worker  | queue:nuclei      | Template-based vulnerability scan
notify_worker  | queue:notify      | Format and send Telegram alerts

Workers are stateless, horizontally scalable, communicate only via Redis queues.
Worker failure does not affect others.

================================================================================
JOB QUEUE SYSTEM (REDIS)
================================================================================

Lifecycle: Enqueue (LPUSH) → Dequeue (BRPOP) → Process → Acknowledge (auto remove)
Retry: Not automatic; worker must implement retry logic if needed.
Monitoring: GET /queue/length endpoint provides queue lengths.

================================================================================
TOOL EXECUTION LAYER
================================================================================

All tools invoked via run_command_safe() which provides:
- Subprocess isolation (process group)
- Timeout enforcement (per job and per tool)
- SIGKILL on timeout (entire process group)
- No shell=True for user input

Integrated tools:
subfinder, assetfinder, httpx, gau, waybackurls, katana, nuclei

================================================================================
DATA MODEL OVERVIEW
================================================================================

Target: domain, status, scan_mode, timestamps
Scan: target_id, scan_type, status, duration, error_message
Finding: scan_id, target_id, finding_type (subdomain/url/vuln), finding_data (JSON),
         severity, is_new, dedup_hash

================================================================================
TRIAGE & NOTIFICATION FLOW
================================================================================

Scoring (filter_worker):
- Base: admin=90, api=70, param=50, static=10
- Bonus: high-value params (id, token, url)
- Penalty: very long URLs

Notification rules:
- Recon completion summary – always
- Nuclei findings with severity ≥ medium – immediate
- High-score URLs (≥70) – immediate
- Failed jobs – with error excerpt

All notifications sent to internal Telegram chat.

================================================================================
DEPLOYMENT
================================================================================

A. Docker (Preferred)
   git clone <internal-repo>
   cp .env.example .env   # edit TELEGRAM_BOT_TOKEN, ADMIN_CHAT_ID, POSTGRES_PASSWORD
   docker compose up -d
   Verify: curl http://localhost:8000/health

B. Manual
   - Dependencies: Python 3.11+, PostgreSQL 15+, Redis 7+, Go 1.21+
   - Install tools: subfinder, assetfinder, httpx, gau, waybackurls, katana, nuclei
   - Initialize DB: python -m alembic upgrade head
   - Start: python -m python.main (orchestrator + scheduler)
   - Start workers: recon_worker, filter_worker, nuclei_worker, notify_worker

C. Environment Variables (key ones)
   TELEGRAM_BOT_TOKEN, ADMIN_CHAT_ID, DATABASE_URL, REDIS_URL,
   MAX_CONCURRENT_RECON=2, RECON_TIMEOUT_SECONDS=1800, SCHEDULE_INTERVAL_MINUTES=360,
   LOG_LEVEL=INFO, JSON_LOGS=true

D. Service Boot Order
   1. PostgreSQL → 2. Redis → 3. Scheduler → 4. Workers (any order) → 5. Orchestrator

================================================================================
OPERATIONAL CONSIDERATIONS
================================================================================

Reliability: Workers restart on failure (Docker policy); job data persisted in Redis.
Queue Backlog: Monitor via /queue/length; increase worker replicas or concurrency.
Failure Isolation: Worker crash does not affect others; tool failure logged, job fails.

================================================================================
SECURITY DESIGN
================================================================================

Input Validation: Domain regex validation before storage.
Command Injection Prevention: subprocess_exec with list args, no shell.
Scope Enforcement: scope.txt filters all discovered subdomains; out-of-scope discarded.
Subprocess Isolation: Each tool in its own process group; timeout kills group.
Secrets Protection: Sensitive data only in environment variables; not in logs/code.

================================================================================
LIMITATIONS
================================================================================

Coverage: Only public subdomains; no auth support; no JS parsing.
Scanning: Nuclei runs only on high-score subset; concurrency limited (2 jobs) for 2-core VPS.
False Positives: Nuclei templates may produce false positives; manual verification required.
Operations: No automatic remediation; no SLA; manual DB cleanup needed.

================================================================================
INCIDENT & DEBUGGING GUIDE
================================================================================

Worker crashed: docker compose logs <worker>; restart service.
Queue stuck: Check Redis connectivity; verify worker running; inspect malformed jobs.
Missing findings: Verify scope file; check filter_worker logs; run manual /recon.
Tool not found: Check binary inside container; rebuild image.
DB lock: Restart PostgreSQL; reduce MAX_CONCURRENT_RECON.
Telegram not arriving: Verify token and chat ID; check notify_worker logs.

================================================================================
API ENDPOINTS (Orchestrator)
================================================================================

GET /health      → liveness probe
GET /metrics     → Prometheus metrics (optional)
GET /queue/length→ JSON with queue lengths

================================================================================
END OF SUMMARY
================================================================================