#!/bin/bash
# entrypoint.sh — wait for dependencies, run migrations, exec the application.
set -euo pipefail

# Maximum seconds to wait for each service before giving up.
# Override with STARTUP_TIMEOUT env var if needed.
STARTUP_TIMEOUT="${STARTUP_TIMEOUT:-60}"

# ─────────────────────────────────────────────────────────────
# wait_for <host> <port> <label>
#   Loops until the TCP port is open or STARTUP_TIMEOUT expires.
#   Exits with code 1 on timeout so Docker marks the container
#   as failed instead of looping forever.
# ─────────────────────────────────────────────────────────────
wait_for() {
    local host="$1"
    local port="$2"
    local label="$3"
    local elapsed=0

    echo "[entrypoint] Waiting for ${label} (${host}:${port})..."

    while ! nc -z "${host}" "${port}" 2>/dev/null; do
        if [ "${elapsed}" -ge "${STARTUP_TIMEOUT}" ]; then
            echo "[entrypoint] ERROR: ${label} (${host}:${port}) not ready after ${STARTUP_TIMEOUT}s. Aborting."
            exit 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    echo "[entrypoint] ${label} is ready (${elapsed}s)"
}

# Wait for required services
wait_for postgres 5432 "PostgreSQL"
wait_for redis    6379 "Redis"

# Run database migrations
echo "[entrypoint] Running database migrations..."
alembic upgrade head
echo "[entrypoint] Migrations complete"

# Hand off to the actual process (CMD from Dockerfile or docker-compose)
exec "$@"