#!/bin/bash
# Common functions for bash wrappers

set -o pipefail

LOG_PREFIX="[$(date '+%Y-%m-%d %H:%M:%S')]"

log_info() {
    echo "$LOG_PREFIX [INFO] $*" >&2
}

log_error() {
    echo "$LOG_PREFIX [ERROR] $*" >&2
}

log_debug() {
    if [[ "${DEBUG:-0}" == "1" ]]; then
        echo "$LOG_PREFIX [DEBUG] $*" >&2
    fi
}