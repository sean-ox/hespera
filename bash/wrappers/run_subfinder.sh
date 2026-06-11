#!/bin/bash
# Wrapper for subfinder with JSONL output

source "$(dirname "$0")/../lib/common.sh"
source "$(dirname "$0")/../lib/json_output.sh"

DOMAIN="$1"
if [[ -z "$DOMAIN" ]]; then
    log_error "Usage: $0 <domain>"
    exit 1
fi

output=$(subfinder -d "$DOMAIN" -silent 2>/dev/null)
if [[ -n "$output" ]]; then
    echo "$output" | while read -r sub; do
        output_json "subfinder" "$sub"
    done
fi