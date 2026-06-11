#!/bin/bash
# Wrapper for assetfinder with JSONL output

source "$(dirname "$0")/../lib/common.sh"

DOMAIN="$1"
if [[ -z "$DOMAIN" ]]; then
    log_error "Usage: $0 <domain>"
    exit 1
fi

assetfinder --subs-only "$DOMAIN" 2>/dev/null | while read -r sub; do
    echo "{\"tool\":\"assetfinder\",\"data\":\"$sub\"}"
done
