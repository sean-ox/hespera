#!/bin/bash
# JSON output formatting for tool wrappers

output_json() {
    local tool="$1"
    local data="$2"
    local timestamp=$(date -Iseconds)
    
    # Escape JSON string
    data_escaped=$(echo "$data" | jq -Rs .)
    
    jq -n \
        --arg tool "$tool" \
        --arg timestamp "$timestamp" \
        --argjson data "$data_escaped" \
        '{tool: $tool, timestamp: $timestamp, data: $data}'
}