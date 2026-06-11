#!/bin/bash
# Wrapper for dalfox to run on a file of URLs
INPUT_FILE="$1"
if [ -z "$INPUT_FILE" ]; then
    echo "Usage: $0 <urls_file>"
    exit 1
fi

dalfox file "$INPUT_FILE" --skip-bav --no-spinner --silent --output /dev/stdout --format json