#!/bin/bash
# Simple health check for orchestrator
curl -f http://localhost:8000/health || exit 1