#!/usr/bin/env bash
set -euo pipefail
mkdir -p /Users/ms/Downloads/Aegis-Zero/sandbox
claude mcp add aegis-guarded-filesystem -- \
  python3 /Users/ms/Downloads/Aegis-Zero/aegis_mcp_stdio.py \
  --intent "read and summarize project files inside sandbox" \
  --workdir /Users/ms/Downloads/Aegis-Zero/sandbox \
  -- npx -y @modelcontextprotocol/server-filesystem /Users/ms/Downloads/Aegis-Zero/sandbox
