#!/usr/bin/env bash
# Verification script: Ensure no em dash characters exist in any file.
# Exit code 0 indicates clean repository; non-zero indicates violations found.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Scanning repository for em dash characters (U+2014)..."

# Search for the unicode character U+2014 or literal em dash
VIOLATIONS=$(grep -rn $'\u2014' "$REPO_ROOT" \
    --exclude-dir=".git" \
    --exclude="verify_no_em_dash.sh" 2>/dev/null || true)

if [ -n "$VIOLATIONS" ]; then
    echo "ERROR: Em dash characters detected:"
    echo "$VIOLATIONS"
    exit 1
fi

echo "Clean: Zero em dashes detected across repository."
exit 0
