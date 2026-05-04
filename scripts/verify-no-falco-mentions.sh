#!/usr/bin/env bash
# verify-no-falco-mentions.sh — anchor for Wave 8f (2026-05-04).
#
# Falco was removed as an integration in Wave 8b/8c. Internal code in
# `crates/agent/src/` used to call its rules-only deployment idiom
# "Falco-mode" / "Falco-like" — Wave 8f renamed every reference to
# "rules-only mode". This script keeps the rename honest by failing
# CI if any new "Falco" mention lands in the agent source tree.
#
# Allowed callouts:
# - CHANGELOG.md, history files, .claude/personas.md (operator-local
#   gitignored), .claude-local/ (gitignored): historical references
#   are fine and live outside the source tree this script scans.
# - benchmark-reports/ and similar fixture data: also outside scope.
#
# Distro/shell-portable: POSIX-y bash, no GNU-only flags. Works on
# macOS (BSD coreutils) and Linux (GNU coreutils) the same way.
#
# Usage:
#   ./scripts/verify-no-falco-mentions.sh
#
# Exit codes:
#   0 — clean, no Falco mentions in scoped paths
#   1 — drift detected; offending lines printed to stderr

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Scope: agent source code only. Other crates and docs may legitimately
# reference Falco for historical or comparative reasons.
SCOPE="$REPO_ROOT/crates/agent/src"

if [ ! -d "$SCOPE" ]; then
  echo "verify-no-falco-mentions: $SCOPE not found" >&2
  exit 1
fi

# Use grep -r with -I (binary skip) and case-insensitive match. Print
# every offender on its own line so the operator can see exactly which
# file + line + context to fix.
hits="$(grep -rIn -i 'falco' "$SCOPE" || true)"

if [ -n "$hits" ]; then
  echo "verify-no-falco-mentions: Falco mention(s) detected in agent source:" >&2
  echo "$hits" | sed 's/^/  /' >&2
  cat >&2 <<EOF

Wave 8f renamed every "Falco-mode" / "Falco-like" reference in
crates/agent/src/ to "rules-only mode" / "rules-only" because Falco
no longer has integration in the agent. New mentions of Falco here
re-introduce the anachronism. If the new reference is intentional
(e.g. you are re-introducing a Falco integration), update this
script and ANCHOR_TESTS.md to relax the gate.
EOF
  exit 1
fi

echo "verify-no-falco-mentions: clean (0 Falco mentions in $SCOPE)."
