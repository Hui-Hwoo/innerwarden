#!/usr/bin/env bash
# verify-anchor-tests.sh — assert every named test in ANCHOR_TESTS.md
# still exists in the source tree.
#
# Anchor tests are the long-term regression contract: each one pins
# a bug class so it cannot come back silently. Deleting or renaming
# an anchor without updating ANCHOR_TESTS.md is a silent regression
# of the regression discipline. This script runs in CI to make
# that visible.
#
# Usage:
#   ./scripts/verify-anchor-tests.sh          # check
#   ./scripts/verify-anchor-tests.sh --list   # print the manifest

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="$REPO_ROOT/ANCHOR_TESTS.md"

if [[ ! -f "$MANIFEST" ]]; then
  echo "fail: ANCHOR_TESTS.md not found at $MANIFEST" >&2
  exit 2
fi

# Extract entries: lines matching the format
#   `crates/.../*.rs::test_name` — description
# We accept both `tests::name` and `name` forms (some anchors live
# in cfg(test) inner mods, some don't).
#
# Portable across bash 3.2 (macOS default) — no mapfile.
entries_text="$(
  grep -oE '`[a-zA-Z0-9_/.:-]+`' "$MANIFEST" \
    | tr -d '`' \
    | grep -E '\.rs::' \
    | sort -u
)"

if [[ -z "$entries_text" ]]; then
  echo "fail: ANCHOR_TESTS.md contains no entries (regex match found 0)" >&2
  exit 2
fi

if [[ "${1:-}" == "--list" ]]; then
  printf '%s\n' "$entries_text"
  exit 0
fi

missing=0
total=0
while IFS= read -r entry; do
  [[ -z "$entry" ]] && continue
  total=$((total + 1))
  # Split on `::` from the right — file path is everything before the
  # last `::test_name`. A test inside `mod tests {}` has the form
  # `crates/.../foo.rs::tests::test_name`; outer-scope tests have
  # `crates/.../foo.rs::test_name`. Strip the trailing `::name` for
  # the file path, then accept either form when grepping.
  test_name="${entry##*::}"
  file_path="${entry%::*}"
  # If file_path still contains `::` (mod-scoped test), strip again.
  while [[ "$file_path" == *::* ]]; do
    file_path="${file_path%::*}"
  done

  if [[ ! -f "$REPO_ROOT/$file_path" ]]; then
    echo "MISSING file: $file_path (referenced by $entry)" >&2
    missing=$((missing + 1))
    continue
  fi

  # Look for `fn <test_name>(` in the file. Tolerant of `async fn`,
  # leading whitespace, and visibility modifiers.
  if ! grep -qE "(^|[[:space:]])fn[[:space:]]+${test_name}[[:space:]]*\(" \
        "$REPO_ROOT/$file_path"; then
    echo "MISSING test: $entry" >&2
    missing=$((missing + 1))
  fi
done <<< "$entries_text"

if [[ $missing -gt 0 ]]; then
  echo "" >&2
  echo "verify-anchor-tests: $missing entries missing." >&2
  echo "If a test was renamed or moved, update ANCHOR_TESTS.md in the same PR." >&2
  echo "If a test was deleted intentionally, remove the entry from ANCHOR_TESTS.md" >&2
  echo "AND document in the PR description why the bug class no longer needs an anchor." >&2
  exit 1
fi

echo "verify-anchor-tests: all $total anchors present."
