#!/usr/bin/env bash
# 2026-05-03 — Update Repository Ruleset to close OSSF Scorecard
# branch-protection warnings.
#
# Run AFTER PR #421 (CODEOWNERS handle fix) has merged into main —
# without that PR, `require_code_owner_review = true` would gate
# every PR on a non-existent owner and nothing would be mergeable.
#
# Usage:
#   ./scripts/update-branch-protection.sh
#
# Requires:
#   - gh CLI authenticated as a repo admin (`gh auth status`)
#   - jq (for safe JSON construction)

set -euo pipefail

REPO="InnerWarden/innerwarden"
RULESET_ID=15088940  # "Copilot review for default branch"

echo "==> Reading current ruleset"
current=$(gh api "repos/${REPO}/rulesets/${RULESET_ID}")

# Build the PUT body. Strip computed fields the API rejects, then
# patch in the three changes:
#   1. require_last_push_approval = true (block "approve, then push
#      malicious commit, then merge")
#   2. require_code_owner_review = true (depends on PR #421 landing)
#   3. extend ref_name.include to development + release/*
#
# Rename the ruleset too — it now covers more than the default branch.
new_body=$(echo "$current" | jq '
  del(.id, .source, .source_type, .node_id, ._links,
      .created_at, .updated_at, .current_user_can_bypass)
  | .name = "Branch protection for protected branches"
  | .conditions.ref_name.include = [
      "~DEFAULT_BRANCH",
      "refs/heads/development",
      "refs/heads/release/*"
    ]
  | (.rules[] | select(.type == "pull_request") | .parameters)
      |= ( .require_last_push_approval = true
         | .require_code_owner_review  = true )
')

echo "==> Proposed change:"
echo "$new_body" | jq '.conditions, (.rules[] | select(.type == "pull_request") | .parameters)'

read -r -p "Apply (y/N)? " confirm
if [[ "${confirm,,}" != "y" ]]; then
  echo "aborted"
  exit 1
fi

echo "==> Pushing update"
echo "$new_body" | gh api -X PUT "repos/${REPO}/rulesets/${RULESET_ID}" --input -

echo "==> Done. Verify in the UI:"
echo "    https://github.com/${REPO}/rules"
