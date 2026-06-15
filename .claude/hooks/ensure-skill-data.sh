#!/usr/bin/env bash
#
# PreToolUse hook for the Skill tool. Lazily fetches the source trees the
# `linux` and `bhyve` skills search, the first time one of those skills runs.
#
# Stdin is the PreToolUse JSON payload; `.tool_input.skill` names the skill.
# Behavior:
#   - unrelated skill (sdm, determ-analysis, ...) or unparseable input -> no-op
#   - data already present                                             -> no-op
#   - data missing -> run contrib/setup-skills.sh <skill>; block the skill
#     (exit 2) only if that fetch fails, so the skill never runs blind.
#
# The fast path (data present) is a single directory test, so this adds no
# meaningful latency to normal skill use.

set -uo pipefail

# Project root: prefer the harness-provided dir, else derive from this script.
ROOT="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

payload="$(cat)"

# Extract the invoked skill name (jq if present, tolerant grep fallback).
if command -v jq >/dev/null 2>&1; then
  skill="$(printf '%s' "$payload" | jq -r '.tool_input.skill // empty' 2>/dev/null)"
else
  skill="$(printf '%s' "$payload" \
    | grep -oE '"skill"[[:space:]]*:[[:space:]]*"[^"]+"' \
    | head -1 | sed -E 's/.*"([^"]+)"$/\1/')"
fi

# Map the skill to the tree it needs; anything else proceeds untouched.
case "${skill:-}" in
  linux) dest="$ROOT/.claude/skills/linux/linux" ;;
  bhyve) dest="$ROOT/.claude/skills/bhyve/freebsd-src" ;;
  *) exit 0 ;;
esac

# Already fetched -> nothing to do.
if [[ -d "$dest" ]]; then
  exit 0
fi

# Fetch it. Setup output goes to stderr so stdout stays clean for hook JSON.
# On success, `systemMessage` surfaces a note to the user (the only hook field
# that is user-visible; it appears once the blocking fetch completes), while
# `additionalContext` tells the model the same. Hook stdout/progress is never
# shown to the user, so without this the fetch would be silent.
if "$ROOT/contrib/setup-skills.sh" "$skill" >&2; then
  msg="Fetched '$skill' skill source — one-time first-use setup (can take a few minutes and ~1.5GB of disk)."
  printf '{"systemMessage":"%s","hookSpecificOutput":{"hookEventName":"PreToolUse","additionalContext":"%s"}}\n' "$msg" "$msg"
  exit 0
fi

echo "setup-skills.sh failed for '$skill'. Run 'contrib/setup-skills.sh $skill' manually, then retry." >&2
exit 2
