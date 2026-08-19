#!/usr/bin/env bash
# kali-master installer — copies the skill into Claude Code's skills directory.
#
# Usage:
#   bash install.sh              # user-level  (~/.claude/skills, all projects)
#   bash install.sh --project    # project-level (.claude/skills, current dir)
#
# The script only copies files. Read it before running — never blind-pipe
# scripts from the internet, especially in a security context.
set -euo pipefail

DEST="${HOME}/.claude/skills"
SCOPE="user"
[ "${1:-}" = "--project" ] && { DEST=".claude/skills"; SCOPE="project"; }

# locate the skill directory (repo layout: this script sits next to kali-master/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/kali-master"

if [ ! -f "$SRC/SKILL.md" ]; then
  echo "error: $SRC/SKILL.md not found — this script must sit next to the kali-master/ directory (repo root)" >&2
  exit 1
fi

mkdir -p "$DEST"
rm -rf "$DEST/kali-master"
cp -r "$SRC" "$DEST/kali-master"

# plugin/local state must never ship
rm -rf "$DEST/kali-master/.omc"

COUNT=$(find "$DEST/kali-master" -type f | wc -l | tr -d ' ')
echo "installed: $DEST/kali-master ($COUNT files, $SCOPE scope)"
echo "restart Claude Code (or open a new session) to activate the skill"
