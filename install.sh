#!/usr/bin/env bash
# Install the Defensive SOC Skills into ~/.claude/skills/
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${HOME}/.claude/skills"
mkdir -p "${DEST}"

echo "==> Installing Defensive SOC Skills into ${DEST}"
for skill in "${REPO_DIR}/skills"/*/; do
  name="$(basename "$skill")"
  if [ -e "${DEST}/${name}" ]; then
    read -r -p "    ${name} exists — overwrite? [y/N] " a
    case "${a:-N}" in [yY]*) rm -rf "${DEST:?}/${name}";; *) echo "    skipped"; continue;; esac
  fi
  cp -R "$skill" "${DEST}/${name}"
  echo "    installed: ${name}"
done
echo "==> Done. Start a new Claude Code session to load the skills."
