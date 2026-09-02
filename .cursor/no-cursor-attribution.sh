#!/usr/bin/env bash
# Environment hygiene: enforce ZERO Cursor attribution on commits in Cursor Cloud VMs.
#
# Cursor Cloud installs an agent-managed commit-msg hook
# (~/.cursor/agent-hooks/<workspace>/commit-msg.cursor.co-author) that appends a
# Co-authored-by / cursoragent@cursor.com trailer. The IDE "Attribution" toggle does
# not apply to cloud agents, so we remove it here and keep it removed.
#
# Usage:
#   no-cursor-attribution.sh              # one sweep + launch background reaper (used by `start`)
#   no-cursor-attribution.sh --reap-loop  # internal: the background reaper loop
#
# Idempotent. Safe to run on every agent start. Never touches application behavior.
set -euo pipefail

AGENT_HOOKS_DIR="${HOME}/.cursor/agent-hooks"
STATE_DIR="${HOME}/.cursor/no-attribution"
REAPER_PID_FILE="${STATE_DIR}/reaper.pid"
REAPER_LOG="${STATE_DIR}/reaper.log"
# Sorts AFTER commit-msg.cursor and commit-msg.cursor.co-author in the dispatcher glob,
# so it runs last and can strip anything an earlier cursor hook appended. The name
# deliberately avoids the substring "co-author" so the reaper never deletes it.
STRIPPER_NAME="commit-msg.cursor.zzz-no-attribution"

SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
mkdir -p "${STATE_DIR}"

# Write the commit-msg stripper program to $1. It removes Cursor attribution lines
# from a commit message file and never fails the commit.
write_stripper() {
  local dest="$1"
  cat > "${dest}" <<'STRIP'
#!/usr/bin/env bash
# Strip Cursor attribution from a commit message. Must never block a commit.
set -e
msg="${1:-}"
[ -n "${msg}" ] && [ -f "${msg}" ] || exit 0
tmp="$(mktemp)"
# Remove, case-insensitively:
#   - Co-authored-by trailers that reference Cursor (name or email)
#   - any line containing cursoragent@cursor.com
#   - "Made/Generated/Created/Built with Cursor" marketing lines
grep -viE \
  '(^[[:space:]]*co-authored-by:.*cursor)|(cursoragent@cursor\.com)|((made|generated|created|built)[[:space:]]+with[[:space:]]+cursor)' \
  "${msg}" > "${tmp}" || true
# Collapse any blank lines left dangling at the end of the message.
sed -i -e :a -e '/^[[:space:]]*$/{$d;N;ba}' "${tmp}" 2>/dev/null || true
mv "${tmp}" "${msg}"
exit 0
STRIP
  chmod +x "${dest}"
}

# Delete every *co-author* hook file under the agent-hooks tree.
reap_co_author_files() {
  [ -d "${AGENT_HOOKS_DIR}" ] || return 0
  find "${AGENT_HOOKS_DIR}" -name '*co-author*' -exec rm -f {} + 2>/dev/null || true
}

# Ensure our last-running stripper is present in every workspace hook dir, and also
# in the repo's own hooks dir as a fallback if core.hooksPath is ever reset.
install_strippers() {
  local d
  if [ -d "${AGENT_HOOKS_DIR}" ]; then
    for d in "${AGENT_HOOKS_DIR}"/*/; do
      [ -d "${d}" ] || continue
      [ -x "${d}${STRIPPER_NAME}" ] || write_stripper "${d}${STRIPPER_NAME}"
    done
  fi
  if [ -d "/workspace/.git/hooks" ]; then
    [ -x "/workspace/.git/hooks/commit-msg" ] || write_stripper "/workspace/.git/hooks/commit-msg"
  fi
}

# One hygiene pass.
sweep() {
  reap_co_author_files
  install_strippers
}

# Stop a previous reaper (this run's own background loop) if it is still alive,
# so `start` running on every boot never stacks duplicate reapers.
stop_previous_reaper() {
  [ -f "${REAPER_PID_FILE}" ] || return 0
  local old
  old="$(cat "${REAPER_PID_FILE}" 2>/dev/null || true)"
  if [ -n "${old:-}" ] && kill -0 "${old}" 2>/dev/null; then
    # Only kill if the PID is actually our reaper, to avoid touching unrelated PIDs.
    if tr '\0' ' ' < "/proc/${old}/cmdline" 2>/dev/null | grep -q -- '--reap-loop'; then
      kill "${old}" 2>/dev/null || true
    fi
  fi
  rm -f "${REAPER_PID_FILE}"
}

# The background loop. Cursor may recreate the co-author hook at commit time, so keep
# deleting it (and keep our stripper present) for the life of the session.
reap_loop() {
  while true; do
    sweep
    sleep 2
  done
}

start_reaper() {
  stop_previous_reaper
  setsid bash "${SCRIPT_PATH}" --reap-loop >> "${REAPER_LOG}" 2>&1 &
  local pid=$!
  echo "${pid}" > "${REAPER_PID_FILE}"
  echo "no-attribution: reaper started (pid ${pid}); log ${REAPER_LOG}"
}

main() {
  if [ "${1:-}" = "--reap-loop" ]; then
    reap_loop
    exit 0
  fi
  sweep
  start_reaper
  echo "no-attribution: swept ${AGENT_HOOKS_DIR}; installed ${STRIPPER_NAME}"
}

main "$@"
