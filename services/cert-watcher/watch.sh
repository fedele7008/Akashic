#!/bin/bash
# Cert Watcher — monitors certificate files and signals target containers on change.
#
# Environment variables:
#   WATCH_FILES      — comma-separated list of cert file paths to watch
#   TARGET_CONTAINER — container name to signal/restart
#   SIGNAL           — signal to send (HUP for reload, TERM for restart)

set -u

SIGNAL="${SIGNAL:-TERM}"
TARGET_CONTAINER="${TARGET_CONTAINER:-}"
IFS=',' read -ra FILES <<< "${WATCH_FILES}"

echo "[cert-watcher] Starting certificate watcher"
echo "[cert-watcher] Watching: ${WATCH_FILES}"
echo "[cert-watcher] Target: ${TARGET_CONTAINER} (SIG${SIGNAL})"

# Collect unique directories to watch
declare -A WATCH_DIRS
for f in "${FILES[@]}"; do
    f=$(echo "$f" | xargs) # trim whitespace
    dir=$(dirname "$f")
    WATCH_DIRS["$dir"]=1
done

DIR_LIST=""
for dir in "${!WATCH_DIRS[@]}"; do
    DIR_LIST="${DIR_LIST} ${dir}"
done

echo "[cert-watcher] Watching directories:${DIR_LIST}"

# Use inotifywait to efficiently watch for file modifications
while true; do
    # Wait for modify/create/move events on watched directories
    inotifywait -q -e modify,create,moved_to ${DIR_LIST} 2>/dev/null

    # Brief delay to let Vault Agent finish writing all files
    sleep 2

    echo "[cert-watcher] Certificate change detected"

    if [ -n "${TARGET_CONTAINER}" ]; then
        echo "[cert-watcher] Sending SIG${SIGNAL} to container: ${TARGET_CONTAINER}"
        docker kill --signal="${SIGNAL}" "${TARGET_CONTAINER}" 2>/dev/null

        if [ $? -eq 0 ]; then
            echo "[cert-watcher] Signal sent successfully"
        else
            echo "[cert-watcher] Failed to signal container (may not be running)"
        fi
    fi

    # Cooldown to avoid rapid-fire signals during batch writes
    sleep 5
done
