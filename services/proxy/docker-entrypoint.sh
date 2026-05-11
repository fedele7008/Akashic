#!/bin/sh

# -e : in case of err, exit immediately
set -e

# On Docker Desktop for Mac with IPv6 enabled, 'extra_hosts' entries
# using 'host-gateway' get both IPv4 and IPv6 line in /etc/hosts.
# If so, nginx's proxy_pass will resolve domain using IPv6 entry,
# which could cause network failure so removing IPv6 lines explicitly.
HOSTS_TMP="$(mktemp)"
awk '
  # Pass through any line that does not have ":" in the first column —
  # i.e., everything that is not an IPv6 entry. This includes blank
  # lines, comments, and IPv4 entries.
  $1 !~ /:/ { print; next }

  # For IPv6 entries, drop the line if any subsequent token names one
  # of our host-gateway aliases. Keep all other IPv6 lines intact
  # (loopback, link-local, etc.).
  {
    drop = 0
    for (i = 2; i <= NF; i++) {
      if ($i == "auth.akashic.local" \
          || $i == "ctrl.akashic.local" \
          || $i == "api.akashic.local" \
          || $i == "host.docker.internal") {
        drop = 1
        break
      }
    }
    if (!drop) print
  }
' /etc/hosts > "$HOSTS_TMP"
cat "$HOSTS_TMP" > /etc/hosts
rm -f "$HOSTS_TMP"
echo "[proxy] /etc/hosts IPv6 entries for host-gateway aliases removed"

exec nginx -g "daemon off;"
