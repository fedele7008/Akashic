#!/bin/sh
# Splits a PEM bundle file into separate cert and key files.
# Usage: split-bundle.sh <bundle-file>
# Output: replaces .bundle extension with .crt and .key

BUNDLE="$1"

# Wait for file to be fully written (Vault Agent may still be flushing)
sleep 1

if [ -z "$BUNDLE" ] || [ ! -f "$BUNDLE" ]; then
    echo "split-bundle: bundle file not found: $BUNDLE" >&2
    exit 1
fi

BASE="${BUNDLE%.bundle}"
CRT="${BASE}.crt"
KEY="${BASE}.key"

sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' "$BUNDLE" > "$CRT"
sed -n '/BEGIN.*PRIVATE KEY/,/END.*PRIVATE KEY/p' "$BUNDLE" > "$KEY"
chmod 644 "$CRT"
chmod 600 "$KEY"

echo "split-bundle: $BUNDLE → $CRT + $KEY"
