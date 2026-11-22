#!/bin/bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIVE="$ROOT/live"
STAGE="$LIVE/config/includes.chroot/opt/secbox/build"
DIST="$ROOT/dist"

cd "$ROOT"

rm -rf "$STAGE"
mkdir -p "$STAGE/install"
mkdir -p "$DIST"

echo "=== Build SecBox wheel ==="

python3 -m pip wheel \
    --no-deps \
    --wheel-dir "$STAGE" \
    "$ROOT"

echo "=== Stage installation files ==="

cp -a \
    "$ROOT/packaging" \
    "$STAGE/install/"

cp -a \
    "$ROOT/config" \
    "$STAGE/install/"

echo "=== Prepare live-build ==="

cd "$LIVE"

sudo lb clean --purge || true

./auto/config

echo "=== Build ISO ==="

sudo lb build

ISO="$(
    find . \
        -maxdepth 1 \
        -type f \
        -name '*.iso' \
        | head -1
)"

if [ -z "$ISO" ]; then
    echo "ISO build completed but no ISO file was found" >&2
    exit 1
fi

DEST="$DIST/secbox-0.1.0-amd64.iso"

cp -f "$ISO" "$DEST"

echo
echo "============================================================"
echo " SecBox ISO READY"
echo "============================================================"

ls -lh "$DEST"
sha256sum "$DEST"
