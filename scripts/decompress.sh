#!/bin/bash
set -e

# Check argument
if [ -z "$1" ]; then
    echo "Usage: $0 <basename-of-cpio.gz>"
    echo "Example: $0 initramfs   (will use initramfs.cpio.gz)"
    echo "         $0 rootfs      (will use rootfs.cpio.gz)"
    exit 1
fi

BASENAME="$1"
TARGET_DIR="./$BASENAME"

# Decompress a .cpio.gz packed file system
rm -rf "$TARGET_DIR" && mkdir "$TARGET_DIR"
pushd "$TARGET_DIR" >/dev/null
cp "../${BASENAME}.cpio.gz" .
gzip -dc "${BASENAME}.cpio.gz" | cpio -idm &>/dev/null
rm "${BASENAME}.cpio.gz"
popd >/dev/null
