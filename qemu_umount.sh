#!/bin/bash
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <qcow2_file>"
    exit 1
fi

QCOW2="$1"
RAW="${QCOW2%.qcow2}.raw"

if [ ! -f "$RAW" ]; then
    echo "Error: $RAW not found"
    exit 1
fi

LOOPDEV=$(losetup -j "$RAW" | cut -d: -f1)
if [ -z "$LOOPDEV" ]; then
    echo "[1/4] No loop device found for $RAW"
    PARTS=""
else
    PARTS=$(ls "${LOOPDEV}p"* 2>/dev/null || true)
fi

echo "[1/4] Unmounting partitions ..."
if [ -n "$PARTS" ]; then
    for PARTDEV in $PARTS; do
        PARTNAME=$(basename "$PARTDEV")
        MNT="/mnt/$PARTNAME"
        if mountpoint -q "$MNT" 2>/dev/null; then
            umount "$MNT"
            echo "  Unmounted $MNT"
        fi
    done
fi

if [ -n "$LOOPDEV" ]; then
    echo "[2/4] Detaching loop device $LOOPDEV ..."
    losetup -d "$LOOPDEV"
else
    echo "[2/4] No loop device to detach"
fi

QCOW2_OUT="${RAW%.raw}.qcow2"
if [ -f "$QCOW2_OUT" ]; then
    echo "Error: $QCOW2_OUT already exists, remove it first"
    exit 1
fi

echo "[3/4] Converting $RAW -> $QCOW2_OUT ..."
qemu-img convert -f raw -O qcow2 "$RAW" "$QCOW2_OUT"

echo "[4/4] Done. Converted to $QCOW2_OUT"
