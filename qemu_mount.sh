#!/bin/bash
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <qcow2_file>"
    exit 1
fi

QCOW2="$1"
RAW="${QCOW2%.qcow2}.raw"

if [ ! -f "$QCOW2" ]; then
    echo "Error: $QCOW2 not found"
    exit 1
fi

if [ -f "$RAW" ]; then
    echo "Error: $RAW already exists, remove it first"
    exit 1
fi

echo "[1/3] Converting $QCOW2 -> $RAW ..."
qemu-img convert -f qcow2 -O raw "$QCOW2" "$RAW"

echo "[2/3] Setting up loop device ..."
LOOPDEV=$(losetup --find --show --partscan "$RAW")
echo "Loop device: $LOOPDEV"

sleep 1

PARTS=$(ls "${LOOPDEV}p"* 2>/dev/null || true)
if [ -z "$PARTS" ]; then
    echo "No partitions found on $LOOPDEV, trying partprobe ..."
    partprobe "$LOOPDEV" 2>/dev/null || true
    sleep 1
    PARTS=$(ls "${LOOPDEV}p"* 2>/dev/null || true)
fi

if [ -z "$PARTS" ]; then
    echo "Error: no partitions found on $LOOPDEV"
    echo "Detaching loop device ..."
    losetup -d "$LOOPDEV"
    exit 1
fi

echo "[3/3] Mounting partitions ..."
MOUNTED=()
for PARTDEV in $PARTS; do
    PARTNAME=$(basename "$PARTDEV")
    MNT="/mnt/$PARTNAME"
    mkdir -p "$MNT"
    mount "$PARTDEV" "$MNT" && MOUNTED+=("$MNT")
    echo "  $PARTDEV -> $MNT"
done

echo "Done."
echo "  QCOW2 : $QCOW2"
echo "  RAW   : $RAW"
echo "  LOOP  : $LOOPDEV"
echo "  MOUNTS: ${MOUNTED[*]}"
