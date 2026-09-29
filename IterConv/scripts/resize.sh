#!/usr/bin/env bash
# 给云镜像扩容：先在宿主机增大 .img，再在虚拟机内扩展分区和文件系统
# 用法: ./resize.sh [大小]  例: ./resize.sh +20G （默认 +20G）
set -euo pipefail

cd "$(dirname "$0")"

IMG="jammy-server-cloudimg-amd64.img"
SIZE="${1:-+20G}"
REMOTE="${2:-ubuntu@localhost}"
SSH_PORT="${SSH_PORT:-2222}"
SSH_OPTS="-p $SSH_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

echo "[:0] 检测镜像是否被 QEMU 占用..."
if pgrep -f "qemu-system-x86_64.*$IMG" >/dev/null; then
  echo "    [错误] 检测到 $IMG 正被 QEMU 占用。"
  echo "    qemu-img resize 不能在有虚拟机挂载镜像时进行。"
  echo "    请先在虚拟机内执行 Ctrl-A x 退出 QEMU（或 kill 对应进程）后再重试。"
  exit 1
fi

echo "[:1] 当前磁盘大小:"
qemu-img info "$IMG" | grep -E '^virtual size'

echo "[:2] 宿主机侧扩容磁盘文件 (+$SIZE)..."
# 仅增大镜像文件；分区表与文件系统需在虚拟机内扩展（第4步）
qemu-img resize "$IMG" "$SIZE"

echo "[:3] 扩大后:"
qemu-img info "$IMG" | grep -E '^virtual size'

echo "[:4] 进入虚拟机扩展分区与文件系统（需虚拟机已运行且能 SSH）..."
ssh $SSH_OPTS "$REMOTE" bash -s <<'REMOTE'
set -euo pipefail

echo "    - 请确认磁盘设备 (/dev/vda):"
lsblk

# growpart 扩展 <设备> <分区号>；云镜像根分区通常是第1个分区
sudo growpart /dev/vda 1 || echo "    [!] growpart 跳过（可能已扩展）"
sudo resize2fs /dev/vda1

echo "    - 扩展完成:"
df -h /
REMOTE

echo "[:5] 完成"