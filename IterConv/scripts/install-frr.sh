#!/usr/bin/env bash
# 在虚拟机内安装 FRR 路由软件
# 前置: 虚拟机已启动, 且能通过 ssh 登录
set -euo pipefail

REMOTE="${1:-ubuntu@localhost}"
SSH_PORT="${SSH_PORT:-2222}"
SSH_OPTS="-p $SSH_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

# 把安装逻辑作为一个 heredoc 脚本在远端执行
ssh $SSH_OPTS "$REMOTE" bash -s <<'REMOTE'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "[1/5] 添加 FRR 官方仓库 GPG 密钥"
curl -s https://deb.frrouting.org/frr/keys.gpg | sudo tee /usr/share/keyrings/frrouting.gpg > /dev/null

# 可选版本: frr-6 ... frr-10.7 / frr-rc / frr-stable（最新稳定版）
FRRVER="frr-stable"
echo "deb [signed-by=/usr/share/keyrings/frrouting.gpg] https://deb.frrouting.org/frr \
     $(lsb_release -s -c) $FRRVER" | sudo tee /etc/apt/sources.list.d/frr.list > /dev/null
echo "    FRRVER=$FRRVER (发行版: $(lsb_release -s -c))"

echo "[2/5] 更新 apt 源"
sudo apt-get update -y

echo "[3/5] 安装 FRR"
sudo apt-get install -y frr frr-pythontools

echo "[4/5] 设置 FRR 开机自启并启动"
sudo systemctl enable frr
sudo systemctl start frr || true

echo "[5/5] 版本:"
dpkg -l | grep frr | awk '{print $2, $3}'
REMOTE