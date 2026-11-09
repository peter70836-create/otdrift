#!/usr/bin/env bash
# ==============================================================================
# setup_ubuntu_docker.sh
# 適用環境：Ubuntu 20.04 / 22.04 / 24.04 LTS 虛擬機
# 功能：自動化建置 Docker CE、Docker Compose 插件與防火牆規則，為 Portainer 及 OpenPLC 提供底層運行環境。
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err() { echo -e "${RED}[ERROR]${NC} $1"; }

# 檢查是否為 root 或具備 sudo 權限
if [ "$(id -u)" -ne 0 ]; then
    log_err "請使用 sudo 執行此安裝腳本：sudo bash $0"
    exit 1
fi

CURRENT_USER="${SUDO_USER:-$USER}"

log_info "=== [步驟 1/5] 更新 Ubuntu 系統套件庫 ==="
apt-get update -y
apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    tar \
    gzip \
    ufw

log_info "=== [步驟 2/5] 設定 Docker 官方 GPG 金鑰與套件庫 ==="
mkdir -p /etc/apt/keyrings
if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
fi

ARCH="$(dpkg --print-architecture)"
UBUNTU_CODENAME="$(lsb_release -cs)"

echo \
  "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  ${UBUNTU_CODENAME} stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update -y

log_info "=== [步驟 3/5] 安裝 Docker CE、Containerd 與 Docker Compose 插件 ==="
apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

log_info "=== [步驟 4/5] 啟動 Docker 服務並配置使用者權限 ==="
systemctl enable docker
systemctl start docker

# 將當前非 root 使用者加入 docker 群組，免 sudo 執行 docker 命令
if ! getent group docker > /dev/null; then
    groupadd docker
fi
usermod -aG docker "${CURRENT_USER}"

log_ok "已將使用者 '${CURRENT_USER}' 加入 docker 群組 (重新登入或執行 'newgrp docker' 後生效)"

log_info "=== [步驟 5/5] 配置 UFW 防火牆規則 (Portainer & OpenPLC) ==="
if command -v ufw > /dev/null 2>&1; then
    # 放行 Portainer Web GUI
    ufw allow 9000/tcp comment 'Portainer HTTP'
    ufw allow 9443/tcp comment 'Portainer HTTPS'
    # 放行 OpenPLC 管理與 Modbus 通訊
    ufw allow 8080/tcp comment 'OpenPLC Web Console'
    ufw allow 502/tcp comment 'OpenPLC Modbus TCP'
    log_ok "已放行連接埠: 9000 (Portainer HTTP), 9443 (Portainer HTTPS), 8080 (OpenPLC), 502 (Modbus TCP)"
fi

echo ""
log_ok "======================================================================"
log_ok " Docker 環境建置完成！"
log_ok " Docker 版本: $(docker --version)"
log_ok " Compose 版本: $(docker compose version)"
log_ok " 下一步：請切換至專案目錄執行 'bash docker/scripts/deploy_portainer_and_ot.sh'"
log_ok "======================================================================"
