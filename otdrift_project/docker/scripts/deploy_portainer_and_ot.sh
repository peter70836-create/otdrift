#!/usr/bin/env bash
# ==============================================================================
# deploy_portainer_and_ot.sh
# 功能：自動啟動 Portainer CE 容器與 OpenPLC Runtime 工控載體容器堆疊
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(dirname "${SCRIPT_DIR}")"

echo "======================================================================"
echo " 正在啟動 Portainer 與 OT 工控載體 (OpenPLC Runtime)..."
echo " Compose 檔案路徑: ${DOCKER_DIR}/docker-compose.yml"
echo "======================================================================"

cd "${DOCKER_DIR}"

# 檢查 Docker 是否運作中
if ! docker info > /dev/null 2>&1; then
    echo "[ERROR] Docker 未啟動或目前使用者無權限存取 /var/run/docker.sock。"
    echo "請確認 docker service 已啟動，或執行 'sudo usermod -aG docker $USER' 後重新登入。"
    exit 1
fi

# 下載映像檔並啟動容器堆疊
echo "[1/3] 正在拉取 Docker 映像檔..."
docker compose pull

echo "[2/3] 啟動容器群組..."
docker compose up -d

echo "[3/3] 檢查容器運行狀態..."
docker compose ps

HOST_IP="$(hostname -I | awk '{print $1}')"

echo ""
echo "======================================================================"
echo " [OK] 容器載體部署成功！"
echo " 1. Portainer 視覺化管理介面:"
echo "    - HTTPS (推薦): https://${HOST_IP}:9443"
echo "    - HTTP : http://${HOST_IP}:9000"
echo "    (初次造訪請在 5 分鐘內設定管理員 admin 帳號與密碼)"
echo ""
echo " 2. OpenPLC Runtime v3 工控載體:"
echo "    - 網頁控制台: http://${HOST_IP}:8080"
echo "    - 預設帳號: openplc  /  預設密碼: openplc"
echo "    - Modbus TCP 埠號: 502"
echo ""
echo " 3. 設定飄移比對工具 (otdrift):"
echo "    - 使用 export_current_config.sh 擷取現況快照後，執行 otdrift 進行資安稽核"
echo "======================================================================"
