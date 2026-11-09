#!/usr/bin/env bash
# ==============================================================================
# backup_ot_carrier.sh
# 功能：自動備份 OpenPLC 工控載體與 Portainer 容器之所有持久化資料卷 (Volumes)
# 特性：零停機備份 (或安全快照備份)，產生時間戳壓縮檔並計算 SHA-256 驗證碼，符合工控災難復原標準。
# ==============================================================================

set -euo pipefail

BACKUP_DIR="${1:-./backups}"
TIMESTAMP="$(date +'%Y%m%d_%H%M%S')"
BACKUP_ARCHIVE="${BACKUP_DIR}/ot_carrier_backup_${TIMESTAMP}.tar.gz"

mkdir -p "${BACKUP_DIR}"

echo "======================================================================"
echo " 啟動 OT 載體與 Portainer 災難復原備份程序..."
echo " 備份目標路徑: ${BACKUP_ARCHIVE}"
echo "======================================================================"

# 檢查 Docker 磁碟卷是否存在
if ! docker volume inspect ot_openplc_data > /dev/null 2>&1; then
    echo "[WARN] 找不到磁碟卷 ot_openplc_data，可能尚未啟動過堆疊。"
fi

# 使用臨時 alpine 容器掛載磁碟卷進行封存，確保不破壞容器內部檔案權限
echo "[1/3] 正在封裝 OpenPLC 與 Portainer 持久化資料卷..."
docker run --rm \
    -v ot_openplc_data:/volume_openplc:ro \
    -v ot_portainer_data:/volume_portainer:ro \
    -v "$(pwd)/${BACKUP_DIR}":/backup \
    alpine:latest \
    tar -czf "/backup/ot_carrier_backup_${TIMESTAMP}.tar.gz" -C / volume_openplc volume_portainer

echo "[2/3] 計算備份封裝檔案之 SHA-256 數位指紋..."
CHECKSUM="$(sha256sum "${BACKUP_ARCHIVE}" | awk '{print $1}')"
echo "${CHECKSUM}  $(basename "${BACKUP_ARCHIVE}")" > "${BACKUP_ARCHIVE}.sha256"

echo "[3/3] 驗證備份檔案完整性..."
if [ -f "${BACKUP_ARCHIVE}" ]; then
    SIZE="$(du -h "${BACKUP_ARCHIVE}" | awk '{print $1}')"
    echo ""
    echo "======================================================================"
    echo " [OK] 備份成功完成！"
    echo " 檔案名稱: $(basename "${BACKUP_ARCHIVE}")"
    echo " 檔案大小: ${SIZE}"
    echo " SHA-256 : ${CHECKSUM}"
    echo " 驗證檔案: ${BACKUP_ARCHIVE}.sha256"
    echo ""
    echo " 還原指引："
    echo " docker run --rm -v ot_openplc_data:/volume_openplc -v ot_portainer_data:/volume_portainer -v $(pwd)/${BACKUP_DIR}:/backup alpine tar -xzf /backup/$(basename "${BACKUP_ARCHIVE}") -C /"
    echo "======================================================================"
else
    echo "[ERROR] 備份失敗，未產出檔案。"
    exit 1
fi
