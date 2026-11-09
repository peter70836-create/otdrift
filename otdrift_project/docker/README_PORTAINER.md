# Portainer 與 OpenPLC 工控載體容器化管理指南

本指南提供在 Linux (Ubuntu 20.04 / 22.04 / 24.04 LTS) 虛擬機中，完整搭建 Docker、Portainer CE 視覺化容器平台，並將虛擬工控環境 (OpenPLC Runtime v3) 容器化部署與管理的端到端教學。

---

## 目錄
1. [架構說明](#1-架構說明)
2. [步驟一：Ubuntu 虛擬機環境準備與 Docker 安裝](#2-步驟一ubuntu-虛擬機環境準備與-docker-安裝)
3. [步驟二：啟動 Portainer 與 OpenPLC 堆疊](#3-步驟二啟動-portainer-與-openplc-堆疊)
4. [步驟三：Portainer 視覺化介面操作](#4-步驟三portainer-視覺化介面操作)
5. [步驟四：OpenPLC 工控載體驗證與配置](#5-步驟四openplc-工控載體驗證與配置)
6. [步驟五：零中斷離線快照擷取與飄移比對](#6-步驟五零中斷離線快照擷取與飄移比對)
7. [步驟六：災難復原與自動備份](#7-步驟六災難復原與自動備份)

---

## 1. 架構說明

本專案將工控測試載體 (OpenPLC) 與維運儀表板 (Portainer) 全面容器化：
- **Portainer CE** (連接埠 `9443` HTTPS / `9000` HTTP)：提供 Web GUI 視覺化監控容器資源、狀態與網路拓撲。
- **OpenPLC Runtime v3** (連接埠 `8080` Web / `502` Modbus TCP)：作為獨立隔離之虛擬 PLC 控制器載體。
- **專屬橋接網段 (`ot_carrier_net` `172.28.0.0/16`)**：建立隔離工控模擬網路，保護宿主機。
- **離線零中斷分析架構**：透過掛載磁碟卷或離線匯出工具，在不向 PLC 發送探測封包的前提下提取當前組態。

---

## 2. 步驟一：Ubuntu 虛擬機環境準備與 Docker 安裝

在 Ubuntu 終端機中，執行專案隨附的一鍵安裝腳本：

```bash
# 賦予執行權限並執行自動化建置
chmod +x docker/scripts/*.sh
sudo bash docker/scripts/setup_ubuntu_docker.sh
```

此腳本將自動：
1. 更新 APT 套件庫並安裝安全證書。
2. 配置 Docker 官方套件來源與 GPG 金鑰。
3. 安裝 `docker-ce`、`containerd` 與 `docker-compose-plugin`。
4. 將當前使用者加入 `docker` 使用者組 (免 `sudo` 權限)。
5. 配置 UFW 防火牆，放行 `9000`, `9443`, `8080`, `502` 連接埠。

---

## 3. 步驟二：啟動 Portainer 與 OpenPLC 堆疊

透過 `docker compose` 一鍵啟動：

```bash
bash docker/scripts/deploy_portainer_and_ot.sh
```

或是手動啟動：

```bash
cd docker
docker compose up -d
```

檢查容器運作狀態：
```bash
docker compose ps
```
預期輸出：
- `ot_portainer`: 狀態 `Up` (連接埠 `9443`, `9000`)
- `ot_openplc_carrier`: 狀態 `Up` (連接埠 `8080`, `502`)

---

## 4. 步驟三：Portainer 視覺化介面操作

1. 打開瀏覽器，造訪：
   - **HTTPS 推薦**：`https://<虛擬機IP>:9443`
   - **HTTP**：`http://<虛擬機IP>:9000`
2. **初次設定管理員密碼**：
   - 系統提示建立新密碼 (建議使用強密碼，至少 12 碼)。
3. **進入環境儀表板**：
   - 點選 `local` 環境，即可檢視 CPU 使用率、記憶體消耗、Containers 與 Volumes。
4. **管理 OT 載體堆疊 (Stacks)**：
   - 點擊左側選單 **Stacks**。
   - 點擊 **Add stack**，名稱輸入 `ot-carrier-production`。
   - 可直接貼上 `docker/docker-compose.yml` 內容，實現視覺化一鍵部署與滾動更新。

---

## 5. 步驟四：OpenPLC 工控載體驗證與配置

1. 打開瀏覽器，造訪 OpenPLC 網頁控制台：
   - 網址：`http://<虛擬機IP>:8080`
   - **預設帳號**：`openplc`
   - **預設密碼**：`openplc` (登入後強烈建議至 Settings 更改密碼)
2. **查看 Modbus TCP 監聽狀態**：
   - 點擊 **Hardware** / **Settings**，確認 Modbus 正在 `502` 埠運作。
   - 狀態顯示：`PLC Status: RUNNING`。
3. **安全配置黃金標準**：
   - 透過 Portainer 或設定檔，確保身分驗證開啟 (`auth_required = true`)，並禁止外網未授權來源存取。

---

## 6. 步驟五：零中斷離線快照擷取與飄移比對

為了不干擾實體工控產線之毫秒級掃描週期，我們採用**離線設定提取架構**：

```bash
# 1. 離線提取目前載體運作快照至 JSON (絕不發送網路掃描封包)
bash docker/scripts/export_current_config.sh configs/current_snapshot.json

# 2. 呼叫 otdrift CLI 引擎進行黃金標準比對與 MITRE 映射
otdrift check -b configs/baseline.json -c configs/current_snapshot.json -f console

# 3. 輸出包含處置建議的 HTML 互動報告
otdrift check -b configs/baseline.json -c configs/current_snapshot.json -f html -o reports/audit_result.html
```

---

## 7. 步驟六：災難復原與自動備份

利用容器化載體特性，定期備份磁碟卷以滿足 IEC 62443 工控災難復原標準：

```bash
# 執行自動化備份 (自動計算 SHA-256 驗證碼)
bash docker/scripts/backup_ot_carrier.sh ./backups
```

產出檔案範例：
- `backups/ot_carrier_backup_20261001_010000.tar.gz`
- `backups/ot_carrier_backup_20261001_010000.tar.gz.sha256`

若發生勒索軟體攻擊或 PLC 韌體損毀，僅需一條指令即可秒級還原整套環境！
