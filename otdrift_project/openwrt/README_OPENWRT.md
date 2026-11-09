# 🛡️ otdrift-edge：OpenWrt 工控閘道器邊緣安全審計引擎

> **定位**：專為嵌入式 **OpenWrt 工控路由器 / 邊緣閘道器 (Purdue 1.5 層)** 設計之超輕量自包含安全引擎。  
> **核心特色**：**零外部依賴 (Zero External Dependencies)**，在 OpenWrt 僅需標準 `python3` 或 `python3-light` 即可直接原生執行（無需安裝 `pip`、`gcc`、`deepdiff` 或 `rich`）。

---

## 一、 系統架構：雙軌邊緣審計 (Dual-Track Edge Auditing)

```
┌────────────────────────────────────────────────────────┐
│               Level 2 控制室 SCADA / HMI                │
└───────────────────────────┬────────────────────────────┘
                            │ (WAN: 192.168.1.0/24)
                            ▼
┌────────────────────────────────────────────────────────┐
│  🛡️ Purdue 1.5 層【OpenWrt 工控邊緣安全閘道器】         │
│  (IP: 172.28.0.2，內嵌 otdrift-edge 邊緣引擎)          │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │ 軌道 1：本機 UCI 防火牆審計 (/etc/config/firewall)│  │
│  │  • 監控 Modbus TCP 502 規則是否遭竄改外曝至 WAN  │  │
│  │  • 監控預設轉發政策 (Forward Policy) 是否弱化     │  │
│  └──────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────┐  │
│  │ 軌道 2：下向 Modbus 現場總線審計 (FC 03 讀取)    │  │
│  │  • 原生 Socket 發送工控報文，提取保持暫存器快照  │  │
│  │  • 檢驗停機壓力閥值 (85 psi) 與製程不變量        │  │
│  └──────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────┐  │
│  │ 邊緣推理：W-STED 距離計算 ＋ 閉環主動防禦        │  │
│  │  • 計算 W-STED 與 NDI 歸一化飄移指數             │  │
│  │  • 觸發 CRITICAL 告警時，動態注入 iptables 阻斷   │  │
│  └──────────────────────────────────────────────────┘  │
└───────────────────────────┬────────────────────────────┘
                            │ (LAN: 172.28.0.0/16 隔離現場匯流排)
                            ▼
┌────────────────────────────────────────────────────────┐
│             Level 1 現場實體：OpenPLC 工控載體          │
│             (IP: 172.28.0.50，Port 502 Modbus TCP)      │
└────────────────────────────────────────────────────────┘
```

---

## 二、 檔案清單與功能

* **`openwrt/otdrift_edge.py`**：自包含單一執行檔（包含 UCI 解析器、原生語意比對器、W-STED 距離計算器、MITRE ICS 規則庫、Raw Socket Modbus 探針與 ANSI 終端彩色儀表板）。
* **`configs/openwrt/baseline_firewall.uci`**：標準合規 OpenWrt 工控防火牆金級組態。
* **`configs/openwrt/tampered_firewall.uci`**：模擬攻擊者竄改 Modbus 規則至 WAN 外網之攻擊快照。
* **`docker/docker-compose.yml`**：已納入 `openwrt_gateway` (`openwrt/rootfs:x86_64`) 容器服務。
* **`tools/deploy_openwrt.sh`**：一鍵部署 OpenWrt 容器並與 OpenPLC 串接之自動化腳本。

---

## 三、 在 OpenWrt 上的執行指令指南

### 1. 靜態檔案稽核 (UCI vs UCI 或 JSON vs JSON)
```bash
python3 otdrift_edge.py -b /etc/config/firewall.baseline -c /etc/config/firewall
```

### 2. 即時雙軌審計 (Local UCI + Live Modbus TCP)
```bash
python3 otdrift_edge.py \
    -b /etc/config/firewall.baseline \
    --live \
    --modbus-host 172.28.0.50 \
    --modbus-port 502
```

### 3. 機器可讀輸出模式 (SIEM / SCADA 整合)
```bash
python3 otdrift_edge.py -b baseline.uci -c current.uci --json
```

### 4. 啟用閉環主動隔離防禦 (--auto-block)
若偵測到 CRITICAL 飄移（例如 Modbus 502 被開放給外網，或壓力暫存器被竄改），自動調用 OpenWrt 底層 `iptables` 阻斷連線：
```bash
python3 otdrift_edge.py -b baseline.uci -c /etc/config/firewall --auto-block
```

---

## 四、 實測輸出範例

```
╔════════════════════════════════════════════════════════════════════════════╗
║          🛡️  otdrift-edge : OpenWrt 工控閘道器邊緣安全審計報告            ║
╚════════════════════════════════════════════════════════════════════════════╝
 • 審計評定 (Severity)     : CRITICAL
 • 飄移總數 (Total Drifts) : 2
 • W-STED 語意距離 (D)     : 4.00
 • 歸一化飄移指數 (NDI)    : 0.7981
 • 整體工控風險分值        : 80 / 100

┌───┬───────────────────────────────────────────┬────────┬────────┬──────┬─────────┐
│等 │ 參數路徑 (Parameter Path)                 │ 基準   │ 現況   │ 距離 │ MITRE   │
├───┼───────────────────────────────────────────┼────────┼────────┼──────┼─────────┤
│CRI│ firewall.rules.Allow-Modbus-TCP-Internal... │  lan   │  wan   │ 2.00 │ T0855   │
│CRI│ firewall.defaults.defaults_0.forward        │ REJECT │ ACCEPT │ 2.00 │ T0855   │
└───┴───────────────────────────────────────────┴────────┴────────┴──────┴─────────┘

🚨 高危險飄移現場處置手冊 (Incident Playbook):
▶ [CRITICAL] firewall.rules.Allow-Modbus-TCP-Internal.src (T0855 - Unauthorized Command Message)
   威脅說明：OpenWrt 工控防火牆規則外曝：Modbus TCP 502 來源被竄改為 'wan' (原為 'lan')！外網可直接注入工控指令。
   建議處置：立即執行 '/etc/init.d/firewall restart' 還原標準規則，並檢查 /etc/config/firewall 確保 Modbus 規則 src 限縮為 lan。
```
