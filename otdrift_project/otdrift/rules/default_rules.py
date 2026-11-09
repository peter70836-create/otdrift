"""
Built-in OT/ICS security drift evaluation rules and MITRE ATT&CK for ICS mappings.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional


class SecurityRule:
    """Represents a rule for evaluating parameter drift security implications."""

    def __init__(
        self,
        rule_id: str,
        path_pattern: str,
        name: str,
        severity: str,
        risk_score: int,
        mitre_technique_id: str,
        threat_template: str,
        remediation_template: str,
        condition: Optional[Callable[[Any, Any, str], bool]] = None,
    ):
        self.rule_id = rule_id
        self.path_pattern = path_pattern
        self.name = name
        self.severity = severity
        self.risk_score = risk_score
        self.mitre_technique_id = mitre_technique_id
        self.threat_template = threat_template
        self.remediation_template = remediation_template
        self.condition = condition

    def matches(self, path: str, baseline_val: Any, current_val: Any, change_type: str) -> bool:
        if self.path_pattern != path and not path.startswith(self.path_pattern):
            return False
        if self.condition:
            return self.condition(baseline_val, current_val, change_type)
        return True


def get_default_rules() -> List[SecurityRule]:
    """Return default set of OT / ICS drift security rules."""
    rules: List[SecurityRule] = [
        # 1. Modbus Authentication Disabled
        SecurityRule(
            rule_id="RULE-OT-001",
            path_pattern="protocols.modbus_tcp.auth_required",
            name="Modbus TCP 身分驗證遭停用",
            severity="CRITICAL",
            risk_score=95,
            mitre_technique_id="T0812",
            threat_template=(
                "偵測到 Modbus TCP 身分驗證機制遭關閉 (auth_required = {current_val})。"
                "任何連入工控網段之未授權裝置皆可直接向 PLC 發送未授權功能碼 (如 05/06/15/16)，"
                "任意讀寫暫存器與線圈，導致實體製程遭惡意操控或產線停擺。"
            ),
            remediation_template=(
                "1. 立即隔離該 PLC 網路區段 (VLAN/工控防火牆)。\n"
                "2. 透過 Portainer 容器主控台或本機終端將 auth_required 復原為 true。\n"
                "3. 稽核周邊 SCADA/HMI 存取日誌，排查是否有非白名單 IP 嘗試建立 Modbus 連線。"
            ),
            condition=lambda b, c, ct: c is False or str(c).lower() in ["false", "0", "no"],
        ),

        # 2. Modbus Port Tampered
        SecurityRule(
            rule_id="RULE-OT-002",
            path_pattern="protocols.modbus_tcp.port",
            name="Modbus TCP 服務通訊埠異常異動",
            severity="HIGH",
            risk_score=80,
            mitre_technique_id="T0885",
            threat_template=(
                "Modbus 通訊埠由標準 {baseline_val} 變更為 {current_val}。"
                "此類異動常見於攻擊者規避工控入侵偵測系統 (IDS/DPI) 檢查，或建立隱蔽通訊通道。"
            ),
            remediation_template=(
                "1. 將 Modbus 通訊埠復原為黃金標準 502。\n"
                "2. 檢查內部邊界工控防火牆 (OT Firewall) 是否放行非預期埠號之工控流量。\n"
                "3. 檢驗 PLC 容器內部是否有新增異常轉發程序或反向代理。"
            ),
        ),

        # 3. Modbus Master IP Whitelist Tampered
        SecurityRule(
            rule_id="RULE-OT-003",
            path_pattern="protocols.modbus_tcp.allowed_master_ips",
            name="Modbus 主站連線白名單遭竄改或擴大",
            severity="HIGH",
            risk_score=85,
            mitre_technique_id="T0855",
            threat_template=(
                "Modbus 允許連線的主站白名單 (allowed_master_ips) 發生漂移。"
                "非預期的來源 IP 可能獲得向控制器發送控制指令之權限。"
            ),
            remediation_template=(
                "1. 審查目前設定中新增的 IP 位址，確認是否為合法的工程維護工作站。\n"
                "2. 嚴格限縮白名單至授權之 SCADA/HMI 伺服器 IP。\n"
                "3. 阻斷非授權來源 IP 與控制器之間的網路路由。"
            ),
        ),

        # 4. Remote Programming Logic Modification Enabled
        SecurityRule(
            rule_id="RULE-OT-004",
            path_pattern="management.allow_remote_programming",
            name="PLC 遠端邏輯重寫權限遭非法開啟",
            severity="CRITICAL",
            risk_score=95,
            mitre_technique_id="T0843",
            threat_template=(
                "偵測到遠端程式下載與邏輯修改權限遭開啟 (allow_remote_programming = {current_val})。"
                "攻擊者可利用此權限上傳未經驗證的階梯圖 (Ladder Diagram) 或結構化文字 (ST)，"
                "直接置換製程安全邏輯。"
            ),
            remediation_template=(
                "1. 實體或遠端將 allow_remote_programming 設定重置為 false。\n"
                "2. 將 PLC 運作切換為硬體鎖定模式 (RUN/LOCK)。\n"
                "3. 立即重算控制器現存程式之 SHA-256 雜湊值，比對是否已遭惡意程式碼竄改。"
            ),
            condition=lambda b, c, ct: c is True or str(c).lower() in ["true", "1", "yes"],
        ),

        # 5. Web Admin Interface Enabled in Production
        SecurityRule(
            rule_id="RULE-OT-005",
            path_pattern="management.web_admin_enabled",
            name="生產環境非預期啟用 Web 管理介面",
            severity="HIGH",
            risk_score=85,
            mitre_technique_id="T0886",
            threat_template=(
                "生產運作環境中擅自開啟 Web 網頁管理介面 (web_admin_enabled = {current_val})。"
                "工控控制器 Web 介面經常存在跨站請求偽造 (CSRF)、弱密碼認證或命令注入風險，"
                "大幅增加攻擊面。"
            ),
            remediation_template=(
                "1. 生產運行時關閉 Web 網頁管理介面 (web_admin_enabled = false)。\n"
                "2. 若維護需要開啟，必須綁定獨立維護專用網卡 (OOBM) 並搭配跳板機存取。\n"
                "3. 確保 Web 介面密碼已由原廠預設 (admin/admin) 變更為高強度複雜密碼。"
            ),
            condition=lambda b, c, ct: c is True or str(c).lower() in ["true", "1", "yes"],
        ),

        # 6. Firmware Downgrade or Tampering
        SecurityRule(
            rule_id="RULE-OT-006",
            path_pattern="device_info.firmware_version",
            name="韌體版本發生異動或遭降級 (Firmware Downgrade)",
            severity="CRITICAL",
            risk_score=90,
            mitre_technique_id="T0857",
            threat_template=(
                "韌體版本由基準 {baseline_val} 變更為 {current_val}。"
                "若版本降級，攻擊者可能意圖重新引入已修補之高危漏洞 (1-day) 進行攻擊，"
                "或植入具備惡意後門的特製韌體鏡像。"
            ),
            remediation_template=(
                "1. 立即暫停該設備聯網，隔離待查。\n"
                "2. 提取目前韌體鏡像與數位簽章，與設備原廠 (Vendor) 官方驗證檔比對。\n"
                "3. 使用原廠官方安全載具重新刷寫至受驗證之最新韌體版本。"
            ),
        ),

        # 7. Safety Program Checksum Mismatch
        SecurityRule(
            rule_id="RULE-OT-007",
            path_pattern="safety_and_integrity.program_checksum",
            name="PLC 控制邏輯 SHA-256 數位指紋不符",
            severity="CRITICAL",
            risk_score=100,
            mitre_technique_id="T0843",
            threat_template=(
                "控制程式雜湊值與黃金基準不符 (基準: {baseline_val}, 現況: {current_val})。"
                "高度懷疑 PLC 內部控制邏輯已被竄改或植入未授權惡意指令 (如震網 Stuxnet 模式)！"
            ),
            remediation_template=(
                "1. 立即啟動重大工控資安事件響應 (Level 1 Incident Response)。\n"
                "2. 現場啟動實體備援系統或安全互鎖，停止可疑控制器運作。\n"
                "3. 從乾淨離線備份磁碟還原已簽署的標準程式檔案。\n"
                "4. 保留日誌與記憶體傾印進行鑑識調查。"
            ),
        ),

        # 8. PLC Operating Mode Drift (e.g. RUN -> STOP)
        SecurityRule(
            rule_id="RULE-OT-008",
            path_pattern="safety_and_integrity.plc_mode",
            name="PLC 運作模式異常偏離",
            severity="HIGH",
            risk_score=80,
            mitre_technique_id="T0831",
            threat_template=(
                "控制器運作模式由 {baseline_val} 偏離為 {current_val}。"
                "非預期的 STOP 或 PROGRAM 狀態會導致週期控制掃描中斷，造成製程停產或失控。"
            ),
            remediation_template=(
                "1. 現場確認設備物理安全與人員狀況。\n"
                "2. 排除異常因素後，透過合法工程站或硬體鑰匙開關切換回 RUN 模式。\n"
                "3. 調查切換模式的來源 IP 與登入憑證。"
            ),
            condition=lambda b, c, ct: str(c).upper() != "RUN",
        ),

        # 9. Read-Only Safety Registers Tampered
        SecurityRule(
            rule_id="RULE-OT-009",
            path_pattern="safety_and_integrity.read_only_registers",
            name="安全防寫暫存器保護範圍遭縮減或修改",
            severity="CRITICAL",
            risk_score=90,
            mitre_technique_id="T0836",
            threat_template=(
                "關鍵保護暫存器防寫範圍遭到修改。"
                "防護解除後，攻擊者可覆寫關鍵警報門檻 (Setpoints) 或中斷緊急停機互鎖機制。"
            ),
            remediation_template=(
                "1. 立即於 OpenPLC Runtime 設定檔中還原唯讀暫存器定義區段。\n"
                "2. 檢查是否有已遭覆寫之關鍵暫存器數值，校正為安全閥值。"
            ),
        ),

        # 10. Insecure Cleartext Protocol (Telnet) Enabled
        SecurityRule(
            rule_id="RULE-OT-010",
            path_pattern="management.telnet_access",
            name="啟用不安全的明文 Telnet 服務",
            severity="CRITICAL",
            risk_score=90,
            mitre_technique_id="T0886",
            threat_template=(
                "偵測到開啟明文 Telnet 遠端管理服務 (telnet_access = {current_val})。"
                "Telnet 傳輸所有帳號密碼皆為明文，極易遭受內網 ARP 欺騙與封包監聽竊密。"
            ),
            remediation_template=(
                "1. 關閉 Telnet 服務 (telnet_access: false)。\n"
                "2. 全面改用基於 SSHv2 或加密 VPN 之受保護通道進行遠端管理。"
            ),
            condition=lambda b, c, ct: c is True or str(c).lower() in ["true", "1", "yes"],
        ),

        # 11. SSH Service Enabled on PLC
        SecurityRule(
            rule_id="RULE-OT-011",
            path_pattern="management.ssh_access",
            name="PLC 開啟 SSH 遠端終端服務",
            severity="MEDIUM",
            risk_score=60,
            mitre_technique_id="T0886",
            threat_template=(
                "PLC 啟用 SSH 終端服務 (ssh_access = {current_val})。"
                "若未實施金鑰驗證與 IP 限制，可能遭受暴力破解攻擊。"
            ),
            remediation_template=(
                "1. 非維護期間關閉 SSH 存取。\n"
                "2. 若需使用，僅允許專用管理 VLAN 來源 IP 連線，並強制使用 Ed25519 金鑰認證。"
            ),
            condition=lambda b, c, ct: c is True or str(c).lower() in ["true", "1", "yes"],
        ),

        # 12. Password Complexity Enforcement Disabled
        SecurityRule(
            rule_id="RULE-OT-012",
            path_pattern="management.password_complexity_enforced",
            name="密碼複雜度強制政策遭停用",
            severity="MEDIUM",
            risk_score=65,
            mitre_technique_id="T0859",
            threat_template=(
                "密碼複雜度政策遭關閉 (password_complexity_enforced = {current_val})。"
                "弱密碼或預設密碼可能被輕易猜測或字典攻擊成功。"
            ),
            remediation_template=(
                "1. 重新啟用密碼複雜度強制原則 (最少 12 碼並包含大小寫英文、數字與特殊符號)。\n"
                "2. 要求所有帳號在下次登入時立即輪替密碼。"
            ),
            condition=lambda b, c, ct: c is False or str(c).lower() in ["false", "0", "no"],
        ),

        # 13. Critical Process Setpoint / Register Drift
        SecurityRule(
            rule_id="RULE-OT-013",
            path_pattern="process_registers",
            name="關鍵製程運作參數 (Setpoint/Register) 異常飄移",
            severity="CRITICAL",
            risk_score=95,
            mitre_technique_id="T0839",
            threat_template=(
                "製程暫存器數值偏離安全基準 ({path}: 基準={baseline_val}, 現況={current_val})。"
                "未授權修改關鍵安全門檻值可能導致實體管線超壓、物理溢流或引發連鎖停機。"
            ),
            remediation_template=(
                "1. 立即派員核對現場儀表物理讀數，確認設備無超壓/超溫危險。\n"
                "2. 透過 Modbus 寫入指令或 SCADA 控制台將數值還原為標準安全值 {baseline_val}。\n"
                "3. 調查竄改此暫存器之來源主機 IP 與功能碼發送日誌。"
            ),
        ),

        # =====================================================================
        # 智慧製造與 CNC 加工中心專屬安全規則 (Smart Manufacturing & CNC)
        # =====================================================================
        # 14. CNC Spindle RPM Over-speed Limit Tampered
        SecurityRule(
            rule_id="RULE-CNC-001",
            path_pattern="process_machining.spindle_max_rpm",
            name="CNC 主軸最高安全轉速上限遭惡意調升",
            severity="CRITICAL",
            risk_score=98,
            mitre_technique_id="T0839",
            threat_template=(
                "CNC 主軸轉速上限由標準 {baseline_val} RPM 被調升為 {current_val} RPM。"
                "切削離心力與負載嚴重超標，可能引發刀具碎裂、主軸軸承燒熔或機台高速撞車事故。"
            ),
            remediation_template=(
                "1. 立即暫停 CNC 加工排程 (FEED HOLD / E-STOP)。\n"
                "2. 透過控制器面板將 spindle_max_rpm 還原至額定安全值 {baseline_val} RPM。\n"
                "3. 排查近 1 小時內連線至控制器之工程站或 CAM 軟體連線紀錄。"
            ),
            condition=lambda b, c, ct: isinstance(c, (int, float)) and c > b,
        ),

        # 15. CNC Tool Wear Compensation Offset Tampered
        SecurityRule(
            rule_id="RULE-CNC-002",
            path_pattern="tool_offset.tool_01_wear_compensation_mm",
            name="精密刀具磨耗補償 (Tool Wear Offset) 異常偏離",
            severity="HIGH",
            risk_score=85,
            mitre_technique_id="T0836",
            threat_template=(
                "刀具補償值由 {baseline_val} mm 變更為 {current_val} mm (超出精密加工允許公差)。"
                "肉眼無法辨識此微小偏離，但將導致整批航太/半導體精密加工件在品管檢驗時全面報廢。"
            ),
            remediation_template=(
                "1. 立即暫停目前工件批次切削。\n"
                "2. 派遣對刀儀重新量測刀具實體幾何尺寸與磨耗，校正至標準偏置。\n"
                "3. 抽檢已加工之工件關鍵尺寸公差。"
            ),
        ),

        # 16. CNC Coolant Pressure Lowered
        SecurityRule(
            rule_id="RULE-CNC-003",
            path_pattern="safety_interlocks.coolant_pressure_min_bar",
            name="切削液/冷卻油泵最低壓力閥門門檻遭調降",
            severity="CRITICAL",
            risk_score=92,
            mitre_technique_id="T0831",
            threat_template=(
                "切削冷卻壓力門檻由 {baseline_val} bar 降為 {current_val} bar。"
                "冷卻液供應中斷將導致加工區高溫積熱，嚴重時引燃切削油氣霧造成火災事故。"
            ),
            remediation_template=(
                "1. 立即派員檢查切削油泵物理壓力表與管路通暢度。\n"
                "2. 將最低冷卻保護壓力設定還原為安全值 {baseline_val} bar。\n"
                "3. 確認冷卻液低壓警報連動停機機制 (Interlock) 正常啟用。"
            ),
            condition=lambda b, c, ct: isinstance(c, (int, float)) and c < b,
        ),

        # 17. CNC Safety Door Interlock Bypassed
        SecurityRule(
            rule_id="RULE-CNC-004",
            path_pattern="safety_interlocks.safety_door_bypass",
            name="機台防護罩/安全門物理互鎖遭強制旁路",
            severity="CRITICAL",
            risk_score=95,
            mitre_technique_id="T0831",
            threat_template=(
                "偵測到機台防護罩安全門互鎖訊號遭旁路 (safety_door_bypass = {current_val})。"
                "防護罩在開門狀態下機台仍能全速運轉，極易引發高溫金屬碎屑或飛刀傷及現場作業人員。"
            ),
            remediation_template=(
                "1. 立即終止機台自動循環 (Cycle Stop)。\n"
                "2. 還原 safety_door_bypass 為 false，強制執行開門即時安全切斷。\n"
                "3. 現場檢查安全門限位開關是否遭到實體短路或機械卡扣竄改。"
            ),
            condition=lambda b, c, ct: c is True or str(c).lower() in ["true", "1", "yes"],
        ),

        # 18. NC G-Code Program Integrity Tampered
        SecurityRule(
            rule_id="RULE-CNC-005",
            path_pattern="system_integrity.nc_program_checksum",
            name="正在加工之 NC G-Code 數位指紋與生產工單不符",
            severity="CRITICAL",
            risk_score=99,
            mitre_technique_id="T0843",
            threat_template=(
                "正在執行的加工 G-code 數位雜湊發生飄移。"
                "控制器可能遭置換為未經驗證之加工檔案，或被植入 Stuxnet 模式之惡意潛伏加工路徑。"
            ),
            remediation_template=(
                "1. 立即暫停控制器加工程序。\n"
                "2. 自受保護之版本庫 (MES/CAM Server) 重新同步授權之 G-code 程式。\n"
                "3. 稽核控制器檔案上傳存取紀錄與操作者登入簽章。"
            ),
        ),

        # 19. CNC Comm Policy Auth Disabled
        SecurityRule(
            rule_id="RULE-CNC-006",
            path_pattern="comm_policy.modbus_tcp.auth_required",
            name="CNC Modbus 通訊身分驗證遭停用",
            severity="CRITICAL",
            risk_score=95,
            mitre_technique_id="T0812",
            threat_template=(
                "CNC 控制器 Modbus TCP 身分驗證遭關閉 (auth_required = {current_val})。"
                "任何連入工控網段之主機皆可直接篡改主軸速度與刀具補償暫存器。"
            ),
            remediation_template=(
                "1. 將 comm_policy.modbus_tcp.auth_required 復原為 true。\n"
                "2. 嚴格限縮只允許授權 MES 系統 IP 連線。"
            ),
            condition=lambda b, c, ct: c is False or str(c).lower() in ["false", "0", "no"],
        ),

        # 20. CNC Comm Policy Remote Programming Enabled
        SecurityRule(
            rule_id="RULE-CNC-007",
            path_pattern="comm_policy.allow_remote_programming",
            name="CNC 遠端 NC 程式上傳重寫權限遭非法開啟",
            severity="CRITICAL",
            risk_score=96,
            mitre_technique_id="T0843",
            threat_template=(
                "CNC 遠端程式覆寫權限遭開啟 (allow_remote_programming = {current_val})。"
                "遠端未授權使用者可覆寫 CNC 加工循環與刀具路徑。"
            ),
            remediation_template=(
                "1. 重設 allow_remote_programming 為 false。\n"
                "2. 實體切換 CNC 鑰匙開關為 Memory Lock / Run 模式。"
            ),
            condition=lambda b, c, ct: c is True or str(c).lower() in ["true", "1", "yes"],
        ),

        # 21. OpenWrt Gateway Modbus TCP WAN Ingress Exposure
        SecurityRule(
            rule_id="RULE-GW-001",
            path_pattern="firewall.rules",
            name="OpenWrt 網關工控防火牆規則外曝 (Modbus WAN Ingress)",
            severity="CRITICAL",
            risk_score=98,
            mitre_technique_id="T0855",
            threat_template=(
                "OpenWrt 工控閘道器防火牆規則 '{path}' 遭竄改 (基準={baseline_val}, 現況={current_val})。"
                "外網 (WAN) 來源可能已獲准直接穿越網關存取內網 Modbus TCP Port 502 設備！"
            ),
            remediation_template=(
                "1. 立即登入 OpenWrt 閘道器執行 '/etc/init.d/firewall restart' 還原標準規則。\n"
                "2. 檢查 /etc/config/firewall 確保 Modbus 規則之 src 僅限於 'lan'。\n"
                "3. 立即阻斷未授權之 WAN IP 連線。"
            ),
            condition=lambda b, c, ct: (
                ("src" in str(ct).lower() or True)
                and (str(c).lower() in ["wan", "internet", "0.0.0.0/0", "any"])
            ),
        ),

        # 22. OpenWrt Gateway Firewall Forward Policy Drifted
        SecurityRule(
            rule_id="RULE-GW-002",
            path_pattern="firewall.defaults",
            name="OpenWrt 網關預設轉發政策弱化 (Forward Policy ACCEPT)",
            severity="CRITICAL",
            risk_score=95,
            mitre_technique_id="T0855",
            threat_template=(
                "OpenWrt 網關預設封包轉發政策由 {baseline_val} 變更為 {current_val}。"
                "所有穿透閘道器的網路封包將不再預設被攔阻，工控隔離邊界瓦解。"
            ),
            remediation_template=(
                "1. 執行 'uci set firewall.@defaults[0].forward=REJECT && uci commit firewall'。\n"
                "2. 重啟防火牆服務並稽核誰在管理主控台執行了變更。"
            ),
            condition=lambda b, c, ct: str(c).upper() in ["ACCEPT", "ALLOW"],
        ),
    ]
    return rules

