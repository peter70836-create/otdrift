#!/bin/bash
# ==============================================================================
# deploy_openwrt.sh: Automated OpenWrt Gateway & otdrift Edge Engine Provisioner
# Runs on Ubuntu VM (OT1) to deploy OpenWrt container and link with OpenPLC
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=========================================================================="
echo "🛡️  Deploying OpenWrt Industrial Edge Security Gateway for otdrift"
echo "=========================================================================="

cd "$PROJECT_ROOT/docker"

# 1. Start OpenWrt container
echo "[1/4] Starting OpenWrt Gateway container (ot_openwrt_gateway)..."
docker compose up -d openwrt_gateway openplc

# Wait for container initialization
echo "[2/4] Waiting for OpenWrt init..."
sleep 3

# 2. Install Python3 inside OpenWrt
echo "[3/4] Installing Python3 runtime inside OpenWrt (opkg update & install)..."
docker exec ot_openwrt_gateway sh -c "
    if ! command -v python3 >/dev/null 2>&1; then
        echo 'Updating opkg repositories...'
        opkg update
        echo 'Installing python3-light...'
        opkg install python3 python3-light
    else
        echo 'Python3 already installed in OpenWrt.'
    fi
"

# Ensure executable permissions on otdrift-edge
docker exec ot_openwrt_gateway chmod +x /usr/bin/otdrift-edge 2>/dev/null || true

# 3. Test running otdrift-edge inside OpenWrt
echo "[4/4] Executing otdrift-edge INSIDE the OpenWrt container..."
docker exec ot_openwrt_gateway python3 /usr/bin/otdrift-edge \
    -b /etc/otdrift_configs/baseline_firewall.uci \
    -c /etc/config/firewall \
    --modbus-host 172.28.0.50 \
    --modbus-port 502 \
    --live

echo ""
echo "=========================================================================="
echo "✓ OpenWrt Industrial Gateway is LIVE and running otdrift-edge!"
echo "  • OpenWrt Gateway IP: 172.28.0.2 (Port 8081 for Web UI, Port 2222 for SSH)"
echo "  • OpenPLC Target IP : 172.28.0.50 (Port 502 for Modbus TCP)"
echo "  • Execute inside OpenWrt anytime via:"
echo "    docker exec -it ot_openwrt_gateway python3 /usr/bin/otdrift-edge --help"
echo "=========================================================================="
