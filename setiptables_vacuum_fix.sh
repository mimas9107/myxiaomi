#!/bin/bash
# =================================================================
# Vacuumd 終極修復腳本 (V3 - 強制 DNS 攔截版)
# =================================================================
ROUTER_WAN_IP="192.168.88.24" # RPi4 看到的分享器 IP
RPI4_IP="192.168.88.1"        # RPi4 在 eth0 的 IP
echo "--- 正在套用 Vacuumd 終極修復 (不讓機器人重啟 Wi-Fi) ---"
# 1. 清除舊規則
sudo iptables -t nat -D PREROUTING -s $ROUTER_WAN_IP -p udp --dport 53 -j DNAT --to $RPI4_IP:53 2>/dev/null
sudo iptables -D FORWARD -s $ROUTER_WAN_IP ! -d 192.168.0.0/16 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null
# 2. 【關鍵】強制 DNS 攔截
# 即使機器人想找 8.8.8.8，也會被 RPi4 強制攔截回自己的 dnsmasq
echo "[1/3] 強制攔截 DNS 請求 (防止機器人發現解析失敗)..."
sudo iptables -t nat -I PREROUTING -s $ROUTER_WAN_IP -p udp --dport 53 -j DNAT --to $RPI4_IP:53
# 3. IPTables 快速拒絕 (防止掛起)
echo "[2/3] 設定快速拒絕規則..."
sudo iptables -I FORWARD -s $ROUTER_WAN_IP ! -d 192.168.0.0/16 -j REJECT --reject-with icmp-port-unreachable
# 4. DNS 劫持清單擴充
echo "[3/3] 確保 dnsmasq 包含所有必要網域..."
DOMAINS=("io.mi.com" "miwifi.com" "mi.com" "ntp.org")
RESTART_DNS=false
for domain in "${DOMAINS[@]}"; do
    if ! grep -q "address=/$domain/" /etc/dnsmasq.conf; then
        echo "address=/$domain/127.0.0.1" | sudo tee -a /etc/dnsmasq.conf > /dev/null
        RESTART_DNS=true
    fi
done
if [ "$RESTART_DNS" = true ] || [ "$1" == "restart" ]; then
    sudo systemctl restart dnsmasq
    echo "   - dnsmasq 已重啟"
fi
echo "--- 設定完成 ---"
echo "提示：現在機器人應該會以為 DNS 解析永遠成功，且連線會被快速拒絕而不掛起。"
