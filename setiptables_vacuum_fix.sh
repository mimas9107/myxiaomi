#!/bin/bash

# =================================================================
# Vacuumd 終極修復腳本 (V4 - MiCloud Faker 整合版)
# =================================================================

ROUTER_WAN_IP="192.168.88.24" # RPi4 看到的分享器 IP
RPI4_IP="192.168.88.1"        # RPi4 在 eth0 的 IP
FAKER_PORT="8053"

echo "--- 正在套用 Vacuumd 終極修復 (MiCloud Faker 模式) ---"

# 1. 清除舊規則
sudo iptables -t nat -F PREROUTING 2>/dev/null
sudo iptables -D FORWARD -s $ROUTER_WAN_IP ! -d 192.168.0.0/16 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null

# 2. 檢測 usb0 狀態
if ip addr show usb0 2>/dev/null | grep -q "UP"; then
    echo "[狀態] 對外網路 (usb0) 正常：模式 -> 雲端優先"
    # 在有網路時，我們只做 DNS 攔截，不做連線攔截，讓 App 能用
    # 但為了防止斷網瞬間掛起，我們保留 DNS 導向到 RPi4 (dnsmasq 會處理轉發)
    sudo iptables -t nat -I PREROUTING -s $ROUTER_WAN_IP -p udp --dport 53 -j DNAT --to $RPI4_IP:53
else
    echo "[狀態] 對外網路斷開：模式 -> 本地 Fake Cloud 保護"
    
    # A. 強制 DNS 攔截 (確保 STUN/Cloud 解析回 RPi4)
    sudo iptables -t nat -I PREROUTING -s $ROUTER_WAN_IP -p udp --dport 53 -j DNAT --to $RPI4_IP:53
    
    # B. 【核心】將小米雲端流量導向本地 Faker (8053)
    # 攔截所有對外的 UDP 8053 (miio cloud)
    sudo iptables -t nat -A PREROUTING -s $ROUTER_WAN_IP -p udp --dport 8053 -j DNAT --to $RPI4_IP:$FAKER_PORT
    # 攔截所有對外的 TCP 80/443 (HTTP/HTTPS cloud) 轉向 Faker
    sudo iptables -t nat -A PREROUTING -s $ROUTER_WAN_IP -p tcp --dport 80 -j DNAT --to $RPI4_IP:$FAKER_PORT
    
    # C. 其他非 LAN 流量快速拒絕
    sudo iptables -I FORWARD -s $ROUTER_WAN_IP ! -d 192.168.0.0/16 -j REJECT --reject-with icmp-port-unreachable
fi

# 3. DNS 劫持清單擴充 (確保所有小米網域解析到 RPi4)
echo "[DNS] 檢查 dnsmasq 劫持設定..."
DOMAINS=("io.mi.com" "miwifi.com" "mi.com")
RESTART_DNS=false

for domain in "${DOMAINS[@]}"; do
    if ! grep -q "address=/$domain/" /etc/dnsmasq.conf; then
        echo "address=/$domain/127.0.0.1" | sudo tee -a /etc/dnsmasq.conf > /dev/null
        RESTART_DNS=true
    fi
done

if [ "$RESTART_DNS" = true ] || [ "$1" == "restart" ]; then
    sudo systemctl restart dnsmasq
    echo "   - dnsmasq 服務已同步"
fi

echo "--- 設定完成 ---"
echo "MiCloud Faker 已在後台運行 (Port $FAKER_PORT)。"
