#!/bin/bash

set -euo pipefail

# =================================================================
# Vacuumd 網路保活腳本 (V6 - idempotent chain)
# 目標：
# 1) usb0 有外網 -> 雲端優先（僅 DNS 導向本機）
# 2) usb0 斷線 -> Fake Cloud 保活（導向 8053）
# 3) 不破壞系統其他 iptables 規則（不 flush 全表）
#
# 重要（依你目前拓樸）：
# - RPi4 上可見來源通常是「WiFi 分享器 WAN IP」（例如 192.168.88.24）
# - 非掃地機 WiFi IP（例如 192.168.1.9）
# =================================================================

USB_IF="${USB_IF:-usb0}"
LAN_IF="${LAN_IF:-eth0}"
FAKER_PORT="${FAKER_PORT:-8053}"
NAT_CHAIN="VACUUMD_FAKE_NAT"
FWD_CHAIN="VACUUMD_FAKE_FWD"

ROUTER_WAN_IP="${ROUTER_WAN_IP:-192.168.88.24}"
RPI_LAN_IP="${RPI_LAN_IP:-}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "請使用 root 權限執行（例如: sudo bash $0）"
  exit 1
fi

if [[ -z "${ROUTER_WAN_IP}" ]]; then
  echo "找不到 ROUTER_WAN_IP。請以環境變數指定，例如："
  echo "  sudo ROUTER_WAN_IP=192.168.88.24 bash $0"
  exit 1
fi

if [[ -z "${RPI_LAN_IP}" ]]; then
  RPI_LAN_IP="$(ip -4 addr show "${LAN_IF}" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true)"
fi

if [[ -z "${RPI_LAN_IP}" ]]; then
  echo "無法取得 ${LAN_IF} 的 IPv4，請以 RPI_LAN_IP 指定，例如："
  echo "  sudo ROUTER_WAN_IP=${ROUTER_WAN_IP} RPI_LAN_IP=192.168.88.1 bash $0"
  exit 1
fi

is_usb_online() {
  ip link show "${USB_IF}" >/dev/null 2>&1 || return 1
  ip link show "${USB_IF}" | grep -q "state UP" || return 1
  ip route show default dev "${USB_IF}" | grep -q "default" || return 1
}

ensure_chain() {
  local table="$1"
  local chain="$2"
  if ! iptables -t "${table}" -L "${chain}" >/dev/null 2>&1; then
    iptables -t "${table}" -N "${chain}"
  fi
}

delete_jump_if_exists() {
  local table="$1"
  local parent="$2"
  local expr="$3"
  while iptables -t "${table}" -C "${parent}" ${expr} >/dev/null 2>&1; do
    iptables -t "${table}" -D "${parent}" ${expr}
  done
}

echo "--- Vacuumd Fake Cloud 規則套用中 (V6) ---"
echo "ROUTER_WAN_IP=${ROUTER_WAN_IP} | RPI_LAN_IP=${RPI_LAN_IP} | USB_IF=${USB_IF} | FAKER_PORT=${FAKER_PORT}"

ensure_chain nat "${NAT_CHAIN}"
ensure_chain filter "${FWD_CHAIN}"

# 每次重建專屬 chain，確保 idempotent
iptables -t nat -F "${NAT_CHAIN}"
iptables -t filter -F "${FWD_CHAIN}"

# 掛回主鏈（不碰其他規則）
delete_jump_if_exists nat PREROUTING "-s ${ROUTER_WAN_IP} -j ${NAT_CHAIN}"
iptables -t nat -I PREROUTING 1 -s "${ROUTER_WAN_IP}" -j "${NAT_CHAIN}"

delete_jump_if_exists filter FORWARD "-s ${ROUTER_WAN_IP} -j ${FWD_CHAIN}"
iptables -t filter -I FORWARD 1 -s "${ROUTER_WAN_IP}" -j "${FWD_CHAIN}"

if is_usb_online; then
  echo "[模式] 雲端優先：usb0 可用"

  # 仍固定 DNS 導向本機，讓本地 DNS 決策可控
  iptables -t nat -A "${NAT_CHAIN}" -p udp --dport 53 -j DNAT --to-destination "${RPI_LAN_IP}:53"
  iptables -t nat -A "${NAT_CHAIN}" -p tcp --dport 53 -j DNAT --to-destination "${RPI_LAN_IP}:53"

  # 在線模式不做額外封鎖
  iptables -t filter -A "${FWD_CHAIN}" -j RETURN
else
  echo "[模式] 本地保活：usb0 不可用"

  # A) DNS 全導向本機（避免 Cloud 網域解析到外部）
  iptables -t nat -A "${NAT_CHAIN}" -p udp --dport 53 -j DNAT --to-destination "${RPI_LAN_IP}:53"
  iptables -t nat -A "${NAT_CHAIN}" -p tcp --dport 53 -j DNAT --to-destination "${RPI_LAN_IP}:53"

  # B) Fake Cloud 端口攔截（TCP/UDP）
  iptables -t nat -A "${NAT_CHAIN}" -p udp --dport 8053 -j DNAT --to-destination "${RPI_LAN_IP}:${FAKER_PORT}"
  for port in 8053 80 443 8443 8080; do
    iptables -t nat -A "${NAT_CHAIN}" -p tcp --dport "${port}" -j DNAT --to-destination "${RPI_LAN_IP}:${FAKER_PORT}"
  done

  # C) FORWARD 降噪：允許 LAN，快速拒絕非 LAN，避免 SYN 重傳風暴
  iptables -t filter -A "${FWD_CHAIN}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -t filter -A "${FWD_CHAIN}" -d 192.168.0.0/16 -j ACCEPT

  # 先放行少量新連線（保留觀察空間）
  iptables -t filter -A "${FWD_CHAIN}" ! -d 192.168.0.0/16 -m conntrack --ctstate NEW -m limit --limit 30/min --limit-burst 30 -j REJECT --reject-with icmp-host-prohibited
  # 其餘直接丟棄
  iptables -t filter -A "${FWD_CHAIN}" ! -d 192.168.0.0/16 -j DROP
fi

# chain 末端回主流程
iptables -t nat -A "${NAT_CHAIN}" -j RETURN

echo "--- 套用完成 ---"
echo "[NAT] ${NAT_CHAIN}"
iptables -t nat -S "${NAT_CHAIN}"
echo

echo "[FILTER] ${FWD_CHAIN}"
iptables -t filter -S "${FWD_CHAIN}"
