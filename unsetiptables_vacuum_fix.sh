#!/bin/bash

set -euo pipefail

# =================================================================
# Vacuumd Fake Cloud 回滾腳本
# 只移除 vacuumd 專屬 chain 與 jump，不影響其他 iptables 規則
# =================================================================

NAT_CHAIN="VACUUMD_FAKE_NAT"
FWD_CHAIN="VACUUMD_FAKE_FWD"

if [[ "${EUID}" -ne 0 ]]; then
  echo "請使用 root 權限執行（例如: sudo bash $0）"
  exit 1
fi

delete_jump() {
  local table="$1"
  local parent="$2"
  local chain="$3"

  while iptables -t "${table}" -C "${parent}" -j "${chain}" >/dev/null 2>&1; do
    iptables -t "${table}" -D "${parent}" -j "${chain}"
  done
}

delete_jump nat PREROUTING "${NAT_CHAIN}"
delete_jump filter FORWARD "${FWD_CHAIN}"

if iptables -t nat -L "${NAT_CHAIN}" >/dev/null 2>&1; then
  iptables -t nat -F "${NAT_CHAIN}" || true
  iptables -t nat -X "${NAT_CHAIN}" || true
fi

if iptables -t filter -L "${FWD_CHAIN}" >/dev/null 2>&1; then
  iptables -t filter -F "${FWD_CHAIN}" || true
  iptables -t filter -X "${FWD_CHAIN}" || true
fi

echo "--- Vacuumd Fake Cloud 規則已回滾 ---"
iptables -t nat -S | grep -E "VACUUMD_FAKE|PREROUTING" || true
iptables -t filter -S | grep -E "VACUUMD_FAKE|FORWARD" || true
