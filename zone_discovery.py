#!/usr/bin/env python3
"""
Zone ID 發現工具 (zone_discovery.py)

用途：協助找出 Roborock S5 機器人的分區 ID

使用方式：
1. 先確認機器人已在充電座上且電量充足
2. 從米家 APP 選擇一個分區（例：客廳）並啟動清掃
3. 立即執行此腳本：uv run python zone_discovery.py
4. 腳本會嘗試在機器人清掃時偵測當前分區 ID
5. 重複步驟 2-4 對每個分區進行測試

注意：由於 S5 舊韌體限制，可能無法自動偵測。
      此時請使用「手動試探法」：在 config.yaml 中設定 zones: [16]
      然後執行全屋清掃，觀察清掃開始的位置來判斷 ID。
"""

import os
import sys
import time

# 確保可以從專案根目錄匯入 vacuumd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 載入環境變數
if os.path.exists(".env"):
    with open(".env") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ[key] = value

from vacuumd.controller.manager import manager


def discover_zone():
    """嘗試在機器人清掃時偵測當前分區資訊"""

    print("=== Zone ID 發現工具 ===")
    print("請確保機器人正在清掃中，再執行此腳本。\n")

    try:
        controller = manager.get_device("robot_s5")

        print("1. 檢查機器人狀態...")
        status = controller.status()
        print(f"   狀態: {status.state}")
        print(f"   電量: {status.battery}%")

        if "Cleaning" not in status.state and "Segment" not in status.state:
            print("\n⚠️  機器人目前不在清掃狀態！")
            print("   請先從米家 APP 啟動分區清掃，再立即執行此腳本。")
            return

        print("\n2. 嘗試獲取分區資訊...")
        print(f"   檢測到正在清掃中: {status.state}")

        # 嘗試多種可能的方法
        methods = [
            ("get_segment_status", []),
            ("get_room_mapping", []),
            ("get_current_segment", []),
            ("get_current_zone", []),
        ]

        found_info = {}
        for method_name, params in methods:
            try:
                result = controller.device.send(method_name, params)
                if result and result != "unknown_method":
                    found_info[method_name] = result
                    print(f"   {method_name}: {result}")
            except Exception as e:
                pass

        if not found_info:
            print("   ❌ 無法自動偵測分區 ID")
            print("\n3. 建議手動對應方法：")
            print(
                "   - 在 config.yaml 中先設定 room_mapping: {16: 'Zone1', 17: 'Zone2', ...}"
            )
            print("   - 嘗試修改排程 zones: [16] 並觀察機器人清掃的區域")
            print("   - 逐一測試每個 ID，直到找到正確的對應關係")
        else:
            print(f"\n✅ 找到分區資訊: {found_info}")

    except Exception as e:
        print(f"錯誤: {e}")
        import traceback

        traceback.print_exc()


def test_zone(zone_id: int):
    """測試特定 Zone ID 是否可以觸發清掃"""

    print(f"=== 測試 Zone ID: {zone_id} ===")

    try:
        controller = manager.get_device("robot_s5")
        status = controller.status()

        print(f"當前狀態: {status.state}, 電量: {status.battery}%")

        if status.battery < 20:
            print("❌ 電量不足，無法測試")
            return

        if "Charging" not in status.state and "Charged" not in status.state:
            print("⚠️  建議將機器人放在充電座上再測試")

        print(f"\n發送 segment_clean([{zone_id}]) 指令...")

        # 嘗試分區清掃
        result = controller.segment_clean([zone_id])
        print(f"回傳結果: {result}")

        print("\n請觀察機器人是否開始清掃特定區域。")
        print("如果機器人無反應或報錯，請嘗試其他 Zone ID。")

    except Exception as e:
        print(f"錯誤: {e}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Zone ID 發現工具")
    parser.add_argument("--test", "-t", type=int, help="直接測試指定的 Zone ID")
    parser.add_argument(
        "--list", "-l", action="store_true", help="顯示目前 config.yaml 中的映射"
    )

    args = parser.parse_args()

    if args.test:
        test_zone(args.test)
    else:
        discover_zone()
