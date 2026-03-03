import logging
import os
import sys
from vacuumd.controller.manager import manager
import json

logging.basicConfig(level=logging.ERROR)


def load_env():
    if os.path.exists(".env"):
        with open(".env") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ[key] = value


load_env()


def deep_inspect():
    try:
        controller = manager.get_device("robot_s5")
        dev = controller.device

        print("=== 深入分區偵測 ===\n")

        # 1. 嘗試獲取地圖列表 (需要先了解地圖結構)
        print("1. 獲取地圖資訊...")
        try:
            maps = dev.get_maps()
            print(f"   get_maps(): {maps}")
            # 嘗試取得地圖詳情
            if hasattr(maps, "map_info"):
                print(f"   地圖數量: {len(maps.map_info)}")
                for idx, mi in enumerate(maps.map_info):
                    print(f"   - Map {idx}: {mi}")
        except Exception as e:
            print(f"   get_maps() 失敗: {e}")

        # 2. 嘗試發送原始指令獲取 room_id (常見於 miIO)
        print("\n2. 嘗試獲取 Room/Segment ID...")

        # 這些是常見的 miIO 指令
        commands = [
            ("get_room_mapping", []),
            ("get_segment_status", []),
            ("get_map", []),
            ("get_vi_map", []),
        ]

        for cmd, params in commands:
            if hasattr(dev, "send"):
                try:
                    print(f"   發送 {cmd}...", end=" ")
                    result = dev.send(cmd, params)
                    print(f"成功: {result[:200] if len(str(result)) > 200 else result}")
                except Exception as e:
                    print(f"失敗: {e}")

        # 3. 嘗試手動建立映射測試
        print("\n3. 測試分區 ID 範圍...")
        # 根據 config.yaml，現有映射是 16, 17, 18
        # 讓我們嘗試讀取機器的當前地圖結構
        try:
            # 嘗試取得正在使用的地圖 ID
            print("   嘗試獲取當前地圖...")
            # 某些機型可以透過 get_status 取得 map_present
            status = dev.status()
            print(f"   機器人狀態: {status.state}, 電量: {status.battery}%")
            if hasattr(status, "map_present"):
                print(f"   地圖存在: {status.map_present}")
        except Exception as e:
            print(f"   取得狀態失敗: {e}")

        # 4. 顯示當前 config.yaml 的映射設定
        print("\n4. 目前 config.yaml 中的 room_mapping:")
        print(f"   {controller.room_mapping}")

    except Exception as e:
        print(f"偵測失敗: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    deep_inspect()
