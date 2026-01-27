import logging
from vacuumd.controller.manager import manager
from miio.integrations.roborock.vacuum.vacuumcontainers import MapList

logging.basicConfig(level=logging.INFO)


def debug_robot(device_id="robot_s5"):
    try:
        controller = manager.get_device(device_id)
        print(f"--- 偵錯設備: {device_id} ---")

        # 1. 檢查基本狀態
        status = controller.status()
        print(f"目前狀態: {status.state}, 電量: {status.battery}%")

        # 2. 獲取原始房間映射
        print("\n嘗試獲取原始房間映射 (get_room_mapping)...")
        rooms = controller.get_room_mapping()
        print(f"結果: {rooms}")

        # 3. 獲取地圖清單
        print("\n嘗試獲取地圖清單 (get_maps)...")
        maps = controller.get_maps()
        if isinstance(maps, MapList):
            print(f"地圖數量: {maps.map_count}")
            print(f"地圖 ID 列表: {maps.map_id_list}")
            print(f"地圖名稱字典: {maps.map_name_dict}")
        else:
            print(f"無法取得 MapList 物件，回傳值: {maps}")

    except Exception as e:
        print(f"偵錯過程中發生錯誤: {e}")


if __name__ == "__main__":
    debug_robot()
