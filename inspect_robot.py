import logging
from vacuumd.controller.manager import manager
import json

logging.basicConfig(level=logging.ERROR)


def inspect():
    try:
        controller = manager.get_device("robot_s5")
        dev = controller.device

        print(f"--- 設備方法掃描 ---")
        # 找出所有包含關鍵字的方法
        keywords = ["map", "segment", "room", "floor"]
        available_methods = [
            m
            for m in dir(dev)
            if any(k in m.lower() for k in keywords) and not m.startswith("_")
        ]

        print(f"發現相關方法: {available_methods}")

        results = {}
        for method_name in available_methods:
            try:
                method = getattr(dev, method_name)
                # 只嘗試不需參數的方法
                if callable(method):
                    print(f"嘗試執行: {method_name}()...", end=" ")
                    res = method()
                    print("成功!")
                    results[method_name] = str(res)
            except Exception as e:
                print(f"失敗: {e}")

        print("\n--- 執行結果分析 ---")
        print(json.dumps(results, indent=2, ensure_ascii=False))

    except Exception as e:
        print(f"偵測失敗: {e}")


if __name__ == "__main__":
    inspect()
