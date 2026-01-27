import sys
from pathlib import Path

# Add project root to path to allow imports
sys.path.append(str(Path(__file__).parent.parent))

from vacuumd.controller.manager import manager
import logging

logging.basicConfig(level=logging.INFO)


def test_status():
    print("--- Vacuumd Foundation Verification ---")
    devices = manager.list_devices()
    print(f"Found {len(devices)} devices in config.")

    for dev_info in devices:
        dev_id = dev_info["id"]
        print(f"\nTesting device: {dev_info['name']} ({dev_id})")
        try:
            controller = manager.get_device(dev_id)
            status = controller.status()
            print(f"  Success! Status: {status.state}")
            print(f"  Battery: {status.battery}%")
            print(f"  Fanspeed: {status.fanspeed}%")
            print(f"  Area: {status.cleaned_area} m2")
        except Exception as e:
            print(f"  Failed: {e}")


if __name__ == "__main__":
    test_status()
