from typing import Dict, List
from vacuumd.config.settings import settings
from vacuumd.controller.vacuum_controller import VacuumController


class DeviceManager:
    """
    Manages multiple vacuum robot instances.
    """

    def __init__(self):
        self.devices: Dict[str, VacuumController] = {}
        self._initialize_devices()

    def _initialize_devices(self):
        for dev_cfg in settings.devices:
            controller = VacuumController(
                ip=dev_cfg.ip, token=dev_cfg.token, name=dev_cfg.name
            )
            self.devices[dev_cfg.id] = controller
            print(f"Initialized device: {dev_cfg.name} ({dev_cfg.id})")

    def get_device(self, device_id: str) -> VacuumController:
        if device_id not in self.devices:
            raise KeyError(f"Device with ID '{device_id}' not found")
        return self.devices[device_id]

    def list_devices(self) -> List[Dict[str, str]]:
        return [
            {"id": dev_id, "name": dev.name, "ip": dev.ip}
            for dev_id, dev in self.devices.items()
        ]


# Global manager instance
manager = DeviceManager()
