from pydantic import BaseModel


class DeviceInfo(BaseModel):
    id: str
    name: str
    ip: str
    token: str
    model: str = "roborock.vacuum.s5"  # Default based on experiments
