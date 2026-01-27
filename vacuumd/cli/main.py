import typer
import requests
import json
from typing import Optional
from tabulate import tabulate  # I'll add this for nice tables

app = typer.Typer(help="Vacuumd LAN Controller CLI")

API_BASE = "http://localhost:8000/v1"


@app.command()
def list():
    """List all configured devices."""
    try:
        resp = requests.get(f"{API_BASE}/devices/")
        resp.raise_for_status()
        devices = resp.json()
        print(tabulate(devices, headers="keys", tablefmt="grid"))
    except Exception as e:
        print(f"Error connecting to API: {e}")


@app.command()
def status(device_id: str = "robot_s5"):
    """Get the status of a robot."""
    try:
        resp = requests.get(f"{API_BASE}/devices/{device_id}/status")
        resp.raise_for_status()
        data = resp.json()

        # Prepare for table
        table = [[k, v] for k, v in data.items()]
        print(f"\nStatus for {device_id}:")
        print(tabulate(table, tablefmt="simple"))
    except Exception as e:
        print(f"Error: {e}")


@app.command()
def start(device_id: str = "robot_s5"):
    """Start cleaning."""
    _execute(device_id, "start")


@app.command()
def pause(device_id: str = "robot_s5"):
    """Pause cleaning."""
    _execute(device_id, "pause")


@app.command()
def home(device_id: str = "robot_s5"):
    """Send robot back to dock."""
    _execute(device_id, "home")


def _execute(device_id: str, command: str, params: dict = {}):
    try:
        resp = requests.post(
            f"{API_BASE}/control/execute",
            json={"device_id": device_id, "command": command, "params": params},
        )
        resp.raise_for_status()
        print(resp.json()["message"])
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    app()
