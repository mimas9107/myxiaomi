from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from vacuumd.api.routes import devices, control
from vacuumd.config.settings import settings
from vacuumd.scheduler.engine import automation
import os
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Vacuumd LAN Controller API")


# Startup event to initialize the automation engine and load tasks
@app.on_event("startup")
async def startup_event():
    # Start the automation engine which handles scheduled cleaning jobs
    automation.start()

    # Load initial tasks from settings or a database
    # For demo, let's add a fixed task: 13:00 everyday
    automation.add_cleaning_job(
        task_id="daily_clean", device_id="robot_s5", cron="00 13 * * *", est_duration=40
    )
    logger.info("Startup complete: Scheduler loaded.")


@app.on_event("shutdown")
async def shutdown_event():
    automation.scheduler.shutdown()
    logger.info("Shutdown: Scheduler stopped.")


# Include routers
app.include_router(devices.router, prefix="/v1/devices", tags=["devices"])
app.include_router(control.router, prefix="/v1/control", tags=["control"])

# Static files
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "view")
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
async def root():
    return FileResponse(os.path.join(static_dir, "index.html"))


@app.get("/health")
async def health():
    return {
        "project": "vacuumd",
        "status": "online",
        "devices_configured": len(settings.devices),
    }
