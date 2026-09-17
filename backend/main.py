"""
Central FastAPI Monitoring Backend Application
----------------------------------------------
Serves the REST API, WebSocket streams, and mounts the Cyber SOC Dashboard UI.
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from backend.database.models import init_db
from backend.monitoring.log_watcher import ContinuousLogMonitor
import backend.api.routes as routes

# Application Lifespan Handler
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup tasks
    print("[*] Initializing Database schema...")
    init_db()

    print("[*] Initializing Continuous Log Monitoring Engine...")
    routes.log_monitor_instance = ContinuousLogMonitor(broadcast_callback=routes.ws_manager.broadcast)
    
    # Auto-start monitoring on server launch
    routes.log_monitor_instance.start()

    yield

    # Shutdown tasks
    print("[*] Shutting down Log Monitoring Engine...")
    if routes.log_monitor_instance:
        routes.log_monitor_instance.stop()

app = FastAPI(
    title="AI Web Threat Detection & Monitoring System",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration for cross-origin local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Router
app.include_router(routes.router, prefix="/api")

# Mount Frontend Static Assets
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend"))

app.mount("/css", StaticFiles(directory=os.path.join(FRONTEND_DIR, "css")), name="css")
app.mount("/js", StaticFiles(directory=os.path.join(FRONTEND_DIR, "js")), name="js")

@app.get("/")
async def serve_dashboard():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

if __name__ == "__main__":
    import uvicorn
    print("[*] Starting Monitoring Backend on http://127.0.0.1:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000)
